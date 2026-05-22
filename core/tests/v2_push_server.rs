//! Hand-rolled ZMTP/2.0 PUSH server for testing rzmq's v2 downgrade path.
//!
//! Pure raw-TCP — no rzmq, no libzmq, no tokio-util codec. Every byte
//! that goes on the wire is written here, so tests can assert exactly
//! what rzmq sent in reply.
//!
//! Speaks only what's needed for the PUSH side of a PUSH/PULL session:
//!
//!   1. v2.0 greeting — 10-byte signature + revision + socket-type
//!   2. Empty identity frame (v2-framed: `\x00 \x00`)
//!   3. N data frames of configured fill pattern, optionally multipart
//!   4. Hold open briefly so the peer's recv() can drain
//!
//! Used as `mod v2_push_server;` at the top of integration tests under
//! `core/tests/`.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

// === ZMTP/2.0 socket-type bytes (RFC 15 §4) ===
pub const PAIR: u8 = 0x00;
pub const PUB: u8 = 0x01;
pub const SUB: u8 = 0x02;
pub const REQ: u8 = 0x03;
pub const REP: u8 = 0x04;
pub const DEALER: u8 = 0x05;
pub const ROUTER: u8 = 0x06;
pub const PULL: u8 = 0x07;
pub const PUSH: u8 = 0x08;

pub const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(5);

const MORE_FLAG: u8 = 0x01;
const LONG_FLAG: u8 = 0x02;

/// What to put in each emitted frame body.
#[derive(Debug, Clone)]
pub enum FillPattern {
  /// Every body byte = `(frame_index * parts_per_frame + part_index) as u8`.
  /// Fast assertion via `body.iter().all(|&b| b == expected)`.
  ByteN,
  /// Body starts with an 8-byte little-endian counter equal to
  /// `start + (frame_index * parts_per_frame + part_index)`, rest is
  /// zeros. Catches ordering and frame-boundary corruption that
  /// `ByteN`'s modular wrap would mask.
  Counter { start: u64 },
}

impl FillPattern {
  pub fn fill(&self, frame: usize, part: usize, parts_per_frame: usize, body_size: usize) -> Vec<u8> {
    let global = frame
      .saturating_mul(parts_per_frame)
      .saturating_add(part);
    match *self {
      FillPattern::ByteN => vec![global as u8; body_size],
      FillPattern::Counter { start } => {
        let mut buf = vec![0u8; body_size];
        let n = start.wrapping_add(global as u64).to_le_bytes();
        let prefix = 8.min(body_size);
        buf[..prefix].copy_from_slice(&n[..prefix]);
        buf
      }
    }
  }
}

/// Points at which the server deliberately drops the connection.
/// Used for negative-path tests — rzmq must error cleanly, not
/// reconnect-storm.
#[derive(Debug, Clone, Copy)]
pub enum AbortPoint {
  /// Close after writing 10 bytes (signature only).
  PostSignature,
  /// Close after writing the full 12-byte greeting.
  PostGreeting,
  /// Close after writing greeting + empty identity frame.
  PostIdentity,
  /// Close after sending N *messages* (all their parts). Consistent
  /// multipart boundaries — useful for "torn-down mid-stream" tests.
  AfterNMessages(usize),
  /// Close after sending N *wire frames* (parts). Use with
  /// `frame_parts > 1` to tear down mid-message — verifies the SUT
  /// doesn't deliver a partial multipart to the application.
  AfterNParts(usize),
}

#[derive(Debug, Clone)]
pub struct V2PushServerConfig {
  /// Number of logical messages. Each message is `frame_parts` v2 frames.
  pub frame_count: usize,
  /// Number of v2 frames per logical message. 1 = single-part. ≥2 sets
  /// the MORE flag on all but the last part.
  pub frame_parts: usize,
  /// Body size per *part* (not per message). Same size for every part.
  pub frame_size: usize,
  pub fill: FillPattern,
  /// Socket-type byte we advertise. Default `PUSH`; override for
  /// mismatch tests (e.g. `PUB` to verify the SUT rejects cleanly).
  pub send_socket_type: u8,
  /// Revision byte we advertise. Default `0x01`; override to probe
  /// how the SUT reacts to unknown revisions.
  pub send_revision: u8,
  /// How long to hold the socket open after the last data frame so
  /// the peer can drain its recv buffer.
  pub hold_after_send: Duration,
  /// If `Some`, abort the session at this point.
  pub abort_after: Option<AbortPoint>,
  /// Per-phase timeout. `None` ⇒ [`DEFAULT_PHASE_TIMEOUT`].
  pub phase_timeout: Option<Duration>,
}

impl Default for V2PushServerConfig {
  fn default() -> Self {
    Self {
      frame_count: 256,
      frame_parts: 1,
      frame_size: 512,
      fill: FillPattern::ByteN,
      send_socket_type: PUSH,
      send_revision: 0x01,
      hold_after_send: Duration::from_secs(2),
      abort_after: None,
      phase_timeout: None,
    }
  }
}

/// Everything the harness observed on the wire from the SUT.
///
/// Tests assert on these fields to verify the SUT's *outgoing* wire
/// behaviour — complementing payload-level assertions on what rzmq
/// delivered to the application.
#[derive(Debug, Clone)]
pub struct V2ServerOutcome {
  /// Logical messages fully written (all parts flushed).
  pub messages_sent: usize,
  /// Total v2 frames pushed onto the wire. Equals
  /// `messages_sent * frame_parts` when no abort fires.
  pub parts_sent: usize,
  /// Peer's byte 10. `0x01` ⇒ rzmq downgraded; `0x03` ⇒ it didn't.
  /// Zero if the peer wrote fewer than 11 bytes.
  pub peer_revision: u8,
  /// Peer's byte 11. For `peer_revision == 0x01` this is the
  /// socket-type byte; for `0x03` it's the v3 minor version.
  /// Zero if the peer wrote fewer than 12 bytes.
  pub peer_byte11: u8,
  /// Identity frame body the peer sent post-greeting. Empty for
  /// anonymous PULL/PUSH peers.
  pub peer_identity: Vec<u8>,
  /// Every byte the peer wrote to the socket — greeting, identity,
  /// any trailing commands or surprises. Print as hex on test
  /// failure for forensics.
  pub peer_raw_bytes: Vec<u8>,
  /// Stringified anyhow error if the harness gave up before finishing
  /// the normal flow (e.g. read timeout while waiting for a v2-only
  /// peer that's still expecting more v3 greeting bytes). `None` ⇒
  /// the session completed without an internal error. Tests that
  /// want a "fully clean run" should assert this is `None`.
  pub error: Option<String>,
}

/// A growing buffer of peer-side bytes plus a cursor into it.
///
/// Reads append to `bytes`; parsers advance `cursor`. The full
/// transcript ends up in `bytes` regardless of how far parsers got,
/// so the test always gets a complete capture.
struct Capture {
  bytes: Vec<u8>,
  cursor: usize,
}

impl Capture {
  fn new() -> Self {
    Self {
      bytes: Vec::with_capacity(128),
      cursor: 0,
    }
  }

  /// Block until at least `n` bytes are available past the cursor.
  /// Reads from `conn` in 1 KiB chunks; errors on EOF or timeout.
  async fn ensure(&mut self, conn: &mut TcpStream, n: usize, to: Duration) -> Result<()> {
    let target = self.cursor.saturating_add(n);
    let deadline = tokio::time::Instant::now() + to;
    let mut tmp = [0u8; 1024];
    while self.bytes.len() < target {
      let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
      if remain.is_zero() {
        bail!(
          "read timeout (have {} bytes, want {})",
          self.bytes.len(),
          target
        );
      }
      let r = timeout(remain, conn.read(&mut tmp))
        .await
        .map_err(|_| anyhow::anyhow!("read timeout"))??;
      if r == 0 {
        bail!(
          "EOF after {} bytes (wanted {})",
          self.bytes.len(),
          target
        );
      }
      self.bytes.extend_from_slice(&tmp[..r]);
    }
    Ok(())
  }

  fn consume(&mut self, n: usize) -> &[u8] {
    let end = self.cursor + n;
    let slice = &self.bytes[self.cursor..end];
    self.cursor = end;
    slice
  }

  /// Best-effort drain — read whatever's still in flight, append to
  /// the buffer, until EOF or `cap` elapses. Used at the end of the
  /// session and after aborts to capture trailing bytes.
  async fn drain(&mut self, conn: &mut TcpStream, cap: Duration) {
    let deadline = tokio::time::Instant::now() + cap;
    let mut tmp = [0u8; 1024];
    loop {
      let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
      if remain.is_zero() {
        break;
      }
      match timeout(remain, conn.read(&mut tmp)).await {
        Ok(Ok(0)) => break,
        Ok(Ok(n)) => self.bytes.extend_from_slice(&tmp[..n]),
        _ => break,
      }
    }
  }
}

/// Read one v2 frame off the wire, appending raw bytes to `cap` as
/// we go, and return the body.
async fn read_v2_frame_via(conn: &mut TcpStream, cap: &mut Capture, to: Duration) -> Result<Vec<u8>> {
  cap.ensure(conn, 1, to).await?;
  let flags = cap.consume(1)[0];
  let body_len = if flags & LONG_FLAG != 0 {
    cap.ensure(conn, 8, to).await?;
    let bytes: [u8; 8] = cap.consume(8).try_into().unwrap();
    u64::from_be_bytes(bytes) as usize
  } else {
    cap.ensure(conn, 1, to).await?;
    cap.consume(1)[0] as usize
  };
  cap.ensure(conn, body_len, to).await?;
  Ok(cap.consume(body_len).to_vec())
}

/// Encode a v2 data frame: flags + length + body.
fn encode_v2_data_frame(body: &[u8], more: bool) -> Vec<u8> {
  let mut flags = if more { MORE_FLAG } else { 0 };
  let mut out = Vec::with_capacity(body.len() + 9);
  if body.len() <= 255 {
    out.push(flags);
    out.push(body.len() as u8);
  } else {
    flags |= LONG_FLAG;
    out.push(flags);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
  }
  out.extend_from_slice(body);
  out
}

/// A spawned PUSH-side v2 server bound on an ephemeral 127.0.0.1 port.
///
/// Construct with [`V2PushServer::spawn`], pass `endpoint()` to the
/// SUT's `connect()`, then `finish()` to await the outcome.
pub struct V2PushServer {
  addr: SocketAddr,
  handle: JoinHandle<V2ServerOutcome>,
}

impl V2PushServer {
  /// Bind 127.0.0.1 on an ephemeral port and spawn the server task.
  /// Returns once `bind()` has succeeded so the caller can immediately
  /// `connect()` without a race.
  pub async fn spawn(cfg: V2PushServerConfig) -> Result<Self> {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .context("v2 push server bind")?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(run(listener, cfg));
    Ok(Self { addr, handle })
  }

  pub fn endpoint(&self) -> String {
    format!("tcp://{}", self.addr)
  }

  pub fn addr(&self) -> SocketAddr {
    self.addr
  }

  /// Await the server task and return its observed outcome.
  /// The outcome always carries whatever the harness managed to see
  /// on the wire; tests should inspect `outcome.error` to know whether
  /// the harness ran to completion or bailed out early.
  pub async fn finish(self) -> Result<V2ServerOutcome> {
    self.handle.await.context("v2 push server join")
  }
}

async fn run(listener: TcpListener, cfg: V2PushServerConfig) -> V2ServerOutcome {
  let mut state = RunState::default();
  let err = run_inner(listener, cfg, &mut state).await.err();
  // Even if `run_inner` short-circuited (an abort point, a read error,
  // or any `?` along the way) we still want the test to see what the
  // SUT actually put on the wire. Look at the raw capture and surface
  // bytes 10/11 — that's where revision and socket-type live in both
  // v2 (12-byte) and v3 (64-byte) greetings, so the test can assert on
  // the SUT's negotiation behaviour without caring which abort fired.
  if state.peer_revision == 0 {
    state.peer_revision = state.cap.bytes.get(10).copied().unwrap_or(0);
  }
  if state.peer_byte11 == 0 {
    state.peer_byte11 = state.cap.bytes.get(11).copied().unwrap_or(0);
  }
  state.into_outcome(err.map(|e| format!("{:#}", e)))
}

/// Accumulated state during `run_inner`. Always returnable as an
/// outcome, even when `run_inner` bailed mid-flow.
#[derive(Default)]
struct RunState {
  cap: Capture,
  peer_revision: u8,
  peer_byte11: u8,
  peer_identity: Vec<u8>,
  messages_sent: usize,
  parts_sent: usize,
}

impl Default for Capture {
  fn default() -> Self {
    Self::new()
  }
}

impl RunState {
  fn into_outcome(self, error: Option<String>) -> V2ServerOutcome {
    V2ServerOutcome {
      messages_sent: self.messages_sent,
      parts_sent: self.parts_sent,
      peer_revision: self.peer_revision,
      peer_byte11: self.peer_byte11,
      peer_identity: self.peer_identity,
      peer_raw_bytes: self.cap.bytes,
      error,
    }
  }
}

async fn run_inner(
  listener: TcpListener,
  cfg: V2PushServerConfig,
  state: &mut RunState,
) -> Result<()> {
  let phase_to = cfg.phase_timeout.unwrap_or(DEFAULT_PHASE_TIMEOUT);

  let (mut conn, _peer_addr) = timeout(phase_to, listener.accept())
    .await
    .context("accept timed out")??;
  // Drop the listener immediately so a SUT in a reconnect loop can't
  // open a second connection mid-test and confuse the outcome.
  drop(listener);
  conn.set_nodelay(true).ok();

  // === Stage 1: signature (10 bytes) ===
  conn
    .write_all(&[0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f])
    .await?;

  if matches!(cfg.abort_after, Some(AbortPoint::PostSignature)) {
    state
      .cap
      .drain(&mut conn, Duration::from_millis(200))
      .await;
    conn.shutdown().await.ok();
    return Ok(());
  }

  // === Stage 2: revision + socket-type ===
  conn
    .write_all(&[cfg.send_revision, cfg.send_socket_type])
    .await?;

  if matches!(cfg.abort_after, Some(AbortPoint::PostGreeting)) {
    state
      .cap
      .drain(&mut conn, Duration::from_millis(200))
      .await;
    conn.shutdown().await.ok();
    return Ok(());
  }

  // === Stage 3: capture peer's greeting bytes ===
  //
  // This harness is a *ZMTP/2.0* peer: we advertised revision
  // `send_revision` (0x01 by default), so as far as we are concerned
  // the session is v2 and the peer's greeting is exactly 12 bytes —
  // `signature(10) + revision + socket-type`. We deliberately do NOT
  // use the peer's byte 10 to decide the greeting length: a real v3
  // peer (libzmq, or rzmq's downgrade path) writes `0x03` at byte 10
  // *even when downgrading to talk to us*, and a faithful v2 peer
  // just reads 12 bytes regardless and treats byte 11 as the peer's
  // socket-type.
  //
  // `peer_revision`/`peer_byte11` are recorded purely for the test's
  // forensic assertions; the downgrade signal a test should key on is
  // `peer_byte11` being a valid socket-type code (in a v3 greeting
  // byte 11 is the minor-version `0x00`), plus a successful v2
  // identity exchange below. If the SUT failed to downgrade and sent
  // a 64-byte v3 greeting, the bytes past offset 12 get misparsed as
  // frames and the harness surfaces an `error`.
  state.cap.ensure(&mut conn, 12, phase_to).await?;
  state.peer_revision = state.cap.bytes[10];
  state.peer_byte11 = state.cap.bytes[11];
  state.cap.cursor = 12;

  // === Stage 4: send empty identity frame ===
  conn.write_all(&[0x00, 0x00]).await?; // flags=0, len=0

  if matches!(cfg.abort_after, Some(AbortPoint::PostIdentity)) {
    state
      .cap
      .drain(&mut conn, Duration::from_millis(200))
      .await;
    conn.shutdown().await.ok();
    return Ok(());
  }

  // === Stage 5: read peer's identity frame ===
  // Sequenced after our own send rather than concurrently — keeps the
  // harness simple and tracing-readable. Both libzmq and rzmq write
  // eagerly so the bytes are already buffered locally.
  state.peer_identity = read_v2_frame_via(&mut conn, &mut state.cap, phase_to).await?;

  // === Stage 6: send data frames ===
  'outer: for frame in 0..cfg.frame_count {
    if let Some(AbortPoint::AfterNMessages(n)) = cfg.abort_after {
      if frame == n {
        conn.shutdown().await.ok();
        break;
      }
    }
    for part in 0..cfg.frame_parts {
      if let Some(AbortPoint::AfterNParts(n)) = cfg.abort_after {
        if state.parts_sent == n {
          conn.shutdown().await.ok();
          break 'outer;
        }
      }
      let body = cfg
        .fill
        .fill(frame, part, cfg.frame_parts, cfg.frame_size);
      let more = part + 1 < cfg.frame_parts;
      let wire = encode_v2_data_frame(&body, more);
      if let Err(e) = conn.write_all(&wire).await {
        tracing::warn!(
          "v2 push server: peer hung up at message {} part {}: {}",
          frame,
          part,
          e
        );
        break 'outer;
      }
      state.parts_sent += 1;
    }
    state.messages_sent += 1;
  }

  // === Stage 7: hold + drain concurrently ===
  // The hold gives the peer time to drain its recv buffer; the drain
  // captures any trailing bytes (PINGs, surprises) for forensics.
  // Whichever finishes first stops the wait.
  let hold = cfg.hold_after_send;
  tokio::select! {
    _ = state.cap.drain(&mut conn, hold) => {}
    _ = tokio::time::sleep(hold) => {}
  }
  conn.shutdown().await.ok();
  Ok(())
}
