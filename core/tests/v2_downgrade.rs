//! Happy-path tests for rzmq's ZMTP/2.0 downgrade.
//!
//! Drives the raw-TCP `V2PushServer` harness against an rzmq PULL socket
//! and asserts both wire-level and payload-level properties.
//!
//! The downgrade signal is byte 11 of the SUT's greeting: rzmq (like
//! libzmq) always writes its own major version `0x03` at byte 10 even
//! when downgrading, so byte 10 alone tells you nothing. The session
//! is v2 because the *peer* (this harness) only offered revision
//! `0x01`. The observable proof rzmq downgraded is therefore that it
//! wrote a 12-byte greeting whose byte 11 is the PULL socket-type code
//! `0x07` (in a 64-byte v3 greeting, byte 11 would be the minor
//! version `0x00`) and then completed a v2 identity exchange.
//!
//! On rzmq <= 0.5.15 these tests fail meaningfully: rzmq sends a full
//! 64-byte v3 greeting, the harness misparses bytes 12+ as frames, and
//! recv() hangs or errors. The multipart and counter-fill variants are
//! Phase 4 acceptance signals — they exercise data-frame paths that
//! COMMAND-flag suppression and v2 codec choices have to keep intact.

use std::time::Duration;

use rzmq::{Msg, MsgFlags, SocketType, ZmqError};

mod common;
mod v2_push_server;

use v2_push_server::{FillPattern, V2PushServer, V2PushServerConfig};

const HANDSHAKE_GRACE: Duration = Duration::from_millis(200);
const PER_RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Pretty-print the harness's transcript on failure. The first 16 bytes
/// of byte 10–11 tell you the version negotiated; the rest is forensics.
fn dump_transcript(label: &str, bytes: &[u8]) -> String {
  let preview: Vec<String> = bytes
    .iter()
    .take(72)
    .map(|b| format!("{:02x}", b))
    .collect();
  format!(
    "{} ({} bytes): {}{}",
    label,
    bytes.len(),
    preview.join(" "),
    if bytes.len() > 72 { " ..." } else { "" },
  )
}

/// Spawn the harness with `cfg`, connect an rzmq PULL, receive
/// `frame_count * frame_parts` parts, and assert that:
///
/// - the SUT downgraded to v2 on the wire (byte 10 = `0x01`, byte 11 =
///   the PULL socket-type byte);
/// - each part has the correct fill;
/// - multipart boundaries (MORE flag) are preserved exactly as the
///   harness wrote them.
async fn run_v2_pull_test(cfg: V2PushServerConfig) -> Result<(), ZmqError> {
  let ctx = common::test_context();

  let expected_messages = cfg.frame_count;
  let parts_per_msg = cfg.frame_parts;
  let frame_size = cfg.frame_size;
  let fill = cfg.fill.clone();
  let total_parts = expected_messages.saturating_mul(parts_per_msg);

  let server = V2PushServer::spawn(cfg).await.expect("spawn v2 server");
  let endpoint = server.endpoint();

  let pull = ctx.socket(SocketType::Pull)?;
  pull.connect(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  // Drain everything. Each frame should arrive within PER_RECV_TIMEOUT
  // once the handshake is past. If recv times out keep going so the
  // wire-level assertions can fire with the captured transcript.
  let mut received: Vec<Msg> = Vec::with_capacity(total_parts);
  let mut recv_error: Option<(usize, ZmqError)> = None;
  for i in 0..total_parts {
    match common::recv_timeout(&pull, PER_RECV_TIMEOUT).await {
      Ok(msg) => received.push(msg),
      Err(e) => {
        recv_error = Some((i, e));
        break;
      }
    }
  }

  // Tear down the rzmq side first so the harness's hold_after_send
  // wait completes promptly and we can collect the transcript.
  drop(pull);

  let outcome = server.finish().await.expect("server task join");
  let transcript = dump_transcript("peer transcript", &outcome.peer_raw_bytes);

  // === Wire-level assertions ===
  // byte 10 is rzmq's own major version — always 0x03, exactly like
  // libzmq, even on a downgraded session.
  assert_eq!(
    outcome.peer_revision, 0x03,
    "expected rzmq to advertise major version 0x03 at byte 10 (libzmq-faithful), \
     got 0x{:02x}. harness_error={:?}. {}",
    outcome.peer_revision, outcome.error, transcript
  );
  // byte 11 is the real downgrade signal: the PULL socket-type code in
  // a 12-byte v2 greeting (it would be the minor-version 0x00 in a
  // 64-byte v3 greeting).
  assert_eq!(
    outcome.peer_byte11,
    v2_push_server::PULL,
    "expected byte 11 == PULL (0x07) — proof rzmq wrote a v2 greeting — got 0x{:02x}. \
     harness_error={:?}. {}",
    outcome.peer_byte11, outcome.error, transcript
  );

  // === Payload-level assertions ===
  if let Some((i, e)) = recv_error.as_ref() {
    panic!(
      "recv #{} failed: {:?} (got {} frames so far). harness_error={:?}. {}",
      i,
      e,
      received.len(),
      outcome.error,
      transcript
    );
  }
  assert_eq!(
    outcome.error, None,
    "harness reported error: {:?}. {}",
    outcome.error, transcript
  );
  assert_eq!(
    received.len(),
    total_parts,
    "part count mismatch (expected {} msgs × {} parts = {}). {}",
    expected_messages,
    parts_per_msg,
    total_parts,
    transcript
  );

  for global_idx in 0..total_parts {
    let frame = global_idx / parts_per_msg;
    let part = global_idx % parts_per_msg;
    let msg = &received[global_idx];
    let body = msg.data().unwrap_or_default();

    assert_eq!(
      body.len(),
      frame_size,
      "part #{} (msg {}, sub-part {}) wrong size. {}",
      global_idx,
      frame,
      part,
      transcript
    );

    let expected = fill.fill(frame, part, parts_per_msg, frame_size);
    assert_eq!(
      body,
      expected.as_slice(),
      "part #{} (msg {}, sub-part {}) body mismatch. {}",
      global_idx,
      frame,
      part,
      transcript
    );

    let is_last_part_of_msg = part + 1 == parts_per_msg;
    let has_more = msg.flags().contains(MsgFlags::MORE);
    assert_eq!(
      has_more,
      !is_last_part_of_msg,
      "part #{} (msg {}, sub-part {}): MORE flag is {} but expected {}. {}",
      global_idx,
      frame,
      part,
      has_more,
      !is_last_part_of_msg,
      transcript
    );
  }

  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_push_to_rzmq_pull_negotiates_v2_and_delivers_payload() -> Result<(), ZmqError> {
  // Defaults: 256 single-part messages, 512-byte bodies, ByteN fill.
  run_v2_pull_test(V2PushServerConfig::default()).await
}

#[tokio::test]
async fn v2_push_to_rzmq_pull_multipart_messages() -> Result<(), ZmqError> {
  // Multipart: 64 messages × 3 parts each. The MORE flag must be set on
  // parts 0 and 1 and cleared on part 2 of every message. Catches
  // "rzmq surfaced 2 messages where it should have surfaced 1
  // multipart" — which is exactly what the original Eiger workload
  // would suffer from.
  let cfg = V2PushServerConfig {
    frame_count: 64,
    frame_parts: 3,
    frame_size: 128,
    fill: FillPattern::ByteN,
    ..V2PushServerConfig::default()
  };
  run_v2_pull_test(cfg).await
}

#[tokio::test]
async fn v2_push_to_rzmq_pull_counter_fill() -> Result<(), ZmqError> {
  // Counter fill catches reordering and frame-boundary corruption that
  // ByteN's per-byte wrap would mask: each body starts with an 8-byte
  // little-endian counter that increments by 1 per part, globally.
  let cfg = V2PushServerConfig {
    frame_count: 64,
    frame_parts: 2,
    frame_size: 32,
    fill: FillPattern::Counter { start: 1_000_000 },
    ..V2PushServerConfig::default()
  };
  run_v2_pull_test(cfg).await
}

#[tokio::test]
async fn v2_push_to_rzmq_pull_long_frames() -> Result<(), ZmqError> {
  // Bodies >255 bytes go through the LONG-flag (8-byte length) path in
  // the v2 framing. Make sure rzmq's parser handles them without
  // confusion. 8KB is comfortably larger than 255 and matches typical
  // Eiger-detector image-payload sizes.
  let cfg = V2PushServerConfig {
    frame_count: 16,
    frame_parts: 1,
    frame_size: 8192,
    fill: FillPattern::Counter { start: 0 },
    ..V2PushServerConfig::default()
  };
  run_v2_pull_test(cfg).await
}
