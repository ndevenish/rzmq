#![cfg(feature = "io-uring")]
//! io_uring-path variant of the ZMTP/2.0 downgrade happy-path test.
//!
//! `v2_downgrade.rs` exercises the `sessionx` (Tokio-stream) handshake.
//! This file drives the same raw-TCP `V2PushServer` harness against an
//! rzmq PULL socket whose session runs on the **io_uring backend**
//! (`IO_URING_SESSION_ENABLED`). It is the Phase 5 acceptance signal:
//! the parallel handshake state machine in
//! `io_uring_backend/zmtp_handler.rs` must downgrade to ZMTP/2.0 the
//! same way the `sessionx` path does.
//!
//! The downgrade proof is identical: rzmq (like libzmq) always writes
//! its own major version `0x03` at byte 10, so byte 11 being the PULL
//! socket-type code `0x07` — i.e. a 12-byte v2 greeting rather than a
//! 64-byte v3 one — is what shows the io_uring handler downgraded.

use std::sync::Once;
use std::time::Duration;

use rzmq::socket::options::IO_URING_SESSION_ENABLED;
use rzmq::uring::{initialize_uring_backend, UringConfig};
use rzmq::{Msg, MsgFlags, SocketType, ZmqError};

mod common;
mod v2_push_server;

use v2_push_server::{FillPattern, V2PushServer, V2PushServerConfig};

const HANDSHAKE_GRACE: Duration = Duration::from_millis(300);
const PER_RECV_TIMEOUT: Duration = Duration::from_secs(3);

static URING_INIT: Once = Once::new();

/// Initialize the process-global io_uring backend exactly once. The
/// backend is a singleton shared by every io_uring socket in the
/// process, so repeated test runs must tolerate "already initialized".
fn ensure_uring_backend() {
  URING_INIT.call_once(|| {
    match initialize_uring_backend(UringConfig::default()) {
      Ok(()) => {}
      Err(ZmqError::InvalidState(msg)) if msg.contains("already initialized") => {}
      Err(e) => panic!("failed to initialize io_uring backend: {:?}", e),
    }
  });
}

fn dump_transcript(label: &str, bytes: &[u8]) -> String {
  let preview: Vec<String> = bytes.iter().take(72).map(|b| format!("{:02x}", b)).collect();
  format!(
    "{} ({} bytes): {}{}",
    label,
    bytes.len(),
    preview.join(" "),
    if bytes.len() > 72 { " ..." } else { "" },
  )
}

/// Spawn the harness with `cfg`, connect an io_uring-backed rzmq PULL,
/// drain all parts, and assert the wire downgraded to v2 and the
/// payload arrived intact with multipart boundaries preserved.
async fn run_v2_iouring_pull_test(cfg: V2PushServerConfig) -> Result<(), ZmqError> {
  ensure_uring_backend();
  let ctx = common::test_context();

  let expected_messages = cfg.frame_count;
  let parts_per_msg = cfg.frame_parts;
  let frame_size = cfg.frame_size;
  let fill = cfg.fill.clone();
  let total_parts = expected_messages.saturating_mul(parts_per_msg);

  let server = V2PushServer::spawn(cfg).await.expect("spawn v2 server");
  let endpoint = server.endpoint();

  let pull = ctx.socket(SocketType::Pull)?;
  pull.set_option(IO_URING_SESSION_ENABLED, 1i32).await?;
  pull.connect(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

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

  drop(pull);

  let outcome = server.finish().await.expect("server task join");
  let transcript = dump_transcript("peer transcript", &outcome.peer_raw_bytes);

  // === Wire-level assertions ===
  assert_eq!(
    outcome.peer_revision, 0x03,
    "expected rzmq io_uring handler to advertise major version 0x03 at byte 10, \
     got 0x{:02x}. harness_error={:?}. {}",
    outcome.peer_revision, outcome.error, transcript
  );
  assert_eq!(
    outcome.peer_byte11,
    v2_push_server::PULL,
    "expected byte 11 == PULL (0x07) — proof the io_uring handler wrote a v2 \
     greeting — got 0x{:02x}. harness_error={:?}. {}",
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
async fn v2_push_to_iouring_pull_negotiates_v2_and_delivers_payload() -> Result<(), ZmqError> {
  // Defaults: 256 single-part messages, 512-byte bodies, ByteN fill.
  run_v2_iouring_pull_test(V2PushServerConfig::default()).await
}

#[tokio::test]
async fn v2_push_to_iouring_pull_multipart_messages() -> Result<(), ZmqError> {
  // 64 messages × 3 parts. Catches an io_uring handler that surfaces
  // multipart frames as separate messages or drops MORE flags.
  let cfg = V2PushServerConfig {
    frame_count: 64,
    frame_parts: 3,
    frame_size: 128,
    fill: FillPattern::ByteN,
    ..V2PushServerConfig::default()
  };
  run_v2_iouring_pull_test(cfg).await
}

#[tokio::test]
async fn v2_push_to_iouring_pull_long_frames() -> Result<(), ZmqError> {
  // Bodies >255 bytes exercise the LONG-flag (8-byte length) framing.
  let cfg = V2PushServerConfig {
    frame_count: 16,
    frame_parts: 1,
    frame_size: 8192,
    fill: FillPattern::Counter { start: 0 },
    ..V2PushServerConfig::default()
  };
  run_v2_iouring_pull_test(cfg).await
}
