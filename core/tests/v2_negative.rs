//! Negative-path tests for rzmq's ZMTP/2.0 downgrade.
//!
//! Each test drives the raw-TCP `V2PushServer` harness with a
//! deliberately broken stage and asserts that rzmq:
//!
//!   - errors cleanly out of `recv()` (or returns the data it already
//!     received up to the abort point) within a bounded time,
//!   - does not deliver partial multipart messages to the application,
//!   - did write a ZMTP/2.0 greeting tail when it got far enough —
//!     observable as byte 11 being the PULL socket-type code (byte 10
//!     is always rzmq's own major version 0x03, libzmq-faithful).
//!
//! Together these guard against the failure modes that motivated the
//! v2 downgrade work in the first place: reconnect storms, partial
//! deliveries, and silent stalls.
//!
//! We don't bother counting accept attempts — the harness drops the
//! listener immediately after its first accept, so any reconnect
//! attempt from rzmq fails at the TCP layer and is invisible to the
//! harness by construction.

use std::time::Duration;

use rzmq::socket::options::{RECONNECT_IVL, ZMTP2_ALLOWED};
use rzmq::{MsgFlags, SocketType, ZmqError};

mod common;
mod v2_push_server;

use v2_push_server::{AbortPoint, FillPattern, V2PushServer, V2PushServerConfig};

const HANDSHAKE_GRACE: Duration = Duration::from_millis(200);
const PER_RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Big reconnect interval so that, if rzmq decides to retry after the
/// peer aborts, the retry doesn't race against the rest of the test.
/// The harness has already dropped its listener at this point so any
/// retry would just fail with ECONNREFUSED anyway, but a 30s interval
/// keeps the trace logs uncluttered.
const QUIET_RECONNECT_IVL_MS: i32 = 30_000;

/// Pretty-print the harness's transcript on failure.
fn dump_transcript(label: &str, bytes: &[u8]) -> String {
  let preview: Vec<String> = bytes
    .iter()
    .take(32)
    .map(|b| format!("{:02x}", b))
    .collect();
  format!(
    "{} ({} bytes): {}{}",
    label,
    bytes.len(),
    preview.join(" "),
    if bytes.len() > 32 { " ..." } else { "" },
  )
}

/// Connect a PULL socket with a long reconnect interval so retries
/// don't race the test, then return both the context and the socket.
async fn pull_at(endpoint: &str) -> Result<(rzmq::Context, rzmq::Socket), ZmqError> {
  let ctx = common::test_context();
  let pull = ctx.socket(SocketType::Pull)?;
  pull
    .set_option(RECONNECT_IVL, &QUIET_RECONNECT_IVL_MS.to_ne_bytes())
    .await?;
  pull.connect(endpoint).await?;
  Ok((ctx, pull))
}

// --- Aborts during the handshake stages -------------------------------

#[tokio::test]
async fn v2_abort_after_signature_errors_within_timeout() -> Result<(), ZmqError> {
  // Harness writes only the 10-byte signature, then closes. rzmq is in
  // `WaitingForPeerRevision` (Phase 2 state) — it can't peek byte 10
  // because the peer hung up first. Should surface as a recv error or
  // timeout, *not* hang forever.
  let cfg = V2PushServerConfig {
    abort_after: Some(AbortPoint::PostSignature),
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error after peer aborted post-signature, got {:?}",
    result.as_ref().map(|m| m.data().map(|d| d.len()))
  );
  drop(pull);
  let outcome = server.finish().await.expect("server join");
  // rzmq didn't get far enough to write its own tail, so we don't
  // assert on peer_revision here — it'll be 0 (nothing past byte 10).
  assert_eq!(outcome.messages_sent, 0);
  assert_eq!(outcome.parts_sent, 0);
  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_abort_after_greeting_errors_within_timeout() -> Result<(), ZmqError> {
  // Harness writes signature + revision/type then closes. rzmq peeks
  // byte 10=0x01, writes its v2 tail, transitions to V2IdentityExchange
  // — then hits EOF reading the peer's identity frame.
  let cfg = V2PushServerConfig {
    abort_after: Some(AbortPoint::PostGreeting),
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error after peer aborted post-greeting"
  );
  drop(pull);
  let outcome = server.finish().await.expect("server join");
  let transcript = dump_transcript("transcript", &outcome.peer_raw_bytes);
  // rzmq peeked the harness's revision 0x01, wrote its v2 tail (byte
  // 11 == socket-type), then hit EOF reading the identity frame. byte
  // 10 is rzmq's own major version 0x03 (libzmq-faithful); the v2
  // downgrade is visible as byte 11 being the PULL socket-type code.
  assert_eq!(
    outcome.peer_byte11,
    v2_push_server::PULL,
    "rzmq should have written a v2 greeting tail even though peer aborted. {}",
    transcript
  );
  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_abort_after_identity_errors_within_timeout() -> Result<(), ZmqError> {
  // Harness writes full greeting + identity, then closes before any
  // data. rzmq completes the v2 handshake successfully, then sees EOF
  // in the operational phase. recv() should error out, not hang.
  let cfg = V2PushServerConfig {
    abort_after: Some(AbortPoint::PostIdentity),
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error after peer aborted post-identity (handshake completed but no data)"
  );
  drop(pull);
  let outcome = server.finish().await.expect("server join");
  // byte 10 = rzmq's own major version (0x03); byte 11 = the v2
  // socket-type code, proof the downgrade greeting was written.
  assert_eq!(outcome.peer_revision, 0x03);
  assert_eq!(outcome.peer_byte11, v2_push_server::PULL);
  ctx.term().await?;
  Ok(())
}

// --- Aborts during the data phase ------------------------------------

#[tokio::test]
async fn v2_abort_after_n_messages_delivers_n_then_errors() -> Result<(), ZmqError> {
  // The peer sends 5 single-part messages then closes. rzmq must
  // deliver exactly 5; recv #6 must error.
  const N: usize = 5;
  let cfg = V2PushServerConfig {
    frame_count: 100,
    frame_parts: 1,
    frame_size: 16,
    fill: FillPattern::Counter { start: 0 },
    abort_after: Some(AbortPoint::AfterNMessages(N)),
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  for i in 0..N {
    let msg = common::recv_timeout(&pull, PER_RECV_TIMEOUT)
      .await
      .unwrap_or_else(|e| panic!("recv #{} failed: {:?}", i, e));
    let body = msg.data().unwrap_or_default();
    let expected_first = (i as u64).to_le_bytes();
    assert_eq!(
      &body[..8],
      &expected_first[..],
      "msg #{} counter mismatch",
      i
    );
  }

  let after = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    after.is_err(),
    "expected recv #{} to error after peer aborted, got msg of len {:?}",
    N,
    after.as_ref().map(|m| m.data().map(|d| d.len()))
  );

  drop(pull);
  let outcome = server.finish().await.expect("server join");
  assert_eq!(outcome.messages_sent, N);
  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_abort_mid_multipart_never_delivers_partial() -> Result<(), ZmqError> {
  // 3 parts per message; the harness tears down after the FIRST part
  // of the second message (parts_sent == 4, i.e. 3 parts of msg 0 then
  // part 0 of msg 1). rzmq must deliver msg 0 in full and MUST NOT
  // surface msg 1's partial first part — its FairQueue assembles
  // multipart messages atomically.
  const PARTS_PER_MSG: usize = 3;
  let cfg = V2PushServerConfig {
    frame_count: 4,
    frame_parts: PARTS_PER_MSG,
    frame_size: 32,
    fill: FillPattern::ByteN,
    abort_after: Some(AbortPoint::AfterNParts(PARTS_PER_MSG + 1)),
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  // Drain msg 0 (3 parts). All but the last carry MORE.
  for part in 0..PARTS_PER_MSG {
    let msg = common::recv_timeout(&pull, PER_RECV_TIMEOUT)
      .await
      .unwrap_or_else(|e| panic!("msg 0 part {} recv failed: {:?}", part, e));
    let has_more = msg.flags().contains(MsgFlags::MORE);
    let is_last = part + 1 == PARTS_PER_MSG;
    assert_eq!(
      has_more, !is_last,
      "msg 0 part {}: MORE flag mismatch",
      part
    );
  }

  // Now no further full message can arrive — msg 1 is incomplete on
  // the wire. recv must time out / error rather than delivering a
  // partial message.
  let after = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    after.is_err(),
    "rzmq must not surface a partial multipart message"
  );

  drop(pull);
  let _ = server.finish().await.expect("server join");
  ctx.term().await?;
  Ok(())
}

// --- Mismatched configuration ----------------------------------------

#[tokio::test]
async fn v2_socket_type_mismatch_errors_cleanly() -> Result<(), ZmqError> {
  // Harness advertises PUB (0x01); we connect PULL. PULL ↔ PUB is not
  // a valid pairing, so v2_path::validate_v2_socket_type_compat must
  // reject the session. recv() must error rather than hang or — worse
  // — proceed to accept frames from an incompatible peer.
  let cfg = V2PushServerConfig {
    send_socket_type: v2_push_server::PUB,
    abort_after: None,
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error on incompatible socket pairing (PULL ↔ PUB)"
  );
  drop(pull);
  let outcome = server.finish().await.expect("server join");
  // rzmq still wrote its v2 greeting tail advertising PULL before
  // detecting the incompatible pairing and tearing down. byte 10 is
  // rzmq's own major version 0x03; byte 11 is the PULL socket-type.
  assert_eq!(outcome.peer_revision, 0x03);
  assert_eq!(outcome.peer_byte11, v2_push_server::PULL);
  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_bad_revision_rejected_without_retry() -> Result<(), ZmqError> {
  // Harness advertises revision 0x02 — unknown. `wait_for_peer_revision`
  // must reject (it accepts 0x01 or ≥0x03 only). recv() errors.
  let cfg = V2PushServerConfig {
    send_revision: 0x02,
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();
  let (ctx, pull) = pull_at(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error on unknown peer revision 0x02"
  );
  drop(pull);
  // rzmq saw 0x02 at the peek and rejected without ever writing its
  // own tail — so we don't assert on peer_revision (it'll be 0x00 or
  // whatever bytes rzmq managed to send before erroring, but never a
  // committed tail).
  let _ = server.finish().await.expect("server join");
  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v2_downgrade_refused_when_zmtp2_disabled() -> Result<(), ZmqError> {
  // A v2-only peer, but the PULL socket has ZMTP2_ALLOWED set to 0 —
  // strict v3-only mode. rzmq peeks the peer's revision 0x01 and must
  // refuse to downgrade: recv() errors instead of completing a v2
  // session. This pins the opt-out behaviour of the ZMTP2_ALLOWED
  // socket option.
  let cfg = V2PushServerConfig {
    phase_timeout: Some(Duration::from_secs(3)),
    ..V2PushServerConfig::default()
  };

  let server = V2PushServer::spawn(cfg).await.expect("spawn");
  let endpoint = server.endpoint();

  let ctx = common::test_context();
  let pull = ctx.socket(SocketType::Pull)?;
  pull
    .set_option(RECONNECT_IVL, &QUIET_RECONNECT_IVL_MS.to_ne_bytes())
    .await?;
  // 0 == strict v3-only; refuse the ZMTP/2.0 downgrade.
  pull
    .set_option(ZMTP2_ALLOWED, &0i32.to_ne_bytes())
    .await?;
  pull.connect(&endpoint).await?;
  tokio::time::sleep(HANDSHAKE_GRACE).await;

  let result = common::recv_timeout(&pull, PER_RECV_TIMEOUT).await;
  assert!(
    result.is_err(),
    "expected recv to error: ZMTP2_ALLOWED=0 must refuse the v2 downgrade"
  );

  drop(pull);
  let _ = server.finish().await.expect("server join");
  ctx.term().await?;
  Ok(())
}
