//! Phase 6d regression guard: the staged-greeting change must not
//! break rzmq↔rzmq, which always negotiates ZMTP/3.x.
//!
//! The interesting case is two rzmq peers both running the staged
//! greeting: each writes its 10-byte signature and waits for the
//! other's revision byte. Neither sends byte 10 eagerly, so the
//! `PEER_REVISION_FALLBACK` timer is what breaks the tie — both fall
//! back, both commit to v3, both complete the handshake. This file
//! exercises exactly that path with PUSH↔PULL and DEALER↔ROUTER and
//! asserts data flows in both directions.
//!
//! The broader regression surface (every existing `push_pull.rs`,
//! `req_rep.rs`, … test) is covered by running the normal suite; this
//! file just pins the specific "both peers stage the greeting" case
//! with an explicit assertion so a future change to the fallback
//! logic fails here loudly rather than as a mysterious timeout
//! somewhere else.

use std::time::Duration;

use rzmq::{Msg, SocketType, ZmqError};

mod common;

const SETTLE: Duration = Duration::from_millis(150);
const RECV_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test]
async fn v3_push_pull_tcp_still_negotiates() -> Result<(), ZmqError> {
  let ctx = common::test_context();
  let push = ctx.socket(SocketType::Push)?;
  let pull = ctx.socket(SocketType::Pull)?;

  // Fixed port, kept distinct from the ports used in other test files.
  let endpoint = "tcp://127.0.0.1:5701";
  pull.bind(endpoint).await?;
  tokio::time::sleep(SETTLE).await;
  push.connect(endpoint).await?;
  tokio::time::sleep(SETTLE).await;

  for i in 0..32 {
    push
      .send(Msg::from_vec(format!("v3-msg-{}", i).into_bytes()))
      .await?;
  }
  for i in 0..32 {
    let msg = common::recv_timeout(&pull, RECV_TIMEOUT).await?;
    assert_eq!(
      msg.data().unwrap_or_default(),
      format!("v3-msg-{}", i).as_bytes()
    );
  }

  ctx.term().await?;
  Ok(())
}

#[tokio::test]
async fn v3_dealer_router_tcp_still_negotiates() -> Result<(), ZmqError> {
  let ctx = common::test_context();
  let router = ctx.socket(SocketType::Router)?;
  let dealer = ctx.socket(SocketType::Dealer)?;

  let endpoint = "tcp://127.0.0.1:5702";
  router.bind(endpoint).await?;
  tokio::time::sleep(SETTLE).await;
  dealer.connect(endpoint).await?;
  tokio::time::sleep(SETTLE).await;

  // DEALER → ROUTER: ROUTER prepends the dealer's identity frame.
  dealer.send(Msg::from_static(b"ping")).await?;
  let identity = common::recv_timeout(&router, RECV_TIMEOUT).await?;
  assert!(
    identity.is_more(),
    "ROUTER should deliver an identity frame with MORE set"
  );
  let body = common::recv_timeout(&router, RECV_TIMEOUT).await?;
  assert_eq!(body.data().unwrap_or_default(), b"ping");

  // ROUTER → DEALER: echo back, addressed by identity.
  let mut id_frame = Msg::from_vec(identity.data().unwrap_or_default().to_vec());
  id_frame.set_flags(rzmq::MsgFlags::MORE);
  router.send(id_frame).await?;
  router.send(Msg::from_static(b"pong")).await?;
  let reply = common::recv_timeout(&dealer, RECV_TIMEOUT).await?;
  assert_eq!(reply.data().unwrap_or_default(), b"pong");

  ctx.term().await?;
  Ok(())
}
