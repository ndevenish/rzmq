//! ZMTP/2.0 identity exchange and v2-specific guards.
//!
//! v2 has no security handshake and no READY command — after the
//! 12-byte greeting both sides send a single identity frame (empty
//! for anonymous PUSH/PULL/PUB/SUB) and then start exchanging data
//! frames. See RFC 15 §3.
//!
//! This module is entered from `handshake::wait_for_peer_revision_impl`
//! once the peer advertised revision `0x01`. It owns the
//! `V2IdentityExchange` sub-phase and transitions to `Done` on success.

use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ZmtpProtocolHandlerX;
use crate::error::ZmqError;
use crate::message::{Msg, MsgFlags};
use crate::protocol::zmtp::greeting::{
  V2_GREETING_LENGTH, V2_SOCKET_TYPE_DEALER, V2_SOCKET_TYPE_PAIR, V2_SOCKET_TYPE_PUB,
  V2_SOCKET_TYPE_PULL, V2_SOCKET_TYPE_PUSH, V2_SOCKET_TYPE_REP, V2_SOCKET_TYPE_REQ,
  V2_SOCKET_TYPE_ROUTER, V2_SOCKET_TYPE_SUB, socket_type_name_from_code,
};
use crate::sessionx::types::{HandshakeSubPhaseX, ZmtpHandshakeProgressX};
use crate::transport::ZmtpStdStream;

/// Perform the v2 identity exchange:
///   1. Ensure the full 12-byte peer greeting is in the read buffer,
///      consume it, validate the peer's socket-type byte.
///   2. Write our empty identity frame (`0x00 0x00`).
///   3. Read peer's identity frame (expected empty, body ≤ 255 bytes,
///      no MORE flag).
///   4. Transition to `Done`.
pub(crate) async fn exchange_v2_identity<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let peer_socket_type_byte = consume_peer_v2_greeting(handler, operation_timeout).await?;
  validate_v2_socket_type_compat(&handler.config.socket_type_name, peer_socket_type_byte)?;
  if let Some(name) = socket_type_name_from_code(peer_socket_type_byte) {
    tracing::debug!(
      sca_handle = handler.actor_handle,
      peer_socket_type = %name,
      "v2 peer socket-type accepted."
    );
    handler.handshake_state.peer_socket_type = Some(name.to_string());
  }

  send_empty_identity_frame_v2(handler, operation_timeout).await?;
  let peer_identity = read_v2_identity_frame(handler, operation_timeout).await?;
  if !peer_identity.is_empty() {
    handler.handshake_state.peer_identity_from_ready =
      Some(crate::Blob::from(peer_identity.clone()));
    tracing::debug!(
      sca_handle = handler.actor_handle,
      identity_len = peer_identity.len(),
      "v2 peer sent non-empty identity."
    );
  }

  handler.handshake_state.sub_phase = HandshakeSubPhaseX::Done;
  tracing::info!(
    sca_handle = handler.actor_handle,
    "ZMTP/2.0 handshake complete."
  );
  Ok(handler
    .handshake_state
    .peer_identity_from_ready
    .take()
    .map_or(ZmtpHandshakeProgressX::HandshakeComplete, ZmtpHandshakeProgressX::IdentityReady))
}

/// Ensure `network_read_buffer` holds the full 12-byte v2 greeting,
/// then consume it. Returns the peer's socket-type byte (offset 11).
async fn consume_peer_v2_greeting<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<u8, ZmqError> {
  let deadline = std::time::Instant::now() + operation_timeout;
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;

  while handler.network_read_buffer.len() < V2_GREETING_LENGTH {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
      return Err(ZmqError::Timeout);
    }
    let br = tokio::time::timeout(
      remaining,
      stream.read_buf(&mut handler.network_read_buffer),
    )
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "v2 greeting read"))?;
    if br == 0 {
      return Err(ZmqError::ConnectionClosed);
    }
    handler.heartbeat_state.record_activity();
  }

  let socket_type_byte = handler.network_read_buffer[11];
  // Consume the 12-byte greeting; anything after stays in the buffer
  // for the identity-frame parser below to pick up.
  handler.network_read_buffer.advance(V2_GREETING_LENGTH);
  Ok(socket_type_byte)
}

/// Refuse v2 sessions where the peer's socket type cannot interoperate
/// with ours. Conservative: only allow the canonical bidirectional
/// pairs.
fn validate_v2_socket_type_compat(own_name: &str, peer_byte: u8) -> Result<(), ZmqError> {
  let peer_name = socket_type_name_from_code(peer_byte).ok_or_else(|| {
    ZmqError::ProtocolViolation(format!(
      "v2 peer advertised unknown socket-type byte {:#04x}",
      peer_byte
    ))
  })?;
  let ok = match (own_name, peer_byte) {
    ("PULL", V2_SOCKET_TYPE_PUSH) | ("PUSH", V2_SOCKET_TYPE_PULL) => true,
    ("PUB", V2_SOCKET_TYPE_SUB) | ("SUB", V2_SOCKET_TYPE_PUB) => true,
    ("REQ", V2_SOCKET_TYPE_REP) | ("REP", V2_SOCKET_TYPE_REQ) => true,
    ("REQ", V2_SOCKET_TYPE_ROUTER) | ("ROUTER", V2_SOCKET_TYPE_REQ) => true,
    ("REP", V2_SOCKET_TYPE_DEALER) | ("DEALER", V2_SOCKET_TYPE_REP) => true,
    ("DEALER", V2_SOCKET_TYPE_ROUTER) | ("ROUTER", V2_SOCKET_TYPE_DEALER) => true,
    ("DEALER", V2_SOCKET_TYPE_DEALER)
    | ("ROUTER", V2_SOCKET_TYPE_ROUTER)
    | ("PAIR", V2_SOCKET_TYPE_PAIR) => true,
    _ => false,
  };
  if !ok {
    return Err(ZmqError::ProtocolViolation(format!(
      "incompatible ZMTP/2.0 socket pairing: local {} ↔ peer {}",
      own_name, peer_name
    )));
  }
  Ok(())
}

/// Write an empty v2 data frame: `flags=0, length=0`.
async fn send_empty_identity_frame_v2<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<(), ZmqError> {
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;
  let bytes = [0x00u8, 0x00];
  tokio::time::timeout(operation_timeout, stream.write_all(&bytes))
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "v2 identity send"))?;
  tokio::time::timeout(operation_timeout, stream.flush())
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "v2 identity flush"))?;
  handler.heartbeat_state.record_activity();
  Ok(())
}

/// Decode the peer's identity frame using the manual parser. v2
/// identity frames carry no COMMAND flag (commands didn't exist in v2)
/// and must not have MORE set — anything else is a protocol violation.
async fn read_v2_identity_frame<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<Vec<u8>, ZmqError> {
  let deadline = std::time::Instant::now() + operation_timeout;

  loop {
    if !handler.network_read_buffer.is_empty() {
      match handler
        .zmtp_manual_parser
        .decode_from_buffer(&mut handler.network_read_buffer)
      {
        Ok(Some(msg)) => {
          enforce_v2_identity_constraints(&msg)?;
          handler.heartbeat_state.record_activity();
          return Ok(msg.data().unwrap_or(&[]).to_vec());
        }
        Ok(None) => {}
        Err(e) => return Err(e),
      }
    }

    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
      return Err(ZmqError::Timeout);
    }
    let stream = handler
      .stream
      .as_mut()
      .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;
    let br = tokio::time::timeout(remaining, stream.read_buf(&mut handler.network_read_buffer))
      .await
      .map_err(|_| ZmqError::Timeout)?
      .map_err(|e| ZmqError::from_io_endpoint(e, "v2 identity read"))?;
    if br == 0 {
      return Err(ZmqError::ConnectionClosed);
    }
    handler.heartbeat_state.record_activity();
  }
}

/// `MORE` and `COMMAND` flags on a v2 identity frame are both invalid.
fn enforce_v2_identity_constraints(msg: &Msg) -> Result<(), ZmqError> {
  if msg.flags().contains(MsgFlags::COMMAND) {
    return Err(ZmqError::ProtocolViolation(
      "ZMTP/2.0 identity frame had COMMAND flag set (commands do not exist in v2)".into(),
    ));
  }
  if msg.flags().contains(MsgFlags::MORE) {
    return Err(ZmqError::ProtocolViolation(
      "ZMTP/2.0 identity frame had MORE flag set (identity is a single frame)".into(),
    ));
  }
  // Identities are bounded at 255 bytes per the ZMTP spec.
  if msg.data().map_or(0, |b| b.len()) > 255 {
    return Err(ZmqError::ProtocolViolation(
      "ZMTP/2.0 identity frame exceeded 255 bytes".into(),
    ));
  }
  Ok(())
}

// Silence "unused import" warnings on the rare types we only reach
// through generic re-exports during builds without certain features.
#[allow(dead_code)]
fn _imports_in_use(_b: BytesMut) {}
