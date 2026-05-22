use super::ZmtpProtocolHandlerX;
use crate::Blob;
use crate::MsgFlags;
use crate::error::ZmqError;
use crate::message::Msg;
use crate::protocol::zmtp::ZmtpCodec;
use crate::protocol::zmtp::command::{ZmtpCommand, ZmtpReady};
use crate::protocol::zmtp::greeting::{
  GREETING_LENGTH, GREETING_VERSION_MAJOR_BYTE, NegotiatedVersion, SIGNATURE_LENGTH, ZmtpGreeting,
  ZmtpV2Greeting, encode_signature, encode_v3_tail_post_major, peek_revision, socket_type_code,
};
#[cfg(feature = "noise_xx")]
use crate::security::NoiseXxMechanism;
#[cfg(feature = "plain")]
use crate::security::PlainMechanism;
use crate::security::mechanism::ProcessTokenAction;
use crate::security::{NullMechanism, negotiate_security_mechanism};
use crate::transport::ZmtpStdStream;

use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::Encoder;

use crate::sessionx::types::{HandshakeSubPhaseX, ZmtpHandshakeProgressX};

pub(crate) async fn advance_handshake_step_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  // The overall handshake timeout (handler.config.handshake_timeout)
  // will be enforced by SessionConnectionActorX.
  let operation_timeout = handler.config.handshake_timeout.unwrap_or(Duration::from_secs(15));

  match handler.handshake_state.sub_phase {
    HandshakeSubPhaseX::GreetingExchange => send_signature_impl(handler, operation_timeout).await,
    HandshakeSubPhaseX::WaitingForPeerRevision => {
      wait_for_peer_revision_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::WaitingForGreeting => receive_greeting_impl(handler, operation_timeout).await,
    HandshakeSubPhaseX::SecurityHandshake => {
      perform_security_handshake_step_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::ReadyExchange => {
      perform_ready_exchange_step_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::ClientSentReady => {
      client_receive_peer_ready_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::ServerReceivedReady => {
      server_send_ready_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::V2IdentityExchange => {
      perform_v2_identity_exchange_impl(handler, operation_timeout).await
    }
    HandshakeSubPhaseX::Done => Ok(ZmtpHandshakeProgressX::HandshakeComplete),
  }
}

/// Reads from the stream until one complete ZMTP frame is available, then parses it.
/// This function is specifically for the handshake phase where messages are unencrypted.
/// It ensures that the returned message is a command, returning a ProtocolViolation error otherwise.
async fn read_handshake_command_frame_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  timeout_duration: Duration,
) -> Result<Msg, ZmqError> {
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable for reading handshake command".into()))?;

  // Use an overall deadline for the entire operation of getting one command.
  let deadline = tokio::time::Instant::now() + timeout_duration;

  loop {
    // 1. Attempt to parse a message from any data already in the buffer.
    if !handler.network_read_buffer.is_empty() {
      match handler
        .zmtp_manual_parser
        .decode_from_buffer(&mut handler.network_read_buffer)
      {
        Ok(Some(msg)) => {
          // Successfully parsed a message.
          handler.heartbeat_state.record_activity();

          // During the handshake, all messages MUST be command frames.
          if !msg.is_command() {
            tracing::error!(
              sca_handle = handler.actor_handle,
              "Expected COMMAND frame during handshake, but received a data frame."
            );
            return Err(ZmqError::ProtocolViolation(
              "Expected COMMAND frame in handshake".into(),
            ));
          }
          return Ok(msg);
        }
        Ok(None) => {
          // Not enough data in the buffer for a full frame. Continue to read from network.
        }
        Err(e) => return Err(e), // A parsing error occurred.
      }
    }

    // 2. If no message was parsed, read more data from the network.
    let remaining_time = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining_time.is_zero() {
      return Err(ZmqError::Timeout);
    }

    let bytes_read = tokio::time::timeout(
      remaining_time,
      stream.read_buf(&mut handler.network_read_buffer),
    )
    .await
    .map_err(|_| ZmqError::Timeout)? // Map tokio's timeout to our ZmqError::Timeout
    .map_err(|e| ZmqError::from_io_endpoint(e, "handshake command read"))?;

    if bytes_read == 0 {
      // The stream was closed by the peer.
      return Err(ZmqError::ConnectionClosed);
    }

    handler.heartbeat_state.record_activity();
    // Loop will now repeat, attempting to parse again with the new data.
  }
}

async fn send_handshake_command_frame_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  mut command_msg: Msg,
  timeout_duration: Duration,
) -> Result<(), ZmqError> {
  command_msg.set_flags(MsgFlags::COMMAND);
  let mut temp_zmtp_encoder = ZmtpCodec::new();
  let mut encoded_command_buffer = BytesMut::new();
  temp_zmtp_encoder.encode(command_msg.clone(), &mut encoded_command_buffer)?;

  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable for send".into()))?;
  tokio::time::timeout(timeout_duration, stream.write_all(&encoded_command_buffer))
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "handshake command send"))?;
  handler.heartbeat_state.record_activity();
  Ok(())
}

/// Stage A of the staged greeting: write `signature(10) + 0x03` —
/// the 10-byte ZMTP signature followed immediately by our own major
/// version byte. Then transition to `WaitingForPeerRevision`.
///
/// This is exactly libzmq's behaviour. Byte 10 is *always* the
/// sender's own major version — it is not a "downgrade request" and
/// is not version-dependent, so it is safe to send before learning
/// anything about the peer:
///
/// - a v3 peer reads `0x03` and is satisfied;
/// - a v2-only peer reads `0x03`, treats it as "remote is ≥ v2", and
///   caps the session at its own max (v2) — it does not reject it.
///
/// Only the bytes from offset 11 onward differ between v2 and v3, and
/// those are held back until `WaitingForPeerRevision` has seen the
/// peer's byte 10. Because every installment a peer needs to advance
/// (signature, then byte 10) is sent unconditionally before any
/// version-dependent byte, two rzmq peers doing this dance never
/// deadlock — no negotiation timeout is required.
async fn send_signature_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;

  // Signature (10 bytes) + our major version byte (0x03).
  let mut prelude = BytesMut::with_capacity(SIGNATURE_LENGTH + 1);
  encode_signature(&mut prelude);
  prelude.put_u8(GREETING_VERSION_MAJOR_BYTE);

  tokio::time::timeout(operation_timeout, stream.write_all(&prelude))
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g sig send"))?;
  tokio::time::timeout(operation_timeout, stream.flush())
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g sig flush"))?;

  handler.heartbeat_state.record_activity();
  tracing::debug!(
    sca_handle = handler.actor_handle,
    role = if handler.is_server { "S" } else { "C" },
    "Sent ZMTP signature + major version (11 bytes); awaiting peer revision."
  );

  // We're about to read into network_read_buffer. Clear it so reads of
  // the peer's signature+revision don't accidentally pick up stale
  // bytes from a prior cancelled handshake.
  handler.network_read_buffer.clear();
  if handler.network_read_buffer.capacity() < GREETING_LENGTH {
    handler.network_read_buffer.reserve(GREETING_LENGTH);
  }
  handler.handshake_state.sub_phase = HandshakeSubPhaseX::WaitingForPeerRevision;
  Ok(ZmtpHandshakeProgressX::InProgress)
}

/// Stage B of the staged greeting: read until we have the peer's first
/// 11 bytes (signature + revision), inspect byte 10, then write our
/// version-dependent tail and transition to the appropriate state.
///
/// - peer revision `0x01` ⇒ write our v2 tail (1 byte: socket-type)
///   and jump to `V2IdentityExchange`. `negotiated_version` ← `V2`.
/// - peer revision `0x03+` ⇒ write our v3 tail (53 bytes) and continue
///   into `WaitingForGreeting`. `negotiated_version` is set to
///   `V3 { minor }` once we've seen the full v3 greeting.
/// - any other revision ⇒ `ProtocolViolation`. ZMTP/1.0 framing is
///   different enough that we intentionally don't try to negotiate it.
async fn wait_for_peer_revision_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  const PEEK_LEN: usize = SIGNATURE_LENGTH + 1; // 11 bytes — signature + byte 10

  let peer_revision =
    read_peer_signature_and_peek_revision(handler, operation_timeout, PEEK_LEN).await?;
  tracing::debug!(
    sca_handle = handler.actor_handle,
    role = if handler.is_server { "S" } else { "C" },
    peer_revision = format_args!("{:#04x}", peer_revision),
    "Peeked peer revision byte; selecting greeting tail."
  );
  match peer_revision {
    ZmtpV2Greeting::REVISION => write_v2_tail_and_advance(handler, operation_timeout).await,
    v if v >= GREETING_VERSION_MAJOR_BYTE => {
      write_v3_tail_and_advance(handler, operation_timeout).await
    }
    other => Err(ZmqError::ProtocolViolation(format!(
      "Unsupported ZMTP revision {:#04x} (only 0x01 and 0x03+ are supported)",
      other
    ))),
  }
}

/// Read from the stream until `network_read_buffer` holds at least
/// `peek_len` bytes, then validate the ZMTP signature and return the
/// revision byte at offset 10. Bounded by `operation_timeout`; no
/// shorter fallback is needed because the peer always sends its
/// signature + byte 10 unconditionally (see `send_signature_impl`).
async fn read_peer_signature_and_peek_revision<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
  peek_len: usize,
) -> Result<u8, ZmqError> {
  let deadline = Instant::now() + operation_timeout;
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;

  while handler.network_read_buffer.len() < peek_len {
    let remaining_time = deadline.saturating_duration_since(Instant::now());
    if remaining_time.is_zero() {
      return Err(ZmqError::Timeout);
    }
    let br = tokio::time::timeout(
      remaining_time,
      stream.read_buf(&mut handler.network_read_buffer),
    )
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g peek read"))?;
    if br == 0 {
      return Err(ZmqError::ConnectionClosed);
    }
    handler.heartbeat_state.record_activity();
  }
  // peek_revision validates signature bytes 0..9 and returns byte 10.
  peek_revision(&handler.network_read_buffer[..peek_len])
}

/// Write our 1-byte v2 tail — the socket-type byte at offset 11.
/// Byte 10 (our major version `0x03`) was already sent with the
/// signature in `send_signature_impl`, so the greeting on the wire
/// ends up as `signature(10) + 0x03 + socket_type` = 12 bytes. This
/// matches libzmq, whose downgraded greeting also carries `0x03` at
/// byte 10; a v2 peer keys the session version off its *own* offered
/// revision, not off ours. Transitions to `V2IdentityExchange`.
async fn write_v2_tail_and_advance<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  if !handler.config.allow_zmtp2 {
    return Err(ZmqError::ProtocolViolation(
      "peer advertised ZMTP/2.0 but allow_zmtp2 is disabled".into(),
    ));
  }
  let stype_byte = socket_type_code(&handler.config.socket_type_name).ok_or_else(|| {
    ZmqError::ProtocolViolation(format!(
      "no ZMTP/2.0 socket-type byte for socket type {:?}",
      handler.config.socket_type_name
    ))
  })?;
  let mut tail = BytesMut::with_capacity(1);
  tail.put_u8(stype_byte);

  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;
  tokio::time::timeout(operation_timeout, stream.write_all(&tail))
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g v2 tail send"))?;
  tokio::time::timeout(operation_timeout, stream.flush())
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g v2 tail flush"))?;

  handler.negotiated_version = Some(NegotiatedVersion::V2);
  tracing::info!(
    sca_handle = handler.actor_handle,
    socket_type = %handler.config.socket_type_name,
    socket_type_code = stype_byte,
    "Downgraded to ZMTP/2.0 after peer advertised revision 0x01."
  );
  handler.handshake_state.sub_phase = HandshakeSubPhaseX::V2IdentityExchange;
  Ok(ZmtpHandshakeProgressX::InProgress)
}

/// Write our 53-byte v3 tail — bytes 11..63 of the greeting: minor +
/// 20-byte mechanism + as-server + 31 padding. Byte 10 (major `0x03`)
/// was already sent with the signature in `send_signature_impl`, so
/// the complete greeting on the wire is 64 bytes. Transitions to
/// `WaitingForGreeting`.
async fn write_v3_tail_and_advance<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let mech = determine_own_greeting_mechanism_impl(handler);
  let is_server = handler.is_server;
  let mut tail = BytesMut::with_capacity(GREETING_LENGTH - SIGNATURE_LENGTH - 1);
  encode_v3_tail_post_major(mech, is_server, &mut tail);

  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;
  tokio::time::timeout(operation_timeout, stream.write_all(&tail))
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g v3 tail send"))?;
  tokio::time::timeout(operation_timeout, stream.flush())
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g v3 tail flush"))?;

  tracing::debug!(
    sca_handle = handler.actor_handle,
    "Sent v3 greeting tail (53 bytes); awaiting full peer greeting."
  );
  handler.handshake_state.sub_phase = HandshakeSubPhaseX::WaitingForGreeting;
  Ok(ZmtpHandshakeProgressX::InProgress)
}

/// Receives the peer's ZMTP greeting.  Does NOT clear `network_read_buffer` so
/// that any bytes accumulated before a prior cancellation are preserved.
async fn receive_greeting_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let deadline = Instant::now() + operation_timeout;
  let stream = handler
    .stream
    .as_mut()
    .ok_or_else(|| ZmqError::Internal("Stream unavailable".into()))?;
  while handler.network_read_buffer.len() < GREETING_LENGTH {
    let remaining_time = deadline.saturating_duration_since(Instant::now());
    if remaining_time.is_zero() {
      return Err(ZmqError::Timeout);
    }
    let br = tokio::time::timeout(
      remaining_time,
      stream.read_buf(&mut handler.network_read_buffer),
    )
    .await
    .map_err(|_| ZmqError::Timeout)?
    .map_err(|e| ZmqError::from_io_endpoint(e, "g read"))?;
    if br == 0 {
      return Err(ZmqError::ConnectionClosed);
    }
    handler.heartbeat_state.record_activity();
  }
  match ZmtpGreeting::decode(&mut handler.network_read_buffer) {
    Ok(Some(pg)) => {
      if pg.version.0 < 3 {
        // Shouldn't happen — staged greeting would have caught a v2
        // peer in `WaitingForPeerRevision`. Treat as a protocol bug.
        return Err(ZmqError::ProtocolViolation(format!(
          "V {}.{}",
          pg.version.0, pg.version.1
        )));
      }
      handler.negotiated_version = Some(NegotiatedVersion::V3 {
        minor: pg.version.1,
      });
      handler.pending_peer_greeting = Some(pg);
      handler.handshake_state.sub_phase = HandshakeSubPhaseX::SecurityHandshake;
      Ok(ZmtpHandshakeProgressX::InProgress)
    }
    Ok(None) => Err(ZmqError::ProtocolViolation("g decode".into())),
    Err(e) => Err(e),
  }
}

/// Phase 3 entry point — performs the ZMTP/2.0 identity exchange and
/// transitions the handshake state machine to `Done`. Implemented in
/// the v2-path module.
async fn perform_v2_identity_exchange_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  super::v2_path::exchange_v2_identity(handler, operation_timeout).await
}

fn determine_own_greeting_mechanism_impl<S: ZmtpStdStream>(
  handler: &ZmtpProtocolHandlerX<S>,
) -> &'static [u8; 20] {
  #[cfg(feature = "noise_xx")]
  if handler.config.use_noise_xx {
    let can_propose_noise = if handler.is_server {
      handler.config.noise_xx_local_sk_bytes_for_engine.is_some()
    } else {
      handler.config.noise_xx_local_sk_bytes_for_engine.is_some()
        && handler.config.noise_xx_remote_pk_bytes_for_engine.is_some()
    };
    if can_propose_noise {
      return NoiseXxMechanism::NAME_BYTES;
    }
  }

  #[cfg(feature = "curve")]
  if handler.config.use_curve {
    return crate::security::CurveMechanism::NAME_BYTES;
  }

  #[cfg(feature = "plain")]
  if handler.config.use_plain {
    return PlainMechanism::NAME_BYTES;
  }

  return NullMechanism::NAME_BYTES;
}

async fn perform_security_handshake_step_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  // 1. One-time setup: On the first entry into this phase, negotiate and
  //    initialize the actual security mechanism based on the peer's greeting.
  if handler.security_mechanism.name() == "NULL" {
    let peer_greeting = handler.pending_peer_greeting.as_ref().ok_or_else(|| {
      ZmqError::Internal("Handshake entered security phase without a peer greeting".to_string())
    })?;

    // This replaces the initial NullMechanism with the negotiated one (e.g., CurveMechanism).
    handler.security_mechanism = negotiate_security_mechanism(
      handler.is_server,
      &handler.config,
      peer_greeting,
      handler.actor_handle,
    )?;

    tracing::debug!(
      sca_handle = handler.actor_handle,
      mechanism = handler.security_mechanism.name(),
      "Security mechanism negotiated and initialized."
    );
  }

  // 2. Main handshake loop: Drive the mechanism's state machine.
  loop {
    // Check for terminal states first.
    if handler.security_mechanism.is_complete() {
      // The handshake is done. Finalize it by creating the framer.
      let mechanism_to_finalize =
        std::mem::replace(&mut handler.security_mechanism, Box::new(NullMechanism));

      let (new_framer, id_opt) = mechanism_to_finalize.into_framer(handler.config.max_msg_size)?;
      handler.framer = new_framer;

      // Transition the main handshake state machine to the next phase.
      handler.handshake_state.sub_phase = HandshakeSubPhaseX::ReadyExchange;

      // Report progress, including the identity if the mechanism provided one.
      return if let Some(identity) = id_opt {
        Ok(ZmtpHandshakeProgressX::IdentityReady(identity.into()))
      } else {
        Ok(ZmtpHandshakeProgressX::InProgress)
      };
    }

    if handler.security_mechanism.is_error() {
      return Err(ZmqError::SecurityError(
        handler
          .security_mechanism
          .error_reason()
          .unwrap_or("Unknown security error")
          .to_string(),
      ));
    }

    // A. Ask the mechanism if it has a token to send.
    if let Some(token_to_send) = handler.security_mechanism.produce_token()? {
      tracing::debug!(
        sca_handle = handler.actor_handle,
        token_len = token_to_send.len(),
        mechanism = handler.security_mechanism.name(),
        "Handshake: Producing and sending security token."
      );
      let command_msg = Msg::from_vec(token_to_send);
      send_handshake_command_frame_impl(handler, command_msg, operation_timeout).await?;
      // After sending, loop immediately to check the new state. The mechanism might
      // be complete now (e.g., client after sending INITIATE).
      continue;
    }

    // B. If no token to send, we must be waiting for the peer.
    tracing::trace!(
      sca_handle = handler.actor_handle,
      mechanism = handler.security_mechanism.name(),
      "Handshake: Waiting to read security token from peer."
    );
    let received_msg = read_handshake_command_frame_impl(handler, operation_timeout).await?;
    let token_data = received_msg.data().unwrap_or(&[]);
    tracing::debug!(
      sca_handle = handler.actor_handle,
      token_len = token_data.len(),
      mechanism = handler.security_mechanism.name(),
      "Handshake: Read and processing peer's security token."
    );

    // C. Process the received token and determine the next action.
    let action = handler.security_mechanism.process_token(token_data)?;

    match action {
      ProcessTokenAction::ContinueWaiting => {
        // The mechanism consumed the token and is still waiting for more from the peer.
        // The loop will repeat, which will lead back to reading from the network.
      }
      ProcessTokenAction::ProduceAndSend => {
        // The mechanism has a reply ready. Send it immediately.
        if let Some(token_to_send) = handler.security_mechanism.produce_token()? {
          tracing::debug!(
            sca_handle = handler.actor_handle,
            token_len = token_to_send.len(),
            "Handshake: Immediately producing and sending reply token."
          );
          let command_msg = Msg::from_vec(token_to_send);
          send_handshake_command_frame_impl(handler, command_msg, operation_timeout).await?;
          // After sending the reply, loop again to check the new state.
        } else {
          // This indicates a logic error within the mechanism's implementation.
          return Err(ZmqError::Internal(
            "Mechanism requested ProduceAndSend but then produced no token.".to_string(),
          ));
        }
      }
      ProcessTokenAction::HandshakeComplete => {
        // The mechanism is now complete after processing the peer's token.
        // The loop will repeat and the `is_complete()` check at the top will catch this
        // and trigger the transition to the next phase.
      }
    }
    // After any action, we loop to re-evaluate the state machine.
  }
}

fn build_ready_properties<S: ZmtpStdStream>(handler: &ZmtpProtocolHandlerX<S>) -> HashMap<String, Vec<u8>> {
  let mut props = HashMap::new();
  props.insert(
    "Socket-Type".to_string(),
    handler.config.socket_type_name.as_bytes().to_vec(),
  );
  let socket_type = &handler.config.socket_type_name;
  if socket_type == "REQ" || socket_type == "DEALER" || socket_type == "ROUTER" {
    let identity = handler.config.routing_id.as_ref().map_or_else(
      Vec::new,
      |blob| blob.to_vec(),
    );
    if identity.len() <= 255 {
      props.insert("Identity".to_string(), identity);
    }
  }
  props
}

fn parse_peer_ready_identity(peer_ready_data: &ZmtpReady) -> Option<Blob> {
  peer_ready_data.properties.get("Identity")
    .filter(|id_v| !id_v.is_empty() && id_v.len() <= 255)
    .map(|id_v| id_v.clone().into())
}

/// Client: sends its READY command and transitions to `ClientSentReady`.
/// Server: reads the client's READY, stores parsed data, transitions to `ServerReceivedReady`.
async fn perform_ready_exchange_step_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  if !handler.is_server {
    let props = build_ready_properties(handler);
    send_handshake_command_frame_impl(handler, ZmtpReady::create_msg(props), operation_timeout)
      .await?;
    tracing::debug!(sca_handle = handler.actor_handle, "Client sent READY.");
    handler.handshake_state.sub_phase = HandshakeSubPhaseX::ClientSentReady;
    Ok(ZmtpHandshakeProgressX::InProgress)
  } else {
    let recv_ready_msg = read_handshake_command_frame_impl(handler, operation_timeout).await?;
    let peer_ready_data = match ZmtpCommand::parse(&recv_ready_msg) {
      Some(ZmtpCommand::Ready(data)) => data,
      _ => return Err(ZmqError::ProtocolViolation("Expected READY".into())),
    };
    let peer_socket_type_str = peer_ready_data
      .properties
      .get("Socket-Type")
      .and_then(|bytes| String::from_utf8(bytes.clone()).ok());
    if let Some(ref peer_type) = peer_socket_type_str {
      tracing::debug!(sca_handle = handler.actor_handle, %peer_type, "Peer announced its Socket-Type in READY command.");
      handler.handshake_state.peer_socket_type = Some(peer_type.clone());
    } else {
      tracing::warn!(sca_handle = handler.actor_handle, "Peer did not announce Socket-Type in READY command. Assuming legacy or non-compliant peer.");
    }
    tracing::debug!(sca_handle = handler.actor_handle, "Recvd peer READY.");
    handler.handshake_state.peer_identity_from_ready = parse_peer_ready_identity(&peer_ready_data);
    handler.handshake_state.sub_phase = HandshakeSubPhaseX::ServerReceivedReady;
    Ok(ZmtpHandshakeProgressX::InProgress)
  }
}

/// Client: reads the server's READY and completes the handshake.
async fn client_receive_peer_ready_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let recv_ready_msg = read_handshake_command_frame_impl(handler, operation_timeout).await?;
  let peer_ready_data = match ZmtpCommand::parse(&recv_ready_msg) {
    Some(ZmtpCommand::Ready(data)) => data,
    _ => return Err(ZmqError::ProtocolViolation("Expected READY".into())),
  };
  let peer_socket_type_str = peer_ready_data
    .properties
    .get("Socket-Type")
    .and_then(|bytes| String::from_utf8(bytes.clone()).ok());
  if let Some(ref peer_type) = peer_socket_type_str {
    tracing::debug!(sca_handle = handler.actor_handle, %peer_type, "Peer announced its Socket-Type in READY command.");
    handler.handshake_state.peer_socket_type = Some(peer_type.clone());
  } else {
    tracing::warn!(sca_handle = handler.actor_handle, "Peer did not announce Socket-Type in READY command. Assuming legacy or non-compliant peer.");
  }
  tracing::debug!(sca_handle = handler.actor_handle, "Recvd peer READY.");
  let final_peer_id = parse_peer_ready_identity(&peer_ready_data);
  handler.handshake_state.sub_phase = HandshakeSubPhaseX::Done;
  Ok(final_peer_id.map_or(ZmtpHandshakeProgressX::HandshakeComplete, ZmtpHandshakeProgressX::IdentityReady))
}

/// Server: sends its own READY command and completes the handshake.
/// The peer identity (parsed in `perform_ready_exchange_step_impl`) is taken from state.
async fn server_send_ready_impl<S: ZmtpStdStream>(
  handler: &mut ZmtpProtocolHandlerX<S>,
  operation_timeout: Duration,
) -> Result<ZmtpHandshakeProgressX, ZmqError> {
  let props = build_ready_properties(handler);
  send_handshake_command_frame_impl(handler, ZmtpReady::create_msg(props), operation_timeout)
    .await?;
  tracing::debug!(sca_handle = handler.actor_handle, "Server sent READY.");
  let final_peer_id = handler.handshake_state.peer_identity_from_ready.take();
  handler.handshake_state.sub_phase = HandshakeSubPhaseX::Done;
  Ok(final_peer_id.map_or(ZmtpHandshakeProgressX::HandshakeComplete, ZmtpHandshakeProgressX::IdentityReady))
}
