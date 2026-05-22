#![allow(dead_code)] // Allow dead code for now as we build incrementally

use crate::error::ZmqError;
use crate::Blob;

/// Phases for the SessionConnectionActorX lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionPhaseX {
  /// Actor just started, stream might be present but no pipes from SocketCore yet.
  Initial,
  /// ZMTP handshake (Greeting, Security, Ready) is in progress.
  HandshakeInProgress,
  /// Handshake complete, but waiting for AttachPipesAndRoutingInfo from SocketCore.
  WaitingForPipes,
  /// Handshake done, pipes attached. Normal data transfer phase.
  Operational,
  /// Graceful shutdown of the ZMTP stream and connection initiated.
  ShuttingDownStream,
  /// Actor is finalizing and loop should exit.
  Terminating,
}

/// Progress of the ZMTP handshake, returned by `ZmtpProtocolHandlerX::advance_handshake`.
#[derive(Debug, Clone)] // Clone needed if we store it temporarily
pub(crate) enum ZmtpHandshakeProgressX {
  /// Handshake is ongoing, more steps needed.
  InProgress,
  /// Security mechanism has established a peer identity.
  IdentityReady(Blob),
  /// Entire ZMTP handshake (Greeting, Security, Ready) is complete.
  HandshakeComplete,
  /// A ZMTP-level error occurred during handshake that might be recoverable by retrying a step,
  /// or might need to be escalated by the SessionConnectionActorX.
  ProtocolError(String),
  /// An unrecoverable error occurred.
  FatalError(ZmqError),
}

/// Internal sub-phases for ZmtpProtocolHandlerX's handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeSubPhaseX {
  /// Sending the 10-byte ZMTP signature to the peer. This is Stage A of
  /// the staged-greeting dance — libzmq writes 10 bytes and waits for
  /// the peer's revision byte before deciding which tail to send.
  GreetingExchange,
  /// Signature sent; reading the peer's first 11 bytes so we can peek
  /// byte 10 (the revision) and decide whether to write our v2 or v3
  /// tail. Once we have ≥11 bytes, we write our tail and transition to
  /// either `WaitingForGreeting` (v3) or `V2IdentityExchange` (v2).
  WaitingForPeerRevision,
  /// Tail sent; reading the rest of the peer's v3 greeting (bytes
  /// 11..63). Some bytes may already be in the read buffer from the
  /// peek.
  WaitingForGreeting,
  SecurityHandshake,
  /// About to do READY exchange: client sends first, server receives first.
  ReadyExchange,
  /// Client has sent its READY; waiting to receive the server's READY.
  ClientSentReady,
  /// Server has received the client's READY; needs to send its own READY.
  ServerReceivedReady,
  /// ZMTP/2.0 path: exchange empty identity frames with the peer, then
  /// transition straight to `Done`. There is no security handshake or
  /// READY exchange in v2.
  V2IdentityExchange,
  Done,
}