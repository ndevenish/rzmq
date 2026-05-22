use crate::error::ZmqError;
use bytes::{BufMut, BytesMut};
use std::convert::TryInto;
use tracing;

// --- Constants ---
pub const GREETING_LENGTH: usize = 64;
pub const MECHANISM_LENGTH: usize = 20;

// ZMTP version this implementation sends and expects from peers.
pub const GREETING_VERSION_MAJOR_BYTE: u8 = 0x03;
pub const GREETING_VERSION_MINOR_BYTE: u8 = 0x00;

/// The first 10 bytes of every ZMTP greeting — the same for v1, v2 and
/// v3: `0xff` start byte, 8 zero bytes, `0x7f` final marker. Byte 10
/// (revision/major-version) is the first version-bearing byte and is
/// what the staged-greeting peek inspects.
pub const SIGNATURE_LENGTH: usize = 10;

/// Total bytes a ZMTP/2.0 greeting occupies on the wire: 10-byte
/// signature + revision (1 byte) + socket-type (1 byte).
pub const V2_GREETING_LENGTH: usize = SIGNATURE_LENGTH + 2;

// Byte offsets within the 64-byte greeting.
const VERSION_MAJOR_OFFSET: usize = 10;
const VERSION_MINOR_OFFSET: usize = 11;
pub const MECHANISM_OFFSET: usize = 12;
pub const AS_SERVER_OFFSET: usize = MECHANISM_OFFSET + MECHANISM_LENGTH; // 32
const PADDING_OFFSET: usize = AS_SERVER_OFFSET + 1; // 33
const PADDING_LENGTH: usize = GREETING_LENGTH - PADDING_OFFSET; // 31

/// The ZMTP wire-protocol revision that was settled on after a staged
/// greeting exchange. Returned by the handshake state machine; carried
/// on the protocol handler so downstream code (codec assertions,
/// heartbeat suppression) can branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedVersion {
  /// ZMTP/2.0 (revision byte = `0x01`). No security mechanism, no
  /// READY command, no command frames.
  V2,
  /// ZMTP/3.x (major byte = `0x03`). `minor` is the peer's advertised
  /// minor version. We send `0x00` (3.0) ourselves but accept any.
  V3 { minor: u8 },
}

impl NegotiatedVersion {
  pub fn is_v2(self) -> bool {
    matches!(self, NegotiatedVersion::V2)
  }
  pub fn is_v3(self) -> bool {
    matches!(self, NegotiatedVersion::V3 { .. })
  }
}

/// Validate the 10-byte ZMTP signature prefix and return byte 10 (the
/// revision / major-version byte) so the caller can decide what tail
/// to send next. This is the core of the libzmq-style staged-greeting
/// dance — write 10, peek byte 10, then write the v2 or v3 tail.
///
/// Returns `Err(ProtocolViolation)` if the first 10 bytes are not a
/// valid ZMTP signature (`0xff` + 8×`0x00` + `0x7f`). Returns the byte
/// at offset 10 otherwise, without committing the caller to any
/// particular version.
pub fn peek_revision(buf: &[u8]) -> Result<u8, ZmqError> {
  if buf.len() < SIGNATURE_LENGTH + 1 {
    return Err(ZmqError::ProtocolViolation(format!(
      "peek_revision: need {} bytes, got {}",
      SIGNATURE_LENGTH + 1,
      buf.len()
    )));
  }
  if buf[0] != 0xFF {
    return Err(ZmqError::ProtocolViolation(format!(
      "greeting signature byte 0: expected 0xff, got {:#04x}",
      buf[0]
    )));
  }
  if buf[9] != 0x7F {
    return Err(ZmqError::ProtocolViolation(format!(
      "greeting signature byte 9: expected 0x7f, got {:#04x}",
      buf[9]
    )));
  }
  // Bytes 1..9 are reserved/zero in canonical ZMTP, but libzmq has
  // historically not enforced this and lets the field carry anything
  // (it was even briefly used to disambiguate v1 vs v2). Stay
  // permissive at the peek stage — we'll re-validate padding when we
  // decode the full v3 greeting if that's the path we take.
  Ok(buf[VERSION_MAJOR_OFFSET])
}

/// A parsed ZMTP/2.0 greeting. v2 greetings carry only a revision
/// (always `0x01`) and a socket-type byte. There is no mechanism,
/// no as-server flag, and no padding — the entire greeting is 12
/// bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZmtpV2Greeting {
  /// Revision byte (offset 10). For ZMTP/2.0 this is always `0x01`.
  pub revision: u8,
  /// Socket-type byte (offset 11). See [`socket_type_code`] for the
  /// canonical mapping; the v2 numbering predates v3's named READY
  /// `Socket-Type` property.
  pub socket_type: u8,
}

impl ZmtpV2Greeting {
  pub const REVISION: u8 = 0x01;

  /// Encode the 2-byte v2 tail (revision + socket-type) into `buffer`.
  /// The caller is responsible for having already written the 10-byte
  /// signature; this writes the bytes that go at offsets 10 and 11.
  pub fn encode_tail(socket_type: u8, buffer: &mut BytesMut) {
    buffer.reserve(2);
    buffer.put_u8(Self::REVISION);
    buffer.put_u8(socket_type);
  }

  /// Encode a complete 12-byte v2 greeting: signature + revision +
  /// socket-type. Primarily for testing and for peers that want to
  /// initiate as v2 unilaterally; the staged-greeting flow writes the
  /// signature and tail separately.
  pub fn encode_full(socket_type: u8, buffer: &mut BytesMut) {
    buffer.reserve(V2_GREETING_LENGTH);
    buffer.put_u8(0xFF);
    buffer.put_bytes(0, 8);
    buffer.put_u8(0x7F);
    Self::encode_tail(socket_type, buffer);
    debug_assert_eq!(buffer.len(), V2_GREETING_LENGTH);
  }

  /// Decode the two bytes immediately following a validated 10-byte
  /// signature: revision (must be `0x01`) and socket-type. The caller
  /// must have already inspected byte 10 via [`peek_revision`] and
  /// confirmed it is `0x01` before invoking this; we re-check here as
  /// a defensive measure.
  ///
  /// `tail` must be exactly 2 bytes — the byte at offset 10 (revision)
  /// and the byte at offset 11 (socket-type) of the wire greeting.
  pub fn decode_tail(tail: [u8; 2]) -> Result<Self, ZmqError> {
    let revision = tail[0];
    if revision != Self::REVISION {
      return Err(ZmqError::ProtocolViolation(format!(
        "ZMTP/2.0 greeting: expected revision 0x01, got {:#04x}",
        revision
      )));
    }
    Ok(Self {
      revision,
      socket_type: tail[1],
    })
  }
}

// === ZMTP/2.0 socket-type byte codes (RFC 15 §4) ===
// v2 carried the socket type as a byte in the greeting; v3 dropped
// that in favour of the `Socket-Type` property in the READY command.
// The byte assignments below are the canonical v2 mapping.
pub const V2_SOCKET_TYPE_PAIR: u8 = 0x00;
pub const V2_SOCKET_TYPE_PUB: u8 = 0x01;
pub const V2_SOCKET_TYPE_SUB: u8 = 0x02;
pub const V2_SOCKET_TYPE_REQ: u8 = 0x03;
pub const V2_SOCKET_TYPE_REP: u8 = 0x04;
pub const V2_SOCKET_TYPE_DEALER: u8 = 0x05;
pub const V2_SOCKET_TYPE_ROUTER: u8 = 0x06;
pub const V2_SOCKET_TYPE_PULL: u8 = 0x07;
pub const V2_SOCKET_TYPE_PUSH: u8 = 0x08;

/// Map a ZMTP `Socket-Type` property string (the v3 name, uppercase) to
/// the v2 socket-type byte that goes at offset 11 of a ZMTP/2.0
/// greeting. Returns `None` if the name is unknown — XPUB/XSUB are not
/// representable in v2 since they postdate it.
pub fn socket_type_code(name: &str) -> Option<u8> {
  match name {
    "PAIR" => Some(V2_SOCKET_TYPE_PAIR),
    "PUB" => Some(V2_SOCKET_TYPE_PUB),
    "SUB" => Some(V2_SOCKET_TYPE_SUB),
    "REQ" => Some(V2_SOCKET_TYPE_REQ),
    "REP" => Some(V2_SOCKET_TYPE_REP),
    "DEALER" => Some(V2_SOCKET_TYPE_DEALER),
    "ROUTER" => Some(V2_SOCKET_TYPE_ROUTER),
    "PULL" => Some(V2_SOCKET_TYPE_PULL),
    "PUSH" => Some(V2_SOCKET_TYPE_PUSH),
    _ => None,
  }
}

/// Write the canonical 10-byte ZMTP signature: `0xff` + 8 zero bytes
/// + `0x7f`. Identical across v1/v2/v3.
pub fn encode_signature(buffer: &mut BytesMut) {
  buffer.reserve(SIGNATURE_LENGTH);
  buffer.put_u8(0xFF);
  buffer.put_bytes(0, 8);
  buffer.put_u8(0x7F);
}

/// Write the 54-byte ZMTP/3.x greeting tail starting at byte 10:
/// major + minor + 20-byte mechanism name + 1-byte as-server flag +
/// 31 zero padding bytes. Used by the single-shot
/// [`ZmtpGreeting::encode`] path.
fn encode_v3_tail(mechanism: &[u8; MECHANISM_LENGTH], as_server: bool, buffer: &mut BytesMut) {
  let start = buffer.len();
  buffer.put_u8(GREETING_VERSION_MAJOR_BYTE);
  encode_v3_tail_post_major(mechanism, as_server, buffer);
  debug_assert_eq!(buffer.len() - start, GREETING_LENGTH - SIGNATURE_LENGTH);
}

/// Write the 53-byte ZMTP/3.x greeting tail starting at byte 11 — i.e.
/// AFTER the signature and the major-version byte have already been
/// written: minor + 20-byte mechanism name + 1-byte as-server flag +
/// 31 zero padding bytes.
///
/// The staged-greeting flow uses this: it sends `signature + 0x03`
/// (11 bytes) up front — exactly like libzmq, whose byte 10 is always
/// the sender's own major version — and only the bytes from offset 11
/// on are version-dependent. This is the v3 branch of that tail.
pub fn encode_v3_tail_post_major(
  mechanism: &[u8; MECHANISM_LENGTH],
  as_server: bool,
  buffer: &mut BytesMut,
) {
  let target = GREETING_LENGTH - SIGNATURE_LENGTH - 1; // 53 bytes
  let start = buffer.len();
  buffer.reserve(target);
  buffer.put_u8(GREETING_VERSION_MINOR_BYTE);
  buffer.put_slice(mechanism);
  buffer.put_u8(as_server as u8);
  let written = buffer.len() - start;
  if written < target {
    buffer.put_bytes(0, target - written);
  }
  debug_assert_eq!(buffer.len() - start, target);
}

/// Inverse of [`socket_type_code`]: given a v2 socket-type byte,
/// return the canonical uppercase ZMTP name, or `None` if the byte
/// doesn't decode to a known socket type.
pub fn socket_type_name_from_code(code: u8) -> Option<&'static str> {
  Some(match code {
    V2_SOCKET_TYPE_PAIR => "PAIR",
    V2_SOCKET_TYPE_PUB => "PUB",
    V2_SOCKET_TYPE_SUB => "SUB",
    V2_SOCKET_TYPE_REQ => "REQ",
    V2_SOCKET_TYPE_REP => "REP",
    V2_SOCKET_TYPE_DEALER => "DEALER",
    V2_SOCKET_TYPE_ROUTER => "ROUTER",
    V2_SOCKET_TYPE_PULL => "PULL",
    V2_SOCKET_TYPE_PUSH => "PUSH",
    _ => return None,
  })
}

/// Represents the parsed content of a ZMTP/3.1 greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZmtpGreeting {
  pub version: (u8, u8),
  pub mechanism: [u8; MECHANISM_LENGTH], // ASCII mechanism name padded with nulls
  pub as_server: bool,
}

impl ZmtpGreeting {
  /// Creates a canonical greeting message to be sent.
  pub fn encode(mechanism: &[u8; MECHANISM_LENGTH], as_server: bool, buffer: &mut BytesMut) {
    buffer.reserve(GREETING_LENGTH);
    encode_signature(buffer);
    encode_v3_tail(mechanism, as_server, buffer);
    debug_assert_eq!(buffer.len(), GREETING_LENGTH);
  }

  /// Encodes the 54-byte ZMTP/3.x greeting tail (everything after the
  /// 10-byte signature: major + minor + mechanism + as-server +
  /// padding). The staged-greeting flow writes the signature alone
  /// first, peeks the peer's revision byte, then either writes this
  /// tail (for v3) or [`ZmtpV2Greeting::encode_tail`] (for v2).
  pub fn encode_tail(mechanism: &[u8; MECHANISM_LENGTH], as_server: bool, buffer: &mut BytesMut) {
    encode_v3_tail(mechanism, as_server, buffer);
  }

  /// Parses a received greeting message with improved tolerance for implementation variations.
  pub fn decode(buffer: &mut BytesMut) -> Result<Option<Self>, ZmqError> {
    if buffer.len() < GREETING_LENGTH {
      return Ok(None); // Need more data
    }

    let data = buffer.split_to(GREETING_LENGTH); // Consume the 64 bytes

    // 1. Validate fixed signature markers (more robust than a full prefix match).
    // The spec guarantees the first byte is 0xFF, but the middle bytes have varied.
    // We check the first byte and can optionally check the 10th byte (0x7F), though it was also part of the issue.
    // For maximum compatibility, checking only the first byte and padding is often sufficient.
    if data[0] != 0xFF {
      tracing::error!("Greeting does not start with 0xFF (got {:#04x})", data[0]);
      return Err(ZmqError::ProtocolViolation(
        "Greeting does not start with 0xFF".into(),
      ));
    }

    // 2. Validate that the required padding area is all zeros.
    // The ZMTP spec (RFC 23, Section 3.1) requires these bytes to be zero.
    for i in 0..PADDING_LENGTH {
      let idx = PADDING_OFFSET + i;
      if data[idx] != 0x00 {
        tracing::error!(
          "Invalid ZMTP greeting: non-zero padding byte at index {}: {:#04x}",
          idx,
          data[idx]
        );
        return Err(ZmqError::ProtocolViolation(
          "Non-zero byte in greeting padding".into(),
        ));
      }
    }

    // 3. Extract and Validate Version (at fixed offsets).
    let major_version = data[VERSION_MAJOR_OFFSET];
    let minor_version = data[VERSION_MINOR_OFFSET];

    if major_version != GREETING_VERSION_MAJOR_BYTE {
      return Err(ZmqError::ProtocolViolation(format!(
        "Unsupported ZMTP major version {}.{}",
        major_version, minor_version
      )));
    }
    let version = (major_version, minor_version);

    // 4. Extract Mechanism.
    let mechanism_slice = &data[MECHANISM_OFFSET..MECHANISM_OFFSET + MECHANISM_LENGTH];
    let mechanism: [u8; MECHANISM_LENGTH] = mechanism_slice.try_into().unwrap();

    // 5. Extract As-Server Flag.
    let as_server_byte = data[AS_SERVER_OFFSET];
    let as_server = match as_server_byte {
      0x00 => false,
      0x01 => true,
      _ => return Err(ZmqError::ProtocolViolation("Invalid as-server flag".into())),
    };

    tracing::debug!(?version, mechanism_name = %std::str::from_utf8(&mechanism).unwrap_or("").trim_end_matches('\0'), as_server, "Parsed ZMTP Greeting");
    Ok(Some(Self {
      version,
      mechanism,
      as_server,
    }))
  }

  /// Helper to get mechanism name as &str (trimming nulls).
  pub fn mechanism_name(&self) -> &str {
    let first_null = self
      .mechanism
      .iter()
      .position(|&b| b == 0)
      .unwrap_or(MECHANISM_LENGTH);
    std::str::from_utf8(&self.mechanism[..first_null]).unwrap_or("<invalid_utf8>")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn peek_revision_accepts_v2_signature() {
    let buf = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0x01];
    assert_eq!(peek_revision(&buf).unwrap(), 0x01);
  }

  #[test]
  fn peek_revision_accepts_v3_signature() {
    let buf = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0x03];
    assert_eq!(peek_revision(&buf).unwrap(), 0x03);
  }

  #[test]
  fn peek_revision_rejects_bad_start_byte() {
    let buf = [0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0x03];
    assert!(peek_revision(&buf).is_err());
  }

  #[test]
  fn peek_revision_rejects_bad_marker_byte() {
    let buf = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7e, 0x03];
    assert!(peek_revision(&buf).is_err());
  }

  #[test]
  fn peek_revision_requires_enough_bytes() {
    let buf = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f]; // only 10 bytes
    assert!(peek_revision(&buf).is_err());
  }

  #[test]
  fn v2_greeting_encodes_to_canonical_bytes() {
    let mut buf = BytesMut::new();
    ZmtpV2Greeting::encode_full(V2_SOCKET_TYPE_PULL, &mut buf);
    assert_eq!(buf.len(), V2_GREETING_LENGTH);
    assert_eq!(
      &buf[..],
      &[0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 0x01, 0x07]
    );
  }

  #[test]
  fn v2_greeting_tail_round_trip() {
    let mut buf = BytesMut::new();
    ZmtpV2Greeting::encode_tail(V2_SOCKET_TYPE_PUSH, &mut buf);
    assert_eq!(&buf[..], &[0x01, 0x08]);
    let parsed = ZmtpV2Greeting::decode_tail([buf[0], buf[1]]).unwrap();
    assert_eq!(parsed.revision, 0x01);
    assert_eq!(parsed.socket_type, V2_SOCKET_TYPE_PUSH);
  }

  #[test]
  fn v2_greeting_rejects_wrong_revision() {
    // Revision must be 0x01 for v2; we test 0x02 (unknown future v2 minor)
    // and 0x03 (v3 path; should never reach decode_tail).
    assert!(ZmtpV2Greeting::decode_tail([0x02, 0x07]).is_err());
    assert!(ZmtpV2Greeting::decode_tail([0x03, 0x07]).is_err());
  }

  #[test]
  fn socket_type_code_is_inverse_of_name() {
    for name in &[
      "PAIR", "PUB", "SUB", "REQ", "REP", "DEALER", "ROUTER", "PULL", "PUSH",
    ] {
      let code = socket_type_code(name).expect("known socket type");
      assert_eq!(socket_type_name_from_code(code), Some(*name));
    }
    assert_eq!(socket_type_code("UNKNOWN"), None);
    assert_eq!(socket_type_name_from_code(0xff), None);
  }

  #[test]
  fn negotiated_version_branches() {
    assert!(NegotiatedVersion::V2.is_v2());
    assert!(!NegotiatedVersion::V2.is_v3());
    assert!(NegotiatedVersion::V3 { minor: 1 }.is_v3());
    assert!(!NegotiatedVersion::V3 { minor: 1 }.is_v2());
  }

  #[test]
  fn signature_plus_v3_tail_equals_full_v3_encoding() {
    let mech = b"NULL\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut full = BytesMut::new();
    ZmtpGreeting::encode(mech, false, &mut full);

    let mut staged = BytesMut::new();
    encode_signature(&mut staged);
    ZmtpGreeting::encode_tail(mech, false, &mut staged);

    assert_eq!(staged.len(), GREETING_LENGTH);
    assert_eq!(&full[..], &staged[..]);
  }
}
