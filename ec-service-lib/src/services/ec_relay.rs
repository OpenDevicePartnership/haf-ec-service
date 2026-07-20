//! `ec_relay` — generic ODP-over-MCTP relay infrastructure for SP-side
//! FFA services that proxy requests to the EC firmware.
//!
//! # Architecture
//!
//! The EC firmware exposes a set of services (Battery, Thermal, FwMgmt,
//! TimeAlarm) behind a single [`uart_service::Service`] that wraps an
//! [`mctp_rs::MctpMedium`] over a UART. SP-side FFA services that proxy
//! to the EC all need the same three-step dance:
//!
//! 1. Build a 4-byte [`OdpHeader`]-style bitfield identifying the target
//!    service + message id.
//! 2. MCTP-frame the header + body into a wire-ready packet and write
//!    it to a transport.
//! 3. Read a framed response packet back from the transport, MCTP-strip
//!    it, return the response header + body to the caller.
//!
//! This module owns framing, transport I/O, and ODP response-envelope
//! validation. Per-service shims such as Battery, Thermal, and TimeAlarm
//! are generic over `R: Relay`; they provide service ids, command ids,
//! request bodies, and exact response parsers without naming a transport.
//!
//! Bytes produced by [`build_odp_header`] plus each caller's request body
//! are checked by per-service host wire-format tests against the EC's own
//! `SerializableMessage` implementations.

use mctp_rs::{
    EndpointId, MctpMedium, MctpMessageHeaderTrait, MctpMessageTag, MctpMessageTrait, MctpPacketContext,
    MctpPacketError, MctpPacketResult, MctpReplyContext, MctpSequenceNumber, MctpSerialMedium, EC_EID, SP_EID,
};

// ===========================================================================
// ODP wire-format constants + bitfield helpers
// ===========================================================================

/// MCTP message-type byte for ODP relay traffic. Matches the EC's
/// `impl_odp_mctp_relay_handler!` `HostRequest::MESSAGE_TYPE` constant in
/// `embedded-services::relay::mctp`.
pub const ODP_MESSAGE_TYPE: u8 = 0x7D;

/// Build a 4-byte big-endian OdpHeader from its bitfield components.
///
/// Bitfield layout (matches `OdpHeaderWireFormat` in
/// `embedded-services/embedded-service/src/relay/mod.rs:285-303`):
///
/// | bit 25 | bits 23..16 | bit 15   | bits 14..0  |
/// |--------|-------------|----------|-------------|
/// | is_req | service_id  | is_error | message_id  |
///
/// This helper constructs SP requests and synthetic success responses.
/// EC error responses set `is_error` and use the service error
/// discriminant as `message_id`; host tests construct those with
/// `test_util::build_odp_error_header`.
pub fn build_odp_header(is_request: bool, service_id: u8, message_id: u16) -> [u8; 4] {
    let mut raw: u32 = 0;
    if is_request {
        raw |= 1 << 25;
    }
    raw |= (service_id as u32) << 16;
    raw |= (message_id as u32) & 0x7FFF;
    raw.to_be_bytes()
}

/// Parse a 4-byte BE OdpHeader; returns `(is_request, service_id, is_error, message_id)`.
pub fn parse_odp_header(bytes: &[u8]) -> Result<(bool, u8, bool, u16), &'static str> {
    if bytes.len() < 4 {
        return Err("OdpHeader buffer < 4 bytes");
    }
    let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let is_request = (raw & (1 << 25)) != 0;
    let service_id = ((raw >> 16) & 0xFF) as u8;
    let is_error = (raw & (1 << 15)) != 0;
    let message_id = (raw & 0x7FFF) as u16;
    Ok((is_request, service_id, is_error, message_id))
}

/// Split the first `N` bytes off `body` as an owned array, returning the
/// remaining bytes for chained reads, or [`EcRelayError::BodyTooShort`].
/// `N` is inferred from the caller (e.g. `u32::from_le_bytes` fixes it at
/// 4), so a command's response length stays derived from its parse rather
/// than a separate constant that can drift.
pub fn take_array<const N: usize>(body: &[u8]) -> Result<([u8; N], &[u8]), EcRelayError> {
    let (head, rest) = body.split_first_chunk::<N>().ok_or(EcRelayError::BodyTooShort)?;
    Ok((*head, rest))
}

/// Convert an exact-length response body into an owned array.
///
/// New fixed-size service parsers use this rather than silently accepting
/// a trailing suffix.
pub fn take_exact_array<const N: usize>(body: &[u8]) -> Result<[u8; N], EcRelayError> {
    let (exact, rest) = take_array(body)?;
    if rest.is_empty() {
        Ok(exact)
    } else {
        Err(EcRelayError::BodyTooLong)
    }
}

// ===========================================================================
// MctpMessageTrait shims so `MctpPacketContext::serialize_packet` accepts
// our raw header + body bytes (no full SerializableMessage impl needed).
// ===========================================================================

/// Wraps the 4 BE bytes of an OdpHeader for use with
/// [`MctpPacketContext::serialize_packet`].
pub struct OdpRawHeader(pub [u8; 4]);

impl MctpMessageHeaderTrait for OdpRawHeader {
    fn serialize<M: MctpMedium>(self, buffer: &mut [u8]) -> MctpPacketResult<usize, M> {
        if buffer.len() < 4 {
            return Err(MctpPacketError::SerializeError("buffer too small for odp raw header"));
        }
        buffer[..4].copy_from_slice(&self.0);
        Ok(4)
    }

    fn deserialize<M: MctpMedium>(buffer: &[u8]) -> MctpPacketResult<(Self, &[u8]), M> {
        if buffer.len() < 4 {
            return Err(MctpPacketError::HeaderParseError("buffer too small for odp raw header"));
        }
        let mut h = [0u8; 4];
        h.copy_from_slice(&buffer[..4]);
        Ok((OdpRawHeader(h), &buffer[4..]))
    }
}

/// Wraps the body bytes (post-OdpHeader) of an ODP relay message — i.e.
/// the `SerializableMessage::serialize` output for a specific
/// request/response variant. SP-side this is constructed manually by
/// per-service callers; the wire bytes match the EC's decoder by
/// construction (verified per-service in its `tests` module).
pub struct OdpRawMessage<'b>(pub &'b [u8]);

impl<'buf> MctpMessageTrait<'buf> for OdpRawMessage<'buf> {
    type Header = OdpRawHeader;
    const MESSAGE_TYPE: u8 = ODP_MESSAGE_TYPE;

    fn serialize<M: MctpMedium>(self, buffer: &mut [u8]) -> MctpPacketResult<usize, M> {
        let n = self.0.len();
        if buffer.len() < n {
            return Err(MctpPacketError::SerializeError("buffer too small for odp raw body"));
        }
        buffer[..n].copy_from_slice(self.0);
        Ok(n)
    }

    fn deserialize<M: MctpMedium>(_h: &OdpRawHeader, buffer: &'buf [u8]) -> MctpPacketResult<Self, M> {
        Ok(OdpRawMessage(buffer))
    }
}

// ===========================================================================
// Transport abstraction
// ===========================================================================

/// Errors returned by the relay invocation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcRelayError {
    /// Transport-layer write failure (UART TX, SMBUS NACK, etc.).
    TransportWrite,
    /// Transport-layer read failure (UART RX timeout, etc.).
    TransportRead,
    /// Read budget exhausted before a framed response arrived. Distinct
    /// from `TransportRead` so callers can fail deterministically.
    TransportReadTimeout,
    /// `MctpPacketContext::serialize_packet` failed.
    MctpSerialize(&'static str),
    /// Bytes received from transport could not be parsed as a complete
    /// MCTP packet (e.g., framing mismatch, body too long for the
    /// assembly buffer).
    MctpDecode(&'static str),
    /// `MctpPacketContext::deserialize_packet` returned `None` (partial
    /// packet — the transport delivered an incomplete frame).
    MctpRecvIncomplete,
    /// Response packet's MCTP message-type byte was not [`ODP_MESSAGE_TYPE`].
    UnexpectedMessageType,
    /// Response ODP header had an unexpected service id or a
    /// successful-response message id.
    UnexpectedOdpService,
    /// Response packet's OdpHeader could not be parsed.
    OdpHeaderParse(&'static str),
    /// Response packet was marked as an ODP request.
    UnexpectedOdpRequest,
    /// EC service returned an error; the value is its error discriminant.
    Remote(u16),
    /// Response body was shorter than the per-service expected length.
    BodyTooShort,
    /// Response body was longer than the per-service expected length.
    BodyTooLong,
}

/// Transport-agnostic packet I/O. An [`OdpTransport`] knows how to:
/// - write a wire-ready, already-MCTP-framed packet to its wire, and
/// - read one back, returning the framed packet bytes verbatim for the
///   relay to MCTP-strip.
///
/// Implementations decide their own framing-aware read strategy (e.g.,
/// "read until [`MctpSerialMedium`] sentinel 0x7E"). The trait deliberately
/// does NOT couple to a specific medium — a hypothetical
/// `MctpSmbusEspiTransport` would use length-prefix framing and implement
/// the same trait.
pub trait OdpTransport {
    fn send_packet(&mut self, packet: &[u8]) -> Result<(), EcRelayError>;

    /// Read one complete framed packet into `buf`; return the number of
    /// bytes consumed. Implementation chooses framing strategy based on
    /// its medium.
    fn recv_framed_packet(&mut self, buf: &mut [u8]) -> Result<usize, EcRelayError>;
}

/// MCTP-via-PL011-UART transport. Reads byte-at-a-time until the DSP0253
/// 0x7E END flag appears, framing-aware-by-construction. Wraps any
/// `embedded_io::Read + Write` UART driver.
pub struct MctpSerialTransport<U: embedded_io::Read + embedded_io::Write> {
    uart: U,
}

impl<U: embedded_io::Read + embedded_io::Write> MctpSerialTransport<U> {
    pub fn new(uart: U) -> Self {
        Self { uart }
    }
}

/// MCTP serial framing END flag (DSP0253 0x7E). Re-exported from the
/// transport's framing for documentation only — callers don't need it.
const SERIAL_END_FLAG: u8 = 0x7E;

impl<U: embedded_io::Read + embedded_io::Write> OdpTransport for MctpSerialTransport<U> {
    fn send_packet(&mut self, packet: &[u8]) -> Result<(), EcRelayError> {
        self.uart.write_all(packet).map_err(|_| EcRelayError::TransportWrite)
    }

    fn recv_framed_packet(&mut self, buf: &mut [u8]) -> Result<usize, EcRelayError> {
        // Read byte-at-a-time until the DSP0253 END flag (0x7E) appears
        // at the end of the framed packet.
        let mut filled = 0usize;
        loop {
            if filled >= buf.len() {
                return Err(EcRelayError::MctpRecvIncomplete);
            }
            let mut byte = [0u8; 1];
            self.uart.read_exact(&mut byte).map_err(|e| match e {
                embedded_io::ReadExactError::Other(inner)
                    if embedded_io::Error::kind(&inner) == embedded_io::ErrorKind::TimedOut =>
                {
                    EcRelayError::TransportReadTimeout
                }
                _ => EcRelayError::TransportRead,
            })?;
            buf[filled] = byte[0];
            filled += 1;
            if byte[0] == SERIAL_END_FLAG {
                return Ok(filled);
            }
        }
    }
}

// ===========================================================================
// Round-trip invocation: the generic operation per-service callers use.
// ===========================================================================

/// Decoded ODP response: header fields + body slice.
///
/// Body lifetime is bounded by the closure call in [`invoke`]. Parse
/// inside the closure; only owned values can escape.
pub struct OdpResponse<'b> {
    pub is_request: bool,
    pub service_id: u8,
    pub is_error: bool,
    pub message_id: u16,
    pub body: &'b [u8],
}

/// Service-layer view of "the channel to the EC". Decouples per-service
/// code (`Battery`, future `EcThermal`, etc.) from transport-layer
/// concerns: service code declares its dependency as `R: Relay` and
/// never sees `OdpTransport`, UART types, or MCTP framing.
///
/// The shipped concrete impl is [`EcRelay<T>`] (an [`OdpTransport`]
/// wrapping a UART). Alternative impls — diagnostic recorders,
/// loopback mocks lighter than `EcRelay<LoopbackTransport>`, multiplex
/// routers — can be added without touching service code.
///
/// # Object safety
///
/// `invoke` is generic over `R` (the closure return type) and `F` (the
/// closure type), which makes this trait NOT object-safe. Use it as a
/// bound (`R: Relay`) rather than a trait object (`dyn Relay`). The
/// generic-method shape is necessary to support the borrow-bounded
/// `&[u8]` response slice without forcing every caller to copy bytes
/// out into an owned type.
pub trait Relay {
    fn invoke<R, F>(
        &mut self,
        request_header: [u8; 4],
        request_body: &[u8],
        parse_response: F,
    ) -> Result<R, EcRelayError>
    where
        F: FnOnce(OdpResponse<'_>) -> Result<R, EcRelayError>;

    /// Build a request and validate a success response whose discriminant is
    /// the same as the request message id.
    fn invoke_request<R, F>(
        &mut self,
        service_id: u8,
        message_id: u16,
        request_body: &[u8],
        parse_body: F,
    ) -> Result<R, EcRelayError>
    where
        F: FnOnce(&[u8]) -> Result<R, EcRelayError>,
    {
        self.invoke_request_with_response_id(service_id, message_id, message_id, request_body, parse_body)
    }

    /// Build a request and validate a success response with an explicit
    /// response discriminant before parsing its body.
    fn invoke_request_with_response_id<R, F>(
        &mut self,
        service_id: u8,
        request_message_id: u16,
        expected_response_message_id: u16,
        request_body: &[u8],
        parse_body: F,
    ) -> Result<R, EcRelayError>
    where
        F: FnOnce(&[u8]) -> Result<R, EcRelayError>,
    {
        let request_header = build_odp_header(true, service_id, request_message_id);
        self.invoke(request_header, request_body, |response| {
            if response.is_request {
                return Err(EcRelayError::UnexpectedOdpRequest);
            }
            if response.service_id != service_id {
                return Err(EcRelayError::UnexpectedOdpService);
            }
            if response.is_error {
                return Err(EcRelayError::Remote(response.message_id));
            }
            if response.message_id != expected_response_message_id {
                return Err(EcRelayError::UnexpectedOdpService);
            }
            parse_body(response.body)
        })
    }
}

/// Owning relay handle to the EC firmware over an `OdpTransport`. Owns
/// the transport and the MCTP packet-assembly buffer. SP-side FFA
/// services that proxy to the EC (`Battery`, future `EcThermal`, etc.)
/// hold a borrow of a shared `RefCell<EcRelay<T>>`; they call
/// `relay.borrow_mut().invoke(...)` per request and never touch the
/// transport or buffer directly.
///
/// # Why this is a struct rather than free functions
///
/// The transport is a single physical resource (one PL011 UART). It
/// must be owned by exactly one place. Service code shouldn't own it
/// (multiple services can't co-own a UART, and "transport-aware
/// service" is a layer violation). The wiring layer (`main.rs`) owns
/// the `RefCell<EcRelay<T>>`; services borrow handles via the [`Relay`]
/// trait.
///
/// # Single-threaded SP runtime
///
/// `RefCell` interior mutability is the right tool here: the SP runtime
/// is single-threaded synchronous, so `borrow_mut` failures only happen
/// on programming errors (nested calls into the same service while
/// holding the relay). The runtime overhead is a single integer
/// increment per call.
pub struct EcRelay<T: OdpTransport> {
    transport: T,
    assembly_buf: [u8; 128],
}

impl<T: OdpTransport> EcRelay<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            assembly_buf: [0u8; 128],
        }
    }

    /// Test-only accessor for inspecting transport state (e.g. what bytes
    /// the relay sent). Not part of the production API.
    #[cfg(test)]
    pub(crate) fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: OdpTransport> Relay for EcRelay<T> {
    /// Perform one ODP request/response round-trip and parse the
    /// response inside a caller-supplied closure.
    ///
    /// - Serializes `(request_header, request_body)` as an MCTP packet
    ///   to the transport.
    /// - Reads one framed packet back from the transport.
    /// - MCTP-strips it; parses the OdpHeader; invokes `parse_response`
    ///   with the resulting [`OdpResponse`] (whose `body` slice borrows
    ///   from the relay's internal assembly buffer).
    /// - Returns whatever owned value `parse_response` produced.
    ///
    /// The closure pattern is required because `MctpPacketContext` owns
    /// the assembly buffer and the body slice it produces cannot
    /// outlive the `MctpPacketContext`. Parsing inside the closure
    /// guarantees only owned types escape.
    fn invoke<R, F>(
        &mut self,
        request_header: [u8; 4],
        request_body: &[u8],
        parse_response: F,
    ) -> Result<R, EcRelayError>
    where
        F: FnOnce(OdpResponse<'_>) -> Result<R, EcRelayError>,
    {
        // ----- 1. Serialize the request into a fresh MctpPacketContext
        //          and push each emitted packet out the transport. Use
        //          a dedicated TX buffer so assembly_buf is free for
        //          the response.
        {
            let mut tx_buf = [0u8; 128];
            let mut tx_ctx = MctpPacketContext::<MctpSerialMedium>::new(MctpSerialMedium, &mut tx_buf);
            let reply_ctx = serial_reply_context(SP_EID, EC_EID);
            let mut state = tx_ctx
                .serialize_packet(reply_ctx, (OdpRawHeader(request_header), OdpRawMessage(request_body)))
                .map_err(|e| EcRelayError::MctpSerialize(mctp_error_str(e)))?;
            while let Some(pkt) = state.next() {
                let pkt = pkt.map_err(|e| EcRelayError::MctpSerialize(mctp_error_str(e)))?;
                self.transport.send_packet(pkt)?;
            }
        }

        // ----- 2. Read one framed packet back into a small RX buffer.
        let mut rx_packet = [0u8; 64];
        let rx_len = self.transport.recv_framed_packet(&mut rx_packet)?;

        // ----- 3. MCTP-strip via a fresh PacketContext borrowing
        //          assembly_buf. The body slice we hand to
        //          `parse_response` borrows from `rx_ctx`'s internal
        //          buffer — it does NOT outlive this method. Callers
        //          must extract owned values from the closure.
        let mut rx_ctx = MctpPacketContext::<MctpSerialMedium>::new(MctpSerialMedium, &mut self.assembly_buf);
        let message = rx_ctx
            .deserialize_packet(&rx_packet[..rx_len])
            .map_err(|e| EcRelayError::MctpDecode(mctp_error_str(e)))?
            .ok_or(EcRelayError::MctpRecvIncomplete)?;

        if message.message_buffer.message_type() != ODP_MESSAGE_TYPE {
            return Err(EcRelayError::UnexpectedMessageType);
        }

        let body = message.message_buffer.body();
        if body.len() < 4 {
            return Err(EcRelayError::BodyTooShort);
        }
        let (is_request, service_id, is_error, message_id) =
            parse_odp_header(body).map_err(EcRelayError::OdpHeaderParse)?;

        parse_response(OdpResponse {
            is_request,
            service_id,
            is_error,
            message_id,
            body: &body[4..],
        })
    }
}

/// Construct an `MctpReplyContext` for `MctpSerialMedium` traffic from
/// `src` to `dst`. `MctpSerialMedium` has no per-medium addressing, so
/// `medium_context = ()`.
fn serial_reply_context(src: EndpointId, dst: EndpointId) -> MctpReplyContext<MctpSerialMedium> {
    MctpReplyContext {
        source_endpoint_id: src,
        destination_endpoint_id: dst,
        packet_sequence_number: MctpSequenceNumber::new(0),
        message_tag: MctpMessageTag::try_from(0).expect("tag 0 always valid"),
        medium_context: (),
    }
}

fn mctp_error_str<M: MctpMedium>(e: MctpPacketError<M>) -> &'static str {
    match e {
        MctpPacketError::HeaderParseError(s) => s,
        MctpPacketError::SerializeError(s) => s,
        MctpPacketError::CommandParseError(s) => s,
        MctpPacketError::MediumError(_) => "medium error",
        MctpPacketError::ProtocolError(_) => "protocol error",
        MctpPacketError::UnsupportedMessageType(_) => "unsupported message type",
    }
}

// ===========================================================================
// Loopback transport for unit tests (host-side only).
// ===========================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// Test-only `OdpTransport` impl: records what was sent and serves
    /// pre-loaded bytes on recv. Used by per-service test modules.
    pub struct LoopbackTransport {
        pub tx: Vec<u8>,
        pub rx: VecDeque<u8>,
    }

    impl LoopbackTransport {
        pub fn new() -> Self {
            Self {
                tx: Vec::new(),
                rx: VecDeque::new(),
            }
        }

        pub fn prime_rx<I: IntoIterator<Item = u8>>(&mut self, bytes: I) {
            self.rx.extend(bytes);
        }
    }

    /// Strip MCTP framing; returns the inner body (ODP header + payload).
    pub fn strip_mctp_framing(framed: &[u8]) -> Vec<u8> {
        use mctp_rs::{MctpPacketContext, MctpSerialMedium};
        let mut buf = [0u8; 256];
        let mut ctx = MctpPacketContext::<MctpSerialMedium>::new(MctpSerialMedium, &mut buf);
        let message = ctx
            .deserialize_packet(framed)
            .expect("deserialize_packet ok")
            .expect("complete message");
        assert_eq!(message.message_buffer.message_type(), ODP_MESSAGE_TYPE);
        message.message_buffer.body().to_vec()
    }

    impl OdpTransport for LoopbackTransport {
        fn send_packet(&mut self, packet: &[u8]) -> Result<(), EcRelayError> {
            self.tx.extend_from_slice(packet);
            Ok(())
        }

        fn recv_framed_packet(&mut self, buf: &mut [u8]) -> Result<usize, EcRelayError> {
            // Mirror MctpSerialTransport's framing: read until 0x7E.
            let mut filled = 0usize;
            loop {
                if filled >= buf.len() {
                    return Err(EcRelayError::MctpRecvIncomplete);
                }
                let b = self.rx.pop_front().ok_or(EcRelayError::TransportRead)?;
                buf[filled] = b;
                filled += 1;
                if b == SERIAL_END_FLAG {
                    return Ok(filled);
                }
            }
        }
    }

    /// Test UART that always reports a timed-out read.
    pub struct TimeoutUart;

    impl embedded_io::ErrorType for TimeoutUart {
        type Error = TimeoutUartErr;
    }

    #[derive(Debug)]
    pub struct TimeoutUartErr;

    impl embedded_io::Error for TimeoutUartErr {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::TimedOut
        }
    }

    impl core::fmt::Display for TimeoutUartErr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "timeout")
        }
    }

    impl core::error::Error for TimeoutUartErr {}

    impl embedded_io::Read for TimeoutUart {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(TimeoutUartErr)
        }
    }

    impl embedded_io::Write for TimeoutUart {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            // Swallow writes so tests reach the RX timeout path
            // (`write_all` panics on `Ok(0)`).
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Build a 4-byte BE OdpHeader for a synthetic EC error response:
    /// `is_error` set, with `error_code` in the message-id field.
    pub fn build_odp_error_header(service_id: u8, error_code: u16) -> [u8; 4] {
        let raw = ((service_id as u32) << 16) | (1 << 15) | (u32::from(error_code) & 0x7FFF);
        raw.to_be_bytes()
    }

    /// Helper used by per-service tests: synthesize a framed response
    /// packet from `(response_header, response_body)` by running the
    /// EC-side framing path (TX from EC_EID to SP_EID).
    pub fn frame_response_packets(header: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut ctx = MctpPacketContext::<MctpSerialMedium>::new(MctpSerialMedium, &mut buf);
        let reply_ctx = serial_reply_context(EC_EID, SP_EID);
        let mut wire: Vec<u8> = Vec::new();
        let mut state = ctx
            .serialize_packet(reply_ctx, (OdpRawHeader(header), OdpRawMessage(payload)))
            .expect("serialize_packet ok");
        while let Some(packet_result) = state.next() {
            wire.extend_from_slice(packet_result.expect("packet ok"));
        }
        wire
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odp_header_round_trip() {
        let bytes = build_odp_header(true, 0x08, 2);
        assert_eq!(bytes, [0x02, 0x08, 0x00, 0x02]);
        let (is_req, svc, is_err, msg_id) = parse_odp_header(&bytes).unwrap();
        assert!(is_req);
        assert_eq!(svc, 0x08);
        assert!(!is_err);
        assert_eq!(msg_id, 2);
    }

    #[test]
    fn odp_header_response_round_trip() {
        let bytes = build_odp_header(false, 0x08, 2);
        assert_eq!(bytes, [0x00, 0x08, 0x00, 0x02]);
        let (is_req, _, is_err, _) = parse_odp_header(&bytes).unwrap();
        assert!(!is_req);
        assert!(!is_err);
    }

    #[test]
    fn parse_odp_header_rejects_short_buffer() {
        assert!(parse_odp_header(&[0x02, 0x08, 0x00]).is_err());
    }

    #[test]
    fn recv_framed_packet_maps_timed_out_kind_to_transport_read_timeout() {
        use test_util::TimeoutUart;
        let mut t = MctpSerialTransport::new(TimeoutUart);
        let mut buf = [0u8; 64];
        let err = t.recv_framed_packet(&mut buf).expect_err("timeout should surface");
        assert_eq!(err, EcRelayError::TransportReadTimeout);
    }

    #[test]
    fn take_exact_array_accepts_exact_body() {
        assert_eq!(take_exact_array::<4>(&[1, 2, 3, 4]), Ok([1, 2, 3, 4]));
    }

    #[test]
    fn take_exact_array_rejects_short_body() {
        assert_eq!(take_exact_array::<4>(&[1, 2, 3]), Err(EcRelayError::BodyTooShort));
    }

    #[test]
    fn take_exact_array_rejects_trailing_body() {
        assert_eq!(take_exact_array::<4>(&[1, 2, 3, 4, 5]), Err(EcRelayError::BodyTooLong));
    }

    #[test]
    fn invoke_request_with_response_id_accepts_distinct_success_id() {
        let header = build_odp_header(false, 0x0B, 5);
        let body = 300u32.to_le_bytes();
        let framed = test_util::frame_response_packets(header, &body);
        let mut transport = test_util::LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let mut relay = EcRelay::new(transport);

        let result = relay.invoke_request_with_response_id(0x0B, 7, 5, &[], |body| {
            Ok(u32::from_le_bytes(take_exact_array::<4>(body)?))
        });

        assert_eq!(result, Ok(300));
    }

    #[test]
    fn invoke_request_with_response_id_rejects_wrong_success_id() {
        let header = build_odp_header(false, 0x0B, 7);
        let framed = test_util::frame_response_packets(header, &300u32.to_le_bytes());
        let mut transport = test_util::LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let mut relay = EcRelay::new(transport);

        let result = relay.invoke_request_with_response_id(0x0B, 7, 5, &[], |_| Ok(()));

        assert_eq!(result, Err(EcRelayError::UnexpectedOdpService));
    }

    #[test]
    fn invoke_request_with_response_id_preserves_remote_error() {
        let header = test_util::build_odp_error_header(0x0B, 1);
        let framed = test_util::frame_response_packets(header, &[]);
        let mut transport = test_util::LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let mut relay = EcRelay::new(transport);

        let result = relay.invoke_request_with_response_id(0x0B, 7, 5, &[], |_| Ok(()));

        assert_eq!(result, Err(EcRelayError::Remote(1)));
    }

    #[test]
    fn invoke_request_preserves_remote_error_code() {
        let header = test_util::build_odp_error_header(0x09, 1);
        let framed = test_util::frame_response_packets(header, &[]);
        let mut transport = test_util::LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let mut relay = EcRelay::new(transport);

        let result = relay.invoke_request(0x09, 4, &[], |_| Ok(()));

        assert_eq!(result, Err(EcRelayError::Remote(1)));
    }

    #[test]
    fn invoke_request_rejects_response_marked_as_request() {
        let header = build_odp_header(true, 0x09, 4);
        let framed = test_util::frame_response_packets(header, &[]);
        let mut transport = test_util::LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let mut relay = EcRelay::new(transport);

        let result = relay.invoke_request(0x09, 4, &[], |_| Ok(()));

        assert_eq!(result, Err(EcRelayError::UnexpectedOdpRequest));
    }
}
