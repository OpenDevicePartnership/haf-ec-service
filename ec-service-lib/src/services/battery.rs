//! `Battery` — FFA service that proxies Normal-World `GetBst` requests
//! to the EC's `BatteryServiceRelayHandler` over MCTP.
//!
//! Transport-agnostic via the [`crate::services::ec_relay::Relay`] trait.
//! [`Battery`] is generic over `R: Relay`; the concrete relay impl
//! (e.g. `EcRelay<MctpSerialTransport<Pl011Uart>>` in production, or
//! `EcRelay<LoopbackTransport>` in tests) is inferred at the wiring
//! call site. Battery itself never names a transport type.
//!
//! # Wire format (must match the EC's `OdpRelayHandler` byte-for-byte)
//!
//! Battery service id = `0x08`; `BatteryCmd::GetBst` = 2.
//!
//! Request body (5 bytes, post the MCTP `MESSAGE_TYPE = 0x7D` byte):
//! ```text
//!     [0x02, 0x08, 0x00, 0x02, 0x00]
//!      \________________/  ^
//!       OdpHeader (BE u32)  battery_id = 0
//!       (req=1, svc=0x08,
//!        is_error=0, msg_id=2)
//! ```
//!
//! Response body (20 bytes): 4-byte BE OdpHeader (req=0, svc=0x08, msg_id=2)
//! followed by 16 bytes (4 LE u32 dwords: `battery_state.bits()`,
//! `battery_present_rate`, `battery_remaining_capacity`,
//! `battery_present_voltage`).
//!
//! # SP-side runtime serialization is manual
//!
//! `embedded_services::relay::SerializableMessage` does not compile for
//! `aarch64-unknown-none-softfloat` (the SBSA SP target) because
//! `embassy-sync::ThreadModeRawMutex` is `cortex_m`-gated. As a
//! workaround, SP-side runtime serialization for `GetBst` is performed
//! MANUALLY (1-byte request payload; 4 LE u32 dwords for the response
//! body). The wire-format gate test in the `tests` module below
//! round-trips bytes through the EC's OWN `SerializableMessage` impl
//! (via `[dev-dependencies]`) so any drift fails the build.

use core::cell::RefCell;

use uuid::{uuid, Uuid};

use crate::services::ec_relay::{take_array, EcRelayError, Relay};
use crate::{Result, Service};
use odp_ffa::{Error as FfaError, HasRegisterPayload, MsgSendDirectReq2, MsgSendDirectResp2};

/// Battery service id in the EC's `OdpRelayHandler` instantiation
/// (canonical value at
/// `OpenDevicePartnership/odp-embedded-controller::platform/platform-common/src/lib.rs:9`).
pub const BATTERY_SERVICE_ID: u8 = 0x08;

/// `BatteryCmd::GetBst` discriminant from
/// `embedded-services/battery-service-relay/src/serialization.rs`.
pub const BATTERY_CMD_GET_BST: u16 = 2;

/// Parsed `GetBst` response (mirrors
/// `battery_service_interface::BstReturn` field-for-field but stays
/// dependency-free at runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BstReturnRaw {
    pub battery_state: u32,
    pub battery_present_rate: u32,
    pub battery_remaining_capacity: u32,
    pub battery_present_voltage: u32,
}

/// Errors returned by [`Battery::get_bst`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatteryError {
    /// Relay (MCTP + transport) failure — see [`EcRelayError`].
    Relay(EcRelayError),
    /// EC's response was not a Battery service response or not the
    /// expected message id.
    UnexpectedResponse,
}

impl From<EcRelayError> for BatteryError {
    fn from(e: EcRelayError) -> Self {
        BatteryError::Relay(e)
    }
}

/// `Battery` holds a handle to a shared [`Relay`] — it owns no
/// transport, no assembly buffer, no MCTP framing state. Construction
/// takes only a borrow of the wiring-layer-owned `RefCell<R>`.
///
/// Battery is generic over `R: Relay` rather than over a transport
/// type: it never names `OdpTransport`, `MctpSerialTransport`, or any
/// UART type. The concrete `R = EcRelay<T>` is inferred at the wiring
/// call site. This keeps transport-layer details out of the service
/// layer's API.
///
/// Future EC-proxy services (`EcThermal`, `EcFwMgmt`, `EcTimeAlarm`)
/// follow the same pattern: `Self::new(relay: &'r RefCell<R>)`. They
/// all share the single physical EC channel by borrowing the same
/// `RefCell`-wrapped relay.
pub struct Battery<'r, R: Relay> {
    relay: &'r RefCell<R>,
}

impl<'r, R: Relay> Battery<'r, R> {
    pub fn new(relay: &'r RefCell<R>) -> Self {
        Self { relay }
    }

    /// Drive a single GetBst request/response round-trip over the EC
    /// MCTP relay. Returns the parsed BST body or a relay/wire-format
    /// error.
    pub fn get_bst(&self, battery_id: u8) -> core::result::Result<BstReturnRaw, BatteryError> {
        self.relay
            .borrow_mut()
            .invoke_request(BATTERY_SERVICE_ID, BATTERY_CMD_GET_BST, &[battery_id], |body| {
                let (state, body) = take_array(body)?;
                let (rate, body) = take_array(body)?;
                let (capacity, body) = take_array(body)?;
                let (voltage, _) = take_array(body)?;
                Ok(BstReturnRaw {
                    battery_state: u32::from_le_bytes(state),
                    battery_present_rate: u32::from_le_bytes(rate),
                    battery_remaining_capacity: u32::from_le_bytes(capacity),
                    battery_present_voltage: u32::from_le_bytes(voltage),
                })
            })
            .map_err(BatteryError::Relay)
    }
}

impl<R: Relay> Service for Battery<'_, R> {
    const UUID: Uuid = uuid!("25cb5207-ac36-427d-aaef-3aa78877d27e");
    const NAME: &'static str = "Battery";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        if msg.payload().u8_at(0) as u16 != BATTERY_CMD_GET_BST {
            return Err(FfaError::Other("Unknown Battery Command"));
        }
        let battery_id = msg.payload().u8_at(1);
        match self.get_bst(battery_id) {
            Ok(bst) => {
                // Pack the 16 BST bytes as 4 LE u32 dwords across the
                // direct-message register payload (mirrors notify.rs's
                // `From<NfyGenericRsp>` pattern of placing scalar
                // values at the start of the payload).
                let payload = odp_ffa::DirectMessagePayload::from_iter(
                    bst.battery_state
                        .to_le_bytes()
                        .into_iter()
                        .chain(bst.battery_present_rate.to_le_bytes())
                        .chain(bst.battery_remaining_capacity.to_le_bytes())
                        .chain(bst.battery_present_voltage.to_le_bytes()),
                );
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
            }
            Err(_) => Err(FfaError::Other(
                "Battery: GetBst round-trip failed (transport or wire decode)",
            )),
        }
    }
}

// ===========================================================================
// Wire-format compatibility gate
//
// Round-trips bytes through the EC's OWN `SerializableMessage::serialize` /
// `deserialize` impls from `embedded-services/battery-service-relay`. Any
// drift in field order, endianness, or discriminant numbering causes the
// assertion to fail. Runs on host (std available) — no QEMU.
// ===========================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ec_relay::test_util::{frame_response_packets, strip_mctp_framing, LoopbackTransport};
    use crate::services::ec_relay::{self, EcRelay};
    use battery_service_interface::{BatteryState, BstReturn};
    use battery_service_relay::{AcpiBatteryRequest, AcpiBatteryResponse};
    use embedded_services::relay::SerializableMessage;
    use odp_ffa::{DirectMessagePayload, HasRegisterPayload};

    fn canned_bst() -> BstReturn {
        BstReturn {
            battery_state: BatteryState::from_bits_truncate(0x0000_0001), // discharging
            battery_present_rate: 0x1122_3344,
            battery_remaining_capacity: 0x5566_7788,
            battery_present_voltage: 0x99AA_BBCC,
        }
    }

    #[test]
    fn produces_canonical_get_bst_request_bytes() {
        // -- Synthesize a response so Battery::get_bst doesn't block on transport read.
        let bst = canned_bst();
        let mut response_payload = [0u8; 16];
        let n = AcpiBatteryResponse::GetBst { bst }
            .serialize(&mut response_payload)
            .expect("ec-side serialize");
        assert_eq!(n, 16, "GetBst response body must be 16 bytes");

        let response_header = ec_relay::build_odp_header(false, BATTERY_SERVICE_ID, BATTERY_CMD_GET_BST);
        let framed_response = frame_response_packets(response_header, &response_payload);

        // -- Construct the shared EcRelay (wrapping a loopback transport)
        //    and hand a borrow to the Battery service.
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed_response.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let svc = Battery::new(&relay);

        // -- Drive the round-trip.
        let result = svc.get_bst(0).expect("get_bst should decode synthesized response");

        // -- ASSERT 1 (request side, byte-level):
        //    Battery's TX bytes (MCTP-framed) decode back to exactly:
        //      OdpHeader [0x02, 0x08, 0x00, 0x02]  +  payload [0x00]
        let tx_bytes = relay.borrow().transport().tx.clone();
        let inner_tx = strip_mctp_framing(&tx_bytes);
        assert_eq!(
            inner_tx,
            std::vec![0x02, 0x08, 0x00, 0x02, 0x00],
            "Battery GetBst request wire bytes must match the EC's expected encoding exactly"
        );

        // -- ASSERT 2 (round-trip via the EC's OWN deserializer):
        //    The bytes Battery produced parse back to GetBst { battery_id: 0 }
        //    via `AcpiBatteryRequest::deserialize`.
        let (is_req, svc_id, _is_err, msg_id) = ec_relay::parse_odp_header(&inner_tx[..4]).expect("parse header");
        assert!(is_req, "must be a request");
        assert_eq!(svc_id, BATTERY_SERVICE_ID);
        assert_eq!(msg_id, BATTERY_CMD_GET_BST);
        let decoded = AcpiBatteryRequest::deserialize(msg_id, &inner_tx[4..])
            .expect("ec-side decoder must accept SP-produced bytes");
        assert!(
            matches!(decoded, AcpiBatteryRequest::GetBst { battery_id: 0 }),
            "EC-side decoder must reconstruct the original request variant"
        );

        // -- ASSERT 3 (response side): Battery returned the BST values
        //    synthesized at the top.
        assert_eq!(result.battery_state, bst.battery_state.bits());
        assert_eq!(result.battery_present_rate, bst.battery_present_rate);
        assert_eq!(result.battery_remaining_capacity, bst.battery_remaining_capacity);
        assert_eq!(result.battery_present_voltage, bst.battery_present_voltage);
    }

    fn relay_primed_with_bst(bst: BstReturn) -> RefCell<EcRelay<LoopbackTransport>> {
        let mut response_payload = [0u8; 16];
        AcpiBatteryResponse::GetBst { bst }
            .serialize(&mut response_payload)
            .expect("ec-side serialize");
        let header = ec_relay::build_odp_header(false, BATTERY_SERVICE_ID, BATTERY_CMD_GET_BST);
        let framed = frame_response_packets(header, &response_payload);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        RefCell::new(EcRelay::new(transport))
    }

    fn make_ffa_request(opcode: u8, battery_id: u8) -> MsgSendDirectReq2 {
        MsgSendDirectReq2::new(
            0x0001,
            0x8001,
            Battery::<EcRelay<LoopbackTransport>>::UUID,
            DirectMessagePayload::from_iter([opcode, battery_id]),
        )
    }

    #[test]
    fn ffa_get_bst_relays_requested_battery_id_and_preserves_response() {
        let bst = canned_bst();
        let relay = relay_primed_with_bst(bst);
        let mut svc = Battery::new(&relay);

        let battery_id = 0x03;
        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(BATTERY_CMD_GET_BST as u8, battery_id))
            .expect("valid GetBst returns DIRECT_RESP2");

        let inner_tx = strip_mctp_framing(&relay.borrow().transport().tx);
        assert_eq!(
            inner_tx,
            std::vec![0x02, 0x08, 0x00, 0x02, battery_id],
            "requested battery_id must appear as the last EC request byte"
        );

        assert_eq!(response.payload().u32_at(0), bst.battery_state.bits());
        assert_eq!(response.payload().u32_at(4), bst.battery_present_rate);
        assert_eq!(response.payload().u32_at(8), bst.battery_remaining_capacity);
        assert_eq!(response.payload().u32_at(12), bst.battery_present_voltage);
    }

    #[test]
    fn ffa_unknown_opcode_is_rejected_without_relaying() {
        let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
        let mut svc = Battery::new(&relay);

        let result = svc.ffa_msg_send_direct_req2(make_ffa_request(0xFF, 0x00));

        assert_eq!(result, Err(FfaError::Other("Unknown Battery Command")));
        assert!(
            relay.borrow().transport().tx.is_empty(),
            "unknown opcode must be rejected before any relay I/O"
        );
    }
}
