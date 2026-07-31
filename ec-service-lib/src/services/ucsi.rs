//! `Ucsi` — secure-world UCSI Platform Policy Manager (PPM) test stub.
//!
//! Returns deterministic fake data so the OS side can exercise the full
//! UCSI-over-FF-A-through-ACPI path against QEMU. The request carries a
//! doorbell tag byte followed by the 48-byte UCSI mailbox inline in the
//! FF-A register payload; the response returns the updated mailbox at
//! payload offset 0.
//!
//! # Mailbox layout (48 bytes, UCSI 1.2)
//! `VERSION@0 (u16)`, `RESERVED@2`, `CCI@4 (u32)`, `CONTROL@8 (8 bytes,
//! opcode at byte 0, connector number at byte 2)`, `MESSAGE IN@16 (16
//! bytes)`, `MESSAGE OUT@32 (16 bytes)`.
//!
//! # Manual encoding
//! `embedded-usb-pd` does not compile for `aarch64-unknown-none[-softfloat]`,
//! so the fake `MESSAGE IN` payloads are held as `const` byte arrays and the
//! CCI is hand-written. The host-only wire-format gate test round-trips each
//! fixture through the upstream `embedded-usb-pd` encoder so the bytes can
//! never silently drift from valid UCSI wire data.

use uuid::{uuid, Uuid};

use crate::{Result, Service};
use odp_ffa::{DirectMessagePayload, Error as FfaError, HasRegisterPayload, MsgSendDirectReq2, MsgSendDirectResp2};

pub const UCSI_UUID: Uuid = uuid!("65467f50-827f-4e4f-8770-dbf4c3f77f45");

const MAILBOX_LEN: usize = 48;
/// The 48-byte mailbox starts after the doorbell tag byte in the FF-A payload.
const MAILBOX_PAYLOAD_START: usize = 1;
const VERSION_OFFSET: usize = 0;
const CCI_OFFSET: usize = 4;
const CONTROL_OFFSET: usize = 8;
const MESSAGE_IN_OFFSET: usize = 16;

/// UCSI 1.2.
const VERSION: u16 = 0x0120;
/// The doorbell tag the OS writes at FF-A payload byte 0.
const DOORBELL: u8 = 0x00;
/// Only a single connector (connector #1) is modeled.
const CONNECTOR_ONE: u8 = 1;

const OP_GET_CAPABILITY: u8 = 0x06;
const OP_GET_CONNECTOR_CAPABILITY: u8 = 0x07;
const OP_GET_CONNECTOR_STATUS: u8 = 0x12;

// CCI = cmd_complete (bit31) | data_len (bits 15..8). See embedded-usb-pd cci.rs.
const CCI_CAPABILITY: u32 = 0x8000_1000;
const CCI_CONNECTOR_CAPABILITY: u32 = 0x8000_0200;
const CCI_CONNECTOR_STATUS: u32 = 0x8000_0B00;
/// not_supported (bit25), no data.
const CCI_NOT_SUPPORTED: u32 = 0x0200_0000;

// Deterministic single-connector USB-PD sink fixtures. Validated byte-for-byte
// against the embedded-usb-pd encoder in `fixtures_match_embedded_usb_pd_encoder`.
const CAPABILITY_MESSAGE_IN: [u8; 16] = [
    0x46, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x03, 0x00, 0x02,
];
const CONNECTOR_CAPABILITY_MESSAGE_IN: [u8; 2] = [0x64, 0x03];
const CONNECTOR_STATUS_MESSAGE_IN: [u8; 11] = [0x00, 0x00, 0x29, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Default)]
pub struct Ucsi;

impl Ucsi {
    pub fn new() -> Self {
        Self
    }
}

impl Service for Ucsi {
    const UUID: Uuid = UCSI_UUID;
    const NAME: &'static str = "Ucsi";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let payload = msg.payload();
        if payload.u8_at(0) != DOORBELL {
            return Err(FfaError::Other("UCSI: unexpected doorbell tag"));
        }

        let mut mailbox = [0u8; MAILBOX_LEN];
        mailbox.copy_from_slice(payload.slice(MAILBOX_PAYLOAD_START..MAILBOX_PAYLOAD_START + MAILBOX_LEN));

        let opcode = mailbox[CONTROL_OFFSET];
        let connector = mailbox[CONTROL_OFFSET + 2];
        let (cci, message_in): (u32, &[u8]) = match opcode {
            OP_GET_CAPABILITY => (CCI_CAPABILITY, &CAPABILITY_MESSAGE_IN),
            OP_GET_CONNECTOR_CAPABILITY if connector == CONNECTOR_ONE => {
                (CCI_CONNECTOR_CAPABILITY, &CONNECTOR_CAPABILITY_MESSAGE_IN)
            }
            OP_GET_CONNECTOR_STATUS if connector == CONNECTOR_ONE => {
                (CCI_CONNECTOR_STATUS, &CONNECTOR_STATUS_MESSAGE_IN)
            }
            _ => (CCI_NOT_SUPPORTED, &[]),
        };

        mailbox[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&VERSION.to_le_bytes());
        mailbox[CCI_OFFSET..CCI_OFFSET + 4].copy_from_slice(&cci.to_le_bytes());
        mailbox[MESSAGE_IN_OFFSET..].fill(0);
        mailbox[MESSAGE_IN_OFFSET..MESSAGE_IN_OFFSET + message_in.len()].copy_from_slice(message_in);

        Ok(MsgSendDirectResp2::from_req_with_payload(
            &msg,
            DirectMessagePayload::from_iter(mailbox),
        ))
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    use embedded_usb_pd::ucsi::cci::LocalCci;
    use embedded_usb_pd::ucsi::lpm::get_connector_capability as gcc;
    use embedded_usb_pd::ucsi::lpm::get_connector_status as gcs;
    use embedded_usb_pd::ucsi::ppm::get_capability as gcap;
    use embedded_usb_pd::ucsi::{lpm, ppm, ResponseData};
    use embedded_usb_pd::PowerRole;

    const DOORBELL: u8 = 0x00;

    /// Build an FF-A request carrying the doorbell tag + a 48-byte mailbox
    /// with `opcode` at CONTROL offset 0 and `connector` at CONTROL offset 2.
    fn request(opcode: u8, connector: u8) -> MsgSendDirectReq2 {
        let mut mailbox = [0u8; MAILBOX_LEN];
        mailbox[CONTROL_OFFSET] = opcode;
        mailbox[CONTROL_OFFSET + 2] = connector;
        let payload = DirectMessagePayload::from_iter(core::iter::once(DOORBELL).chain(mailbox));
        MsgSendDirectReq2::new(0x0001, 0x8001, UCSI_UUID, payload)
    }

    fn respond(opcode: u8, connector: u8) -> DirectMessagePayload {
        Ucsi::new()
            .ffa_msg_send_direct_req2(request(opcode, connector))
            .expect("UCSI always answers with a mailbox")
            .payload()
            .clone()
    }

    fn message_in(mailbox: &DirectMessagePayload, len: usize) -> std::vec::Vec<u8> {
        mailbox.slice(MESSAGE_IN_OFFSET..MESSAGE_IN_OFFSET + len).to_vec()
    }

    #[test]
    fn get_capability_returns_fixture_and_cci() {
        let m = respond(0x06, 0);
        assert_eq!(m.u16_at(VERSION_OFFSET), VERSION);
        assert_eq!(m.u32_at(CCI_OFFSET), CCI_CAPABILITY);
        assert_eq!(message_in(&m, CAPABILITY_MESSAGE_IN.len()), CAPABILITY_MESSAGE_IN);
        // CONTROL is echoed back untouched.
        assert_eq!(m.u8_at(CONTROL_OFFSET), 0x06);
    }

    #[test]
    fn get_connector_capability_returns_fixture_and_cci() {
        let m = respond(0x07, 1);
        assert_eq!(m.u32_at(CCI_OFFSET), CCI_CONNECTOR_CAPABILITY);
        assert_eq!(
            message_in(&m, CONNECTOR_CAPABILITY_MESSAGE_IN.len()),
            CONNECTOR_CAPABILITY_MESSAGE_IN
        );
    }

    #[test]
    fn get_connector_status_returns_fixture_and_cci() {
        let m = respond(0x12, 1);
        assert_eq!(m.u32_at(CCI_OFFSET), CCI_CONNECTOR_STATUS);
        assert_eq!(
            message_in(&m, CONNECTOR_STATUS_MESSAGE_IN.len()),
            CONNECTOR_STATUS_MESSAGE_IN
        );
    }

    #[test]
    fn unknown_opcode_reports_not_supported_with_zeroed_message_in() {
        let m = respond(0x13, 0);
        assert_eq!(m.u16_at(VERSION_OFFSET), VERSION);
        assert_eq!(m.u32_at(CCI_OFFSET), CCI_NOT_SUPPORTED);
        assert_eq!(
            m.slice(MESSAGE_IN_OFFSET..MAILBOX_LEN),
            [0u8; MAILBOX_LEN - MESSAGE_IN_OFFSET]
        );
    }

    #[test]
    fn invalid_connector_reports_not_supported_with_zeroed_message_in() {
        for opcode in [0x07u8, 0x12u8] {
            let m = respond(opcode, 2);
            assert_eq!(m.u32_at(CCI_OFFSET), CCI_NOT_SUPPORTED);
            assert_eq!(
                m.slice(MESSAGE_IN_OFFSET..MAILBOX_LEN),
                [0u8; MAILBOX_LEN - MESSAGE_IN_OFFSET]
            );
        }
    }

    /// Wire-format gate: the hand-encoded fixture consts and CCI values must
    /// equal what the upstream `embedded-usb-pd` encoder produces, proving the
    /// SP emits valid UCSI 1.2 wire bytes (and can never silently drift).
    #[test]
    fn fixtures_match_embedded_usb_pd_encoder() {
        let mut cap = gcap::ResponseData::default();
        cap.attributes
            .set_battery_charging(true)
            .set_usb_power_delivery(true)
            .set_usb_type_c_current(true)
            .set_power_source(*gcap::PowerSource::default().set_use_vbus(true));
        cap.num_connectors = 1;
        cap.bcd_battery_charging_spec = 0x0120;
        cap.bcd_usb_pd_spec = 0x0300;
        cap.bcd_type_c_spec = 0x0200;
        let mut cap_bytes = [0u8; 16];
        ResponseData::Ppm(ppm::ResponseData::GetCapability(cap))
            .encode_into_slice(&mut cap_bytes)
            .unwrap();
        assert_eq!(cap_bytes, CAPABILITY_MESSAGE_IN);

        let mut cc = gcc::ResponseData::default();
        cc.set_operation_mode(
            *gcc::OperationModeFlags::default()
                .set_drp(true)
                .set_usb2(true)
                .set_usb3(true),
        )
        .set_provider(true)
        .set_consumer(true);
        let mut cc_bytes = [0u8; 2];
        ResponseData::Lpm(lpm::ResponseData::GetConnectorCapability(cc))
            .encode_into_slice(&mut cc_bytes)
            .unwrap();
        assert_eq!(cc_bytes, CONNECTOR_CAPABILITY_MESSAGE_IN);

        let mut partner = gcs::ConnectorPartnerFlags::from(0u8);
        partner.set_usb(true);
        let status = gcs::ResponseData {
            status_change: gcs::ConnectorStatusChange::default(),
            connect_status: true,
            status: Some(gcs::ConnectedStatus {
                power_op_mode: gcs::PowerOperationMode::UsbDefault,
                power_direction: PowerRole::Sink,
                partner_flags: partner,
                partner_type: gcs::ConnectorPartnerType::DfpAttached,
                rdo: None,
                battery_charging_status: Some(gcs::BatteryChargingCapabilityStatus::NotCharging),
                provider_caps_limited: None,
                bcd_pd_version: None,
            }),
        };
        let mut cs_bytes = [0u8; 11];
        ResponseData::Lpm(lpm::ResponseData::GetConnectorStatus(status))
            .encode_into_slice(&mut cs_bytes)
            .unwrap();
        assert_eq!(cs_bytes, CONNECTOR_STATUS_MESSAGE_IN);

        assert_eq!(
            u32::from(*LocalCci::new_cmd_complete().set_data_len(16)),
            CCI_CAPABILITY
        );
        assert_eq!(
            u32::from(*LocalCci::new_cmd_complete().set_data_len(2)),
            CCI_CONNECTOR_CAPABILITY
        );
        assert_eq!(
            u32::from(*LocalCci::new_cmd_complete().set_data_len(11)),
            CCI_CONNECTOR_STATUS
        );
        assert_eq!(
            u32::from(*LocalCci::default().set_not_supported(true)),
            CCI_NOT_SUPPORTED
        );
    }
}
