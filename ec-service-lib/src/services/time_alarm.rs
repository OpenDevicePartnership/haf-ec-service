use core::cell::RefCell;

use uuid::{uuid, Uuid};

use crate::services::ec_relay::{take_exact_array, EcRelayError, Relay};
use crate::{Result, Service};
use odp_ffa::{DirectMessagePayload, Error as FfaError, HasRegisterPayload, MsgSendDirectReq2, MsgSendDirectResp2};

pub const TIME_ALARM_SERVICE_ID: u8 = 0x0B;
pub const TIME_ALARM_UUID: Uuid = uuid!("23ea63ed-b593-46ea-b027-8924df88e92f");
const ACPI_TIMESTAMP_LEN: usize = 16;
const INVALID_TIMESTAMP: [u8; ACPI_TIMESTAMP_LEN] = [0u8; ACPI_TIMESTAMP_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u16)]
pub enum TimeAlarmCommand {
    GetRealTime = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAlarmError {
    Relay(EcRelayError),
}

impl From<EcRelayError> for TimeAlarmError {
    fn from(error: EcRelayError) -> Self {
        Self::Relay(error)
    }
}

pub struct TimeAlarm<'r, R: Relay> {
    relay: &'r RefCell<R>,
}

impl<'r, R: Relay> TimeAlarm<'r, R> {
    pub fn new(relay: &'r RefCell<R>) -> Self {
        Self { relay }
    }

    pub fn get_real_time(&self) -> core::result::Result<[u8; ACPI_TIMESTAMP_LEN], TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::GetRealTime.into(),
                &[],
                take_exact_array::<ACPI_TIMESTAMP_LEN>,
            )
            .map_err(TimeAlarmError::Relay)
    }
}

impl<R: Relay> Service for TimeAlarm<'_, R> {
    const UUID: Uuid = TIME_ALARM_UUID;
    const NAME: &'static str = "TimeAlarm";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let command = TimeAlarmCommand::try_from(msg.payload().u8_at(0) as u16)
            .map_err(|_| FfaError::Other("Unknown TimeAlarm Command"))?;

        match command {
            TimeAlarmCommand::GetRealTime => {
                let timestamp = self.get_real_time().unwrap_or(INVALID_TIMESTAMP);
                Ok(MsgSendDirectResp2::from_req_with_payload(
                    &msg,
                    DirectMessagePayload::from_iter(timestamp),
                ))
            }
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::ec_relay::test_util::{frame_response_packets, strip_mctp_framing, LoopbackTransport};
    use crate::services::ec_relay::{self, EcRelay};
    use embedded_services::relay::SerializableMessage;
    use time_alarm_service_interface::AcpiTimestamp;
    use time_alarm_service_relay::{AcpiTimeAlarmRequest, AcpiTimeAlarmResponse};

    const RAW_TIMESTAMP: [u8; ACPI_TIMESTAMP_LEN] = [
        0xEA, 0x07, // 2026
        7, 10, // month, day
        12, 34, 56, 1, 0x15, 0x03, // 789 ms
        0, 0, // UTC
        0, // DST not observed
        0, 0, 0,
    ];

    fn serialized_timestamp() -> [u8; ACPI_TIMESTAMP_LEN] {
        let timestamp = AcpiTimestamp::try_from_bytes(&RAW_TIMESTAMP).expect("valid timestamp");
        let mut body = [0u8; ACPI_TIMESTAMP_LEN];
        let n = AcpiTimeAlarmResponse::RealTime(timestamp)
            .serialize(&mut body)
            .expect("EC-side serialize");
        assert_eq!(n, ACPI_TIMESTAMP_LEN);
        body
    }

    fn response_header() -> [u8; 4] {
        ec_relay::build_odp_header(false, TIME_ALARM_SERVICE_ID, TimeAlarmCommand::GetRealTime.into())
    }

    fn make_ffa_request(command: u8) -> MsgSendDirectReq2 {
        let payload = DirectMessagePayload::from_iter([command]);
        MsgSendDirectReq2::new(0x0001, 0x8001, TIME_ALARM_UUID, payload)
    }

    #[test]
    fn produces_canonical_get_real_time_request_bytes() {
        let body = serialized_timestamp();
        let framed = frame_response_packets(response_header(), &body);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let svc = TimeAlarm::new(&relay);

        assert_eq!(svc.get_real_time().expect("GetRealTime"), body);

        let tx = relay.borrow().transport().tx.clone();
        let inner = strip_mctp_framing(&tx);
        assert_eq!(inner, std::vec![0x02, 0x0B, 0x00, 0x02]);

        let (is_req, service_id, _, message_id) = ec_relay::parse_odp_header(&inner[..4]).expect("header");
        assert!(is_req);
        assert_eq!(service_id, TIME_ALARM_SERVICE_ID);
        let decoded = AcpiTimeAlarmRequest::deserialize(message_id, &inner[4..]).expect("EC decoder accepts request");
        assert!(matches!(decoded, AcpiTimeAlarmRequest::GetRealTime));
    }

    #[test]
    fn rejects_short_get_real_time_response() {
        let framed = frame_response_packets(response_header(), &[0u8; ACPI_TIMESTAMP_LEN - 1]);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let svc = TimeAlarm::new(&relay);
        assert_eq!(
            svc.get_real_time(),
            Err(TimeAlarmError::Relay(EcRelayError::BodyTooShort))
        );
    }

    #[test]
    fn rejects_trailing_get_real_time_response() {
        let framed = frame_response_packets(response_header(), &[0u8; ACPI_TIMESTAMP_LEN + 1]);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let svc = TimeAlarm::new(&relay);
        assert_eq!(
            svc.get_real_time(),
            Err(TimeAlarmError::Relay(EcRelayError::BodyTooLong))
        );
    }

    #[test]
    fn ffa_success_returns_timestamp_at_payload_offset_zero() {
        let body = serialized_timestamp();
        let framed = frame_response_packets(response_header(), &body);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let mut svc = TimeAlarm::new(&relay);

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(2))
            .expect("known command returns DIRECT_RESP2");
        for (offset, expected) in body.into_iter().enumerate() {
            assert_eq!(response.payload().u8_at(offset), expected);
        }
    }

    #[test]
    fn ffa_error_envelope_returns_invalid_zero_timestamp() {
        let header = ec_relay::test_util::build_odp_error_header(TIME_ALARM_SERVICE_ID, 1);
        let framed = frame_response_packets(header, &[]);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        let relay = RefCell::new(EcRelay::new(transport));
        let mut svc = TimeAlarm::new(&relay);

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(2))
            .expect("known command returns invalid timestamp");
        for offset in 0..ACPI_TIMESTAMP_LEN {
            assert_eq!(response.payload().u8_at(offset), 0);
        }
    }

    #[test]
    fn rejects_unknown_ffa_command() {
        let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
        let mut svc = TimeAlarm::new(&relay);
        assert!(svc.ffa_msg_send_direct_req2(make_ffa_request(0xFF)).is_err());
    }
}
