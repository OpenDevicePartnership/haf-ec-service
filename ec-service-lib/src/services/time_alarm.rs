use core::cell::RefCell;

use uuid::{uuid, Uuid};
use zerocopy::{byteorder::little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::parse_ffa_request;
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
    GetCapabilities = 1,
    GetRealTime = 2,
    GetWakeStatus = 4,
    SetTimerValue = 6,
    GetTimerValue = 7,
    GetExpiredTimerPolicy = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::IntoPrimitive)]
#[repr(u16)]
enum TimeAlarmResponseDiscriminant {
    Capabilities = 1,
    TimerStatus = 3,
    WakePolicy = 4,
    TimerSeconds = 5,
    OkNoData = 6,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct GetWakeStatusRequest {
    timer_id: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SetTimerValueRequest {
    timer_id: U32,
    seconds: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct GetTimerValueRequest {
    timer_id: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct GetExpiredTimerPolicyRequest {
    timer_id: U32,
}

fn parse_empty_response(body: &[u8]) -> core::result::Result<(), EcRelayError> {
    take_exact_array::<0>(body).map(|_| ())
}

const LOCAL_ERROR_SENTINEL: u32 = u32::MAX;

fn scalar_payload(value: u32) -> DirectMessagePayload {
    DirectMessagePayload::from_iter(value.to_le_bytes())
}

fn setter_status(result: core::result::Result<(), TimeAlarmError>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(TimeAlarmError::Relay(EcRelayError::Remote(code))) => u32::from(code),
        Err(_) => LOCAL_ERROR_SENTINEL,
    }
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

    fn get_capabilities(&self) -> core::result::Result<u32, TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request_with_response_id(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::GetCapabilities.into(),
                TimeAlarmResponseDiscriminant::Capabilities.into(),
                &[],
                |body| take_exact_array::<4>(body).map(u32::from_le_bytes),
            )
            .map_err(TimeAlarmError::Relay)
    }

    fn get_wake_status(&self, request: &GetWakeStatusRequest) -> core::result::Result<u32, TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request_with_response_id(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::GetWakeStatus.into(),
                TimeAlarmResponseDiscriminant::TimerStatus.into(),
                request.as_bytes(),
                |body| take_exact_array::<4>(body).map(u32::from_le_bytes),
            )
            .map_err(TimeAlarmError::Relay)
    }

    fn set_timer_value(&self, request: &SetTimerValueRequest) -> core::result::Result<(), TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request_with_response_id(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::SetTimerValue.into(),
                TimeAlarmResponseDiscriminant::OkNoData.into(),
                request.as_bytes(),
                parse_empty_response,
            )
            .map_err(TimeAlarmError::Relay)
    }

    fn get_timer_value(&self, request: &GetTimerValueRequest) -> core::result::Result<u32, TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request_with_response_id(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::GetTimerValue.into(),
                TimeAlarmResponseDiscriminant::TimerSeconds.into(),
                request.as_bytes(),
                |body| {
                    let seconds = take_exact_array::<4>(body)?;
                    Ok(u32::from_le_bytes(seconds))
                },
            )
            .map_err(TimeAlarmError::Relay)
    }

    fn get_expired_timer_policy(
        &self,
        request: &GetExpiredTimerPolicyRequest,
    ) -> core::result::Result<u32, TimeAlarmError> {
        self.relay
            .borrow_mut()
            .invoke_request_with_response_id(
                TIME_ALARM_SERVICE_ID,
                TimeAlarmCommand::GetExpiredTimerPolicy.into(),
                TimeAlarmResponseDiscriminant::WakePolicy.into(),
                request.as_bytes(),
                |body| take_exact_array::<4>(body).map(u32::from_le_bytes),
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
            TimeAlarmCommand::GetCapabilities => {
                let value = self.get_capabilities().unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
            }
            TimeAlarmCommand::GetRealTime => {
                let timestamp = self.get_real_time().unwrap_or(INVALID_TIMESTAMP);
                Ok(MsgSendDirectResp2::from_req_with_payload(
                    &msg,
                    DirectMessagePayload::from_iter(timestamp),
                ))
            }
            TimeAlarmCommand::GetWakeStatus => {
                let value = parse_ffa_request::<GetWakeStatusRequest>(msg.payload())
                    .map(|request| self.get_wake_status(request).unwrap_or(LOCAL_ERROR_SENTINEL))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
            }
            TimeAlarmCommand::SetTimerValue => {
                let status = parse_ffa_request::<SetTimerValueRequest>(msg.payload())
                    .map(|request| setter_status(self.set_timer_value(request)))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(status)))
            }
            TimeAlarmCommand::GetTimerValue => {
                let value = parse_ffa_request::<GetTimerValueRequest>(msg.payload())
                    .map(|request| self.get_timer_value(request).unwrap_or(LOCAL_ERROR_SENTINEL))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
            }
            TimeAlarmCommand::GetExpiredTimerPolicy => {
                let value = parse_ffa_request::<GetExpiredTimerPolicyRequest>(msg.payload())
                    .map(|request| self.get_expired_timer_policy(request).unwrap_or(LOCAL_ERROR_SENTINEL))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
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
    use time_alarm_service_interface::{
        AcpiTimerId, AcpiTimestamp, AlarmExpiredWakePolicy, AlarmTimerSeconds, TimeAlarmDeviceCapabilities, TimerStatus,
    };
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

    fn serialized_response<const N: usize>(response: AcpiTimeAlarmResponse) -> ([u8; 4], [u8; N]) {
        let response_id = response.discriminant();
        let mut body = [0u8; N];
        let written = response.serialize(&mut body).expect("EC-side serialize");
        assert_eq!(written, N);
        (
            ec_relay::build_odp_header(false, TIME_ALARM_SERVICE_ID, response_id),
            body,
        )
    }

    fn relay_with_response(header: [u8; 4], body: &[u8]) -> RefCell<EcRelay<LoopbackTransport>> {
        let framed = frame_response_packets(header, body);
        let mut transport = LoopbackTransport::new();
        transport.prime_rx(framed.iter().copied());
        RefCell::new(EcRelay::new(transport))
    }

    fn transmitted_inner(relay: &RefCell<EcRelay<LoopbackTransport>>) -> std::vec::Vec<u8> {
        strip_mctp_framing(&relay.borrow().transport().tx)
    }

    fn make_ffa_request(command: u8, args: &[u8]) -> MsgSendDirectReq2 {
        let payload = DirectMessagePayload::from_iter(core::iter::once(command).chain(args.iter().copied()));
        MsgSendDirectReq2::new(0x0001, 0x8001, TIME_ALARM_UUID, payload)
    }

    fn ffa_scalar_response(
        response_header: Option<[u8; 4]>,
        response_body: &[u8],
        command: TimeAlarmCommand,
        args: &[u8],
    ) -> u32 {
        let mut transport = LoopbackTransport::new();
        if let Some(header) = response_header {
            let framed = frame_response_packets(header, response_body);
            transport.prime_rx(framed.iter().copied());
        }
        let relay = RefCell::new(EcRelay::new(transport));
        let mut svc = TimeAlarm::new(&relay);
        let command = u16::from(command) as u8;
        svc.ffa_msg_send_direct_req2(make_ffa_request(command, args))
            .expect("known command returns DIRECT_RESP2")
            .payload()
            .u32_at(0)
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
    fn get_capabilities_uses_canonical_wire_contract() {
        let capabilities = TimeAlarmDeviceCapabilities(0x1F7);
        let (header, body) = serialized_response::<4>(AcpiTimeAlarmResponse::Capabilities(capabilities));
        let relay = relay_with_response(header, &body);
        let mut svc = TimeAlarm::new(&relay);

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(
                u16::from(TimeAlarmCommand::GetCapabilities) as u8,
                &[],
            ))
            .expect("GetCapabilities returns DIRECT_RESP2");

        assert_eq!(response.payload().u32_at(0), capabilities.0);
        let inner = transmitted_inner(&relay);
        assert_eq!(inner, std::vec![0x02, 0x0B, 0x00, 0x01]);
        assert_eq!(
            AcpiTimeAlarmRequest::deserialize(1, &inner[4..]).expect("EC decoder accepts GetCapabilities"),
            AcpiTimeAlarmRequest::GetCapabilities,
        );
    }

    #[test]
    fn get_wake_status_uses_canonical_wire_contract() {
        let status = TimerStatus(0x03);
        let (header, body) = serialized_response::<4>(AcpiTimeAlarmResponse::TimerStatus(status));
        let relay = relay_with_response(header, &body);
        let mut svc = TimeAlarm::new(&relay);
        let timer_id = u32::from(AcpiTimerId::DcPower).to_le_bytes();

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(
                u16::from(TimeAlarmCommand::GetWakeStatus) as u8,
                &timer_id,
            ))
            .expect("GetWakeStatus returns DIRECT_RESP2");

        assert_eq!(response.payload().u32_at(0), status.0);
        let inner = transmitted_inner(&relay);
        let mut expected = std::vec![0x02, 0x0B, 0x00, 0x04];
        expected.extend_from_slice(&timer_id);
        assert_eq!(inner, expected);
        assert_eq!(
            AcpiTimeAlarmRequest::deserialize(4, &inner[4..]).expect("EC decoder accepts GetWakeStatus"),
            AcpiTimeAlarmRequest::GetWakeStatus(AcpiTimerId::DcPower),
        );
    }

    #[test]
    fn get_expired_timer_policy_uses_canonical_wire_contract() {
        let policy = AlarmExpiredWakePolicy(45);
        let (header, body) = serialized_response::<4>(AcpiTimeAlarmResponse::WakePolicy(policy));
        let relay = relay_with_response(header, &body);
        let mut svc = TimeAlarm::new(&relay);
        let timer_id = u32::from(AcpiTimerId::AcPower).to_le_bytes();

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(
                u16::from(TimeAlarmCommand::GetExpiredTimerPolicy) as u8,
                &timer_id,
            ))
            .expect("GetExpiredTimerPolicy returns DIRECT_RESP2");

        assert_eq!(response.payload().u32_at(0), policy.0);
        let inner = transmitted_inner(&relay);
        let mut expected = std::vec![0x02, 0x0B, 0x00, 0x09];
        expected.extend_from_slice(&timer_id);
        assert_eq!(inner, expected);
        assert_eq!(
            AcpiTimeAlarmRequest::deserialize(9, &inner[4..]).expect("EC decoder accepts GetExpiredTimerPolicy"),
            AcpiTimeAlarmRequest::GetExpiredTimerPolicy(AcpiTimerId::AcPower),
        );
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
    fn set_timer_value_uses_canonical_wire_contract() {
        let (header, body) = serialized_response::<0>(AcpiTimeAlarmResponse::OkNoData);
        let relay = relay_with_response(header, &body);
        let mut svc = TimeAlarm::new(&relay);
        let mut args = [0u8; 8];
        args[..4].copy_from_slice(&0u32.to_le_bytes());
        args[4..].copy_from_slice(&300u32.to_le_bytes());

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(
                u16::from(TimeAlarmCommand::SetTimerValue) as u8,
                &args,
            ))
            .expect("known command returns DIRECT_RESP2");
        assert_eq!(response.payload().u32_at(0), 0);

        let inner = transmitted_inner(&relay);
        let mut expected = std::vec![0x02, 0x0B, 0x00, 0x06];
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&300u32.to_le_bytes());
        assert_eq!(inner, expected);
        assert_eq!(
            AcpiTimeAlarmRequest::deserialize(6, &inner[4..]).expect("EC decoder accepts SetTimerValue"),
            AcpiTimeAlarmRequest::SetTimerValue(AcpiTimerId::AcPower, AlarmTimerSeconds(300),),
        );
    }

    #[test]
    fn get_timer_value_uses_canonical_wire_contract() {
        let (header, body) = serialized_response::<4>(AcpiTimeAlarmResponse::TimerSeconds(AlarmTimerSeconds(297)));
        let relay = relay_with_response(header, &body);
        let mut svc = TimeAlarm::new(&relay);
        let args = 0u32.to_le_bytes();

        let response = svc
            .ffa_msg_send_direct_req2(make_ffa_request(
                u16::from(TimeAlarmCommand::GetTimerValue) as u8,
                &args,
            ))
            .expect("known command returns DIRECT_RESP2");
        assert_eq!(response.payload().u32_at(0), 297);

        let inner = transmitted_inner(&relay);
        let mut expected = std::vec![0x02, 0x0B, 0x00, 0x07];
        expected.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(inner, expected);
        assert_eq!(
            AcpiTimeAlarmRequest::deserialize(7, &inner[4..]).expect("EC decoder accepts GetTimerValue"),
            AcpiTimeAlarmRequest::GetTimerValue(AcpiTimerId::AcPower),
        );
    }

    #[test]
    fn timer_value_rejects_non_exact_response_bodies() {
        let set_header = ec_relay::build_odp_header(
            false,
            TIME_ALARM_SERVICE_ID,
            AcpiTimeAlarmResponse::OkNoData.discriminant(),
        );
        let set_relay = relay_with_response(set_header, &[0]);
        let set_svc = TimeAlarm::new(&set_relay);
        let set_request = SetTimerValueRequest {
            timer_id: U32::new(0),
            seconds: U32::new(300),
        };
        assert_eq!(
            set_svc.set_timer_value(&set_request),
            Err(TimeAlarmError::Relay(EcRelayError::BodyTooLong)),
        );

        let get_header = ec_relay::build_odp_header(
            false,
            TIME_ALARM_SERVICE_ID,
            AcpiTimeAlarmResponse::TimerSeconds(AlarmTimerSeconds(0)).discriminant(),
        );
        let get_request = GetTimerValueRequest { timer_id: U32::new(0) };

        let short_relay = relay_with_response(get_header, &[0; 3]);
        assert_eq!(
            TimeAlarm::new(&short_relay).get_timer_value(&get_request),
            Err(TimeAlarmError::Relay(EcRelayError::BodyTooShort)),
        );

        let trailing_relay = relay_with_response(get_header, &[0; 5]);
        assert_eq!(
            TimeAlarm::new(&trailing_relay).get_timer_value(&get_request),
            Err(TimeAlarmError::Relay(EcRelayError::BodyTooLong)),
        );
    }

    #[test]
    fn ffa_set_timer_value_maps_remote_and_local_errors() {
        let mut args = [0u8; 8];
        args[..4].copy_from_slice(&0u32.to_le_bytes());
        args[4..].copy_from_slice(&300u32.to_le_bytes());

        let remote_header = ec_relay::test_util::build_odp_error_header(TIME_ALARM_SERVICE_ID, 1);
        assert_eq!(
            ffa_scalar_response(Some(remote_header), &[], TimeAlarmCommand::SetTimerValue, &args,),
            1,
        );

        assert_eq!(
            ffa_scalar_response(None, &[], TimeAlarmCommand::SetTimerValue, &args,),
            u32::MAX,
        );
    }

    #[test]
    fn ffa_get_timer_value_maps_remote_and_local_errors() {
        let args = 0u32.to_le_bytes();

        let remote_header = ec_relay::test_util::build_odp_error_header(TIME_ALARM_SERVICE_ID, 1);
        assert_eq!(
            ffa_scalar_response(Some(remote_header), &[], TimeAlarmCommand::GetTimerValue, &args,),
            u32::MAX,
        );

        assert_eq!(
            ffa_scalar_response(None, &[], TimeAlarmCommand::GetTimerValue, &args,),
            u32::MAX,
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
            .ffa_msg_send_direct_req2(make_ffa_request(2, &[]))
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
            .ffa_msg_send_direct_req2(make_ffa_request(2, &[]))
            .expect("known command returns invalid timestamp");
        for offset in 0..ACPI_TIMESTAMP_LEN {
            assert_eq!(response.payload().u8_at(offset), 0);
        }
    }

    #[test]
    fn rejects_unknown_ffa_command() {
        let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
        let mut svc = TimeAlarm::new(&relay);
        assert!(svc.ffa_msg_send_direct_req2(make_ffa_request(0xFF, &[])).is_err());
    }
}
