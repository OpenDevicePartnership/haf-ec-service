use super::*;
use thermal_service_relay::uuid_standard;

const CRT_TEMP: [u8; 16] = uuid_standard::CRT_TEMP;

#[test]
fn get_var_produces_canonical_request_and_parses_value() {
    let mut body = [0u8; 4];
    ThermalResponse::ThermalGetVarResponse { val: 3500 }
        .serialize(&mut body)
        .expect("EC serializer");
    let relay = relay_with_response(success_header(ThermalCommand::GetVar), &body);
    let svc = Thermal::new(&relay);

    assert_eq!(svc.get_var(0, CRT_TEMP), Ok(3500));

    let inner = transmitted_inner(&relay);
    let decoded = ThermalRequest::deserialize(u16::from(ThermalCommand::GetVar), &inner[4..])
        .expect("EC decoder accepts request");
    assert!(matches!(
        decoded,
        ThermalRequest::ThermalGetVarRequest {
            instance_id: 0,
            len: 4,
            var_uuid,
        } if var_uuid == CRT_TEMP
    ));
}

#[test]
fn set_var_produces_canonical_request_bytes() {
    let relay = relay_with_response(success_header(ThermalCommand::SetVar), &[]);
    let svc = Thermal::new(&relay);

    svc.set_var(0, CRT_TEMP, 3500).expect("SetVar success");

    let inner = transmitted_inner(&relay);
    let decoded = ThermalRequest::deserialize(u16::from(ThermalCommand::SetVar), &inner[4..])
        .expect("EC decoder accepts request");
    assert!(matches!(
        decoded,
        ThermalRequest::ThermalSetVarRequest {
            instance_id: 0,
            len: 4,
            var_uuid,
            set_var: 3500,
        } if var_uuid == CRT_TEMP
    ));
}

#[test]
fn get_var_rejects_short_body() {
    let relay = relay_with_response(success_header(ThermalCommand::GetVar), &[0u8; 3]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.get_var(0, CRT_TEMP),
        Err(ThermalError::Relay(EcRelayError::BodyTooShort))
    );
}

#[test]
fn get_var_rejects_trailing_body() {
    let relay = relay_with_response(success_header(ThermalCommand::GetVar), &[0u8; 5]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.get_var(0, CRT_TEMP),
        Err(ThermalError::Relay(EcRelayError::BodyTooLong))
    );
}

#[test]
fn set_var_rejects_trailing_success_body() {
    let relay = relay_with_response(success_header(ThermalCommand::SetVar), &[0xAA]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.set_var(0, CRT_TEMP, 3500),
        Err(ThermalError::Relay(EcRelayError::BodyTooLong))
    );
}

#[test]
fn ffa_get_var_returns_raw_value_at_offset_zero() {
    let mut body = [0u8; 4];
    ThermalResponse::ThermalGetVarResponse { val: 3500 }
        .serialize(&mut body)
        .expect("EC serializer");
    let relay = relay_with_response(success_header(ThermalCommand::GetVar), &body);
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 19];
    args[0] = 0;
    args[1..3].copy_from_slice(&4u16.to_le_bytes());
    args[3..19].copy_from_slice(&CRT_TEMP);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetVar, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &3500u32.to_le_bytes());
}

#[test]
fn ffa_get_var_rejects_non_dword_length_without_relaying() {
    let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 19];
    args[0] = 0;
    args[1..3].copy_from_slice(&8u16.to_le_bytes());
    args[3..19].copy_from_slice(&CRT_TEMP);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetVar, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &u32::MAX.to_le_bytes());
    assert!(relay.borrow().transport().tx.is_empty());
}

#[test]
fn ffa_set_var_rejects_non_dword_length_as_invalid_parameter() {
    let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 23];
    args[0] = 0;
    args[1..3].copy_from_slice(&8u16.to_le_bytes());
    args[3..19].copy_from_slice(&CRT_TEMP);
    args[19..23].copy_from_slice(&3500u32.to_le_bytes());

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::SetVar, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &1u32.to_le_bytes());
    assert!(relay.borrow().transport().tx.is_empty());
}

#[test]
fn ffa_set_var_forwards_raw_uuid_and_returns_zero_status() {
    let relay = relay_with_response(success_header(ThermalCommand::SetVar), &[]);
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 23];
    args[0] = 0;
    args[1..3].copy_from_slice(&4u16.to_le_bytes());
    args[3..19].copy_from_slice(&CRT_TEMP);
    args[19..23].copy_from_slice(&3500u32.to_le_bytes());

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::SetVar, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &0u32.to_le_bytes());
    let inner = transmitted_inner(&relay);
    assert_eq!(&inner[7..23], &CRT_TEMP);
}
