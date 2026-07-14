use super::*;
use thermal_service_relay::DeciKelvin;

#[test]
fn set_threshold_produces_canonical_request_bytes() {
    let relay = relay_with_response(success_header(ThermalCommand::SetThrs), &[]);
    let svc = Thermal::new(&relay);

    svc.set_threshold(0, 0, 3000, 3100).expect("SetThrs success");

    let inner = transmitted_inner(&relay);
    assert_eq!(
        inner,
        std::vec![
            0x02, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x0B, 0x00, 0x00, 0x1C, 0x0C, 0x00, 0x00,
        ]
    );
    let decoded = ThermalRequest::deserialize(u16::from(ThermalCommand::SetThrs), &inner[4..])
        .expect("EC decoder accepts request");
    assert!(matches!(
        decoded,
        ThermalRequest::ThermalSetThrsRequest {
            instance_id: 0,
            timeout: 0,
            low: DeciKelvin(3000),
            high: DeciKelvin(3100),
        }
    ));
}

#[test]
fn get_threshold_parses_exact_canonical_response() {
    let mut body = [0u8; 12];
    ThermalResponse::ThermalGetThrsResponse {
        timeout: 0,
        low: DeciKelvin(3000),
        high: DeciKelvin(3100),
    }
    .serialize(&mut body)
    .expect("EC serializer");
    let relay = relay_with_response(success_header(ThermalCommand::GetThrs), &body);
    let svc = Thermal::new(&relay);

    assert_eq!(svc.get_threshold(0), Ok((0, 3000, 3100)));
}

#[test]
fn set_threshold_rejects_trailing_success_body() {
    let relay = relay_with_response(success_header(ThermalCommand::SetThrs), &[0xAA]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.set_threshold(0, 0, 3000, 3100),
        Err(ThermalError::Relay(EcRelayError::BodyTooLong))
    );
}

#[test]
fn get_threshold_rejects_short_body() {
    let relay = relay_with_response(success_header(ThermalCommand::GetThrs), &[0u8; 11]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.get_threshold(0),
        Err(ThermalError::Relay(EcRelayError::BodyTooShort))
    );
}

#[test]
fn get_threshold_rejects_trailing_body() {
    let relay = relay_with_response(success_header(ThermalCommand::GetThrs), &[0u8; 13]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.get_threshold(0),
        Err(ThermalError::Relay(EcRelayError::BodyTooLong))
    );
}

#[test]
fn ffa_set_threshold_uses_u32_timeout_at_offset_two() {
    let relay = relay_with_response(success_header(ThermalCommand::SetThrs), &[]);
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 13];
    args[0] = 0;
    args[1..5].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    args[5..9].copy_from_slice(&3000u32.to_le_bytes());
    args[9..13].copy_from_slice(&3100u32.to_le_bytes());

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::SetThrs, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &0u32.to_le_bytes());
    let inner = transmitted_inner(&relay);
    assert_eq!(&inner[5..9], &0x1122_3344u32.to_le_bytes());
}

#[test]
fn ffa_get_threshold_returns_raw_three_u32_prefix() {
    let mut body = [0u8; 12];
    ThermalResponse::ThermalGetThrsResponse {
        timeout: 0,
        low: DeciKelvin(3000),
        high: DeciKelvin(3100),
    }
    .serialize(&mut body)
    .expect("EC serializer");
    let relay = relay_with_response(success_header(ThermalCommand::GetThrs), &body);
    let mut svc = Thermal::new(&relay);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetThrs, &[0]))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &body);
}

#[test]
fn ffa_get_threshold_returns_all_ones_on_failure() {
    let relay = relay_with_response(success_header(ThermalCommand::GetThrs), &[0u8; 11]);
    let mut svc = Thermal::new(&relay);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetThrs, &[0]))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &[0xFF; 12]);
}
