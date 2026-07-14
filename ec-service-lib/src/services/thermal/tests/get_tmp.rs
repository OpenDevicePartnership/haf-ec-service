use super::*;
use thermal_service_relay::DeciKelvin;

const GET_TMP_RESPONSE_BODY_LEN: usize = 4;

#[test]
fn produces_canonical_get_tmp_request_bytes() {
    // EC GetTmp response: 2982 dK ≈ 25 °C.
    let mut response_payload = [0u8; GET_TMP_RESPONSE_BODY_LEN];
    let n = ThermalResponse::ThermalGetTmpResponse {
        temperature: DeciKelvin(2982),
    }
    .serialize(&mut response_payload)
    .expect("ec-side serialize");
    assert_eq!(n, GET_TMP_RESPONSE_BODY_LEN, "GetTmp response body must be 4 bytes");

    let relay = relay_with_response(success_header(ThermalCommand::GetTmp), &response_payload);
    let svc = Thermal::new(&relay);

    let dk = svc.get_temperature(0x07).expect("relay GetTmp");
    assert_eq!(dk, 2982);

    // Request bytes: OdpHeader [0x02, 0x09, 0x00, 0x01] + payload [0x07].
    let inner_tx = transmitted_inner(&relay);
    assert_eq!(
        inner_tx,
        std::vec![0x02, 0x09, 0x00, 0x01, 0x07],
        "Thermal GetTmp request wire bytes must match the EC's expected encoding exactly"
    );

    // The SP-produced bytes parse back via the EC's own deserializer.
    let (is_req, svc_id, _is_err, msg_id) = ec_relay::parse_odp_header(&inner_tx[..4]).expect("parse header");
    assert!(is_req, "must be a request");
    assert_eq!(svc_id, THERMAL_SERVICE_ID);
    assert_eq!(msg_id, u16::from(ThermalCommand::GetTmp));
    let decoded =
        ThermalRequest::deserialize(msg_id, &inner_tx[4..]).expect("ec-side decoder must accept SP-produced bytes");
    assert!(
        matches!(decoded, ThermalRequest::ThermalGetTmpRequest { instance_id: 0x07 }),
        "EC-side decoder must reconstruct the original request variant"
    );
}

#[test]
fn get_temperature_surfaces_transport_read_timeout_as_relay_err() {
    let transport = MctpSerialTransport::new(TimeoutUart);
    let relay = RefCell::new(EcRelay::new(transport));
    let svc = Thermal::new(&relay);
    let err = svc.get_temperature(0).expect_err("timeout should propagate");
    assert_eq!(err, ThermalError::Relay(EcRelayError::TransportReadTimeout));
}

#[test]
fn get_temperature_rejects_short_response_body() {
    // EC replies with a valid GetTmp header but a 2-byte payload (< 4).
    let relay = relay_with_response(success_header(ThermalCommand::GetTmp), &[0xAA, 0xBB]);
    let svc = Thermal::new(&relay);
    assert_eq!(
        svc.get_temperature(0x07),
        Err(ThermalError::Relay(EcRelayError::BodyTooShort))
    );
}

#[test]
fn get_temperature_rejects_trailing_response_body() {
    let relay = relay_with_response(success_header(ThermalCommand::GetTmp), &[0xA6, 0x0B, 0x00, 0x00, 0xFF]);
    let svc = Thermal::new(&relay);

    assert_eq!(
        svc.get_temperature(0x07),
        Err(ThermalError::Relay(EcRelayError::BodyTooLong))
    );
}

#[test]
fn ffa_get_tmp_returns_raw_u32_at_offset_zero() {
    let mut body = [0u8; 4];
    ThermalResponse::ThermalGetTmpResponse {
        temperature: DeciKelvin(2982),
    }
    .serialize(&mut body)
    .expect("EC serializer");
    let relay = relay_with_response(success_header(ThermalCommand::GetTmp), &body);
    let mut svc = Thermal::new(&relay);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetTmp, &[0x07]))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &2982u32.to_le_bytes());
}

#[test]
fn ffa_get_tmp_returns_all_ones_on_local_failure() {
    let relay = RefCell::new(EcRelay::new(MctpSerialTransport::new(TimeoutUart)));
    let mut svc = Thermal::new(&relay);

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::GetTmp, &[0x07]))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &u32::MAX.to_le_bytes());
}
