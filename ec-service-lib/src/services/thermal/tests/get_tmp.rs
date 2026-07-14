use super::*;

#[test]
fn relays_get_tmp_with_canonical_wire_bytes() {
    let relay = relay_with_response(success_header(ThermalCommand::GetTmp), &2982u32.to_le_bytes());
    let svc = Thermal::new(&relay);

    assert_eq!(svc.get_temperature(0x07), Ok(2982));
    assert_eq!(transmitted_inner(&relay), std::vec![0x02, 0x09, 0x00, 0x01, 0x07]);
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
