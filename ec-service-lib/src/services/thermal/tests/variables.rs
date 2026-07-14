use super::*;

const UUID: [u8; 16] = [0xA5; 16];

#[test]
fn ffa_get_var_rejects_non_dword_length_without_relaying() {
    let relay = RefCell::new(EcRelay::new(LoopbackTransport::new()));
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 19];
    args[0] = 0;
    args[1..3].copy_from_slice(&8u16.to_le_bytes());
    args[3..19].copy_from_slice(&UUID);

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
    args[3..19].copy_from_slice(&UUID);
    args[19..23].copy_from_slice(&3500u32.to_le_bytes());

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::SetVar, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &1u32.to_le_bytes());
    assert!(relay.borrow().transport().tx.is_empty());
}
