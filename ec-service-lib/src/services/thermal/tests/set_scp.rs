use super::*;
use embedded_services::relay::SerializableMessage;

#[test]
fn set_scp_produces_canonical_request_bytes() {
    let relay = relay_with_response(success_header(ThermalCommand::SetScp), &[]);
    let svc = Thermal::new(&relay);

    svc.set_scp(0, 1, 75, 25).expect("synthetic success");

    let inner = transmitted_inner(&relay);
    let decoded = ThermalRequest::deserialize(u16::from(ThermalCommand::SetScp), &inner[4..])
        .expect("EC decoder accepts request");
    assert!(matches!(
        decoded,
        ThermalRequest::ThermalSetScpRequest {
            instance_id: 0,
            policy_id: 1,
            acoustic_lim: 75,
            power_lim: 25,
        }
    ));
}

#[test]
fn ffa_set_scp_returns_ec_error_code() {
    let relay = relay_with_response(ec_relay::test_util::build_odp_error_header(THERMAL_SERVICE_ID, 1), &[]);
    let mut svc = Thermal::new(&relay);
    let mut args = [0u8; 13];
    args[0] = 0;
    args[1..5].copy_from_slice(&1u32.to_le_bytes());
    args[5..9].copy_from_slice(&75u32.to_le_bytes());
    args[9..13].copy_from_slice(&25u32.to_le_bytes());

    let response = svc
        .ffa_msg_send_direct_req2(make_ffa_request(ThermalCommand::SetScp, &args))
        .expect("known command returns DIRECT_RESP2");

    assert_payload_prefix_and_zero_tail(response.payload(), &1u32.to_le_bytes());
}
