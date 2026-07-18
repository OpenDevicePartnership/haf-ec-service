use super::*;
use core::mem::size_of;
use zerocopy::IntoBytes;

#[test]
fn set_threshold_request_names_and_preserves_wire_fields() {
    assert_eq!(size_of::<SetThresholdRequest>(), 13);
    assert_eq!(size_of::<SetCoolingPolicyRequest>(), 13);
    assert_eq!(size_of::<GetVariableRequest>(), 19);
    assert_eq!(size_of::<SetVariableRequest>(), 23);

    let mut args = [0u8; 13];
    args[0] = 7;
    args[1..5].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    args[5..9].copy_from_slice(&3000u32.to_le_bytes());
    args[9..13].copy_from_slice(&3100u32.to_le_bytes());
    let payload =
        DirectMessagePayload::from_iter(core::iter::once(u16::from(ThermalCommand::SetThrs) as u8).chain(args));

    let request = parse_request::<SetThresholdRequest>(&payload).expect("typed request");

    assert_eq!(request.instance_id, 7);
    assert_eq!(request.timeout.get(), 0x1122_3344);
    assert_eq!(request.low.get(), 3000);
    assert_eq!(request.high.get(), 3100);
    assert_eq!(request.as_bytes(), &args);
}

#[test]
fn parse_request_rejects_type_larger_than_payload() {
    // A future request type whose command-byte-skipped prefix would run
    // past the 112-byte payload must yield None, not panic the helper.
    let payload = DirectMessagePayload::from_iter(core::iter::empty());
    assert!(parse_request::<[u8; 112]>(&payload).is_none());
}
