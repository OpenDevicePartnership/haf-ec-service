use super::*;
use crate::services::ec_relay::test_util::{frame_response_packets, strip_mctp_framing, LoopbackTransport};
use crate::services::ec_relay::{self, EcRelay};
use odp_ffa::{DirectMessagePayload, HasRegisterPayload, MsgSendDirectReq2};
use thermal_service_relay::ThermalRequest;

mod get_tmp;
mod request_layout;
mod set_scp;
mod variables;

fn success_header(command: ThermalCommand) -> [u8; 4] {
    ec_relay::build_odp_header(false, THERMAL_SERVICE_ID, command.into())
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

fn make_ffa_request(command: ThermalCommand, args: &[u8]) -> MsgSendDirectReq2 {
    MsgSendDirectReq2::new(
        0x0001,
        0x8001,
        Thermal::<EcRelay<LoopbackTransport>>::UUID,
        DirectMessagePayload::from_iter(core::iter::once(u16::from(command) as u8).chain(args.iter().copied())),
    )
}

fn assert_payload_prefix_and_zero_tail(payload: &DirectMessagePayload, prefix: &[u8]) {
    for (offset, expected) in prefix.iter().copied().enumerate() {
        assert_eq!(payload.u8_at(offset), expected);
    }
    assert!(payload.u8_iter().skip(prefix.len()).all(|byte| byte == 0));
}
