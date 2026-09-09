use odp_ffa::{MsgSendDirectReq2, MsgSendDirectResp2};

use crate::{msg_loop, Service};

pub struct MessageHandler<N> {
    node: N,
}

impl MessageHandler<HandlerNodeTerminal> {
    pub fn new() -> Self {
        Self {
            node: HandlerNodeTerminal,
        }
    }
}

impl Default for MessageHandler<HandlerNodeTerminal> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> MessageHandler<N>
where
    N: HandlerNode,
{
    pub fn append<S: Service>(self, service: S) -> MessageHandler<HandlerNodeInner<S, N>> {
        let node = HandlerNodeInner {
            service,
            next: self.node,
        };
        MessageHandler { node }
    }

    pub fn run_message_loop(mut self) -> core::result::Result<(), odp_ffa::Error> {
        msg_loop(|msg| self.node.handle(msg), |_| Ok(()))
    }
}

// A node in the linked list of services which handle FFA Direct Request messages
pub trait HandlerNode: Sized {
    fn handle(&mut self, msg: MsgSendDirectReq2) -> core::result::Result<MsgSendDirectResp2, odp_ffa::Error>;
}

// Inner node in the linked list of services
pub struct HandlerNodeInner<S, N> {
    service: S,
    next: N,
}

// Terminal node of the linked list of services
pub struct HandlerNodeTerminal;

impl HandlerNode for HandlerNodeTerminal {
    fn handle(&mut self, _: MsgSendDirectReq2) -> core::result::Result<MsgSendDirectResp2, odp_ffa::Error> {
        Err(odp_ffa::Error::Other("Unknown UUID"))
    }
}

impl<S, N> HandlerNode for HandlerNodeInner<S, N>
where
    S: Service,
    N: HandlerNode,
{
    fn handle(&mut self, msg: MsgSendDirectReq2) -> core::result::Result<MsgSendDirectResp2, odp_ffa::Error> {
        if S::UUID == msg.uuid() {
            self.service.ffa_msg_send_direct_req2(msg)
        } else {
            self.next.handle(msg)
        }
    }
}

// ===========================================================================
// MessageHandler Unit Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Service;
    use odp_ffa::{DirectMessagePayload, HasRegisterPayload};
    use uuid::{uuid, Uuid};

    // ===================================================================
    // Mock Services
    // ===================================================================

    /// A mock service that echoes the first payload register + marker 0xAA.
    struct MockServiceA;

    impl Service for MockServiceA {
        const UUID: Uuid = uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        const NAME: &'static str = "MockA";

        fn ffa_msg_send_direct_req2(
            &mut self,
            msg: MsgSendDirectReq2,
        ) -> core::result::Result<MsgSendDirectResp2, odp_ffa::Error> {
            let input = msg.payload().register_at(0);
            let regs = [input, 0xAA];
            let payload = DirectMessagePayload::from_iter(regs.iter().flat_map(|r| r.to_le_bytes()));
            Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
        }
    }

    /// A mock service that echoes the first payload register + marker 0xBB.
    struct MockServiceB;

    impl Service for MockServiceB {
        const UUID: Uuid = uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        const NAME: &'static str = "MockB";

        fn ffa_msg_send_direct_req2(
            &mut self,
            msg: MsgSendDirectReq2,
        ) -> core::result::Result<MsgSendDirectResp2, odp_ffa::Error> {
            let input = msg.payload().register_at(0);
            let regs = [input, 0xBB];
            let payload = DirectMessagePayload::from_iter(regs.iter().flat_map(|r| r.to_le_bytes()));
            Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
        }
    }

    // ===================================================================
    // Helpers
    // ===================================================================

    fn make_msg(uuid: Uuid, value: u64) -> MsgSendDirectReq2 {
        let regs = [value];
        let payload = DirectMessagePayload::from_iter(regs.iter().flat_map(|r| r.to_le_bytes()));
        MsgSendDirectReq2::new(0x0001, 0x8001, uuid, payload)
    }

    // ===================================================================
    // UUID Routing Tests (MHD-01)
    // ===================================================================
    #[test]
    fn test_routes_to_correct_service_a() {
        let mut handler = MessageHandler::new().append(MockServiceA).append(MockServiceB);
        let msg = make_msg(MockServiceA::UUID, 42);
        let resp = handler.node.handle(msg).unwrap();
        assert_eq!(resp.payload().register_at(0), 42); // echoed value
        assert_eq!(resp.payload().register_at(1), 0xAA); // MockA marker
    }

    #[test]
    fn test_routes_to_correct_service_b() {
        let mut handler = MessageHandler::new().append(MockServiceA).append(MockServiceB);
        let msg = make_msg(MockServiceB::UUID, 99);
        let resp = handler.node.handle(msg).unwrap();
        assert_eq!(resp.payload().register_at(0), 99);
        assert_eq!(resp.payload().register_at(1), 0xBB);
    }

    // ===================================================================
    // Unknown UUID Tests (MHD-02)
    // ===================================================================
    #[test]
    fn test_unknown_uuid_returns_error() {
        let mut handler = MessageHandler::new().append(MockServiceA).append(MockServiceB);
        let unknown_uuid = uuid!("cccccccc-cccc-cccc-cccc-cccccccccccc");
        let msg = make_msg(unknown_uuid, 0);
        let result = handler.node.handle(msg);
        assert!(result.is_err());
        match result.unwrap_err() {
            odp_ffa::Error::Other(s) => assert_eq!(s, "Unknown UUID"),
            e => panic!("Expected Error::Other(\"Unknown UUID\"), got {:?}", e),
        }
    }

    #[test]
    fn test_empty_handler_returns_error() {
        let mut handler = MessageHandler::new();
        let msg = make_msg(MockServiceA::UUID, 0);
        let result = handler.node.handle(msg);
        assert!(result.is_err());
    }

    // ===================================================================
    // Service Chain Ordering Tests (MHD-03)
    // ===================================================================
    #[test]
    fn test_service_chain_ordering_both_reachable() {
        // append order: A first, B second
        // linked list order: B -> A -> Terminal (LIFO)
        let mut handler = MessageHandler::new().append(MockServiceA).append(MockServiceB);

        // Both should be reachable regardless of position in chain
        let resp_a = handler.node.handle(make_msg(MockServiceA::UUID, 1)).unwrap();
        assert_eq!(resp_a.payload().register_at(1), 0xAA);

        let resp_b = handler.node.handle(make_msg(MockServiceB::UUID, 2)).unwrap();
        assert_eq!(resp_b.payload().register_at(1), 0xBB);
    }

    #[test]
    fn test_single_service_routes_correctly() {
        let mut handler = MessageHandler::new().append(MockServiceA);
        let resp = handler.node.handle(make_msg(MockServiceA::UUID, 7)).unwrap();
        assert_eq!(resp.payload().register_at(1), 0xAA);

        // Unknown UUID should still error
        let unknown = uuid!("dddddddd-dddd-dddd-dddd-dddddddddddd");
        assert!(handler.node.handle(make_msg(unknown, 0)).is_err());
    }
}
