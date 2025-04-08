use crate::{Result, Service};
use ffa::msg::FfaMsg;
use ffa::FfaFunctionId;
use log::debug;
use uuid::{uuid, Uuid};

#[derive(Default)]
struct GenericRsp {
    _status: i64,
}

#[derive(Default)]
pub struct Battery {}

impl Battery {
    pub fn new() -> Self {
        Self::default()
    }
}

const UUID: Uuid = uuid!("25cb5207-ac36-427d-aaef-3aa78877d27e");

impl Service for Battery {
    fn service_name(&self) -> &'static str {
        "Battery"
    }

    fn service_uuid(&self) -> &'static Uuid {
        &UUID
    }

    fn ffa_msg_send_direct_req2(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        let cmd = msg.extract_u8_at_index(0);
        debug!("Received Battery command 0x{:x}", cmd);

        // Create new generic rsp packet swap destination and source
        let mut rsp = FfaMsg {
            function_id: FfaFunctionId::FfaMsgSendDirectResp2.into(),
            source_id: msg.destination_id,
            destination_id: msg.source_id,
            uuid: msg.uuid,
            ..Default::default()
        };
        rsp.struct_to_args64(&GenericRsp { _status: 0x0 });
        Ok(rsp)
    }
}
