use crate::{Result, Service};
use ffa::msg::FfaMsg;
use ffa::{FfaError, FfaFunctionId};
use log::{debug, error};
use uuid::{uuid, Uuid};

// Protocol CMD definitions for Notification
const NFY_QUERY: u8 = 0x0;
const NFY_SETUP: u8 = 0x1;
const NFY_DESTROY: u8 = 0x2;

#[derive(Default)]
struct NfyQueryRsp {
    _status: i64,
    _start_id: u16,
    _last_id: u16,
}

#[derive(Default)]
struct _NfySetupReq {
    _cmd: u8,
    _uuid: Uuid,
    _count: u64,
    _vid: u16,
    _pid: u16,
}

#[derive(Default)]
struct NfyGenericRsp {
    _status: i64,
}

#[derive(Default)]
pub struct Notify {}

impl Notify {
    pub fn new() -> Self {
        Self::default()
    }

    fn nfy_query(&self) -> NfyQueryRsp {
        NfyQueryRsp {
            _status: 0x0,
            _start_id: 0x0,
            _last_id: 0x1,
        }
    }

    fn nfy_setup(&self, msg: &FfaMsg) -> NfyGenericRsp {
        debug!("cmd: {}", msg.args64[0]);
        debug!("uuid_lo: 0x{:x}", msg.args64[1]);
        debug!("uuid_hi: 0x{:x}", msg.args64[2]);
        debug!("Count: {}", msg.args64[3]);
        debug!("Mapping1: 0x{:x}", msg.args64[4]);
        debug!("Mapping2: 0x{:x}", msg.args64[5]);
        NfyGenericRsp {
            _status: FfaError::Ok.into(),
        }
    }

    fn nfy_destroy(&self, _msg: &FfaMsg) -> NfyGenericRsp {
        NfyGenericRsp { _status: 0x0 }
    }
}

const UUID: Uuid = uuid!("B510B3A3-59F6-4054-BA7A-FF2EB1EAC765");

impl Service for Notify {
    fn service_name(&self) -> &'static str {
        "Notify"
    }

    fn service_uuid(&self) -> &'static Uuid {
        &UUID
    }

    fn ffa_msg_send_direct_req2(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        let cmd = msg.extract_u8_at_index(0);
        debug!("Received notify command 0x{:x}", cmd);

        // Create new generic rsp packet swap destination and source
        let mut rsp = FfaMsg {
            function_id: FfaFunctionId::FfaMsgSendDirectResp2.into(),
            source_id: msg.destination_id,
            destination_id: msg.source_id,
            uuid: msg.uuid,
            ..Default::default()
        };

        match cmd {
            NFY_QUERY => {
                rsp.struct_to_args64(&self.nfy_query());
                Ok(rsp)
            }
            NFY_SETUP => {
                rsp.struct_to_args64(&self.nfy_setup(msg));
                Ok(rsp)
            }
            NFY_DESTROY => {
                rsp.struct_to_args64(&self.nfy_destroy(msg));
                Ok(rsp)
            }
            _ => {
                error!("Unknown Notify Command: {}", cmd);
                Err(FfaError::InvalidParameters)
            }
        }
    }
}
