use crate::service::{Result, Service};
use ffa::msg::FfaMsg;
use ffa::yld::FfaYield;
use ffa::{FfaError, FfaFunctionId};
use log::{debug, error};
use uuid::{uuid, Builder, Uuid};

// Protocol CMD definitions for Thermal
const EC_THM_GET_TMP: u8 = 0x1;
const EC_THM_SET_THRS: u8 = 0x2;
const EC_THM_GET_THRS: u8 = 0x3;
const EC_THM_SET_SCP: u8 = 0x4;
const EC_THM_GET_VAR: u8 = 0x5;
const EC_THM_SET_VAR: u8 = 0x6;

#[derive(Default)]
struct GenericRsp {
    _status: i64,
}

#[derive(Default)]
struct TempRsp {
    _status: i64,
    _temp: u64,
}

#[derive(Default)]
struct ThresholdReq {
    id: u8,
    timeout: u32,
    low_temp: u32,
    high_temp: u32,
}

#[derive(Default)]
struct ReadVarReq {
    id: u8,
    len: u16,
    var_uuid: Uuid,
}

#[derive(Default)]
struct ReadVarRsp {
    _status: i64,
    _data: u32,
}

#[derive(Default)]
struct SetVarReq {
    id: u8,
    len: u16,
    var_uuid: Uuid,
    data: u32,
}

impl From<&FfaMsg> for ThresholdReq {
    fn from(msg: &FfaMsg) -> ThresholdReq {
        ThresholdReq {
            id: ((msg.args64[0] >> 8) & 0xff) as u8,
            timeout: ((msg.args64[0] >> 16) & 0xffffffff) as u32,
            low_temp: ((msg.args64[0] >> 48) as u32 + ((msg.args64[1] & 0xffff) as u32)) << 16,
            high_temp: ((msg.args64[1] >> 16) & 0xffffffff) as u32,
        }
    }
}

impl From<&FfaMsg> for ReadVarReq {
    fn from(msg: &FfaMsg) -> ReadVarReq {
        let d1 = (msg.args64[0] >> 32) as u32;
        let d2 = msg.args64[1] as u16;
        let d3 = (msg.args64[1] >> 16) as u16;
        let d4 = ((msg.args64[1] >> 32) | ((msg.args64[2] & 0xffffffff) << 32)).to_le_bytes();
        ReadVarReq {
            id: ((msg.args64[0] >> 8) & 0xff) as u8,
            len: ((msg.args64[0] >> 16) & 0xffff) as u16,
            var_uuid: Builder::from_fields(d1, d2, d3, &d4).into_uuid(),
        }
    }
}

impl From<&FfaMsg> for SetVarReq {
    fn from(msg: &FfaMsg) -> SetVarReq {
        let d1 = (msg.args64[0] >> 32) as u32;
        let d2 = msg.args64[1] as u16;
        let d3 = (msg.args64[1] >> 16) as u16;
        let d4 = ((msg.args64[1] >> 32) | ((msg.args64[2] & 0xffffffff) << 32)).to_le_bytes();
        SetVarReq {
            id: ((msg.args64[0] >> 8) & 0xff) as u8,
            len: ((msg.args64[0] >> 16) & 0xffff) as u16,
            var_uuid: Builder::from_fields(d1, d2, d3, &d4).into_uuid(),
            data: (msg.args64[2] >> 32) as u32,
        }
    }
}

#[derive(Default)]
pub struct Thermal {}

impl Thermal {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_temperature(&self, msg: &FfaMsg) -> TempRsp {
        debug!("get_temperature sensor 0x{:x}", msg.extract_u8_at_index(1));

        // Tell OS to delay 1 ms
        let yld = FfaYield::new(0x100000000);
        let result = yld.exec();
        debug!("Return from FfaYield1: {:?}", result);

        let result = yld.exec();
        debug!("Return from FfaYield2: {:?}", result);

        TempRsp {
            _status: 0x0,
            _temp: 0x1234,
        }
    }

    fn set_threshold(&self, msg: &FfaMsg) -> GenericRsp {
        let req: ThresholdReq = msg.into();
        debug!(
            "set_threshold temperature sensor 0x{:x}
                Timeout: 0x{:x}
                LowThreshold: 0x{:x}
                HighThreshold: 0x{:x}",
            req.id, req.timeout, req.low_temp, req.high_temp
        );

        GenericRsp { _status: 0x0 }
    }

    fn get_threshold(&self, _msg: &FfaMsg) -> GenericRsp {
        GenericRsp { _status: 0x0 }
    }

    fn set_cooling_policy(&self, _msg: &FfaMsg) -> GenericRsp {
        GenericRsp { _status: 0x0 }
    }

    fn get_variable(&self, msg: &FfaMsg) -> ReadVarRsp {
        let req: ReadVarReq = msg.into();
        debug!(
            "get_variable instance id: 0x{:x}
                length: 0x{:x}
                uuid: {}",
            req.id, req.len, req.var_uuid
        );

        // Only support DWORD customized IO for now
        if req.len != 4 {
            error!("get_variable only supports DWORD read")
        }

        ReadVarRsp {
            _status: 0x0,
            _data: 0xdeadbeef,
        }
    }

    fn set_variable(&self, msg: &FfaMsg) -> GenericRsp {
        let req: SetVarReq = msg.into();
        debug!(
            "get_variable instance id: 0x{:x}
                length: 0x{:x}
                uuid: {}
                data: 0x{:x}",
            req.id, req.len, req.var_uuid, req.data
        );

        GenericRsp { _status: 0x0 }
    }
}

const UUID: Uuid = uuid!("31f56da7-593c-4d72-a4b3-8fc7171ac073");

impl Service for Thermal {
    fn service_name(&self) -> &'static str {
        "Thermal"
    }

    fn service_uuid(&self) -> &'static Uuid {
        &UUID
    }

    fn ffa_msg_send_direct_req2(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        let cmd = msg.extract_u8_at_index(0);
        debug!("Received ThmMgmt command 0x{:x}", cmd);

        // Create new generic rsp packet swap destination and source
        let mut rsp = FfaMsg {
            function_id: FfaFunctionId::FfaMsgSendDirectResp2.into(),
            source_id: msg.destination_id,
            destination_id: msg.source_id,
            uuid: msg.uuid,
            ..Default::default()
        };

        match cmd {
            EC_THM_GET_TMP => {
                rsp.struct_to_args64(&self.get_temperature(msg));
                Ok(rsp)
            }
            EC_THM_SET_THRS => {
                rsp.struct_to_args64(&self.set_threshold(msg));
                Ok(rsp)
            }
            EC_THM_GET_THRS => {
                rsp.struct_to_args64(&self.get_threshold(msg));
                Ok(rsp)
            }
            EC_THM_SET_SCP => {
                rsp.struct_to_args64(&self.set_cooling_policy(msg));
                Ok(rsp)
            }
            EC_THM_GET_VAR => {
                rsp.struct_to_args64(&self.get_variable(msg));
                Ok(rsp)
            }
            EC_THM_SET_VAR => {
                rsp.struct_to_args64(&self.set_variable(msg));
                Ok(rsp)
            }
            _ => {
                error!("Unknown Thermal Command: {}", cmd);
                Err(FfaError::InvalidParameters)
            }
        }
    }
}
