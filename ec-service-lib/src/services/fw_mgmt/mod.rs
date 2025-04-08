use crate::{Result, Service};
use ffa::indirect::FfaIndirectMsg;
use ffa::memory::FfaMemory;
use ffa::msg::FfaMsg;
#[cfg(debug_assertions)]
use ffa::notify::FfaNotify;
use ffa::{FfaError, FfaFunctionId};
use log::{debug, error};
use uuid::{uuid, Uuid};

// Protocol CMD definitions for FwMgmt
const EC_CAP_INDIRECT_MSG: u8 = 0x0;
const EC_CAP_GET_FW_STATE: u8 = 0x1;
const EC_CAP_GET_SVC_LIST: u8 = 0x2;
const EC_CAP_GET_BID: u8 = 0x3;
#[cfg(debug_assertions)]
const EC_CAP_TEST_NFY: u8 = 0x4;
const EC_CAP_MAP_SHARE: u8 = 0x5;

#[derive(Default)]
struct FwStateRsp {
    _status: i64,
    _fw_version: u16,
    _secure_state: u8,
    _boot_status: u8,
}

#[derive(Default)]
struct ServiceListRsp {
    _status: i64,
    _debug_mask: u16,
    _battery_mask: u8,
    _fan_mask: u8,
    _thermal_mask: u8,
    _hid_mask: u8,
    _key_mask: u16,
}

#[derive(Default)]
struct GetBidRsp {
    _status: i64,
    _bid: u64,
}

#[derive(Default)]
struct GenericRsp {
    _status: i64,
}

#[derive(Default)]
pub struct FwMgmt {}

impl FwMgmt {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_fw_state(&self) -> FwStateRsp {
        FwStateRsp {
            _status: 0x0,
            _fw_version: 0x0100,
            _secure_state: 0x0,
            _boot_status: 0x1,
        }
    }

    fn get_svc_list(&self) -> ServiceListRsp {
        ServiceListRsp {
            _status: 0x0,
            _debug_mask: 0x1,
            _battery_mask: 0x1,
            _fan_mask: 0x1,
            _thermal_mask: 0x1,
            _hid_mask: 0x0,
            _key_mask: 0x7,
        }
    }

    fn get_bid(&self) -> GetBidRsp {
        GetBidRsp {
            _status: 0x0,
            _bid: 0xdead0001,
        }
    }

    fn map_share(&self, address: u64, length: u64) -> GenericRsp {
        let mut _sts = FfaError::Ok.into();

        let mut ffamem = FfaMemory::new();
        let result = ffamem.retrieve_req(address, length);

        match result {
            Ok(_params) => {
                _sts = FfaError::Ok.into();
            }
            Err(e) => {
                _sts = e.into();
            }
        }

        GenericRsp { _status: _sts }
    }

    #[cfg(debug_assertions)]
    fn test_notify(&self, msg: &FfaMsg) -> GenericRsp {
        let nfy = FfaNotify {
            function_id: FfaFunctionId::FfaNotificationSet.into(),
            source_id: msg.destination_id,
            destination_id: msg.source_id,
            args64: [
                0x2, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
        };

        let _result = nfy.exec();

        // Return status success
        GenericRsp { _status: 0x0 }
    }

    fn process_indirect(&self, seq_num: u16, rx_buffer: u64, tx_buffer: u64) -> GenericRsp {
        debug!("Processing indirect message: 0x{:x}", seq_num);
        let msg = FfaIndirectMsg::new();
        let mut in_buf: [u8; 256] = [0; 256];
        let mut status;

        unsafe {
            status = msg.read_indirect_msg(rx_buffer, seq_num, &mut in_buf);
        };

        if status == FfaError::Ok {
            error!("Indirect Message: {:?}", in_buf);
        }

        // Populate TX buffer with response and matching seq num
        let buf: [u8; 16] = [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        ];
        unsafe {
            status = msg.write_indirect_msg(tx_buffer, seq_num, &buf);
        };

        GenericRsp { _status: status.into() }
    }
}

const UUID: Uuid = uuid!("330c1273-fde5-4757-9819-5b6539037502");

impl Service for FwMgmt {
    fn service_name(&self) -> &'static str {
        "FwMgmt"
    }

    fn service_uuid(&self) -> &'static Uuid {
        &UUID
    }

    fn ffa_msg_send_direct_req2(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        let cmd = msg.extract_u8_at_index(0);
        debug!("Received FwMgmt command 0x{:x}", cmd);

        // Create new generic rsp packet swap destination and source
        let mut rsp = FfaMsg {
            function_id: FfaFunctionId::FfaMsgSendDirectResp2.into(),
            source_id: msg.destination_id,
            destination_id: msg.source_id,
            uuid: msg.uuid,
            ..Default::default()
        };
        match cmd {
            EC_CAP_INDIRECT_MSG => {
                rsp.struct_to_args64(&self.process_indirect((msg.args64[0] >> 8) as u16, msg.args64[4], msg.args64[5]));
                Ok(rsp)
            }
            EC_CAP_GET_FW_STATE => {
                rsp.struct_to_args64(&self.get_fw_state());
                Ok(rsp)
            }
            EC_CAP_GET_SVC_LIST => {
                rsp.struct_to_args64(&self.get_svc_list());
                Ok(rsp)
            }
            EC_CAP_GET_BID => {
                rsp.struct_to_args64(&self.get_bid());
                Ok(rsp)
            }
            #[cfg(debug_assertions)]
            EC_CAP_TEST_NFY => {
                rsp.struct_to_args64(&self.test_notify(msg));
                Ok(rsp)
            }
            EC_CAP_MAP_SHARE => {
                // First parameter is pointer to memory descriptor
                rsp.struct_to_args64(&self.map_share(msg.args64[1], msg.args64[2]));
                Ok(rsp)
            }
            _ => {
                error!("Unknown FwMgmt Command: {}", cmd);
                Err(FfaError::InvalidParameters)
            }
        }
    }
}
