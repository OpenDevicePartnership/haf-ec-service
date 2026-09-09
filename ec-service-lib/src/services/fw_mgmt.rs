use crate::{Result, Service};
use log::{debug, error};
use odp_ffa::{DirectMessagePayload, HasRegisterPayload, MemRetrieveReq, MsgSendDirectReq2, MsgSendDirectResp2};
use odp_ffa::{Function, NotificationSet};
use uuid::{uuid, Uuid};

// Protocol CMD definitions for FwMgmt
const EC_CAP_INDIRECT_MSG: u8 = 0x0;
const EC_CAP_GET_FW_STATE: u8 = 0x1;
const EC_CAP_GET_SVC_LIST: u8 = 0x2;
const EC_CAP_GET_BID: u8 = 0x3;
const EC_CAP_TEST_NFY: u8 = 0x4;
const EC_CAP_MAP_SHARE: u8 = 0x5;

#[derive(Default)]
struct FwStateRsp {
    fw_version: u16,
    secure_state: u8,
    boot_status: u8,
}

impl From<FwStateRsp> for DirectMessagePayload {
    fn from(rsp: FwStateRsp) -> Self {
        let iter = rsp
            .fw_version
            .to_le_bytes()
            .into_iter()
            .chain(rsp.secure_state.to_le_bytes())
            .chain(rsp.boot_status.to_le_bytes());

        DirectMessagePayload::from_iter(iter)
    }
}

#[derive(Default)]
struct ServiceListRsp {
    status: i64,
    debug_mask: u16,
    battery_mask: u8,
    fan_mask: u8,
    thermal_mask: u8,
    hid_mask: u8,
    key_mask: u16,
}

impl From<ServiceListRsp> for DirectMessagePayload {
    fn from(rsp: ServiceListRsp) -> Self {
        let iter = rsp
            .status
            .to_le_bytes()
            .into_iter()
            .chain(rsp.debug_mask.to_le_bytes())
            .chain(rsp.battery_mask.to_le_bytes())
            .chain(rsp.fan_mask.to_le_bytes())
            .chain(rsp.thermal_mask.to_le_bytes())
            .chain(rsp.hid_mask.to_le_bytes())
            .chain(rsp.key_mask.to_le_bytes());
        DirectMessagePayload::from_iter(iter)
    }
}

#[derive(Default)]
struct GetBidRsp {
    _status: i64,
    _bid: u64,
}

impl From<GetBidRsp> for DirectMessagePayload {
    fn from(rsp: GetBidRsp) -> Self {
        let iter = rsp._status.to_le_bytes().into_iter().chain(rsp._bid.to_le_bytes());
        DirectMessagePayload::from_iter(iter)
    }
}

#[derive(Default)]
struct GenericRsp {
    _status: i64,
}

impl From<GenericRsp> for DirectMessagePayload {
    fn from(rsp: GenericRsp) -> Self {
        let iter = rsp._status.to_le_bytes().into_iter();
        DirectMessagePayload::from_iter(iter)
    }
}

#[derive(Default)]
pub struct FwMgmt {}

impl FwMgmt {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_fw_state(&self) -> FwStateRsp {
        FwStateRsp {
            fw_version: 0x0100,
            secure_state: 0x0,
            boot_status: 0x1,
        }
    }

    fn get_svc_list(&self) -> ServiceListRsp {
        ServiceListRsp {
            status: 0x0,
            debug_mask: 0x1,
            battery_mask: 0x1,
            fan_mask: 0x1,
            thermal_mask: 0x1,
            hid_mask: 0x0,
            key_mask: 0x7,
        }
    }

    fn get_bid(&self) -> GetBidRsp {
        GetBidRsp {
            _status: 0x0,
            _bid: 0xdead0001,
        }
    }

    fn map_share(&self, _address: u64, _length: u64) -> Result<DirectMessagePayload> {
        // TODO - do not hardcode address and length in MemRetrieveReq
        MemRetrieveReq::new().exec()?;
        Ok(DirectMessagePayload::from(GenericRsp { _status: 0x0 }))
    }

    fn test_notify(&self, msg: MsgSendDirectReq2) -> Result<DirectMessagePayload> {
        let flags = 0b10;
        let notification_bitmap = 0b10;
        NotificationSet::new(msg.destination_id(), msg.source_id(), flags, notification_bitmap).exec()?;

        // Return status success
        Ok(DirectMessagePayload::from(GenericRsp { _status: 0x0 }))
    }

    fn process_indirect(&self, seq_num: u16, _rx_buffer: u64, _tx_buffer: u64) -> Result<DirectMessagePayload> {
        debug!("Processing indirect message: 0x{:x}", seq_num);
        Err(odp_ffa::Error::Other("process_indirect not supported"))
    }
}

impl Service for FwMgmt {
    const UUID: Uuid = uuid!("330c1273-fde5-4757-9819-5b6539037502");
    const NAME: &'static str = "FwMgmt";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let cmd = msg.payload().u8_at(0);
        debug!("Received FwMgmt command 0x{:x}", cmd);

        let payload = match cmd {
            EC_CAP_INDIRECT_MSG => self.process_indirect(
                msg.payload().u8_at(1) as u16,
                msg.payload().register_at(4),
                msg.payload().register_at(5),
            )?,
            EC_CAP_GET_FW_STATE => DirectMessagePayload::from(self.get_fw_state()),
            EC_CAP_GET_SVC_LIST => DirectMessagePayload::from(self.get_svc_list()),
            EC_CAP_GET_BID => DirectMessagePayload::from(self.get_bid()),
            EC_CAP_TEST_NFY => self.test_notify(msg.clone())?,
            EC_CAP_MAP_SHARE => {
                // First parameter is pointer to memory descriptor
                self.map_share(msg.payload().register_at(1), msg.payload().register_at(2))?
            }
            _ => {
                error!("Unknown FwMgmt Command: {}", cmd);
                return Err(odp_ffa::Error::Other("Unknown FwMgmt Command"));
            }
        };

        Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
    }
}

// ===========================================================================
// FwMgmt Unit Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use odp_ffa::{DirectMessagePayload, HasRegisterPayload};

    const FWMGMT_UUID: Uuid = uuid!("330c1273-fde5-4757-9819-5b6539037502");

    /// Build a FwMgmt request with the given command byte.
    fn fwmgmt_req(cmd: u8) -> MsgSendDirectReq2 {
        let mut bytes = [0u8; 14 * 8];
        bytes[0] = cmd;
        let payload = DirectMessagePayload::from_iter(bytes);
        MsgSendDirectReq2::new(0x0001, 0x8001, FWMGMT_UUID, payload)
    }

    /// Extract status (i64) from response payload register 0.
    fn resp_status_i64(resp: &MsgSendDirectResp2) -> i64 {
        resp.payload().u64_at(0) as i64
    }

    // ===================================================================
    // FwMgmt::get_fw_state Test
    // ===================================================================
    #[test]
    fn test_get_fw_state() {
        let mut svc = FwMgmt::new();
        let resp = svc.ffa_msg_send_direct_req2(fwmgmt_req(EC_CAP_GET_FW_STATE)).unwrap();
        let p = resp.payload();
        // FwStateRsp serializes: fw_version(u16 LE) + secure_state(u8) + boot_status(u8) = 4 bytes
        assert_eq!(p.u8_at(0), 0x00); // fw_version low byte
        assert_eq!(p.u8_at(1), 0x01); // fw_version high byte (0x0100 LE)
        assert_eq!(p.u8_at(2), 0x00); // secure_state
        assert_eq!(p.u8_at(3), 0x01); // boot_status
    }

    // ===================================================================
    // FwMgmt::get_svc_list Test
    // ===================================================================
    #[test]
    fn test_get_svc_list() {
        let mut svc = FwMgmt::new();
        let resp = svc.ffa_msg_send_direct_req2(fwmgmt_req(EC_CAP_GET_SVC_LIST)).unwrap();
        // ServiceListRsp: status(i64) + debug_mask(u16) + battery_mask(u8) + fan_mask(u8) +
        //                 thermal_mask(u8) + hid_mask(u8) + key_mask(u16)
        assert_eq!(resp_status_i64(&resp), 0x0); // status
        let p = resp.payload();
        assert_eq!(p.u8_at(8), 0x01); // debug_mask low byte
        assert_eq!(p.u8_at(10), 0x01); // battery_mask
        assert_eq!(p.u8_at(11), 0x01); // fan_mask
        assert_eq!(p.u8_at(12), 0x01); // thermal_mask
        assert_eq!(p.u8_at(13), 0x00); // hid_mask
        assert_eq!(p.u8_at(14), 0x07); // key_mask low byte
    }

    // ===================================================================
    // FwMgmt::get_bid Test
    // ===================================================================
    #[test]
    fn test_get_bid() {
        let mut svc = FwMgmt::new();
        let resp = svc.ffa_msg_send_direct_req2(fwmgmt_req(EC_CAP_GET_BID)).unwrap();
        assert_eq!(resp_status_i64(&resp), 0x0);
        let p = resp.payload();
        let bid = p.u64_at(8); // _bid starts at offset 8 (after i64 status)
        assert_eq!(bid, 0xdead0001);
    }

    // ===================================================================
    // FwMgmt::process_indirect Test
    // ===================================================================
    #[test]
    fn test_process_indirect_returns_error() {
        let mut svc = FwMgmt::new();
        let result = svc.ffa_msg_send_direct_req2(fwmgmt_req(EC_CAP_INDIRECT_MSG));
        assert!(result.is_err(), "process_indirect should return an error");
    }

    // ===================================================================
    // FwMgmt Unknown Command Test
    // ===================================================================
    #[test]
    fn test_unknown_command_returns_error() {
        let mut svc = FwMgmt::new();
        let result = svc.ffa_msg_send_direct_req2(fwmgmt_req(0xFF));
        assert!(result.is_err());
    }
}
