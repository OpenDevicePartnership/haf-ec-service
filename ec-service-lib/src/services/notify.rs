use crate::{Result, Service};
use log::{debug, error};
use odp_ffa::{ErrorCode, MsgSendDirectReq2, MsgSendDirectResp2, Payload, RegisterPayload};
use uuid::{uuid, Uuid};

macro_rules! define_safe_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $type:ty {
        $(
            $variant:ident = $value:expr,
        )*
    }) => {
        $(#[$meta])*
        #[repr($type)]
        $vis enum $name {
            $(
                $variant = $value,
            )*
        }

        impl From<$name> for $type {
            fn from(value: $name) -> Self {
                value as $type
            }
        }

        impl TryFrom<$type> for $name {
            type Error = $type;

            fn try_from(value: $type) -> core::result::Result<Self, $type> {
                Ok(match value {
                    $($value => $name::$variant,)*
                    _ => return Err(value),
                })
            }
        }
    };
}

define_safe_enum! {
    #[derive(Debug,Clone,Copy,PartialEq,Eq)]
    enum MessageID: u8 {
        Setup = 2,
        Destroy = 3,
        Assign = 4,
        Unassign = 5,
    }
}

#[derive(Default,Debug,Clone,Copy)]
enum NotifyType {
    #[default]
    Global,
    PerVcpu,
}

#[derive(Default,Debug)]
struct NfyQueryRsp {
    status: i64,
    start_id: u16,
    last_id: u16,
}

#[derive(Default)]
struct NfyGenericRsp {
    status: i64,
}

#[derive(Debug)]
struct NfySetupRsp {
    reserved: u64,
    sender_uuid: Uuid,
    receiver_uuid: Uuid,
    msg_info: u64,
    status: ErrorCode,
}

#[derive(Debug)]
struct NotifyReq {
    sender_uuid: Uuid,
    receiver_uuid: Uuid,
    msg_info: MessageInfo,
    count: u8,
    notifications: [(u32,u16,NotifyType);7], // Cookie, Notification ID, Type
}

impl NotifyReq {
    fn extract_tuple(value: u64) -> (u32,u16,NotifyType) {
        let cookie = (value >> 32) as u32;
        let id = ((value >> 23) & 0x1FF) as u16;
        let ntype = match (value & 0x1) != 0 {
            false => NotifyType::Global,
            true => NotifyType::PerVcpu,
        };
        (cookie,id,ntype)
    }
}


impl From<MsgSendDirectReq2> for NotifyReq {
    fn from(msg: MsgSendDirectReq2) -> Self {
        let sender_uuid = Uuid::from_u128_le(((msg.register_at(2) as u128) << 64) | (msg.register_at(1) as u128) );
        let receiver_uuid = Uuid::from_u128_le(((msg.register_at(4) as u128) << 64) | (msg.register_at(3) as u128) );
        let msg_info = MessageInfo::from_raw(msg.register_at(5));
        let count = (msg.register_at(6) & 0x1ff).min(7) as u8; // Count is lower 9 bits
        let mut notifications = [(0,0,NotifyType::Global);7];
        for i in 0..count as usize {
            notifications[i] = NotifyReq::extract_tuple(msg.register_at(7+i as usize));
        }

        NotifyReq {
            sender_uuid,
            receiver_uuid,
            msg_info,
            count, 
            notifications,
        }
    }
}

impl From<NfyGenericRsp> for RegisterPayload {
    fn from(value: NfyGenericRsp) -> Self {
        RegisterPayload::from_iter(value.status.to_le_bytes())
    }
}

impl From<NfyQueryRsp> for RegisterPayload {
    fn from(value: NfyQueryRsp) -> Self {
        RegisterPayload::from_iter(
            value
                .status
                .to_le_bytes()
                .into_iter()
                .chain(value.start_id.to_le_bytes())
                .chain(value.last_id.to_le_bytes()),
        )
    }
}

impl From<NfySetupRsp> for RegisterPayload {
    fn from(rsp: NfySetupRsp) -> Self {
        // 
        // x4-x17 are for payload (14 registers)
        let payload_regs = [
            rsp.reserved, 
            rsp.sender_uuid.as_u64_pair().0, 
            rsp.sender_uuid.as_u64_pair().1, 
            rsp.receiver_uuid.as_u64_pair().0, 
            rsp.receiver_uuid.as_u64_pair().1, 
            rsp.msg_info,
            rsp.status as u64,
        ];

        let payload_bytes_iter = payload_regs.iter().flat_map(|&reg| u64::to_le_bytes(reg).into_iter());
        RegisterPayload::from_iter(payload_bytes_iter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageInfo(u64);

impl MessageInfo {
    /// Get the message ID (bits 0–2).
    fn message_id(&self) -> MessageID {
        ((self.0 & 0b111) as u8).try_into().expect("Invalid Message ID")
    }

    /// Construct from a raw u64.
    fn from_raw(value: u64) -> Self {
        MessageInfo(value)
    }
}


#[derive(Default)]
pub struct Notify {
}

impl Notify {
    pub fn new() -> Self {
        Self::default()
    }

    fn nfy_setup(&self, req: NotifyReq) -> NfySetupRsp {
        debug!("cmd: {:?}", req.msg_info.message_id());
        debug!("sender_uuid: {:?}", req.sender_uuid);
        debug!("receiver_uuid: {:?}", req.receiver_uuid);
        debug!("Count: {:?}", req.count);
        debug!("Mapping: {:?}", req.notifications[0]);
        NfySetupRsp {
            reserved: 0,
            sender_uuid: req.sender_uuid,
            receiver_uuid: req.receiver_uuid,
            msg_info: 0x102, // Response message for notification registration
            status: ErrorCode::Ok,
        }
    }

    fn nfy_destroy(&self, req: NotifyReq) -> NfySetupRsp {
        NfySetupRsp {
            reserved: 0,
            sender_uuid: req.sender_uuid,
            receiver_uuid: req.receiver_uuid,
            msg_info: 0x103, // Response message for notification destroy
            status: ErrorCode::Ok,
        }
    }
}

const UUID: Uuid = uuid!("e474d87e-5731-4044-a727-cb3e8cf3c8df");

impl Service for Notify {
    fn service_name(&self) -> &'static str {
        "Notify"
    }

    fn service_uuid(&self) -> Uuid {
        UUID
    }

    async fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let req: NotifyReq = msg.clone().into();
        debug!("Received notify command: {:?}", req.msg_info.message_id());

        let payload = match req.msg_info.message_id() {
            MessageID::Setup => RegisterPayload::from(self.nfy_setup(req)),
            MessageID::Destroy => RegisterPayload::from(self.nfy_destroy(req)),
            _ => {
                error!("Unknown Notify Command: {:?}", req.msg_info.message_id());
                return Err(odp_ffa::Error::Other("Unknown Notify Command"));
            }
        };

        Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
    }
}
