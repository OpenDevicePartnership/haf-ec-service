use ffa::{msg::FfaMsg, FfaError, FfaFunctionId};
use log::error;
use uuid::Uuid;

pub type Result<T> = core::result::Result<T, FfaError>;

pub trait Service {
    fn service_name(&self) -> &'static str;
    fn service_uuid(&self) -> &'static Uuid;

    fn ffa_msg_send_direct_req2(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        self.handler_unimplemented(msg)
    }
}

pub(crate) trait ServiceImpl: Service {
    fn exec(&mut self, msg: &FfaMsg) -> Result<FfaMsg> {
        let id = FfaFunctionId::from(msg.function_id);

        match id {
            FfaFunctionId::FfaMsgSendDirectReq2 => self.ffa_msg_send_direct_req2(msg),
            _ => {
                error!("FfaFunctionId has no handler in {}: {:?}", self.service_name(), id);
                Err(FfaError::InvalidParameters)
            }
        }
    }

    fn handler_unimplemented(&self, msg: &FfaMsg) -> Result<FfaMsg> {
        error!(
            "FfaFunctionId is unimplemented in {}: {:?}",
            self.service_name(),
            msg.function_id
        );
        Err(FfaError::InvalidParameters)
    }
}

impl<T: Service + ?Sized> ServiceImpl for T {}

#[macro_export]
macro_rules! service_array {
    ($($service:expr),*) => {
        [$(core::cell::RefCell::new(&mut $service as &mut dyn $crate::Service)),*]
    };
}
