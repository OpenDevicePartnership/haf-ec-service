#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod service;
pub mod services;
pub mod sp_logger;

use core::cell::RefCell;
use ffa::msg::FfaMsg;
use ffa::rxtx::FfaRxTxMsg;
use ffa::{Ffa, FfaError};
use log::{debug, error, info};
use service::ServiceImpl;
pub use service::{Result, Service};

// For reference, here are the UUIDs for services that ec-service-lib defines (not all of them are implemented)
// const UUID_EC_SVC_NOTIFY: Uuid = uuid!("B510B3A3-59F6-4054-BA7A-FF2EB1EAC765");
// const UUID_EC_SVC_MANAGEMENT: Uuid = uuid!("330c1273-fde5-4757-9819-5b6539037502");
// const UUID_EC_SVC_POWER: Uuid = uuid!("7157addf-2fbe-4c63-ae95-efac16e3b01c");
// const UUID_EC_SVC_BATTERY: Uuid = uuid!("25cb5207-ac36-427d-aaef-3aa78877d27e");
// const UUID_EC_SVC_THERMAL: Uuid = uuid!("31f56da7-593c-4d72-a4b3-8fc7171ac073");
// const UUID_EC_SVC_UCSI: Uuid = uuid!("65467f50-827f-4e4f-8770-dbf4c3f77f45");
// const UUID_EC_SVC_TIME_ALARM: Uuid = uuid!("23ea63ed-b593-46ea-b027-8924df88e92f");
// const UUID_EC_SVC_DEBUG: Uuid = uuid!("0bd66c7c-a288-48a6-afc8-e2200c03eb62");
// const UUID_EC_SVC_OEM: Uuid = uuid!("9a8a1e88-a880-447c-830d-6d764e9172bb");

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug)]
pub enum HafEcError {
    Ok,
    InvalidParameters,
}

#[derive(Default)]
pub struct HafEcService<'svc> {
    tx_buffer_base: u64,
    rx_buffer_base: u64,
    rxtx_page_count: u32,
    services: &'svc [RefCell<&'svc mut dyn Service>],
}

impl<'svc> HafEcService<'svc> {
    pub fn new(services: &'svc [RefCell<&'svc mut dyn Service>]) -> Self {
        Self {
            services,
            ..Default::default()
        }
    }

    pub fn map_rxtx_buffers(&mut self, tx_base: u64, rx_base: u64, page_count: u32) -> HafEcError {
        // Map in shared RX/TX buffers
        debug!(
            "Mapping shared RX/TX buffers:
               TX_BUFFER_BASE: 0x{:x}
               RX_BUFFER_BASE: 0x{:x}
               RXTX_PAGE_COUNT: 0x{:x}",
            tx_base, rx_base, page_count
        );

        let mut rxtx = FfaRxTxMsg::new();
        let result = rxtx.map(tx_base, rx_base, page_count);
        match result {
            FfaError::Ok => {
                debug!("Successfully mapped RXTX buffers");
                self.tx_buffer_base = tx_base;
                self.rx_buffer_base = rx_base;
                self.rxtx_page_count = page_count;
            }

            _ => {
                // This is fatal, terminate SP
                debug!("Error mapping RXTX buffers");
                return HafEcError::InvalidParameters;
            }
        }
        HafEcError::Ok
    }

    fn ffa_msg_handler(&self, msg: &FfaMsg) -> Result<FfaMsg> {
        debug!(
            r#"Successfully received ffa msg:
            function_id = {:08x}
                   uuid = {}"#,
            msg.function_id, msg.uuid
        );

        for service in self.services {
            let mut service = service.borrow_mut();
            if service.service_uuid() == &msg.uuid {
                return service.exec(msg);
            }
        }

        error!("Unknown UUID {}", msg.uuid);
        Err(FfaError::InvalidParameters)
    }

    pub fn sp_main(self) -> ! {
        info!("Entered sp_main");

        // Get current FFA version
        let ffa = Ffa::new();

        // Call the msg_wait method
        match ffa.version() {
            Ok(ver) => info!("FFA Version: {}.{}", ver.major(), ver.minor()),
            Err(_e) => {
                // This is fatal, terminate SP
                error!("FFA Version failed")
            }
        }

        debug!("Entering FFA message loop");
        // Call the msg_wait method
        let mut next_msg = ffa.msg_wait();

        loop {
            match next_msg {
                Ok(ref ffamsg) => match self.ffa_msg_handler(ffamsg) {
                    Ok(msg) => next_msg = ffa.msg_resp(&msg),
                    Err(e) => error!("Failed to handle FFA msg: {:?}", e),
                },
                Err(e) => {
                    error!("Error executing msg_wait: {:?}", e);
                    next_msg = ffa.msg_wait();
                }
            }
        }
    }
}
