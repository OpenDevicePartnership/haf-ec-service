//! `Thermal` — FFA service that relays Normal-World Thermal requests to
//! the EC over MCTP. Mirrors [`crate::services::battery::Battery`].
//!
//! Service id `0x09`; commands `GetTmp=1, SetThrs=2, GetThrs=3, SetScp=4,
//! GetVar=5, SetVar=6`. Only `GetTmp` is relayed so far.

use core::cell::RefCell;

use uuid::{uuid, Uuid};

use crate::services::ec_relay::{take_exact_array, EcRelayError, Relay};
use crate::{Result, Service};
use odp_ffa::{DirectMessagePayload, Error as FfaError, HasRegisterPayload, MsgSendDirectReq2, MsgSendDirectResp2};

pub const THERMAL_SERVICE_ID: u8 = 0x09;

/// Thermal command ids (FFA request byte 0 / ODP message id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u16)]
pub enum ThermalCommand {
    GetTmp = 1,
    SetThrs = 2,
    GetThrs = 3,
    SetScp = 4,
    GetVar = 5,
    SetVar = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalError {
    Relay(EcRelayError),
    UnexpectedResponse,
}

impl From<EcRelayError> for ThermalError {
    fn from(e: EcRelayError) -> Self {
        ThermalError::Relay(e)
    }
}

/// FFA `GetTmp` reply sentinel: reported at payload offset zero when the
/// relay round-trip fails locally (AML reads `0xFFFF_FFFF` as an error).
const LOCAL_ERROR_SENTINEL: u32 = u32::MAX;

fn scalar_payload(value: u32) -> DirectMessagePayload {
    DirectMessagePayload::from_iter(value.to_le_bytes())
}

pub struct Thermal<'r, R: Relay> {
    relay: &'r RefCell<R>,
}

impl<'r, R: Relay> Thermal<'r, R> {
    pub fn new(relay: &'r RefCell<R>) -> Self {
        Self { relay }
    }

    /// Relay a GetTmp round-trip; returns the EC's `u32` DeciKelvin.
    pub fn get_temperature(&self, instance_id: u8) -> core::result::Result<u32, ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::GetTmp.into(),
                &[instance_id],
                |body| {
                    let temp = take_exact_array::<4>(body)?;
                    Ok(u32::from_le_bytes(temp))
                },
            )
            .map_err(ThermalError::Relay)
    }
}

impl<R: Relay> Service for Thermal<'_, R> {
    const UUID: Uuid = uuid!("31f56da7-593c-4d72-a4b3-8fc7171ac073");
    const NAME: &'static str = "Thermal";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let cmd = msg.payload().u8_at(0);
        let Ok(command) = ThermalCommand::try_from(cmd as u16) else {
            return Err(FfaError::Other("Unknown Thermal Command"));
        };

        match command {
            ThermalCommand::GetTmp => {
                let instance_id = msg.payload().u8_at(1);
                let value = self.get_temperature(instance_id).unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
            }
            // The other five commands are relayed in a follow-up.
            ThermalCommand::SetThrs
            | ThermalCommand::GetThrs
            | ThermalCommand::SetScp
            | ThermalCommand::GetVar
            | ThermalCommand::SetVar => Err(FfaError::Other("Thermal command not yet relayed")),
        }
    }
}

// Wire-format gate: round-trips bytes through the EC's own serializer so
// any drift fails the build.

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
