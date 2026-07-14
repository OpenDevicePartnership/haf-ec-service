//! `Thermal` — FFA service that relays Normal-World Thermal requests to
//! the EC over MCTP. Mirrors [`crate::services::battery::Battery`].
//!
//! Service id `0x09`; commands `GetTmp=1, SetThrs=2, GetThrs=3, SetScp=4,
//! GetVar=5, SetVar=6`. `GetTmp`, `SetThrs`, and `GetThrs` are relayed so
//! far.

use core::cell::RefCell;

use uuid::{uuid, Uuid};

use crate::services::ec_relay::{take_array, take_exact_array, EcRelayError, Relay};
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

/// Reject any body for a command whose success response carries no
/// payload (e.g. SetThrs); a trailing byte is a wire-format mismatch.
fn parse_empty_response(body: &[u8]) -> core::result::Result<(), EcRelayError> {
    take_exact_array::<0>(body).map(|_| ())
}

/// Collapse a setter round-trip into the AML status word: `0` on
/// success, the EC's discriminant for a remote error, else the local
/// sentinel.
fn setter_status(result: core::result::Result<(), ThermalError>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(ThermalError::Relay(EcRelayError::Remote(code))) => u32::from(code),
        Err(_) => LOCAL_ERROR_SENTINEL,
    }
}

fn threshold_payload(timeout: u32, low: u32, high: u32) -> DirectMessagePayload {
    DirectMessagePayload::from_iter(
        timeout
            .to_le_bytes()
            .into_iter()
            .chain(low.to_le_bytes())
            .chain(high.to_le_bytes()),
    )
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

    /// Relay a SetThrs round-trip; the canonical EC body is 13 bytes and a
    /// successful reply carries no payload.
    pub fn set_threshold(
        &self,
        instance_id: u8,
        timeout: u32,
        low: u32,
        high: u32,
    ) -> core::result::Result<(), ThermalError> {
        let mut body = [0u8; 13];
        body[0] = instance_id;
        body[1..5].copy_from_slice(&timeout.to_le_bytes());
        body[5..9].copy_from_slice(&low.to_le_bytes());
        body[9..13].copy_from_slice(&high.to_le_bytes());
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::SetThrs.into(),
                &body,
                parse_empty_response,
            )
            .map_err(ThermalError::Relay)
    }

    /// Relay a GetThrs round-trip; returns the EC's `(timeout, low, high)`
    /// from an exact 12-byte response.
    pub fn get_threshold(&self, instance_id: u8) -> core::result::Result<(u32, u32, u32), ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::GetThrs.into(),
                &[instance_id],
                |body| {
                    let (timeout, body) = take_array(body)?;
                    let (low, body) = take_array(body)?;
                    let high = take_exact_array(body)?;
                    Ok((
                        u32::from_le_bytes(timeout),
                        u32::from_le_bytes(low),
                        u32::from_le_bytes(high),
                    ))
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
            // SetThrs and GetThrs relay to the EC; the rest follow later.
            ThermalCommand::SetThrs => {
                let status = setter_status(self.set_threshold(
                    msg.payload().u8_at(1),
                    msg.payload().u32_at(2),
                    msg.payload().u32_at(6),
                    msg.payload().u32_at(10),
                ));
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(status)))
            }
            ThermalCommand::GetThrs => {
                let payload = match self.get_threshold(msg.payload().u8_at(1)) {
                    Ok((timeout, low, high)) => threshold_payload(timeout, low, high),
                    Err(_) => threshold_payload(LOCAL_ERROR_SENTINEL, LOCAL_ERROR_SENTINEL, LOCAL_ERROR_SENTINEL),
                };
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
            }
            // The remaining commands are relayed in a follow-up.
            ThermalCommand::SetScp | ThermalCommand::GetVar | ThermalCommand::SetVar => {
                Err(FfaError::Other("Thermal command not yet relayed"))
            }
        }
    }
}

// Wire-format gate: round-trips bytes through the EC's own serializer so
// any drift fails the build.

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
