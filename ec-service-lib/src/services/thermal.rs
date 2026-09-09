//! `Thermal` — FFA service that relays Normal-World Thermal requests to
//! the EC over MCTP. Mirrors [`crate::services::battery::Battery`].
//!
//! Service id `0x09`; commands `GetTmp=1, SetThrs=2, GetThrs=3, SetScp=4,
//! GetVar=5, SetVar=6`.
//!
//! All six commands are relayed to the EC. FFA requests use one command
//! byte followed by the canonical EC request body; FFA responses expose
//! the AML-compatible raw value/status prefix at payload offset zero.

use core::cell::RefCell;

use uuid::{uuid, Uuid};

use zerocopy::{
    byteorder::little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use super::parse_ffa_request;
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

/// FFA request bodies for the multi-field Thermal commands. Each is the
/// little-endian EC request payload (command byte stripped); the same
/// layout drives both FFA decoding and EC serialization via `as_bytes()`.
/// `IntoBytes` rejects padding at compile time, and the alignment-one
/// byteorder fields and arrays give these `repr(C)` layouts sizes 13,
/// 13, 19, and 23.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SetThresholdRequest {
    instance_id: u8,
    timeout: U32,
    low: U32,
    high: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SetCoolingPolicyRequest {
    instance_id: u8,
    policy_id: U32,
    acoustic_lim: U32,
    power_lim: U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct GetVariableRequest {
    instance_id: u8,
    len: U16,
    uuid: [u8; 16],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct SetVariableRequest {
    instance_id: u8,
    len: U16,
    uuid: [u8; 16],
    value: U32,
}

/// FFA getter error sentinel, returned when the relay fails locally or
/// the EC returns an error (AML reads `0xFFFF_FFFF` as an error).
const LOCAL_ERROR_SENTINEL: u32 = u32::MAX;

/// AML status word for an FFA request the SP rejects before relaying
/// (e.g. a variable command whose length is not the canonical DWORD).
const INVALID_PARAMETER_STATUS: u32 = 1;

/// Canonical MPTF variable payload length: a single DWORD value.
const VARIABLE_VALUE_LEN: u16 = 4;

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

    /// Relay a SetThrs round-trip; the typed request is the canonical
    /// 13-byte EC body and a successful reply carries no payload.
    fn set_threshold(&self, request: &SetThresholdRequest) -> core::result::Result<(), ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::SetThrs.into(),
                request.as_bytes(),
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

    /// Relay a SetScp round-trip; the typed request is the canonical
    /// 13-byte EC body and a successful reply carries no payload.
    fn set_scp(&self, request: &SetCoolingPolicyRequest) -> core::result::Result<(), ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::SetScp.into(),
                request.as_bytes(),
                parse_empty_response,
            )
            .map_err(ThermalError::Relay)
    }

    /// Relay a GetVar round-trip; the typed request is the canonical
    /// 19-byte EC body and the EC's `u32` value comes from an exact
    /// 4-byte response.
    fn get_var(&self, request: &GetVariableRequest) -> core::result::Result<u32, ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::GetVar.into(),
                request.as_bytes(),
                |body| {
                    let value = take_exact_array::<4>(body)?;
                    Ok(u32::from_le_bytes(value))
                },
            )
            .map_err(ThermalError::Relay)
    }

    /// Relay a SetVar round-trip; the typed request is the canonical
    /// 23-byte EC body and a successful reply carries no payload.
    fn set_var(&self, request: &SetVariableRequest) -> core::result::Result<(), ThermalError> {
        self.relay
            .borrow_mut()
            .invoke_request(
                THERMAL_SERVICE_ID,
                ThermalCommand::SetVar.into(),
                request.as_bytes(),
                parse_empty_response,
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
            ThermalCommand::SetThrs => {
                let status = parse_ffa_request::<SetThresholdRequest>(msg.payload())
                    .map(|request| setter_status(self.set_threshold(request)))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(status)))
            }
            ThermalCommand::GetThrs => {
                let payload = match self.get_threshold(msg.payload().u8_at(1)) {
                    Ok((timeout, low, high)) => threshold_payload(timeout, low, high),
                    Err(_) => threshold_payload(LOCAL_ERROR_SENTINEL, LOCAL_ERROR_SENTINEL, LOCAL_ERROR_SENTINEL),
                };
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
            }
            ThermalCommand::SetScp => {
                let status = parse_ffa_request::<SetCoolingPolicyRequest>(msg.payload())
                    .map(|request| setter_status(self.set_scp(request)))
                    .unwrap_or(LOCAL_ERROR_SENTINEL);
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(status)))
            }
            ThermalCommand::GetVar => {
                let value = match parse_ffa_request::<GetVariableRequest>(msg.payload()) {
                    Some(request) if request.len.get() == VARIABLE_VALUE_LEN => {
                        self.get_var(request).unwrap_or(LOCAL_ERROR_SENTINEL)
                    }
                    _ => LOCAL_ERROR_SENTINEL,
                };
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(value)))
            }
            ThermalCommand::SetVar => {
                let status = match parse_ffa_request::<SetVariableRequest>(msg.payload()) {
                    Some(request) if request.len.get() == VARIABLE_VALUE_LEN => setter_status(self.set_var(request)),
                    Some(_) => INVALID_PARAMETER_STATUS,
                    None => LOCAL_ERROR_SENTINEL,
                };
                Ok(MsgSendDirectResp2::from_req_with_payload(&msg, scalar_payload(status)))
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
