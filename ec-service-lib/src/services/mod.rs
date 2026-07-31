use core::mem::size_of;

use odp_ffa::DirectMessagePayload;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

mod battery;
mod ec_relay;
mod fw_mgmt;
mod notify;
mod thermal;
mod time_alarm;
mod tpm;
mod tpm_sst;
mod tpm_stub;
mod ucsi;

pub use battery::Battery;
pub use ec_relay::{EcRelay, MctpSerialTransport, OdpTransport, Relay};
pub use fw_mgmt::FwMgmt;
pub use notify::Notify;
pub use thermal::Thermal;
pub use time_alarm::TimeAlarm;
pub use tpm::TpmService;
pub use tpm_sst::TpmSst;
pub use tpm_stub::TpmServiceStub;
pub use ucsi::Ucsi;

/// Borrow a typed request from an FFA payload after its command byte.
fn parse_ffa_request<T>(payload: &DirectMessagePayload) -> Option<&T>
where
    T: FromBytes + KnownLayout + Immutable + Unaligned,
{
    let start = 1;
    let end = start + size_of::<T>();
    T::ref_from_bytes(payload.get(start..end)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ffa_request_skips_command_byte() {
        let payload = DirectMessagePayload::from_iter([0xAA, 1, 2, 3, 4]);

        assert_eq!(parse_ffa_request::<[u8; 4]>(&payload), Some(&[1, 2, 3, 4]));
    }

    #[test]
    fn parse_ffa_request_rejects_type_larger_than_payload() {
        let payload = DirectMessagePayload::from_iter(core::iter::empty());

        assert!(parse_ffa_request::<[u8; 112]>(&payload).is_none());
    }
}
