//! # TPM Service Library (Rust)
//!
//! Implementation for the TPM Service. This library is based off the ARM spec:
//! TPM Service Command Response Buffer Interface Over FF-A.
//! <https://developer.arm.com/documentation/den0138/0100/?lang=en>
//!
//! The state flow is based off the TCG PC Client Specific Platform TPM Profile
//! for TPM 2.0.
//! <https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/>
//!
//! Figure 4 — TPM State Diagram for CRB Interface
#![allow(dead_code, unused_imports, unused_variables)]

use crate::{Result, Service};
use log::{error, info, trace};
use odp_ffa::HasRegisterPayload;
use odp_ffa::{DirectMessagePayload, ErrorCode, MsgSendDirectReq2, MsgSendDirectResp2};
use uuid::{uuid, Uuid};

use core::mem;
use core::ptr;

// ---------------------------------------------------------------------------
// Import types and constants from TpmServiceStateTranslationLib
// ---------------------------------------------------------------------------
use super::tpm_sst::{
    PtpCrbRegisters, TpmSstOps, CRB_DATA_BUFFER_SIZE, PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY,
    PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE, PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE, PTP_CRB_CONTROL_START,
    PTP_CRB_LOCALITY_CONTROL_RELINQUISH, PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS,
    PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_0, PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_1,
    PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_2, PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_3,
    PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_4, PTP_CRB_LOCALITY_STATE_LOCALITY_ASSIGNED,
    PTP_CRB_LOCALITY_STATE_TPM_REG_VALID_STATUS, PTP_CRB_LOCALITY_STATUS_GRANTED,
};

// ---------------------------------------------------------------------------
// PTP CRB Interface Identifier
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PtpCrbInterfaceType {
    Fifo = 0x0,
    Crb = 0x1,
    Tis = 0xF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PtpCrbInterfaceVersion {
    Fifo = 0x0,
    Crb = 0x1,
    CrbV2 = 0x2,
}

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct PtpCrbInterfaceIdentifier(pub u32);

impl PtpCrbInterfaceIdentifier {
    pub fn new() -> Self {
        Self(0)
    }

    // Bits [0:3]
    pub fn interface_type(self) -> u32 {
        self.0 & 0xF
    }
    pub fn set_interface_type(&mut self, val: u32) {
        self.0 = (self.0 & !0xF) | (val & 0xF);
    }

    // Bits [4:7]
    pub fn interface_version(self) -> u32 {
        (self.0 >> 4) & 0xF
    }
    pub fn set_interface_version(&mut self, val: u32) {
        self.0 = (self.0 & !(0xF << 4)) | ((val & 0xF) << 4);
    }

    // Bit [8]
    pub fn cap_locality(self) -> u32 {
        (self.0 >> 8) & 1
    }
    pub fn set_cap_locality(&mut self, val: u32) {
        self.0 = (self.0 & !(1 << 8)) | ((val & 1) << 8);
    }

    // Bit [9]
    pub fn cap_crb_idle_bypass(self) -> u32 {
        (self.0 >> 9) & 1
    }
    pub fn set_cap_crb_idle_bypass(&mut self, val: u32) {
        self.0 = (self.0 & !(1 << 9)) | ((val & 1) << 9);
    }

    // Bit [14]
    pub fn cap_crb(self) -> u32 {
        (self.0 >> 14) & 1
    }
    pub fn set_cap_crb(&mut self, val: u32) {
        self.0 = (self.0 & !(1 << 14)) | ((val & 1) << 14);
    }

    // Other bits are unused. Can update here if needed in the future.
}

// ---------------------------------------------------------------------------
// TPM Service Function IDs
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TpmFunction {
    GetInterfaceVersion = 0x0f00_0001,
    GetFeatureInfo = 0x0f00_0101,
    Start = 0x0f00_0201,
    RegisterForNotification = 0x0f00_0301,
    UnregisterForNotification = 0x0f00_0401,
    FinishNotified = 0x0f00_0501,
    ManageLocality = 0x1f00_0001,
    #[cfg(feature = "test-bypass-locality-check")]
    TestWriteCrb = 0xDE00_0001,
}

// ---------------------------------------------------------------------------
// TPM Service Status Codes
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TpmStatus {
    Ok = 0x0500_0001,
    OkResultsReturned = 0x0500_0002,
    NoFunc = 0x8e00_0001,
    NotSup = 0x8e00_0002,
    InvArg = 0x8e00_0005,
    InvCrbCtrlData = 0x8e00_0006,
    Already = 0x8e00_0009,
    Denied = 0x8e00_000a,
    NoMem = 0x8e00_000b,
}

// ---------------------------------------------------------------------------
// TPM Service Start Qualifiers / Manage Locality Operations
// ---------------------------------------------------------------------------
pub const TPM2_FFA_START_FUNC_QUALIFIER_COMMAND: u16 = 0x0;
pub const TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY: u16 = 0x1;

pub const TPM2_FFA_MANAGE_LOCALITY_OPEN: u16 = 0x0;
pub const TPM2_FFA_MANAGE_LOCALITY_CLOSE: u16 = 0x1;

// ---------------------------------------------------------------------------
// TPM Service Defines
// ---------------------------------------------------------------------------
pub const TPM_MAJOR_VER: u64 = 0x1;
pub const TPM_MINOR_VER: u64 = 0x0;
pub const NUM_LOCALITIES: u8 = 5;
const NO_ACTIVE_LOCALITY: u8 = NUM_LOCALITIES; // Invalid locality

// GetFeatureInfo payload flags. Bit 0 = TPM notifications supported.
const TPM_FEATURE_NOTIFICATIONS_SUPPORTED: u64 = 1 << 0;

// ---------------------------------------------------------------------------
// TPM Service States
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmState {
    Idle = 0,
    Ready = 1,
    Complete = 2,
}

// ---------------------------------------------------------------------------
// TPM Locality States
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmLocalityState {
    Closed = 0,
    Open = 1,
}

// ---------------------------------------------------------------------------
// TPM Service FF-A Communication Structures
// ---------------------------------------------------------------------------
struct TpmRequest {
    opcode: u64,   // Arg0
    function: u64, // Arg1
    locality: u64, // Arg2
}

struct TpmResponse {
    tpm_status: u64,  // Arg0
    tpm_payload: u64, // Arg1
}

impl From<MsgSendDirectReq2> for TpmRequest {
    fn from(msg: MsgSendDirectReq2) -> Self {
        let payload = msg.payload();
        let opcode = payload.register_at(0); // Arg0, x4
        let function = payload.register_at(1); // Arg1, x5
        let locality = payload.register_at(2); // Arg2, x6

        TpmRequest {
            opcode,
            function,
            locality,
        }
    }
}

impl From<TpmResponse> for DirectMessagePayload {
    fn from(resp: TpmResponse) -> Self {
        // x4-x17 are for payload (14 registers)
        let payload_regs = [resp.tpm_status, resp.tpm_payload];
        let payload_bytes_iter = payload_regs.iter().flat_map(|&reg| u64::to_le_bytes(reg).into_iter());
        DirectMessagePayload::from_iter(payload_bytes_iter)
    }
}

// ---------------------------------------------------------------------------
// TPM Service Implementation
// ---------------------------------------------------------------------------
pub struct TpmService<S: TpmSstOps> {
    current_state: TpmState,
    active_locality: u8,
    interface_id_default: PtpCrbInterfaceIdentifier,
    locality_states: [TpmLocalityState; NUM_LOCALITIES as usize],
    tpm_internal_crb_address: u64,
    notification_registered: bool,
    pub sst: S,
}

impl<S: TpmSstOps> TpmService<S> {
    // Creates an uninitialized 'TpmService'. Call [`init`] to set up state. Init
    // will initialize the internal variables.
    pub fn new(sst: S, tpm_internal_crb_address: u64) -> Self {
        Self {
            current_state: TpmState::Idle,
            active_locality: NO_ACTIVE_LOCALITY,
            interface_id_default: PtpCrbInterfaceIdentifier::new(),
            locality_states: [TpmLocalityState::Closed; NUM_LOCALITIES as usize],
            tpm_internal_crb_address,
            notification_registered: false,
            sst,
        }
    }

    // Returns a mutable pointer to the CRB register block for `locality`.
    fn crb_ptr(&self, locality: u8) -> *mut PtpCrbRegisters {
        let addr =
            self.tpm_internal_crb_address + ((locality as u64) * (core::mem::size_of::<PtpCrbRegisters>() as u64));
        addr as *mut PtpCrbRegisters
    }

    // Converts an [`ErrorCode`] to a [`TpmStatus`].
    fn convert_error_to_status(status: ErrorCode) -> TpmStatus {
        match status {
            ErrorCode::Ok => TpmStatus::Ok,
            ErrorCode::Denied => TpmStatus::Denied,
            ErrorCode::NoMemory => TpmStatus::NoMem,
            _ => TpmStatus::Denied,
        }
    }

    // Initializes the internal CRB for a given locality.
    // SAFETY: Function accesses the internal CRB. The address is defaulted but should
    //         be set during init of the library. The helper that returns the pointer
    //         based on the locality should always return a valid locality region as
    //         locality is always verified before any calls to these functions. It's
    //         the user's responsibility to make sure the address is valid when
    //         initializing the library.
    unsafe fn init_internal_crb(&self, locality: u8) {
        let crb = self.crb_ptr(locality);
        info!("Locality: {:X} - InternalTpmCrb Address: {:X}", locality, crb as usize);
        ptr::write_bytes(crb, 0x00, 1);

        let crb_ref = &mut *crb;
        crb_ref.interface_id = self.interface_id_default.0;
        crb_ref.crb_control_status = PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE;

        // Set the CRB Command/Response buffer address + size.
        let buf_addr = crb_ref.crb_data_buffer.as_ptr() as usize;
        crb_ref.crb_control_command_address_high = (buf_addr >> 32) as u32;
        crb_ref.crb_control_command_address_low = buf_addr as u32;
        crb_ref.crb_control_command_size = mem::size_of_val(&crb_ref.crb_data_buffer) as u32;
        crb_ref.crb_control_response_address = buf_addr as u64;
        crb_ref.crb_control_response_size = mem::size_of_val(&crb_ref.crb_data_buffer) as u32;
    }

    // Cleans the internal CRB, putting registers into a known-good state.
    // SAFETY: Function accesses the internal CRB. The address is defaulted but should
    //         be set during init of the library. The helper that returns the pointer
    //         based on the locality should always return a valid locality region as
    //         locality is always verified before any calls to these functions. It's
    //         the user's responsibility to make sure the address is valid when
    //         initializing the library.
    unsafe fn clean_internal_crb(&self) {
        // If the user has never requested a locality, don't clean, no need.
        // We should only ever clean the active locality as when localities change
        // we clear the entire CRB region.
        if self.active_locality == NO_ACTIVE_LOCALITY {
            return;
        }

        let crb = &mut *self.crb_ptr(self.active_locality);

        // Set the locality state based on the active locality.
        match self.active_locality {
            0 => crb.locality_state |= PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_0,
            1 => crb.locality_state |= PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_1,
            2 => crb.locality_state |= PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_2,
            3 => crb.locality_state |= PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_3,
            4 => crb.locality_state |= PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_4,
            _ => {}
        }

        crb.locality_state |= PTP_CRB_LOCALITY_STATE_TPM_REG_VALID_STATUS;
        crb.locality_state |= PTP_CRB_LOCALITY_STATE_LOCALITY_ASSIGNED;
        crb.locality_status |= PTP_CRB_LOCALITY_STATUS_GRANTED;
        crb.locality_control = 0;
        crb.interface_id = self.interface_id_default.0;
        crb.crb_control_extension = 0;
        crb.crb_control_request = 0;
        crb.crb_control_cancel = 0;
        crb.crb_control_start = 0;
        crb.crb_interrupt_enable = 0;
        crb.crb_interrupt_status = 0;

        // Set the current TPM status based on the current state.
        if self.current_state == TpmState::Idle {
            crb.crb_control_status = PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE;
        } else {
            crb.crb_control_status = 0;
        }

        // Set the CRB Command/Response buffer address + size.
        let buf_addr = crb.crb_data_buffer.as_ptr() as usize;
        crb.crb_control_command_address_high = (buf_addr >> 32) as u32;
        crb.crb_control_command_address_low = buf_addr as u32;
        crb.crb_control_command_size = mem::size_of_val(&crb.crb_data_buffer) as u32;
        crb.crb_control_response_address = buf_addr as u64;
        crb.crb_control_response_size = mem::size_of_val(&crb.crb_data_buffer) as u32;

        // Remaining registers can be ignored.
    }

    // Handles TPM commands according to the CRB state machine.
    // SAFETY: Function may initialize/zero the internal CRB buffer during successful completion
    //         of a TPM transaction. The address is defaulted but should be set during init of the
    //         library. The helper that returns the pointer based on the locality should always
    //         return a valid locality region as locality is always verified before any calls to
    //         these functions. It's the user's responsibility to make sure the address is valid when
    //         initializing the library.
    unsafe fn handle_command(&mut self) -> TpmStatus {
        let crb = &mut *self.crb_ptr(self.active_locality);

        // Per DEN0138, an empty CRB control request/start register returns
        // INV_CRB_CTRL_DATA. This catches the case where Start(COMMAND) is
        // issued before any state-transition bit is written to the CRB.
        if crb.crb_control_request == 0 && crb.crb_control_start == 0 {
            error!("CRB has no operation requested");
            return TpmStatus::InvCrbCtrlData;
        }

        let mut status: ErrorCode = ErrorCode::Denied;

        // The normal state flow should be: IDLE -> READY -> COMPLETE -> IDLE.
        // Depending on our current state, we will investigate specific registers and
        // make state transitions or deny commands.
        match self.current_state {
            // -- IDLE ------------------------------------------------------
            // The TPM can transition to IDLE from any state outside of command execution when the
            // SW sets the goIdle bit in the CrbControlRequest register. When the TPM transitions to
            // IDLE from COMPLETE it should clear the buffer.
            TpmState::Idle => {
                // Check the cmdReady bit in the CrbControlRequest register to see if we need to
                // transition to the READY state, otherwise, deny the request.
                if crb.crb_control_request & PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY != 0 {
                    trace!("IDLE State - Handle TPM Command cmdReady Request");
                    status = self.sst.cmd_ready(self.active_locality);
                    if status == ErrorCode::Ok {
                        self.current_state = TpmState::Ready;
                    }
                }
            }

            // -- READY -----------------------------------------------------
            // The TPM can transition to READY from IDLE or COMPLETE when the SW sets the cmdReady bit
            // in the CrbControlRequest register. When the TPM transitions to READY from COMPLETE it
            // should clear the buffer.
            TpmState::Ready => {
                // Check the goIdle bit in the CrbControlRequest register to see if we need to
                // transition back to the IDLE state.
                if crb.crb_control_request & PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE != 0 {
                    trace!("READY State - Handle TPM Command goIdle Request");
                    status = self.sst.go_idle(self.active_locality);
                    if status == ErrorCode::Ok {
                        self.current_state = TpmState::Idle;
                    }
                // Check the cmdReady bit in the CrbControlRequest register, clear it if it has been
                // set again.
                } else if crb.crb_control_request & PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY != 0 {
                    trace!("READY State - Handle TPM Command cmdReady Request");
                    status = self.sst.cmd_ready(self.active_locality);
                // Check the CrbControlStart register to see if we need to start executing a command.
                // Once the command completes, transition to the COMPLETE state.
                } else if crb.crb_control_start & PTP_CRB_CONTROL_START != 0 {
                    trace!("READY State - Handle TPM Command Start Request");
                    status = self.sst.start(self.active_locality, crb as *mut PtpCrbRegisters);
                    if status == ErrorCode::Ok {
                        self.current_state = TpmState::Complete;
                    }
                }
            }

            // -- COMPLETE --------------------------------------------------
            // The TPM can transition to COMPLETE only from READY when the SW writes a 1 to the
            // CrbControlStart register and the command execution finishes. The SW can write more
            // data to the buffer and set the register again to trigger another command execution;
            // this is only if TPM_CapCRBIdleBypass is 1.
            TpmState::Complete => {
                // Check the goIdle bit in the CrbControlRequest register to see if we need to
                // transition to the IDLE state.
                if crb.crb_control_request & PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE != 0 {
                    trace!("COMPLETE State - Handle TPM Command goIdle Request");
                    status = self.sst.go_idle(self.active_locality);
                    if status == ErrorCode::Ok {
                        self.current_state = TpmState::Idle;
                        ptr::write_bytes(crb.crb_data_buffer.as_mut_ptr(), 0x00, CRB_DATA_BUFFER_SIZE);
                    }
                // Check the cmdReady bit in the CrbControlRequest register to see if we need to
                // transition back to the READY state.
                } else if crb.crb_control_request & PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY != 0 {
                    trace!("COMPLETE State - Handle TPM Command cmdReady Request");
                    if self.sst.is_idle_bypass_supported() {
                        status = self.sst.cmd_ready(self.active_locality);
                        if status == ErrorCode::Ok {
                            self.current_state = TpmState::Ready;
                            ptr::write_bytes(crb.crb_data_buffer.as_mut_ptr(), 0x00, CRB_DATA_BUFFER_SIZE);
                        }
                    }
                // Check the CrbControlStart register to see if we need to execute another command.
                } else if crb.crb_control_start & PTP_CRB_CONTROL_START != 0 {
                    trace!("COMPLETE State - Handle TPM Command Start Request");
                    // Execution of another command from COMPLETE is only supported if TPM_CapCRBIdleBypass
                    // is 1.
                    if self.sst.is_idle_bypass_supported() {
                        status = self.sst.start(self.active_locality, crb as *mut PtpCrbRegisters);
                    }
                }
            }
        }

        // Clear the internal CRB start register to indicate successful completion and response ready.
        if status != ErrorCode::Ok {
            error!("Command Failed w/ Status: {:X}", status as usize);
        }

        Self::convert_error_to_status(status)
    }

    // Handles locality request / relinquish.
    // SAFETY: Upon successful TPM locality request the internal CRB at that locality gets initialized.
    //         The function to handle this is marked as unsafe as it access the memory thus this function
    //         is also unsafe.
    unsafe fn handle_locality_request(&mut self, locality: u8) -> TpmStatus {
        let crb = &mut *self.crb_ptr(locality);
        let status: ErrorCode;
        let new_active_locality: u8;

        // Check if we are doing a locality relinquish.
        if crb.locality_control & PTP_CRB_LOCALITY_CONTROL_RELINQUISH != 0 {
            // Make sure the locality being relinquished is the active locality.
            if locality != self.active_locality {
                error!("Locality Relinquish Failed - Invalid Locality");
                return TpmStatus::Denied;
            }

            info!("Handle TPM Locality{:X} Relinquish", locality);
            status = self.sst.locality_relinquish(locality);
            new_active_locality = NO_ACTIVE_LOCALITY;
        // Check if we are doing a locality request.
        } else if crb.locality_control & PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS != 0 {
            // Make sure there is no active locality if requesting a different locality.
            if self.active_locality != NO_ACTIVE_LOCALITY && self.active_locality != locality {
                error!("Locality Request Failed - Locality Not Relinquished");
                return TpmStatus::Denied;
            }

            info!("Handle TPM Locality{:X} Request", locality);
            status = self.sst.locality_request(locality);
            new_active_locality = locality;
        // Otherwise, the host didn't set the correct bits — per DEN0138, the
        // locality control data is invalid.
        } else {
            error!("Request/Relinquish Bit Not Set");
            return TpmStatus::InvCrbCtrlData;
        }

        // Update the internal TPM CRB.
        if status == ErrorCode::Ok {
            self.init_internal_crb(locality);
            self.active_locality = new_active_locality;
        } else {
            error!("Locality Request Failed w/ Status: {:X}", status as usize);
        }

        Self::convert_error_to_status(status)
    }

    // Specification Functions
    fn get_interface_version_handler(&self, _request: &TpmRequest, response: &mut TpmResponse) -> TpmStatus {
        response.tpm_payload = (TPM_MAJOR_VER << 16) | TPM_MINOR_VER;
        TpmStatus::OkResultsReturned
    }

    fn get_feature_info_handler(&self, request: &TpmRequest, response: &mut TpmResponse) -> TpmStatus {
        // Feature ID is in the function field (Arg1). Only the notification
        // feature (RegisterForNotification) is currently queryable.
        if request.function == TpmFunction::RegisterForNotification as u64 {
            response.tpm_payload = TPM_FEATURE_NOTIFICATIONS_SUPPORTED;
            TpmStatus::OkResultsReturned
        } else {
            TpmStatus::NotSup
        }
    }

    // SAFETY: Function invokes both handle_command and handle_locality_request which can
    //         access/alter the internal CRB. This function also calls clean_internal_crb
    //         which makes sure the CRB at the current active locality is in a known and
    //         valid state by setting the memory contents (registers) to known values.
    unsafe fn start_handler(&mut self, request: &TpmRequest, _response: &mut TpmResponse) -> TpmStatus {
        let function = request.function as u16;
        let locality = request.locality as u8;
        let return_val: TpmStatus;

        if locality >= NUM_LOCALITIES {
            error!("Invalid Locality");
            return_val = TpmStatus::InvArg;
        } else if self.locality_states[locality as usize] == TpmLocalityState::Closed {
            error!("Locality Closed");
            return_val = TpmStatus::Denied;
        } else if function == TPM2_FFA_START_FUNC_QUALIFIER_COMMAND {
            if locality == self.active_locality {
                return_val = self.handle_command();
            } else {
                error!("Locality Mismatch");
                return_val = TpmStatus::InvArg;
            }
        } else if function == TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY {
            return_val = self.handle_locality_request(locality);
        } else {
            error!("Invalid Start Function");
            return_val = TpmStatus::InvArg;
        }

        // Clean up the internal CRB.
        self.clean_internal_crb();
        return_val
    }

    fn register_handler(&mut self, _request: &TpmRequest, _response: &mut TpmResponse) -> TpmStatus {
        if self.notification_registered {
            TpmStatus::Already
        } else {
            self.notification_registered = true;
            TpmStatus::Ok
        }
    }

    fn unregister_handler(&mut self, _request: &TpmRequest, _response: &mut TpmResponse) -> TpmStatus {
        if !self.notification_registered {
            TpmStatus::Denied
        } else {
            self.notification_registered = false;
            TpmStatus::Ok
        }
    }

    fn finish_handler(&mut self, _request: &TpmRequest, _response: &mut TpmResponse) -> TpmStatus {
        if !self.notification_registered {
            TpmStatus::Denied
        } else {
            // Acknowledge notification completion — no additional state change needed
            // since notifications are edge-triggered in this stub implementation
            TpmStatus::Ok
        }
    }

    fn manage_locality_handler(&mut self, request: &TpmRequest, _response: &mut TpmResponse) -> TpmStatus {
        let locality_operation = request.function as u16;
        let locality = request.locality as u8;
        let mut return_val: TpmStatus = TpmStatus::Ok;

        if locality >= NUM_LOCALITIES {
            error!("Invalid Locality");
            return TpmStatus::InvArg;
        }

        if locality_operation == TPM2_FFA_MANAGE_LOCALITY_OPEN {
            info!("Locality{:X} Opened", locality);
            self.locality_states[locality as usize] = TpmLocalityState::Open;
        } else if locality_operation == TPM2_FFA_MANAGE_LOCALITY_CLOSE {
            info!("Locality{:X} Closed", locality);
            self.locality_states[locality as usize] = TpmLocalityState::Closed;
        } else {
            error!("Invalid Manage Locality Operation");
            return_val = TpmStatus::InvArg;
        }

        return_val
    }

    /// Initializes the TPM service (equivalent to `TpmServiceInit`).
    /// # Safety
    /// Function initializes the internal CRB at all localities by calling
    /// init_internal_crb. This sets all locality regions to known valid
    /// values. The internal and external TPM CRB addresses must be valid
    /// memory regions passed in by the caller.
    pub unsafe fn init(&mut self) {
        // Build the default interface ID.
        self.interface_id_default = PtpCrbInterfaceIdentifier::new();
        self.interface_id_default
            .set_interface_type(PtpCrbInterfaceType::Crb as u32);
        self.interface_id_default
            .set_interface_version(PtpCrbInterfaceVersion::Crb as u32);
        self.interface_id_default.set_cap_locality(1); // 5 localities supported
        self.interface_id_default.set_cap_crb(1); // CRB supported

        for locality in 0..NUM_LOCALITIES {
            self.init_internal_crb(locality);
        }

        // Default Locality 0 and Locality 1 to open.
        self.locality_states[0] = TpmLocalityState::Open;
        self.locality_states[1] = TpmLocalityState::Open;

        // Default all other localities to closed.
        self.locality_states[2] = TpmLocalityState::Closed;
        self.locality_states[3] = TpmLocalityState::Closed;
        self.locality_states[4] = TpmLocalityState::Closed;

        // Initialize the TPM Service State Translation Library.
        self.sst.init();

        self.reset_runtime_state();
    }

    // Resets the volatile runtime state shared by init and deinit. Does NOT
    // touch per-locality open/closed state (deinit handles that separately).
    fn reset_runtime_state(&mut self) {
        self.current_state = TpmState::Idle;
        self.active_locality = NO_ACTIVE_LOCALITY;
        self.notification_registered = false;
    }

    /// De-initializes the TPM service (equivalent to `TpmServiceDeInit`).
    pub fn deinit(&mut self) {
        self.reset_runtime_state();
        self.locality_states = [TpmLocalityState::Closed; NUM_LOCALITIES as usize];
    }

    /// Test-only: write a specific value to a CRB register in the internal CRB.
    /// function field selects the operation:
    ///   0 = locality_control = REQUEST_ACCESS
    ///   1 = locality_control = RELINQUISH
    ///   2 = crb_control_request = CMD_READY
    ///   3 = crb_control_request = GO_IDLE
    ///   4 = crb_control_start = START
    ///   5 = prepare TPM2_Startup command in CRB data buffer
    #[cfg(feature = "test-bypass-locality-check")]
    fn test_write_crb(&mut self, request: &TpmRequest) -> TpmStatus {
        let operation = request.function as u16;
        let locality = request.locality as u8;
        if locality >= NUM_LOCALITIES {
            error!("test_write_crb: Invalid Locality");
            return TpmStatus::InvArg;
        }
        // SAFETY: locality is bounds-checked above and the CRB address was
        // validated during init().
        let crb = unsafe { &mut *self.crb_ptr(locality) };
        match operation {
            0 => crb.locality_control = PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS,
            1 => crb.locality_control = PTP_CRB_LOCALITY_CONTROL_RELINQUISH,
            2 => crb.crb_control_request = PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY,
            3 => crb.crb_control_request = PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE,
            4 => crb.crb_control_start = PTP_CRB_CONTROL_START,
            5 => {
                // Write a TPM2_Startup(CLEAR) command into the CRB data buffer.
                // TPM2_Startup header (big-endian):
                //   tag=0x8001, size=12, code=0x144, startupType=0x0000
                let tpm2_startup: [u8; 12] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];
                crb.crb_data_buffer[..12].copy_from_slice(&tpm2_startup);
                crb.crb_control_command_size = 12;
            }
            _ => {
                error!("test_write_crb: Invalid Operation");
                return TpmStatus::InvArg;
            }
        }
        TpmStatus::Ok
    }
}

impl<S: TpmSstOps> Service for TpmService<S> {
    const UUID: Uuid = uuid!("17b862a4-1806-4faf-86b3-089a58353861");
    const NAME: &'static str = "Tpm";

    fn ffa_msg_send_direct_req2(&mut self, msg: MsgSendDirectReq2) -> Result<MsgSendDirectResp2> {
        let req_payload: TpmRequest = msg.clone().into();
        let mut resp_payload: TpmResponse = TpmResponse {
            tpm_status: (TpmStatus::Ok as u64),
            tpm_payload: (0),
        };

        resp_payload.tpm_status = match req_payload.opcode {
            opcode if opcode == TpmFunction::GetInterfaceVersion as u64 => {
                self.get_interface_version_handler(&req_payload, &mut resp_payload) as u64
            }
            opcode if opcode == TpmFunction::GetFeatureInfo as u64 => {
                self.get_feature_info_handler(&req_payload, &mut resp_payload) as u64
            }
            opcode if opcode == TpmFunction::Start as u64 => unsafe {
                self.start_handler(&req_payload, &mut resp_payload) as u64
            },
            opcode if opcode == TpmFunction::RegisterForNotification as u64 => {
                self.register_handler(&req_payload, &mut resp_payload) as u64
            }
            opcode if opcode == TpmFunction::UnregisterForNotification as u64 => {
                self.unregister_handler(&req_payload, &mut resp_payload) as u64
            }
            opcode if opcode == TpmFunction::FinishNotified as u64 => {
                self.finish_handler(&req_payload, &mut resp_payload) as u64
            }
            opcode if opcode == TpmFunction::ManageLocality as u64 => {
                // Only allow from a logical SP owned by TF-A (source_id high byte == 0xFF).
                #[cfg(not(feature = "test-bypass-locality-check"))]
                if (msg.source_id() & 0xFF00) != 0xFF00 {
                    error!("Invalid Source ID: {:X}", msg.source_id());
                    TpmStatus::Denied as u64
                } else {
                    self.manage_locality_handler(&req_payload, &mut resp_payload) as u64
                }
                #[cfg(feature = "test-bypass-locality-check")]
                {
                    self.manage_locality_handler(&req_payload, &mut resp_payload) as u64
                }
            }
            #[cfg(feature = "test-bypass-locality-check")]
            opcode if opcode == TpmFunction::TestWriteCrb as u64 => self.test_write_crb(&req_payload) as u64,
            _ => {
                error!("Invalid TPM Service Opcode");
                TpmStatus::NoFunc as u64
            }
        };

        let payload = DirectMessagePayload::from(resp_payload);
        Ok(MsgSendDirectResp2::from_req_with_payload(&msg, payload))
    }
}

// ---------------------------------------------------------------------------
// TPM Service Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use odp_ffa::DirectMessagePayload;

    const TPM_SERVICE_UUID: Uuid = uuid!("17b862a4-1806-4faf-86b3-089a58353861");
    const EXTERNAL_TPM_CRB_ADDR: u64 = 0x0C000000;

    // =======================================================================
    // Mock CrbRegion
    // =======================================================================
    #[repr(C, align(8))]
    struct CrbRegion {
        data: [u8; (NUM_LOCALITIES as usize) * core::mem::size_of::<PtpCrbRegisters>()],
    }

    // =======================================================================
    // Mock TpmSstOps
    // =======================================================================
    #[derive(Default)]
    struct MockTpmSst {
        // Empty Struct
    }

    impl MockTpmSst {
        fn new() -> Self {
            Self {}
        }
    }

    impl TpmSstOps for MockTpmSst {
        fn go_idle(&mut self, _locality: u8) -> ErrorCode {
            ErrorCode::Ok
        }
        fn cmd_ready(&mut self, _locality: u8) -> ErrorCode {
            ErrorCode::Ok
        }
        fn start(&mut self, _locality: u8, _crb: *mut PtpCrbRegisters) -> ErrorCode {
            ErrorCode::Ok
        }
        fn locality_request(&mut self, _locality: u8) -> ErrorCode {
            ErrorCode::Ok
        }
        fn locality_relinquish(&mut self, _locality: u8) -> ErrorCode {
            ErrorCode::Ok
        }
        fn is_idle_bypass_supported(&self) -> bool {
            false
        }
        fn init(&mut self) {
            // Do nothing
        }
    }

    // =======================================================================
    // Helpers
    // =======================================================================
    fn direct_req2_msg(source: u16, dest: u16, opcode: u64, function: u64, locality: u64) -> MsgSendDirectReq2 {
        let regs = [opcode, function, locality];
        let payload_bytes_iter = regs.iter().flat_map(|&r| u64::to_le_bytes(r).into_iter());
        let payload = DirectMessagePayload::from_iter(payload_bytes_iter);
        MsgSendDirectReq2::new(source, dest, TPM_SERVICE_UUID, payload)
    }

    // Extract the status from the response.
    fn resp_status(resp: &MsgSendDirectResp2) -> u64 {
        let payload = resp.payload();
        payload.register_at(0) // Arg0, x4
    }

    // Extract the payload from the response.
    fn resp_payload(resp: &MsgSendDirectResp2) -> u64 {
        let payload = resp.payload();
        payload.register_at(1) // Arg1, x5
    }

    // Allocates a properly-sized and aligned CRB region.
    fn alloc_crb_region() -> (Box<CrbRegion>, u64) {
        let region = unsafe {
            let layout = std::alloc::Layout::new::<CrbRegion>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut CrbRegion;
            assert!(!ptr.is_null(), "Allocation Failed");
            Box::from_raw(ptr)
        };
        let addr = region.data.as_ptr() as u64;
        (region, addr)
    }

    // =======================================================================
    // PtpCrbInterfaceIdentifier Test(s)
    // =======================================================================
    #[test]
    fn test_interface_id_new_is_zero() {
        let id = PtpCrbInterfaceIdentifier::new();
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_interface_id_set_interface_type() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_interface_type(PtpCrbInterfaceType::Crb as u32);
        assert_eq!(id.interface_type(), PtpCrbInterfaceType::Crb as u32);
        // Only lower 4 bits should be stored.
        id.set_interface_type(0xFF);
        assert_eq!(id.interface_type(), PtpCrbInterfaceType::Tis as u32);
        assert_eq!(id.0, 0x0F); // Bits [0:3]
    }

    #[test]
    fn test_interface_id_set_interface_version() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_interface_version(PtpCrbInterfaceVersion::Crb as u32);
        assert_eq!(id.interface_version(), PtpCrbInterfaceVersion::Crb as u32);
        // Must not clobber other fields.
        id.set_interface_type(PtpCrbInterfaceType::Crb as u32);
        assert_eq!(id.interface_version(), PtpCrbInterfaceVersion::Crb as u32);
        assert_eq!(id.interface_type(), PtpCrbInterfaceType::Crb as u32);
        assert_eq!(id.0, 0x11);
        // Only upper 4 bits should be stored.
        id.set_interface_version(0xFF);
        assert_eq!(id.interface_version(), 0x0F); // Invalid Version
        assert_eq!(id.0, 0xF1); // Bits [4:7]
    }

    #[test]
    fn test_interface_id_set_cap_locality() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_cap_locality(1);
        assert_eq!(id.cap_locality(), 1);
        assert_eq!(id.0, (1 << 8)); // Bit [8]
        id.set_cap_locality(0);
        assert_eq!(id.cap_locality(), 0);
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_interface_id_set_cap_crb_idle_bypass() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_cap_crb_idle_bypass(1);
        assert_eq!(id.cap_crb_idle_bypass(), 1);
        assert_eq!(id.0, (1 << 9)); // Bit [9]
        id.set_cap_crb_idle_bypass(0);
        assert_eq!(id.cap_crb_idle_bypass(), 0);
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_interface_id_set_cap_crb() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_cap_crb(1);
        assert_eq!(id.cap_crb(), 1);
        assert_eq!(id.0, (1 << 14)); // Bit [14]
        id.set_cap_crb(0);
        assert_eq!(id.cap_crb(), 0);
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_interface_id_combined_fields() {
        let mut id = PtpCrbInterfaceIdentifier::new();
        id.set_interface_type(PtpCrbInterfaceType::Crb as u32);
        id.set_interface_version(PtpCrbInterfaceVersion::Crb as u32);
        id.set_cap_locality(1); // 5 Localities Supported
        id.set_cap_crb(1); // CRB Supported
        assert_eq!(id.interface_type(), PtpCrbInterfaceType::Crb as u32);
        assert_eq!(id.interface_version(), PtpCrbInterfaceVersion::Crb as u32);
        assert_eq!(id.cap_locality(), 1);
        assert_eq!(id.cap_crb(), 1);
        assert_eq!(id.cap_crb_idle_bypass(), 0); // Idle Bypass Not Supported
        assert_eq!(id.0, ((1 << 0) | (1 << 4) | (1 << 8) | (1 << 14)));
    }

    // =======================================================================
    // TpmService::new Test(s)
    // =======================================================================
    #[test]
    fn test_tpm_service_new_defaults() {
        let service = TpmService::new(MockTpmSst::new(), 0x0);
        assert_eq!(service.current_state, TpmState::Idle);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);
        assert_eq!(service.interface_id_default.0, 0);
        assert_eq!(
            service.locality_states,
            [TpmLocalityState::Closed; NUM_LOCALITIES as usize],
        );
        assert_eq!(service.tpm_internal_crb_address, 0x0);
    }

    // =======================================================================
    // TpmService::init Test(s)
    // =======================================================================
    #[test]
    fn test_tpm_service_init() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        unsafe { service.init() };
        assert_eq!(
            service.interface_id_default.interface_type(),
            PtpCrbInterfaceType::Crb as u32
        );
        assert_eq!(
            service.interface_id_default.interface_version(),
            PtpCrbInterfaceVersion::Crb as u32
        );
        assert_eq!(service.interface_id_default.cap_locality(), 1); // 5 localities supported
        assert_eq!(service.interface_id_default.cap_crb(), 1); // CRB supported
        assert_eq!(service.tpm_internal_crb_address, addr);
        assert_eq!(service.locality_states[0], TpmLocalityState::Open);
        assert_eq!(service.locality_states[1], TpmLocalityState::Open);
        assert_eq!(service.locality_states[2], TpmLocalityState::Closed);
        assert_eq!(service.locality_states[3], TpmLocalityState::Closed);
        assert_eq!(service.locality_states[4], TpmLocalityState::Closed);
        assert_eq!(service.current_state, TpmState::Idle);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);
    }

    // =======================================================================
    // TpmService::convert_error_to_status Test(s)
    // =======================================================================
    #[test]
    fn test_convert_error_ok() {
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Ok),
            TpmStatus::Ok,
        );
    }

    #[test]
    fn test_convert_error_denied() {
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Denied),
            TpmStatus::Denied,
        );
    }

    #[test]
    fn test_convert_error_no_memory() {
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::NoMemory),
            TpmStatus::NoMem,
        );
    }

    #[test]
    fn test_convert_error_default() {
        // Any other ErrorCode should default to Denied.
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::NotSupported),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::InvalidParameters),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Busy),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Interrupted),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Retry),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::Aborted),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::NoData),
            TpmStatus::Denied,
        );
        assert_eq!(
            TpmService::<MockTpmSst>::convert_error_to_status(ErrorCode::NotReady),
            TpmStatus::Denied,
        );
    }

    // =======================================================================
    // TpmService::GetInterfaceVersion Test(s)
    // =======================================================================
    #[test]
    fn test_get_interface_version() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::GetInterfaceVersion as u64, 0x00, 0x00);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::OkResultsReturned as u64);
        let expected_version = (TPM_MAJOR_VER << 16) | TPM_MINOR_VER;
        assert_eq!(resp_payload(&resp), expected_version);
    }

    // =======================================================================
    // TpmService::GetFeatureInfo Test(s)
    // =======================================================================
    #[test]
    fn test_get_feature_info() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::GetFeatureInfo as u64, 0x00, 0x00);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::NotSup as u64);
    }

    // =======================================================================
    // TpmService::Start Test(s)
    // =======================================================================
    #[test]
    fn test_start_locality_request() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        unsafe { service.init() };
        let crb: &mut PtpCrbRegisters = unsafe { &mut (*service.crb_ptr(0)) };

        let open_msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00, // Locality 0
        );
        let open_resp = service.ffa_msg_send_direct_req2(open_msg).unwrap();
        assert_eq!(resp_status(&open_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);

        // Set the locality control register to indicate a locality request.
        crb.locality_control = PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS;

        let req_locality_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY as u64,
            0x00, // Locality 0
        );
        let req_locality_resp = service.ffa_msg_send_direct_req2(req_locality_msg).unwrap();
        assert_eq!(resp_status(&req_locality_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, 0);
    }

    #[test]
    fn test_start_command() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        unsafe { service.init() };
        let crb: &mut PtpCrbRegisters = unsafe { &mut (*service.crb_ptr(0)) };

        let open_msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00, // Locality 0
        );
        let open_resp = service.ffa_msg_send_direct_req2(open_msg).unwrap();
        assert_eq!(resp_status(&open_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);

        // Set the locality control register to indicate a locality request.
        crb.locality_control = PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS;

        let req_locality_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY as u64,
            0x00, // Locality 0
        );
        let req_locality_resp = service.ffa_msg_send_direct_req2(req_locality_msg).unwrap();
        assert_eq!(resp_status(&req_locality_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, 0);
        assert_eq!(service.current_state, TpmState::Idle);

        // Set the control request register to transition the state to ready.
        crb.crb_control_request = PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY;

        let start_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x00, // Locality 0
        );
        let start_resp = service.ffa_msg_send_direct_req2(start_msg).unwrap();
        assert_eq!(resp_status(&start_resp), TpmStatus::Ok as u64);
        assert_eq!(service.current_state, TpmState::Ready);

        // Set the control start register to initiate the command.
        crb.crb_control_start = PTP_CRB_CONTROL_START;

        let start_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x00, // Locality 0
        );
        let start_resp = service.ffa_msg_send_direct_req2(start_msg).unwrap();
        assert_eq!(resp_status(&start_resp), TpmStatus::Ok as u64);
        assert_eq!(service.current_state, TpmState::Complete);

        // Set the control request register to transition the state to idle.
        crb.crb_control_request = PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE;

        let start_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x00, // Locality 0
        );
        let start_resp = service.ffa_msg_send_direct_req2(start_msg).unwrap();
        assert_eq!(resp_status(&start_resp), TpmStatus::Ok as u64);
        assert_eq!(service.current_state, TpmState::Idle);
    }

    #[test]
    fn test_start_locality_relinquish() {
        let (_buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        unsafe { service.init() };
        let crb: &mut PtpCrbRegisters = unsafe { &mut (*service.crb_ptr(0)) };

        let open_msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00, // Locality 0
        );
        let open_resp = service.ffa_msg_send_direct_req2(open_msg).unwrap();
        assert_eq!(resp_status(&open_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);

        // Set the locality control register to indicate a locality request.
        crb.locality_control = PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS;

        let req_locality_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY as u64,
            0x00, // Locality 0
        );
        let req_locality_resp = service.ffa_msg_send_direct_req2(req_locality_msg).unwrap();
        assert_eq!(resp_status(&req_locality_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, 0);

        // Set the locality control register to indicate a locality request.
        crb.locality_control = PTP_CRB_LOCALITY_CONTROL_RELINQUISH;

        let rel_locality_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_LOCALITY as u64,
            0x00, // Locality 0
        );
        let rel_locality_resp = service.ffa_msg_send_direct_req2(rel_locality_msg).unwrap();
        assert_eq!(resp_status(&rel_locality_resp), TpmStatus::Ok as u64);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);
    }

    #[test]
    fn test_start_invalid_locality() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x10, // Invalid Locality
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::InvArg as u64);
    }

    #[test]
    fn test_start_locality_closed() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x00, // Locality 0
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        // NOTE: Locality 0 defaults to closed.
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    #[test]
    fn test_start_locality_mismatch() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let open_msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00, // Locality 0
        );
        let open_resp = service.ffa_msg_send_direct_req2(open_msg).unwrap();
        assert_eq!(resp_status(&open_resp), TpmStatus::Ok as u64);

        // NOTE: Locality 0 must be requested before initiating a start command.
        let start_msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            TPM2_FFA_START_FUNC_QUALIFIER_COMMAND as u64,
            0x00, // Locality 0
        );
        let start_resp = service.ffa_msg_send_direct_req2(start_msg).unwrap();
        assert_eq!(resp_status(&start_resp), TpmStatus::InvArg as u64);
    }

    #[test]
    fn test_start_invalid_function() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        service.locality_states[0] = TpmLocalityState::Open;
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::Start as u64,
            0xBEEF, // Invalid Function
            0,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::InvArg as u64);
    }

    // =======================================================================
    // TpmService::Register Test(s)
    // =======================================================================
    #[test]
    fn test_register() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0x00, 0x00);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
    }

    // =======================================================================
    // TpmService::Unregister Test(s)
    // =======================================================================
    #[test]
    fn test_unregister() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::UnregisterForNotification as u64,
            0x00,
            0x00,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    // =======================================================================
    // TpmService::Finish Test(s)
    // =======================================================================
    #[test]
    fn test_finish() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::FinishNotified as u64, 0x00, 0x00);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    // =======================================================================
    // TpmService::ManageLocality Test(s)
    // =======================================================================
    #[test]
    fn test_manage_locality_open() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00, // Locality 0
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
        assert_eq!(service.locality_states[0], TpmLocalityState::Open);
    }

    #[test]
    fn test_manage_locality_close() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        // NOTE: This is only possible because this unit test is within this module. The
        //       locality_states array should only be accessible by the service.
        service.locality_states[0] = TpmLocalityState::Open;
        let msg = direct_req2_msg(
            0xFF01,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_CLOSE as u64,
            0x00, // Locality 0
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
        assert_eq!(service.locality_states[0], TpmLocalityState::Closed);
    }

    #[test]
    fn test_manage_locality_invalid_function() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            0xFF, // Invalid Function
            0x00,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::InvArg as u64);
    }

    #[test]
    fn test_manage_locality_invalid_locality() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x10, // Invalid Locality
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::InvArg as u64);
    }

    #[test]
    fn test_manage_locality_invalid_source() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        // source_id high byte is NOT 0xFF → should be denied
        let msg = direct_req2_msg(
            0x0000, // Invalid Source ID
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0x00,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    #[test]
    fn test_manage_locality_open_all_localities() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        for loc in 0..NUM_LOCALITIES {
            let msg = direct_req2_msg(
                0xFF00,
                0x0000,
                TpmFunction::ManageLocality as u64,
                TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
                loc as u64,
            );
            let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
            assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
            assert_eq!(service.locality_states[loc as usize], TpmLocalityState::Open);
        }
    }

    #[test]
    fn test_manage_locality_close_all_localities() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        for locality in 0..NUM_LOCALITIES {
            let msg = direct_req2_msg(
                0xFF00,
                0x0000,
                TpmFunction::ManageLocality as u64,
                TPM2_FFA_MANAGE_LOCALITY_CLOSE as u64,
                locality as u64,
            );
            let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
            assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
            assert_eq!(service.locality_states[locality as usize], TpmLocalityState::Closed);
        }
    }

    // =======================================================================
    // TpmService Invalid Opcode
    // =======================================================================
    #[test]
    fn test_invalid_opcode() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0, 0, 0xDEAD_BEEF, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::NoFunc as u64);
    }

    // =======================================================================
    // TpmService::GetFeatureInfo Extended Test(s)
    // =======================================================================
    #[test]
    fn test_get_feature_info_notification() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::GetFeatureInfo as u64,
            TpmFunction::RegisterForNotification as u64, // Query notification feature
            0x00,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::OkResultsReturned as u64);
        assert_eq!(resp_payload(&resp) & 0x1, 0x1); // Notifications supported
    }

    #[test]
    fn test_get_feature_info_unknown_feature() {
        // Mirrors existing test_get_feature_info — unknown feature returns NotSup
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(
            0x0000,
            0x0000,
            TpmFunction::GetFeatureInfo as u64,
            0x00, // Unknown feature ID
            0x00,
        );
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::NotSup as u64);
    }

    // =======================================================================
    // TpmService::Register/Unregister State Transition Test(s)
    // =======================================================================
    #[test]
    fn test_register_then_unregister() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        // Register
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
        assert!(service.notification_registered);

        // Unregister
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::UnregisterForNotification as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
        assert!(!service.notification_registered);
    }

    #[test]
    fn test_register_double_returns_already() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        service.ffa_msg_send_direct_req2(msg.clone()).unwrap();
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Already as u64);
    }

    #[test]
    fn test_unregister_without_register_returns_denied() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::UnregisterForNotification as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    // =======================================================================
    // TpmService::Finish Test(s) — Extended
    // =======================================================================
    #[test]
    fn test_finish_after_register() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        // Register first
        let reg_msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        service.ffa_msg_send_direct_req2(reg_msg).unwrap();

        // Finish should succeed
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::FinishNotified as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
    }

    #[test]
    fn test_finish_without_register_returns_denied() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        let msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::FinishNotified as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(msg).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Denied as u64);
    }

    // =======================================================================
    // TpmService::Deinit Test(s)
    // =======================================================================
    #[test]
    fn test_deinit_resets_state() {
        let (buff, addr) = alloc_crb_region();
        let mut service = TpmService::new(MockTpmSst::new(), addr);
        unsafe { service.init() };

        // Open a locality
        let open_msg = direct_req2_msg(
            0xFF00,
            0x0000,
            TpmFunction::ManageLocality as u64,
            TPM2_FFA_MANAGE_LOCALITY_OPEN as u64,
            0,
        );
        service.ffa_msg_send_direct_req2(open_msg).unwrap();

        // Register notification
        let reg_msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        service.ffa_msg_send_direct_req2(reg_msg).unwrap();

        // Verify state is modified
        assert_eq!(service.locality_states[0], TpmLocalityState::Open);
        assert!(service.notification_registered);

        // Deinit should reset everything
        service.deinit();
        assert_eq!(service.current_state, TpmState::Idle);
        assert_eq!(service.active_locality, NO_ACTIVE_LOCALITY);
        assert_eq!(
            service.locality_states,
            [TpmLocalityState::Closed; NUM_LOCALITIES as usize]
        );
        assert!(!service.notification_registered);

        drop(buff); // prevent early deallocation
    }

    #[test]
    fn test_register_after_deinit() {
        let mut service = TpmService::new(MockTpmSst::new(), 0x0);
        // Register, then deinit
        let reg_msg = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        service.ffa_msg_send_direct_req2(reg_msg).unwrap();
        assert!(service.notification_registered);

        service.deinit();
        assert!(!service.notification_registered);

        // Re-register should work (state was properly reset)
        let reg_msg2 = direct_req2_msg(0x0000, 0x0000, TpmFunction::RegisterForNotification as u64, 0, 0);
        let resp = service.ffa_msg_send_direct_req2(reg_msg2).unwrap();
        assert_eq!(resp_status(&resp), TpmStatus::Ok as u64);
        assert!(service.notification_registered);
    }
}
