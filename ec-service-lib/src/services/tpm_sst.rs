//! # TPM Service State Translation Library (Rust)
//!
//! Implementation for the TPM Service State Translation Library. This library's
//! main purpose is to translate the states of the TPM service's CRB states to
//! the main TPM's interface states. (i.e. TPM PC CRB -> TPM FIFO) A user of the
//! TPM service should only need to update this library with the proper TPM
//! interface type for their device.
#![allow(dead_code, unused_imports, unused_variables)]

use core::ptr;
use log::info;
use odp_ffa::{ErrorCode, Function, Yield};

// ---------------------------------------------------------------------------
// TPM Service State Translation Defines
// ---------------------------------------------------------------------------
const INTERFACE_TYPE_MASK: u32 = 0x00F;
const IDLE_BYPASS_MASK: u32 = 0x200;

const DELAY_AMOUNT: u64 = 30000;
const YIELD_AMOUNT: u64 = 10 * 1000; // 10ms

const DEBUG_ENABLED: bool = false;

// ---------------------------------------------------------------------------
// PTP CRB Constants
// ---------------------------------------------------------------------------
pub const PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE: u32 = 1 << 1;
pub const PTP_CRB_CONTROL_AREA_STATUS_TPM_STATUS: u32 = 1 << 0;
pub const PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE: u32 = 1 << 1;
pub const PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY: u32 = 1 << 0;
pub const PTP_CRB_CONTROL_START: u32 = 1 << 0;
pub const PTP_CRB_CONTROL_CANCEL: u32 = 1 << 0;

pub const PTP_CRB_LOCALITY_STATE_TPM_REG_VALID_STATUS: u32 = 1 << 7;
pub const PTP_CRB_LOCALITY_STATE_LOCALITY_ASSIGNED: u32 = 1 << 1;
pub const PTP_CRB_LOCALITY_STATE_TPM_ESTABLISHED: u32 = 1 << 0;

pub const PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_0: u32 = 0;
pub const PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_1: u32 = 1 << 2;
pub const PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_2: u32 = 1 << 3;
pub const PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_3: u32 = (1 << 2) | (1 << 3);
pub const PTP_CRB_LOCALITY_STATE_ACTIVE_LOCALITY_4: u32 = 1 << 4;

pub const PTP_CRB_LOCALITY_CONTROL_RELINQUISH: u32 = 1 << 1;
pub const PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS: u32 = 1 << 0;

pub const PTP_CRB_LOCALITY_STATUS_GRANTED: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// PTP FIFO Constants
// ---------------------------------------------------------------------------
pub const PTP_FIFO_STS_VALID: u32 = 1 << 7;
pub const PTP_FIFO_STS_DATA: u32 = 1 << 4;
pub const PTP_FIFO_STS_EXPECT: u32 = 1 << 3;
pub const PTP_FIFO_STS_READY: u32 = 1 << 6;
pub const PTP_FIFO_STS_GO: u32 = 1 << 5;

pub const PTP_FIFO_ACC_RQUUSE: u8 = 1 << 1;
pub const PTP_FIFO_ACC_ACTIVE: u8 = 1 << 5;
pub const PTP_FIFO_VALID: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// PTP Timeout Constants
// ---------------------------------------------------------------------------
pub const PTP_TIMEOUT_A: u64 = 750 * 1000; // 750ms
pub const PTP_TIMEOUT_B: u64 = 2000 * 1000; // 2s
pub const PTP_TIMEOUT_C: u64 = 200 * 1000; // 200ms
pub const PTP_TIMEOUT_D: u64 = 30 * 1000; // 30ms
pub const PTP_TIMEOUT_MAX: u64 = 90000 * 1000; // 90s

// ---------------------------------------------------------------------------
// PTP CRB Registers
// ---------------------------------------------------------------------------
pub const CRB_DATA_BUFFER_SIZE: usize = 0xF80;
const TPM_HEADER_SIZE: usize = 10;

fn tpm_packet_length(header: &[u8], capacity: usize) -> Result<usize, ErrorCode> {
    let header = header.get(..TPM_HEADER_SIZE).ok_or(ErrorCode::InvalidParameters)?;
    let length = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if !(TPM_HEADER_SIZE..=CRB_DATA_BUFFER_SIZE).contains(&capacity) || !(TPM_HEADER_SIZE..=capacity).contains(&length)
    {
        return Err(ErrorCode::InvalidParameters);
    }
    Ok(length)
}

fn read_tpm_response(
    buffer: &mut [u8],
    mut read_byte: impl FnMut(usize) -> Result<u8, ErrorCode>,
) -> Result<usize, ErrorCode> {
    if !(TPM_HEADER_SIZE..=CRB_DATA_BUFFER_SIZE).contains(&buffer.len()) {
        return Err(ErrorCode::InvalidParameters);
    }
    for (offset, byte) in buffer[..TPM_HEADER_SIZE].iter_mut().enumerate() {
        *byte = read_byte(offset)?;
    }
    let length = tpm_packet_length(buffer, buffer.len())?;
    for (offset, byte) in buffer.iter_mut().enumerate().take(length).skip(TPM_HEADER_SIZE) {
        *byte = read_byte(offset)?;
    }
    Ok(length)
}

#[repr(C, packed)]
pub struct PtpCrbRegisters {
    pub locality_state: u32,                         // 0x00
    pub reserved1: [u8; 4],                          // 0x04
    pub locality_control: u32,                       // 0x08
    pub locality_status: u32,                        // 0x0C
    pub reserved2: [u8; 0x20],                       // 0x10
    pub interface_id: u32,                           // 0x30
    pub vid: u16,                                    // 0x34
    pub did: u16,                                    // 0x36
    pub crb_control_extension: u64,                  // 0x38
    pub crb_control_request: u32,                    // 0x40
    pub crb_control_status: u32,                     // 0x44
    pub crb_control_cancel: u32,                     // 0x48
    pub crb_control_start: u32,                      // 0x4C
    pub crb_interrupt_enable: u32,                   // 0x50
    pub crb_interrupt_status: u32,                   // 0x54
    pub crb_control_command_size: u32,               // 0x58
    pub crb_control_command_address_low: u32,        // 0x5C
    pub crb_control_command_address_high: u32,       // 0x60
    pub crb_control_response_size: u32,              // 0x64
    pub crb_control_response_address: u64,           // 0x68
    pub reserved4: [u8; 0x10],                       // 0x70
    pub crb_data_buffer: [u8; CRB_DATA_BUFFER_SIZE], // 0x80
}

// ---------------------------------------------------------------------------
// PTP FIFO Registers
// ---------------------------------------------------------------------------
#[repr(C, packed)]
pub struct PtpFifoRegisters {
    pub access: u8,                // 0x00
    pub reserved1: [u8; 7],        // 0x01
    pub int_enable: u32,           // 0x08
    pub int_vector: u8,            // 0x0C
    pub reserved2: [u8; 3],        // 0x0D
    pub int_sts: u32,              // 0x10
    pub interface_capability: u32, // 0x14
    pub status: u8,                // 0x18
    pub burst_count: u16,          // 0x19
    pub status_ex: u8,             // 0x1B
    pub reserved3: [u8; 8],        // 0x1C
    pub data_fifo: u32,            // 0x24
    pub reserved4: [u8; 8],        // 0x28
    pub interface_id: u32,         // 0x30
    pub reserved5: [u8; 0x4C],     // 0x34
    pub x_data_fifo: u32,          // 0x80
    pub reserved6: [u8; 0xE7C],    // 0x84
    pub vid: u16,                  // 0xF00
    pub did: u16,                  // 0xF02
    pub rid: u8,                   // 0xF04
    pub reserved7: [u8; 0xFB],     // 0xF05
}

// ---------------------------------------------------------------------------
// Debug Helpers
// ---------------------------------------------------------------------------
fn dump_tpm_input_block(input_block_size: u32, input_block: &[u8]) {
    info!("TpmCommand Send - {:02X?}", &input_block[..input_block_size as usize]);
}

fn dump_tpm_output_block(output_block_size: u32, output_block: &[u8]) {
    info!("TpmCommand Rec - {:02X?}", &output_block[..output_block_size as usize]);
}

// ---------------------------------------------------------------------------
// TpmSstOps Trait
// ---------------------------------------------------------------------------
pub trait TpmSstOps {
    fn go_idle(&mut self, locality: u8) -> ErrorCode;
    fn cmd_ready(&mut self, locality: u8) -> ErrorCode;
    fn start(&mut self, locality: u8, crb: *mut PtpCrbRegisters) -> ErrorCode;
    fn locality_request(&mut self, locality: u8) -> ErrorCode;
    fn locality_relinquish(&mut self, locality: u8) -> ErrorCode;
    fn is_idle_bypass_supported(&self) -> bool;
    fn init(&mut self);
}

// ---------------------------------------------------------------------------
// TpmSst — TPM Service State Translation Library implementation
// ---------------------------------------------------------------------------
pub struct TpmSst {
    is_crb_interface: bool,
    pub is_idle_bypass_supported: bool,
    tpm_crb_address: u64,
}

impl Default for TpmSst {
    fn default() -> Self {
        Self::new(0x0)
    }
}

// NOTE: Most of the internal functions to the TPM service state translation library
//       are marked as "unsafe" due to them directly accessing MMIO registers for either
//       a CRB or FIFO interface. The mechanism to read/write to these addresses are
//       inherently unsafe functions as they require pointers to manipulate the memory.
impl TpmSst {
    // Creates a `TpmSst` bound to the external CRB/FIFO MMIO base address.
    pub fn new(tpm_crb_address: u64) -> Self {
        Self {
            is_crb_interface: false,
            is_idle_bypass_supported: false,
            tpm_crb_address,
        }
    }

    // Returns a raw pointer to the external CRB registers for the given locality.
    fn external_crb_ptr(&self, locality: u8) -> *mut PtpCrbRegisters {
        (self.tpm_crb_address + ((locality as u64) * (core::mem::size_of::<PtpCrbRegisters>() as u64)))
            as *mut PtpCrbRegisters
    }

    // Returns a raw pointer to the external FIFO registers for the given locality.
    fn external_fifo_ptr(&self, locality: u8) -> *mut PtpFifoRegisters {
        (self.tpm_crb_address + ((locality as u64) * (core::mem::size_of::<PtpFifoRegisters>() as u64)))
            as *mut PtpFifoRegisters
    }

    // Temp function to busy loop before checking register contents.
    fn delay(&self, delay_amount: u64) {
        for i in 0..delay_amount {
            // Do nothing
        }
    }

    // SAFETY: Function accesses the MMIO region associated with the external FIFO burst count
    //         register. The CRB/FIFO address is defaulted but is passed in during initialization
    //         of the library. It's the user's responsibility to verify they are initializing the
    //         library with a valid CRB/FIFO address.
    unsafe fn fifo_read_burst_count(&self, external_fifo: *mut PtpFifoRegisters) -> Result<u16, ErrorCode> {
        // Slight delay before we start checking the registers.
        self.delay(DELAY_AMOUNT);

        let mut delay_amount: u64 = 0;
        loop {
            let burst_count_ptr = ptr::addr_of!((*external_fifo).burst_count) as *const u8;
            let burst_count_lo: u8 = ptr::read_volatile(burst_count_ptr);
            let burst_count_hi: u8 = ptr::read_volatile(burst_count_ptr.add(1));
            let burst_count: u16 = (burst_count_hi as u16) << 8 | burst_count_lo as u16;

            if burst_count != 0 {
                return Ok(burst_count);
            }

            if delay_amount >= PTP_TIMEOUT_D {
                break;
            }

            // Convert milliseconds to nanoseconds.
            Yield::new(YIELD_AMOUNT * 1000).exec().unwrap();

            delay_amount += YIELD_AMOUNT;
        }

        // NOTE: There should be a timeout or device error code for when the TPM
        //       doesn't respond.
        Err(ErrorCode::Denied)
    }

    // SAFETY: Function accesses the register being passed into the function. The CRB/FIFO address
    //         is defaulted but is passed in during initialization  of the library. It's the user's
    //         responsibility to verify they are initializing the library with a valid CRB/FIFO
    //         address.
    unsafe fn wait_register_bits(&self, register: *mut u32, bit_set: u32, bit_clear: u32, timeout: u64) -> ErrorCode {
        // Slight delay before we start checking the registers.
        self.delay(DELAY_AMOUNT);

        let mut delay_amount: u64 = 0;
        loop {
            // Attempt to read the register based on the TPM type.
            let reg_read = if self.is_crb_interface {
                ptr::read_volatile(register)
            } else {
                ptr::read_volatile(register as *mut u8) as u32
            };

            // Verify the register contents.
            if ((reg_read & bit_set) == bit_set) && ((reg_read & bit_clear) == 0) {
                return ErrorCode::Ok;
            }

            if delay_amount >= timeout {
                break;
            }

            // Convert milliseconds to nanoseconds.
            Yield::new(YIELD_AMOUNT * 1000).exec().unwrap();

            delay_amount += YIELD_AMOUNT;
        }

        // NOTE: There should be a timeout or device error code for when the TPM
        //       doesn't respond.
        ErrorCode::Denied
    }

    // SAFETY: Function copies data from the internal CRB to the external CRB/FIFO. This
    //         function, in the FIFO instance, also calls fifo_read_burst_count and
    //         wait_register_bits which are both marked as unsafe functions.
    unsafe fn copy_command_data(&self, locality: u8, tpm_command_buffer: &[u8], command_data_len: u32) -> ErrorCode {
        // Determine which TPM structure to access.
        if self.is_crb_interface {
            let external_crb = self.external_crb_ptr(locality);

            // Copy the command data to the CRB buffer.
            #[allow(clippy::needless_range_loop)]
            for i in 0..(command_data_len as usize) {
                ptr::write_volatile(
                    ptr::addr_of!((*external_crb).crb_data_buffer[i]) as *mut u8,
                    tpm_command_buffer[i],
                );
            }

            ErrorCode::Ok
        } else {
            let external_fifo = self.external_fifo_ptr(locality);
            let mut status = ErrorCode::Ok;
            let len = command_data_len as usize;

            // Copy the command data to the FIFO depending on the burst count.
            let mut index: usize = 0;
            while index < len {
                let burst_count = match self.fifo_read_burst_count(external_fifo) {
                    Ok(bc) => bc,
                    Err(error) => {
                        status = error;
                        break;
                    }
                };

                let mut remaining_burst = burst_count;
                while remaining_burst > 0 && index < len {
                    ptr::write_volatile(
                        ptr::addr_of!((*external_fifo).data_fifo) as *mut u8,
                        tpm_command_buffer[index],
                    );
                    index += 1;
                    remaining_burst -= 1;
                }
            }

            if status == ErrorCode::Ok {
                // Check to make sure the STS_EXPECT register changed from 1 to 0.
                status = self.wait_register_bits(
                    ptr::addr_of!((*external_fifo).status) as *mut u32,
                    PTP_FIFO_STS_VALID,
                    PTP_FIFO_STS_EXPECT,
                    PTP_TIMEOUT_C,
                );
            }

            status
        }
    }

    // SAFETY: Function writes to the start/go register which initiates a TPM transaction.
    //         This function also calls wait_register_bits which is marked as unsafe.
    unsafe fn start_command(&self, locality: u8) -> ErrorCode {
        // Determine which TPM structure to access.
        if self.is_crb_interface {
            let external_crb = self.external_crb_ptr(locality);

            ptr::write_volatile(
                ptr::addr_of!((*external_crb).crb_control_start) as *mut u32,
                PTP_CRB_CONTROL_START,
            );

            self.wait_register_bits(
                ptr::addr_of!((*external_crb).crb_control_start) as *mut u32,
                0,
                PTP_CRB_CONTROL_START,
                PTP_TIMEOUT_MAX,
            )
        } else {
            let external_fifo = self.external_fifo_ptr(locality);

            // Set the tpmGo bit in the Status register.
            ptr::write_volatile(ptr::addr_of!((*external_fifo).status) as *mut u8, PTP_FIFO_STS_GO as u8);

            self.wait_register_bits(
                ptr::addr_of!((*external_fifo).status) as *mut u32,
                PTP_FIFO_STS_VALID | PTP_FIFO_STS_DATA,
                0,
                PTP_TIMEOUT_MAX,
            )
        }
    }

    // SAFETY: Function copies data from the external CRB/FIFO to the internal CRB. This
    //         function, in the FIFO instance, also calls fifo_read_burst_count which is
    //         also marked as unsafe.
    unsafe fn copy_response_data(&self, locality: u8, tpm_command_buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        // Determine which TPM structure to access.
        if self.is_crb_interface {
            let external_crb = self.external_crb_ptr(locality);

            // Copy the CRB buffer data to the response buffer.
            read_tpm_response(tpm_command_buffer, |offset| {
                Ok(ptr::read_volatile(ptr::addr_of!(
                    (*external_crb).crb_data_buffer[offset]
                )))
            })
        } else {
            let external_fifo = self.external_fifo_ptr(locality);
            let mut remaining_burst = 0;

            read_tpm_response(tpm_command_buffer, |_offset| {
                if remaining_burst == 0 {
                    remaining_burst = self.fifo_read_burst_count(external_fifo)?;
                }
                if ptr::read_volatile(ptr::addr_of!((*external_fifo).status)) & PTP_FIFO_STS_DATA as u8 == 0 {
                    return Err(ErrorCode::Denied);
                }
                let byte = ptr::read_volatile(ptr::addr_of!((*external_fifo).data_fifo) as *mut u8);
                remaining_burst -= 1;
                Ok(byte)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// TpmSstOps Implementation
// ---------------------------------------------------------------------------
impl TpmSstOps for TpmSst {
    // Initiates the transition to the Idle state.
    fn go_idle(&mut self, locality: u8) -> ErrorCode {
        unsafe {
            // Determine which TPM structure to access.
            if self.is_crb_interface {
                let external_crb = self.external_crb_ptr(locality);

                // Set the goIdle bit in the CRB Control Request register. Wait for it
                // to clear and then check the CRB Control Area Status register to make
                // sure the tpmIdle bit was set.
                ptr::write_volatile(
                    ptr::addr_of!((*external_crb).crb_control_request) as *mut u32,
                    PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE,
                );

                let status = self.wait_register_bits(
                    ptr::addr_of!((*external_crb).crb_control_request) as *mut u32,
                    0,
                    PTP_CRB_CONTROL_AREA_REQUEST_GO_IDLE,
                    PTP_TIMEOUT_C,
                );

                if status == ErrorCode::Ok {
                    return self.wait_register_bits(
                        ptr::addr_of!((*external_crb).crb_control_status) as *mut u32,
                        PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE,
                        0,
                        PTP_TIMEOUT_C,
                    );
                }

                status
            } else {
                let external_fifo = self.external_fifo_ptr(locality);

                // Note that there is no goIdle in the FIFO TPM implementation.
                // Going idle is the same as commandReady.
                ptr::write_volatile(
                    ptr::addr_of!((*external_fifo).status) as *mut u8,
                    PTP_FIFO_STS_READY as u8,
                );

                // Set the commandReady bit in the Status register. Read it back and verify it is set which
                // indicates the TPM is ready.
                self.wait_register_bits(
                    ptr::addr_of!((*external_fifo).status) as *mut u32,
                    PTP_FIFO_STS_READY,
                    0,
                    PTP_TIMEOUT_B,
                )
            }
        }
    }

    // Initiates the transition to the commandReady state.
    fn cmd_ready(&mut self, locality: u8) -> ErrorCode {
        unsafe {
            // Determine which TPM structure to access.
            if self.is_crb_interface {
                let external_crb = self.external_crb_ptr(locality);

                // Set the cmdReady bit in the CRB Control Request register. Wait for it
                // to clear and then check the CRB Control Area Status register to make
                // sure the tpmIdle bit was cleared.
                ptr::write_volatile(
                    ptr::addr_of!((*external_crb).crb_control_request) as *mut u32,
                    PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY,
                );

                let status = self.wait_register_bits(
                    ptr::addr_of!((*external_crb).crb_control_request) as *mut u32,
                    0,
                    PTP_CRB_CONTROL_AREA_REQUEST_COMMAND_READY,
                    PTP_TIMEOUT_C,
                );

                if status == ErrorCode::Ok {
                    return self.wait_register_bits(
                        ptr::addr_of!((*external_crb).crb_control_status) as *mut u32,
                        0,
                        PTP_CRB_CONTROL_AREA_STATUS_TPM_IDLE,
                        PTP_TIMEOUT_C,
                    );
                }

                status
            } else {
                let external_fifo = self.external_fifo_ptr(locality);

                // Set the commandReady bit in the Status register. Read it back and
                // verify it is set which indicates the TPM is ready.
                ptr::write_volatile(
                    ptr::addr_of!((*external_fifo).status) as *mut u8,
                    PTP_FIFO_STS_READY as u8,
                );

                self.wait_register_bits(
                    ptr::addr_of!((*external_fifo).status) as *mut u32,
                    PTP_FIFO_STS_READY,
                    0,
                    PTP_TIMEOUT_B,
                )
            }
        }
    }

    // Initiates command execution. Copies command data from the internal CRB
    // to the external TPM, executes the command, and copies the response back.
    fn start(&mut self, locality: u8, internal_tpm_crb: *mut PtpCrbRegisters) -> ErrorCode {
        unsafe {
            let response_capacity = (*internal_tpm_crb).crb_control_response_size as usize;
            let command_capacity = (*internal_tpm_crb).crb_control_command_size as usize;
            if !(TPM_HEADER_SIZE..=CRB_DATA_BUFFER_SIZE).contains(&command_capacity)
                || !(TPM_HEADER_SIZE..=CRB_DATA_BUFFER_SIZE).contains(&response_capacity)
            {
                return ErrorCode::InvalidParameters;
            }

            let mut tpm_command_buffer = [0u8; CRB_DATA_BUFFER_SIZE];

            // Copy the CRB command data to the local buffer.
            ptr::copy_nonoverlapping(
                (*internal_tpm_crb).crb_data_buffer.as_ptr(),
                tpm_command_buffer.as_mut_ptr(),
                TPM_HEADER_SIZE,
            );
            let command_data_len = match tpm_packet_length(&tpm_command_buffer, command_capacity) {
                Ok(length) => length,
                Err(error) => return error,
            };
            ptr::copy_nonoverlapping(
                (*internal_tpm_crb).crb_data_buffer.as_ptr().add(TPM_HEADER_SIZE),
                tpm_command_buffer.as_mut_ptr().add(TPM_HEADER_SIZE),
                command_data_len - TPM_HEADER_SIZE,
            );

            // Debug printout for input data
            if DEBUG_ENABLED {
                dump_tpm_input_block(command_data_len as u32, &tpm_command_buffer[..command_data_len]);
            }

            // Copy the command data to the external TPM.
            let mut status = self.copy_command_data(locality, &tpm_command_buffer, command_data_len as u32);

            if status != ErrorCode::Ok {
                return status;
            }

            // Start command execution.
            status = self.start_command(locality);
            if status != ErrorCode::Ok {
                return status;
            }

            // Copy the response data from the external TPM.
            let response_data_len =
                match self.copy_response_data(locality, &mut tpm_command_buffer[..response_capacity]) {
                    Ok(length) => length,
                    Err(error) => return error,
                };

            // Copy the CRB response data from the local buffer.
            ptr::copy_nonoverlapping(
                tpm_command_buffer.as_ptr(),
                (*internal_tpm_crb).crb_data_buffer.as_mut_ptr(),
                response_data_len,
            );

            // Debug printout for output data
            if DEBUG_ENABLED {
                dump_tpm_output_block(response_data_len as u32, &tpm_command_buffer[..response_data_len]);
            }

            status
        }
    }

    // Requests access to the given locality on the external TPM.
    fn locality_request(&mut self, locality: u8) -> ErrorCode {
        unsafe {
            // Determine which TPM structure to access.
            if self.is_crb_interface {
                let external_crb = self.external_crb_ptr(locality);

                ptr::write_volatile(
                    ptr::addr_of!((*external_crb).locality_control) as *mut u32,
                    PTP_CRB_LOCALITY_CONTROL_REQUEST_ACCESS,
                );

                self.wait_register_bits(
                    ptr::addr_of!((*external_crb).locality_status) as *mut u32,
                    PTP_CRB_LOCALITY_STATUS_GRANTED,
                    0,
                    PTP_TIMEOUT_A,
                )
            } else {
                let external_fifo = self.external_fifo_ptr(locality);

                ptr::write_volatile(ptr::addr_of!((*external_fifo).access) as *mut u8, PTP_FIFO_ACC_RQUUSE);

                self.wait_register_bits(
                    ptr::addr_of!((*external_fifo).access) as *mut u32,
                    (PTP_FIFO_ACC_ACTIVE as u32) | (PTP_FIFO_VALID as u32),
                    0,
                    PTP_TIMEOUT_A,
                )
            }
        }
    }

    // Relinquishes access to the given locality on the external TPM.
    fn locality_relinquish(&mut self, locality: u8) -> ErrorCode {
        unsafe {
            // Determine which TPM structure to access.
            if self.is_crb_interface {
                let external_crb = self.external_crb_ptr(locality);

                ptr::write_volatile(
                    ptr::addr_of!((*external_crb).locality_control) as *mut u32,
                    PTP_CRB_LOCALITY_CONTROL_RELINQUISH,
                );

                self.wait_register_bits(
                    ptr::addr_of!((*external_crb).locality_status) as *mut u32,
                    0,
                    PTP_CRB_LOCALITY_STATUS_GRANTED,
                    PTP_TIMEOUT_A,
                )
            } else {
                let external_fifo = self.external_fifo_ptr(locality);

                ptr::write_volatile(ptr::addr_of!((*external_fifo).access) as *mut u8, PTP_FIFO_ACC_ACTIVE);

                self.wait_register_bits(
                    ptr::addr_of!((*external_fifo).access) as *mut u32,
                    PTP_FIFO_VALID as u32,
                    PTP_FIFO_ACC_ACTIVE as u32,
                    PTP_TIMEOUT_A,
                )
            }
        }
    }

    // Returns if IdleBypass is supported.
    fn is_idle_bypass_supported(&self) -> bool {
        self.is_idle_bypass_supported
    }

    // Initializes the TPM Service State Translation Library by reading the
    // interface identifier register to determine the TPM interface type and
    // idle bypass support.
    fn init(&mut self) {
        // Note that the register we are looking at are located at the same address
        // regardless of if the TPM type is FIFO or CRB.
        let external_crb = self.tpm_crb_address as *const PtpCrbRegisters;

        unsafe {
            // Need to determine the TPM interface type.
            let interface_id = ptr::read_volatile(ptr::addr_of!((*external_crb).interface_id) as *mut u32);
            self.is_crb_interface = (interface_id & INTERFACE_TYPE_MASK) == 1;

            // Need to determine if idle bypass is supported.
            self.is_idle_bypass_supported = (interface_id & IDLE_BYPASS_MASK) != 0;
        }
    }
}

// ---------------------------------------------------------------------------
// TPM SST Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use core::mem;
    use core::ptr;

    // Number of localities in the CRB/FIFO
    const NUM_LOCALITIES: u8 = 0x05;

    // =======================================================================
    // Mock CrbRegion
    // =======================================================================
    #[repr(C, align(8))]
    struct CrbRegion {
        data: [u8; (NUM_LOCALITIES as usize) * core::mem::size_of::<PtpCrbRegisters>()],
    }

    // =======================================================================
    // Helpers
    // =======================================================================
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

    #[test]
    fn test_packet_length_uses_header_not_capacity() {
        let header = [0x80, 0x02, 0, 0, 0, 65, 0, 0, 0x01, 0x82];
        assert_eq!(tpm_packet_length(&header, CRB_DATA_BUFFER_SIZE), Ok(65));
    }

    #[test]
    fn test_packet_length_accepts_boundaries() {
        for length in [TPM_HEADER_SIZE, CRB_DATA_BUFFER_SIZE] {
            let mut header = [0u8; TPM_HEADER_SIZE];
            header[2..6].copy_from_slice(&(length as u32).to_be_bytes());
            assert_eq!(tpm_packet_length(&header, length), Ok(length));
        }
    }

    #[test]
    fn test_packet_length_rejects_invalid_lengths() {
        for length in [0, 9, 66, u32::MAX] {
            let mut header = [0u8; TPM_HEADER_SIZE];
            header[2..6].copy_from_slice(&length.to_be_bytes());
            assert_eq!(tpm_packet_length(&header, 65), Err(ErrorCode::InvalidParameters));
        }
    }

    #[test]
    fn test_packet_length_rejects_invalid_capacity_or_short_header() {
        let header = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01];
        for capacity in [0, 9, CRB_DATA_BUFFER_SIZE + 1] {
            assert_eq!(tpm_packet_length(&header, capacity), Err(ErrorCode::InvalidParameters));
        }
        assert_eq!(tpm_packet_length(&header[..9], 65), Err(ErrorCode::InvalidParameters));
    }

    #[test]
    fn test_read_response_stops_at_packet_length() {
        for length in [TPM_HEADER_SIZE, 19, CRB_DATA_BUFFER_SIZE] {
            let mut packet = std::vec![0x5a; length];
            packet[..2].copy_from_slice(&[0x80, 0x01]);
            packet[2..6].copy_from_slice(&(length as u32).to_be_bytes());
            let mut fifo = std::collections::VecDeque::from(packet.clone());
            fifo.extend([0xee; 8]);
            let mut buffer = [0xcc; CRB_DATA_BUFFER_SIZE];
            let mut reads = 0;

            let result = read_tpm_response(&mut buffer, |offset| {
                assert_eq!(offset, reads);
                reads += 1;
                fifo.pop_front().ok_or(ErrorCode::Denied)
            });

            assert_eq!(result, Ok(length));
            assert_eq!(reads, length);
            assert_eq!(fifo.len(), 8);
            assert_eq!(&buffer[..length], packet.as_slice());
            assert!(buffer[length..].iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn test_read_response_rejects_bad_lengths_before_reading_payload() {
        for length in [0, 9, 20, u32::MAX] {
            let mut header = [0u8; TPM_HEADER_SIZE];
            header[2..6].copy_from_slice(&length.to_be_bytes());
            let mut buffer = [0xcc; 19];
            let mut reads = 0;
            let result = read_tpm_response(&mut buffer, |offset| {
                reads += 1;
                Ok(header[offset])
            });
            assert_eq!(result, Err(ErrorCode::InvalidParameters));
            assert_eq!(reads, TPM_HEADER_SIZE);
            assert!(buffer[TPM_HEADER_SIZE..].iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn test_read_response_rejects_invalid_capacity_without_reading() {
        for capacity in [0, 9, CRB_DATA_BUFFER_SIZE + 1] {
            let mut buffer = std::vec![0; capacity];
            let result = read_tpm_response(&mut buffer, |_offset| panic!("unexpected TPM read"));
            assert_eq!(result, Err(ErrorCode::InvalidParameters));
        }
    }

    #[test]
    fn test_read_response_propagates_header_and_payload_read_errors() {
        let packet = [0x80, 0x02, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for available in [0, 9, 10, 18] {
            let mut fifo = packet[..available].iter().copied();
            let mut buffer = [0; CRB_DATA_BUFFER_SIZE];
            let result = read_tpm_response(&mut buffer, |_offset| fifo.next().ok_or(ErrorCode::Denied));
            assert_eq!(result, Err(ErrorCode::Denied));
        }
    }

    // ===================================================================
    // TpmSst::new & TpmSst::default Test(s)
    // ===================================================================
    #[test]
    fn test_tpm_sst_new_defaults() {
        let sst = TpmSst::new(0x0);
        assert!(!sst.is_crb_interface);
        assert!(!sst.is_idle_bypass_supported);
        assert_eq!(sst.tpm_crb_address, 0x0);
    }

    #[test]
    fn test_tpm_sst_new_equals_default() {
        let tpm_new = TpmSst::new(0x0);
        let tpm_default = TpmSst::default();
        assert_eq!(tpm_new.is_crb_interface, tpm_default.is_crb_interface);
        assert_eq!(tpm_new.is_idle_bypass_supported, tpm_default.is_idle_bypass_supported);
        assert_eq!(tpm_new.tpm_crb_address, tpm_default.tpm_crb_address);
    }

    // ===================================================================
    // PtpCrbRegisters/PtpFifoRegisters Test(s)
    // ===================================================================
    #[test]
    fn test_ptp_crb_registers_size() {
        assert_eq!(mem::size_of::<PtpCrbRegisters>(), 0x1000);
    }

    #[test]
    fn test_ptp_fifo_registers_size() {
        assert_eq!(mem::size_of::<PtpFifoRegisters>(), 0x1000);
    }

    #[test]
    fn test_ptp_crb_equals_ptp_fifo_size() {
        assert_eq!(mem::size_of::<PtpCrbRegisters>(), mem::size_of::<PtpFifoRegisters>());
    }

    #[test]
    fn test_crb_ptr_equals_fifo_ptr() {
        let (buff, addr) = alloc_crb_region();
        let mut sst = TpmSst::new(addr);
        sst.init();
        assert_eq!(sst.external_crb_ptr(0) as *mut u8, sst.external_fifo_ptr(0) as *mut u8);
        assert_eq!(sst.external_crb_ptr(1) as *mut u8, sst.external_fifo_ptr(1) as *mut u8);
        assert_eq!(sst.external_crb_ptr(2) as *mut u8, sst.external_fifo_ptr(2) as *mut u8);
        assert_eq!(sst.external_crb_ptr(3) as *mut u8, sst.external_fifo_ptr(3) as *mut u8);
        assert_eq!(sst.external_crb_ptr(4) as *mut u8, sst.external_fifo_ptr(4) as *mut u8);
    }

    // ===================================================================
    // CRB/FIFO Interface Identifier Register Test(s)
    // ===================================================================
    #[test]
    fn test_is_crb_interface_false() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x00 = FIFO)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x00);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(!sst.is_crb_interface);
    }

    #[test]
    fn test_is_crb_interface_true() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);
    }

    #[test]
    fn test_is_idle_bypass_supported_false() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // CapCRBIdleBypass (Bit 9)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x00);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(!sst.is_idle_bypass_supported);
    }

    #[test]
    fn test_is_idle_bypass_supported_true() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // CapCRBIdleBypass (Bit 9)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x200);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_idle_bypass_supported);
    }

    // ===================================================================
    // TpmSst copy_command_data Test(s)
    // ===================================================================
    // NOTE: There need to be FIFO versions of these tests. However, those are more
    //       complicated as they require reading the burst_count/etc. which would
    //       require mocking the hardware functionality.
    #[test]
    fn test_copy_command_data_crb() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let test_data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
            let status = sst.copy_command_data(0, &test_data, 4);
            assert_eq!(status, ErrorCode::Ok);

            let crb = sst.external_crb_ptr(0);
            #[allow(clippy::needless_range_loop)]
            for i in 0..4 {
                let byte = ptr::read_volatile(ptr::addr_of!((*crb).crb_data_buffer[i]));
                assert_eq!(byte, test_data[i], "Byte Mismatch @ Index:{i}");
            }
        }
    }

    #[test]
    fn test_copy_command_data_zero_length_crb() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let status = sst.copy_command_data(0, &[], 0);
            assert_eq!(status, ErrorCode::Ok);
        }
    }

    #[test]
    fn test_copy_command_data_full_crb() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let mut test_data = [0u8; CRB_DATA_BUFFER_SIZE];
            #[allow(clippy::needless_range_loop)]
            for i in 0..CRB_DATA_BUFFER_SIZE {
                test_data[i] = (i & 0xFF) as u8;
            }

            let status = sst.copy_command_data(0, &test_data, CRB_DATA_BUFFER_SIZE as u32);
            assert_eq!(status, ErrorCode::Ok);

            let crb = sst.external_crb_ptr(0);
            #[allow(clippy::needless_range_loop)]
            for i in 0..CRB_DATA_BUFFER_SIZE {
                let byte = ptr::read_volatile(ptr::addr_of!((*crb).crb_data_buffer[i]));
                assert_eq!(byte, test_data[i], "Byte Mismatch @ Index:{i}");
            }
        }
    }

    #[test]
    fn test_copy_command_data_diff_loc_crb() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let test_data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
            let status = sst.copy_command_data(1, &test_data, 4);
            assert_eq!(status, ErrorCode::Ok);

            let crb = sst.external_crb_ptr(1);
            #[allow(clippy::needless_range_loop)]
            for i in 0..4 {
                let byte = ptr::read_volatile(ptr::addr_of!((*crb).crb_data_buffer[i]));
                assert_eq!(byte, test_data[i], "Byte Mismatch @ Index:{i}");
            }
        }
    }

    // ===================================================================
    // TpmSst copy_response_data Test(s)
    // ===================================================================
    // NOTE: There need to be FIFO versions of these tests. However, those are more
    //       complicated as they require reading the burst_count/etc. which would
    //       require mocking the hardware functionality.
    #[test]
    fn test_copy_response_data() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let test_data = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
            let crb = sst.external_crb_ptr(0);
            #[allow(clippy::needless_range_loop)]
            for index in 0..test_data.len() {
                ptr::write_volatile(
                    ptr::addr_of!((*crb).crb_data_buffer[index]) as *mut u8,
                    test_data[index],
                );
            }

            let mut resp_data = [0xcc; CRB_DATA_BUFFER_SIZE];
            let result = sst.copy_response_data(0, &mut resp_data);
            assert_eq!(result, Ok(test_data.len()));
            assert_eq!(&resp_data[..test_data.len()], &test_data);
            assert!(resp_data[test_data.len()..].iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn test_copy_response_data_zero_length() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let result = sst.copy_response_data(0, &mut []);
            assert_eq!(result, Err(ErrorCode::InvalidParameters));
        }
    }

    #[test]
    fn test_copy_response_data_full_crb() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let mut test_data = [0u8; CRB_DATA_BUFFER_SIZE];
            let crb = sst.external_crb_ptr(0);
            for (index, byte) in test_data.iter_mut().enumerate() {
                *byte = (index & 0xFF) as u8;
            }
            test_data[2..6].copy_from_slice(&(CRB_DATA_BUFFER_SIZE as u32).to_be_bytes());
            #[allow(clippy::needless_range_loop)]
            for index in 0..CRB_DATA_BUFFER_SIZE {
                ptr::write_volatile(
                    ptr::addr_of!((*crb).crb_data_buffer[index]) as *mut u8,
                    test_data[index],
                );
            }

            let mut resp_data = [0u8; CRB_DATA_BUFFER_SIZE];
            let result = sst.copy_response_data(0, &mut resp_data);
            assert_eq!(result, Ok(CRB_DATA_BUFFER_SIZE));
            for i in 0..CRB_DATA_BUFFER_SIZE {
                assert_eq!(resp_data[i], test_data[i], "Byte Mismatch @ Index:{i}");
            }
        }
    }

    #[test]
    fn test_copy_response_data_diff_loc() {
        let (buff, addr) = alloc_crb_region();

        unsafe {
            // NOTE: That this doesn't use the internal function as init has not been
            //       called and as such the TPM address is not valid.
            let crb = addr as *mut PtpCrbRegisters;
            // InterfaceType (0x01 = CRB)
            ptr::write_volatile(ptr::addr_of!((*crb).interface_id) as *mut u32, 0x01);
        }

        let mut sst = TpmSst::new(addr);
        sst.init();
        assert!(sst.is_crb_interface);

        unsafe {
            let test_data = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
            let crb = sst.external_crb_ptr(1);
            #[allow(clippy::needless_range_loop)]
            for index in 0..test_data.len() {
                ptr::write_volatile(
                    ptr::addr_of!((*crb).crb_data_buffer[index]) as *mut u8,
                    test_data[index],
                );
            }

            let mut resp_data = [0u8; 14];
            let result = sst.copy_response_data(1, &mut resp_data);
            assert_eq!(result, Ok(test_data.len()));
            assert_eq!(resp_data, test_data);
        }
    }

    // NOTE: There are many tests that are still required but are difficult to implement
    //       as they require mocking MMIO hardware functionality. There are plans to
    //       update the TPM SST to abstract the hardware portions. When that is complete
    //       we can revisit the unit tests and add any/all that are missing.
}
