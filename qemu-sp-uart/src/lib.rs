#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Minimal blocking PL011 MMIO driver for the QEMU SBSA secure partition.
//!
//! Polled TX (blocks while `UARTFR.TXFF` is set) and bounded polled RX
//! (via [`Pl011Uart::read_byte_blocking`]). MMIO is fronted by the
//! [`Mmio`] trait so the bit-twiddling is host-testable with a mock
//! backend.
//!
//! # Base address contract
//!
//! [`Pl011Uart::new`] takes the MMIO `base` as a constructor parameter; the
//! literal device address (`0x09040000` for the SP-side `ec_uart`) is NOT
//! hard-coded inside this crate. The address is declared in the outer
//! platform repo's SP DTS (`odp-platform-qemu-sbsa` →
//! `mod/secure-services/platform/linker/qemu-ec-sp.dts`). The platform
//! binary wires `Pl011Uart::new(0x09040000)` from `qemu-ec-sp::main`.
//!
//! # Safety contract
//!
//! [`RawMmio::new`] is `unsafe`: caller must have mapped the PL011 device
//! region of at least `0x40` bytes at the supplied `base`, matching the SP
//! manifest device-region attributes (R/W, device memory). The driver does
//! NOT touch `UARTCR` / `UARTLCR_H` — TF-A and QEMU init are assumed.

/// Minimal MMIO abstraction. Real hardware uses [`RawMmio`] with
/// `core::ptr::{read,write}_volatile`; host tests substitute a mock backend.
/// Offsets are byte offsets from the device base.
pub trait Mmio {
    /// Read a `u32` at byte offset `off` from the base.
    ///
    /// # Safety
    /// Caller guarantees the offset addresses a valid device register.
    unsafe fn read32(&self, off: usize) -> u32;
    /// Read a `u8` at byte offset `off`.
    ///
    /// # Safety
    /// See [`Mmio::read32`].
    unsafe fn read8(&self, off: usize) -> u8;
    /// Write a `u8` at byte offset `off`.
    ///
    /// # Safety
    /// See [`Mmio::read32`]. Caller must ensure the offset is writable.
    unsafe fn write8(&mut self, off: usize, val: u8);
}

/// Real-hardware MMIO backend wrapping a raw base pointer.
pub struct RawMmio {
    base: *mut u8,
}

impl RawMmio {
    /// Wrap a raw MMIO base address.
    ///
    /// # Safety
    /// `base` must point to a mapped PL011 device region of at least `0x40`
    /// bytes, matching the SP manifest device-region attributes (R/W, device
    /// memory).
    pub unsafe fn new(base: usize) -> Self {
        Self { base: base as *mut u8 }
    }
}

impl Mmio for RawMmio {
    unsafe fn read32(&self, off: usize) -> u32 {
        // SAFETY: precondition of `RawMmio::new` — `base` is a mapped device
        // region and `off` is within bounds.
        unsafe { core::ptr::read_volatile(self.base.add(off) as *const u32) }
    }
    unsafe fn read8(&self, off: usize) -> u8 {
        // SAFETY: same precondition as `read32`.
        unsafe { core::ptr::read_volatile(self.base.add(off)) }
    }
    unsafe fn write8(&mut self, off: usize, val: u8) {
        // SAFETY: same precondition as `read32`; `off` must be writable.
        unsafe { core::ptr::write_volatile(self.base.add(off), val) }
    }
}

// PL011 register offsets (relative to base). `pub` so test fixtures can
// target the same offsets without redeclaring the magic numbers.
pub const UARTDR: usize = 0x000;
pub const UARTFR: usize = 0x018;

// PL011 flag-register bits.
pub const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
pub const FR_TXFF: u32 = 1 << 5; // TX FIFO full

/// PL011 driver errors.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// RX poll budget exhausted before a byte arrived.
    Timeout,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Timeout => write!(f, "PL011 timeout"),
        }
    }
}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::TimedOut
    }
}

impl core::error::Error for Error {}

/// Blocking PL011 UART driver. Generic over the [`Mmio`] backend.
pub struct Pl011Uart<M: Mmio> {
    mmio: M,
}

impl<M: Mmio> Pl011Uart<M> {
    /// Wrap an [`Mmio`] backend. Does NOT touch UARTCR / UARTLCR_H — TF-A
    /// and QEMU init are assumed.
    ///
    /// Crate-private: only visible to in-crate tests and the production
    /// [`Pl011Uart::new`] constructor.
    pub(crate) const fn from_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Borrow the underlying MMIO backend (test-only inspection helper).
    #[cfg(test)]
    pub(crate) fn mmio_for_test(&self) -> &M {
        &self.mmio
    }

    /// Blocking write of a byte slice. Each byte polls `UARTFR.TXFF` until
    /// clear, then writes `UARTDR`. Returns `Ok(())` (no error path; result
    /// type included for API symmetry + future-proofing).
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for &b in bytes {
            // SAFETY: `UARTFR` / `UARTDR` are in the device region passed to
            // `RawMmio::new` (or the mock backend's tracked offsets in tests).
            // The poll loop reads only; the write goes to the writable
            // `UARTDR` offset.
            unsafe {
                while self.mmio.read32(UARTFR) & FR_TXFF != 0 {
                    core::hint::spin_loop();
                }
                self.mmio.write8(UARTDR, b);
            }
        }
        Ok(())
    }

    /// Default RX-poll budget for `read_byte_blocking`: ample for the
    /// EC's ms-scale responses, finite so a stuck link can't hang.
    pub const RX_POLL_BUDGET: u32 = 10_000_000;

    /// Read one byte, polling `UARTFR.RXFE` up to `budget` times;
    /// `Err(Error::Timeout)` if exhausted.
    pub fn read_byte_bounded(&mut self, budget: u32) -> Result<u8, Error> {
        for _ in 0..budget {
            // SAFETY: see `write_bytes`.
            let fr = unsafe { self.mmio.read32(UARTFR) };
            if fr & FR_RXFE == 0 {
                // SAFETY: RXFE clear ⇒ at least one byte in the RX FIFO.
                return Ok(unsafe { self.mmio.read8(UARTDR) });
            }
            core::hint::spin_loop();
        }
        Err(Error::Timeout)
    }

    /// Blocking read of one byte, bounded by [`Self::RX_POLL_BUDGET`].
    pub fn read_byte_blocking(&mut self) -> Result<u8, Error> {
        self.read_byte_bounded(Self::RX_POLL_BUDGET)
    }
}

impl<M: Mmio> embedded_io::ErrorType for Pl011Uart<M> {
    type Error = Error;
}

impl<M: Mmio> embedded_io::Read for Pl011Uart<M> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.read_byte_blocking()?;
        Ok(1)
    }
}

impl<M: Mmio> embedded_io::Write for Pl011Uart<M> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write_bytes(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Pl011Uart<RawMmio> {
    /// Convenience constructor for the production MMIO backend.
    ///
    /// # Safety
    /// Caller must have mapped the device region declared in
    /// `qemu-ec-sp.dts` (`ec_uart`) at `base`; the SP manifest must grant
    /// R/W access to at least `0x40` bytes there. `base` is `u64` per the
    /// SBSA SP physical-address convention; cast to host pointer width
    /// internally.
    pub unsafe fn new(base: u64) -> Self {
        // SAFETY: precondition propagated to caller per the function-level
        // `# Safety` clause.
        let mmio = unsafe { RawMmio::new(base as usize) };
        Self::from_mmio(mmio)
    }
}

// ---------------------------------------------------------------------------
// Host-side tests. `MockMmio` lives entirely under `#[cfg(test)]` — it does
// NOT exist in the `aarch64-unknown-none[-softfloat]` binary, preserving the
// no-alloc runtime.
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    /// Scripted MMIO backend.
    ///
    /// `fr_script` is a queue of `UARTFR` values consumed in order; once
    /// drained, every subsequent `read32(UARTFR)` returns `fr_default`.
    /// `dr_rx_byte` is what `read8(UARTDR)` returns. `dr_tx_log` records
    /// every `write8(UARTDR, _)` in order. `fr_read_count` lets tests
    /// assert poll-loop iteration counts.
    struct MockMmio {
        fr_script: RefCell<VecDeque<u32>>,
        fr_default: u32,
        fr_read_count: Cell<u32>,
        dr_rx_byte: u8,
        dr_tx_log: RefCell<Vec<u8>>,
    }

    impl MockMmio {
        fn new(fr_default: u32, dr_rx_byte: u8) -> Self {
            Self {
                fr_script: RefCell::new(VecDeque::new()),
                fr_default,
                fr_read_count: Cell::new(0),
                dr_rx_byte,
                dr_tx_log: RefCell::new(Vec::new()),
            }
        }
        fn push_fr(&mut self, v: u32) {
            self.fr_script.borrow_mut().push_back(v);
        }
        fn fr_read_count(&self) -> u32 {
            self.fr_read_count.get()
        }
        fn dr_tx_log(&self) -> Vec<u8> {
            self.dr_tx_log.borrow().clone()
        }
    }

    impl Mmio for MockMmio {
        unsafe fn read32(&self, off: usize) -> u32 {
            assert_eq!(off, UARTFR, "MockMmio only models UARTFR for read32");
            self.fr_read_count.set(self.fr_read_count.get() + 1);
            self.fr_script.borrow_mut().pop_front().unwrap_or(self.fr_default)
        }
        unsafe fn read8(&self, off: usize) -> u8 {
            assert_eq!(off, UARTDR);
            self.dr_rx_byte
        }
        unsafe fn write8(&mut self, off: usize, val: u8) {
            assert_eq!(off, UARTDR);
            self.dr_tx_log.borrow_mut().push(val);
        }
    }

    #[test]
    fn write_bytes_writes_each_byte_in_order() {
        let mock = MockMmio::new(0, 0); // TXFF clear by default → no waiting
        let mut uart = Pl011Uart::from_mmio(mock);
        uart.write_bytes(&[0x01, 0x02, 0x03]).expect("write");
        assert_eq!(uart.mmio_for_test().dr_tx_log(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn write_bytes_polls_txff_until_clear() {
        let mut mock = MockMmio::new(0, 0);
        mock.push_fr(FR_TXFF); // first poll: TX full
        mock.push_fr(FR_TXFF); // second poll: still full
        mock.push_fr(0); // third poll: clear → write
        let mut uart = Pl011Uart::from_mmio(mock);
        uart.write_bytes(&[0x42]).expect("write");
        assert_eq!(uart.mmio_for_test().dr_tx_log(), vec![0x42]);
        assert_eq!(uart.mmio_for_test().fr_read_count(), 3);
    }

    #[test]
    fn read_byte_blocking_returns_byte_when_rxfe_clears() {
        let mut mock = MockMmio::new(0, 0xAB); // FR default 0 = RXFE clear
                                               // Push a couple of "RX still empty" reads first to confirm the loop polls:
        mock.push_fr(FR_RXFE);
        mock.push_fr(FR_RXFE);
        // Then default 0 takes over → RXFE clear → read returns 0xAB.
        let mut uart = Pl011Uart::from_mmio(mock);
        assert_eq!(uart.read_byte_blocking().expect("read"), 0xAB);
        assert!(uart.mmio_for_test().fr_read_count() >= 3);
    }

    #[test]
    fn read_byte_bounded_returns_timeout_when_rxfe_stays_set() {
        let mock = MockMmio::new(FR_RXFE, 0xFF); // RXFE always set → never ready
        let mut uart = Pl011Uart::from_mmio(mock);
        let err = uart.read_byte_bounded(3).expect_err("should time out");
        assert_eq!(err, Error::Timeout);
        assert_eq!(uart.mmio_for_test().fr_read_count(), 3);
    }

    #[test]
    fn read_byte_bounded_returns_byte_when_rxfe_clears_before_budget() {
        let mut mock = MockMmio::new(0, 0xCD); // default 0 = RXFE clear
        mock.push_fr(FR_RXFE); // first poll: empty
        mock.push_fr(FR_RXFE); // second poll: empty
                               // third+ polls: default 0 → ready → reads 0xCD
        let mut uart = Pl011Uart::from_mmio(mock);
        assert_eq!(uart.read_byte_bounded(10).expect("read"), 0xCD);
    }
}
