// This project is dual-licensed under Apache 2.0 and MIT terms.
// See LICENSE-APACHE and LICENSE-MIT for details.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "none")]
mod baremetal;

mod services;

#[cfg(not(target_os = "none"))]
fn main() {
    println!("ihv1-sp stub");
}

#[cfg(target_os = "none")]
fn main() -> ! {
    use ec_service_lib::MessageHandler;
    use odp_ffa::Function;

    log::info!("IHV1 Secure Partition - build time: {}", env!("BUILD_TIME"));

    let version = odp_ffa::Version::new().exec().unwrap();
    log::info!("FFA version: {}.{}", version.major(), version.minor());

    // NOTE: the prior `ec_service_lib::services::Thermal` was a
    // hardcoded-mock service; it is now a relay-backed shim that needs
    // a UART-backed `EcRelay` to construct. `ihv1-sp` has no UART
    // driver wired in, so the (functionally no-op) Thermal append is
    // removed for now. Wiring a real EcRelay here is a follow-up for
    // the IHV1 platform.
    MessageHandler::new()
        .run_message_loop()
        .expect("Error in run_message_loop");

    unreachable!()
}
