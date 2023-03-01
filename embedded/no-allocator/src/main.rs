//! Test `no_std` build of `bech32`.
//!
//! Build with: `cargo rustc -- -C link-arg=-nostartfiles`.
//!

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Note: `#[global_allocator]` is NOT set.

#[allow(unused_imports)]
use bech32;

/// This function is called on panic, defining this ensures build will fail if `std` is enabled
/// because `panic` will be defined twice.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
