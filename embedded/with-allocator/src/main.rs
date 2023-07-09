//! Test `no_std` build of `bech32` with an allocator.
//!
//! Build with: `cargo +nightly rustc -- -C link-arg=-nostartfiles`.

#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

extern crate alloc;
use core::alloc::Layout;

use alloc_cortex_m::CortexMHeap;
use bech32::{u5, ByteIterExt, Hrp, Variant};
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

use self::alloc::string::ToString;
use self::alloc::vec;
use self::alloc::vec::Vec;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024; // in bytes

#[entry]
fn main() -> ! {
    // Initialize the allocator BEFORE you use it
    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let hrp = Hrp::parse("bech32").unwrap();
    let data_iter = [0x00u8, 0x01, 0x02].iter().copied().bytes_to_fes();

    let data = data_iter.collect::<Vec<u5>>();
    let encoded = bech32::encode(hrp, data, Variant::Bech32).expect("failed to encode");

    test(encoded == "bech321qqqsyrhqy2a".to_string());

    hprintln!("{}", encoded).unwrap();

    let (parsed, variant) = bech32::decode(&encoded).expect("failed to decode");

    test(variant == Variant::Bech32);
    test(parsed.hrp() == hrp);
    let data = parsed.byte_iter().collect::<Vec<u8>>();
    test(&data == [0x00, 0x01, 0x02].as_ref());

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    hprintln!("{:?}", layout).unwrap();
    asm::bkpt();

    loop {}
}

#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
