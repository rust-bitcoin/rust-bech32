#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

extern crate alloc;
use core::alloc::Layout;

use alloc_cortex_m::CortexMHeap;
use bech32::{Bech32m, Hrp};
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

use self::alloc::string::ToString;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024; // in bytes

#[entry]
fn main() -> ! {
    // Initialize the allocator BEFORE you use it
    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let data = [0x00u8, 0x01, 0x02];
    let hrp = Hrp::parse("bech32").expect("failed to parse hrp");

    let encoded = bech32::encode::<Bech32m>(hrp, &data).expect("failed to encode");
    test(encoded == "bech321qqqsyktsg0l".to_string());

    hprintln!("{}", encoded).unwrap();

    let (got_hrp, got_data) = bech32::decode(&encoded).expect("failed to decode");

    test(got_hrp == hrp);
    test(&got_data == &data);

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
