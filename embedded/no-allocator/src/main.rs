//! Test `no_std` build of `bech32` without an allocator.
//!
//! Build with: `cargo +nightly rustc -- -C link-arg=-nostartfiles`.

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use arrayvec::{ArrayString, ArrayVec};
use bech32::{u5, ByteIterExt, Hrp, Variant};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

// Note: `#[global_allocator]` is NOT set.

#[entry]
fn main() -> ! {
    let hrp = Hrp::parse("bech32").unwrap();
    let data_iter = [0x00u8, 0x01, 0x02].iter().copied().bytes_to_fes();

    let data = data_iter.collect::<ArrayVec<u5, 30>>();
    let mut encoded = ArrayString::<30>::new();
    bech32::encode_to_fmt(&mut encoded, hrp, data, Variant::Bech32).unwrap();

    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let (parsed, variant) = bech32::decode(&encoded).expect("failed to decode");

    test(variant == Variant::Bech32);
    test(parsed.hrp() == hrp);
    let data = parsed.byte_iter().collect::<ArrayVec<u8, 30>>();
    test(&data == [0x00, 0x01, 0x02].as_ref());

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}
