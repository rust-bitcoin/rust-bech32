//! Test `no_std` build of `bech32`.
//!
//! Build with: `cargo +nightly rustc -- -C link-arg=-nostartfiles`.
//!

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use arrayvec::ArrayString;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

// Note: `#[global_allocator]` is NOT set.

#[entry]
fn main() -> ! {
    let mut encoded = ArrayString::<30>::new();

    let data = [0x00u8, 0x01, 0x02];
    let hrp = Hrp::parse("bech32").expect("failed to parse hrp");

    bech32::encode_to_fmt::<Bech32, _>(&mut encoded, hrp, &data)
        .expect("failed to encode");
    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let unchecked =
        CheckedHrpstring::new::<Bech32>(&encoded).expect("failed to construct CheckedHrpstring");
    let iter = unchecked.byte_iter();

    test(unchecked.hrp() == hrp);
    test(iter.eq(data.iter().map(|&b| b)));

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}
