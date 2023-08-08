//! Test `no_std` build of `bech32`.
//!
//! Build with: `cargo +nightly rustc -- -C link-arg=-nostartfiles`.
//!

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use arrayvec::{ArrayString, ArrayVec};
use bech32::{self, u5, Hrp, Variant, ByteIterExt, Bech32};
use bech32::primitives::decode::CheckedHrpstring;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_halt as _;

// Note: `#[global_allocator]` is NOT set.

#[entry]
fn main() -> ! {
    let mut encoded = ArrayString::<30>::new();

    let base32 = [0x00u8, 0x01, 0x02].iter().copied().bytes_to_fes().collect::<ArrayVec<u5, 30>>();

    let hrp = Hrp::parse("bech32").unwrap();

    bech32::encode_to_fmt_anycase(&mut encoded, hrp, &base32, Variant::Bech32).unwrap().unwrap();
    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let unchecked = CheckedHrpstring::new::<Bech32>(&encoded).unwrap();

    test(unchecked.hrp() == hrp);
    let res = unchecked.byte_iter().collect::<ArrayVec<u8, 30>>();
    test(&res == [0x00, 0x01, 0x02].as_ref());

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}
