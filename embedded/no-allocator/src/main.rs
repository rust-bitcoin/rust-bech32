//! Test `no_std` build of `bech32`.
//!
//! Build with: `cargo rustc -- -C link-arg=-nostartfiles`.
//!

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use panic_halt as _;

use arrayvec::{ArrayString, ArrayVec};
use bech32::{self, u5, ComboError, FromBase32, ToBase32, Variant, Hrp};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

// Note: `#[global_allocator]` is NOT set.

#[entry]
fn main() -> ! {
    let mut encoded = ArrayString::<30>::new();

    let mut base32 = ArrayVec::<u5, 30>::new();

    [0x00u8, 0x01, 0x02].write_base32(&mut base32).unwrap();

    let hrp = Hrp::parse("bech32").unwrap();

    bech32::encode_to_fmt(&mut encoded, hrp, &base32, Variant::Bech32)
        .unwrap()
        .unwrap();
    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let mut decoded = ArrayVec::<u5, 30>::new();

    let mut scratch = ArrayVec::<u5, 30>::new();

    let (got_hrp, data, variant) =
        bech32::decode_lowercase::<ComboError, _, _>(&encoded, &mut decoded, &mut scratch).unwrap();
    test(got_hrp == hrp);
    let res = ArrayVec::<u8, 30>::from_base32(&data).unwrap();
    test(&res == [0x00, 0x01, 0x02].as_ref());
    test(variant == Variant::Bech32);

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}
