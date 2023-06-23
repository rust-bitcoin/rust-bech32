//! Test `no_std` build of `bech32`.
//!
//! Build with: `cargo rustc -- -C link-arg=-nostartfiles`.
//!

#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use panic_halt as _;

use arrayvec::{ArrayString, ArrayVec};
use bech32::{self, u5, ComboError, Variant, Hrp};
use bech32::primitives::iter::{Fe32IterExt, ByteIterExt};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

// Note: `#[global_allocator]` is NOT set.

#[entry]
fn main() -> ! {
    let mut encoded = ArrayString::<30>::new();

    let base32 = [0x00u8, 0x01, 0x02].iter().copied().bytes_to_fes().collect::<ArrayVec<u5, 30>>();

    let hrp = Hrp::parse("bech32").unwrap();

    bech32::encode_to_fmt(&mut encoded, &hrp, base32, Variant::Bech32).unwrap();
    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let mut decoded = ArrayVec::<u5, 30>::new();

    let mut scratch = ArrayVec::<u5, 30>::new();

    let (got_hrp, data, variant) =
        bech32::decode_lowercase::<ComboError, _, _>(&encoded, &mut decoded, &mut scratch).unwrap();
    test(got_hrp == hrp);

    let res = data.iter().copied().fes_to_bytes().collect::<ArrayVec<u8, 30>>();

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
