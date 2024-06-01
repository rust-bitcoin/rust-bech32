//! Demonstrate output from the various crate errors.

#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use std::error::Error;

use bech32::{Fe32, Hrp};

fn main() {
    crate_decode();
    // crate::encode only returns `fmt::Error` errors.

    crate_segwit_decode();
    crate_segwit_encode();

    // TODO: Do the other primitives modules.
    primitives_hrp();
}

/// Demonstrates `bech32::decode` errors.
fn crate_decode() {
    use bech32::decode;
    let function = "bech32::decode";

    // The arguments to pass to `function`.
    let strings = vec!["1qqq", "hrp1abc"];

    for s in strings {
        let err = decode(s).unwrap_err();
        println!("\n\n* Call `{}(\"{}\")` -> {:?}", function, s, err);
        println!("\n------------");
        print_source(&err);
        println!("------------");
    }
}

/// Demonstrates the `Hrp::Error` variants.
fn primitives_hrp() {
    use bech32::primitives::hrp::Error::*;

    println!("\n\n* All errors when parsing an invalid HRP");
    let errs = vec![TooLong(99), Empty, NonAsciiChar('\u{e9}'), InvalidAsciiByte(200), MixedCase];
    println!("\n------------");

    let last = errs.len() - 1;
    for (i, e) in errs.iter().enumerate() {
        println!("Debug: {:?}\nError: {}", e.clone(), e);
        if i != last {
            println!();
        }
    }
    println!("------------");
}

// TODO: Generate address strings to trigger:
// - Padding(PaddingError)
// - WitnessLength(WitnessLengthError)
/// Demonstrates `bech32::segwit::decode` errors.
fn crate_segwit_decode() {
    use bech32::segwit::decode;
    let function = "bech32::segwit::decode";

    // The arguments to pass to `function`.
    let strings = vec!["1qpppppp", "bc1qabc", "bc1", "bc1mpppppp", "bc1qppppp"];

    for s in strings {
        let err = decode(s).unwrap_err();
        println!("\n\n* Call `{}(\"{}\")` -> {:?}", function, s, err);
        println!("\n------------");
        print_source(&err);
        println!("------------");
    }
}

/// Demonstrates `bech32::segwit::encode` errors.
fn crate_segwit_encode() {
    use bech32::segwit::encode;
    let function = "bech32::segwit::encode";

    // The arguments to pass to `function`.
    let hrp = Hrp::parse("bc").expect("a valid HRP string");

    let invalid_witness_version = Fe32::M;

    let valid_witness_program_segwit_v1 = [0x00, 0x01];
    let invalid_witness_program_too_short = [0x00];
    let invalid_witness_program_too_long = [0x00; 50];

    let print = |err| {
        println!("\n\n* Call `{}({}, [])` -> {:?}", function, hrp, err);
        println!("\n------------");
        print_source(&err);
        println!("------------");
    };

    let err = encode(hrp, invalid_witness_version, &valid_witness_program_segwit_v1).unwrap_err();
    print(err);

    let err = encode(hrp, Fe32::P, &invalid_witness_program_too_short).unwrap_err();
    print(err);

    let err = encode(hrp, Fe32::P, &invalid_witness_program_too_long).unwrap_err();
    print(err);

    let err = encode(hrp, Fe32::Q, &valid_witness_program_segwit_v1).unwrap_err();
    print(err);
}

/// Prints `e` in a similar fashion to the output created by `anyhow`.
#[cfg(feature = "std")]
fn print_source(mut e: &dyn Error) {
    println!("Error: {}", e);

    if e.source().is_some() {
        let mut counter = 0;
        println!("\nCaused by: ");

        while e.source().is_some() {
            let inner = e.source().unwrap();
            println!("\t{}: {}", counter, inner);
            e = e.source().unwrap();
            counter += 1;
        }
    }
}

#[cfg(not(feature = "std"))]
fn print_source(e: &dyn fmt::Display) { println!("{}", e) }
