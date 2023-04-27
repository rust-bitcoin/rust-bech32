// Tests the API surface of the hrpstring module (when combined with the bip test vectors tests).

#![cfg(feature = "alloc")]

mod common;

use bech32::primitives::hrp::KnownHrp;
use bech32::primitives::hrpstring::Parsed;
use bech32::segwit::{Bech32, WitnessVersion};

#[test]
fn getters() {
    let (hrp_string, witver) = Parsed::new_with_witness_version("BC1SW50QA3JX3S").unwrap();
    assert_eq!(hrp_string.segwit_known_hrp().expect("bc"), KnownHrp::Bitcoin);
    assert_eq!(witver, WitnessVersion::V16);
    assert_eq!(hrp_string.witness_version().unwrap().to_num(), 16);
    common::check_iter_eq(hrp_string.data_iter::<Bech32>().unwrap(), [0x75, 0x1e].iter().copied());
}

#[test]
fn address() {
    let addr = "bc1qadx88l6juc3lhuz3dvw7frmxujxzv0ralj2y20yq6gurguqyyxxsfq5jv3";
    let (hrp, witver, data) = bech32::segwit::decode_bech32(addr).expect("valid address");
    assert_eq!(hrp, KnownHrp::Bitcoin);
    assert_eq!(witver, WitnessVersion::V0);
    assert_eq!(bech32::segwit::encode(hrp, witver, &data), addr);
}
