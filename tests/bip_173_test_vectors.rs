// BIP-173 test vectors.

#![cfg(feature = "alloc")]

use bech32::primitives::hrpstring::Parsed;
use bech32::segwit::{Bech32, Bech32m};

macro_rules! check_valid_bech32 {
    ($($test_name:ident, $s:literal);* $(;)?) => {
        $(
            #[test]
            fn $test_name() {
                let valid_bech32 = $s;
                let hrps = Parsed::new(valid_bech32).unwrap();

                assert!(hrps.validate_checksum::<Bech32>().is_ok());
                // Valid bech32 strings are by definition invalid bech32m.
                assert!(hrps.validate_checksum::<Bech32m>().is_err());

                // data_iter only checks the checksum length so both checksum algos work.
                let data_iter = hrps.data_iter::<Bech32>().unwrap();
                data_iter.count(); // consume whole iterator
                let data_iter = hrps.data_iter::<Bech32m>().unwrap();
                data_iter.count(); // consume whole iterator
            }
        )*
    }
}
check_valid_bech32! {
    valid_bech32_hrp_string_0, "A12UEL5L";
    valid_bech32_hrp_string_1, "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs";
    valid_bech32_hrp_string_2, "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
    valid_bech32_hrp_string_3, "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j";
    valid_bech32_hrp_string_4, "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w";
}

// This is a separate test because we correctly identify this string as invalid but not for the
// reason given in the bip.
#[test]
fn bip_173_checksum_calculated_with_uppercase_form() {
    // BIP-173 states reason for error should be: "checksum calculated with uppercase form of HRP".
    let s = "A1G7SGD8";
    let p = Parsed::new(s).unwrap();
    assert!(p.validate_checksum::<Bech32>().is_err())
}

macro_rules! check_valid_address_roundtrip {
    ($($test_name:ident, $addr:literal, $hrp:ident);* $(;)?) => {
        $(
            #[test]
            fn $test_name() {
                use bech32::primitives::hrp::KnownHrp::*;

                bech32::segwit::verify($addr).expect("verify_any failed");

                // Test that valid address string uses a bech32 checksum and roundtrips.

                let (hrp, witver, data) = bech32::segwit::decode_bech32($addr).expect("failed to decode_bech32");
                assert_eq!(hrp, $hrp);

                // We cannot use `bech32::encode` here because these strings are explicitly using
                // bech32 for non-zero witness version.
                let encoded = bech32::segwit::encode_force_bech32($hrp, witver, &data);
                if encoded != $addr {
                    let got = encoded.to_uppercase();
                    assert_eq!(got, $addr)
                }
            }
        )*
    }
}
// Note these test vectors include various witness versions.
check_valid_address_roundtrip! {
    bip_173_valid_address_roundtrip_0, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", Bitcoin;
    bip_173_valid_address_roundtrip_1, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", Testnet;
    bip_173_valid_address_roundtrip_2, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", Bitcoin;
    bip_173_valid_address_roundtrip_3, "BC1SW50QA3JX3S", Bitcoin;
    bip_173_valid_address_roundtrip_4, "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", Bitcoin;
    bip_173_valid_address_roundtrip_5, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", Testnet;
}

macro_rules! check_invalid_address {
    ($($test_name:ident, $addr:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert!(bech32::segwit::decode_bech32($addr).is_err(), "validation should fail for: {}", $addr);
            }
        )*
    }
}
check_invalid_address! {
    // Invalid human-readable part
    bip_173_invalid_address_0, "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty";
    // Invalid checksum
    bip_173_invalid_address_1, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
    // Invalid witness version
    bip_173_invalid_address_2, "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2";
    // Invalid program length
    bip_173_invalid_address_3, "bc1rw5uspcuh";
    // Invalid program length
    bip_173_invalid_address_4, "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90";
    // Invalid program length for witness version 0 (per BIP-141)
    bip_173_invalid_address_5, "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P";
    // Mixed case
    bip_173_invalid_address_6, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7";
    // zero padding of more than 4 bits
    bip_173_invalid_address_7, "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du";
    // Non-zero padding in 8-to-5 conversion
    // TODO: Un-comment this test and make it pass.
    // bip_173_invalid_address_8, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv";
}

#[test]
fn bip_173_invalid_hrpstring() {
    use bech32::primitives::hrp::Error as HrpError;
    use bech32::primitives::hrpstring::Error;
    use bech32::primitives::hrpstring::Error::*;

    let invalid: Vec<(&str, Error)> = vec!(
        // 0x20 + 1nwldj5: HRP character out of range
        ("\u{20}1nwldj5",       // space: u{20} encodes as a single byte.
         InvalidHrp(HrpError::InvalidAsciiByte(0x20))),
        // 0x7F + 1axkwrx: HRP character out of range
        ("\u{7F}1axkwrx",       // delete: u{7F} encodes as a single byte.
         InvalidHrp(HrpError::InvalidAsciiByte(0x7F))),
        //
        // 0x80 + 1eym55h: HRP character out of range
        // This test vector is prevented by the Rust type system because we accept `&str` which is
        // made up of utf-8 characters, 0x80 is not a valid utf-8 character.
        //
        ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
         InvalidHrp(HrpError::TooLong(84))),
        ("pzry9x0s0muk",
         MissingSeparator),
        ("1pzry9x0s0muk",
         InvalidHrp(HrpError::Empty)),
        ("x1b4n0q5v",
         InvalidBech32Char('b')),
        ("li1dgmt3",
         InvalidChecksumLength),
        ("de1lg7wt\u{ff}",
         InvalidBech32Char('\u{ff}')),
        ("10a06t8",
         Error::InvalidHrp(HrpError::Empty)),
        ("1qzzfhee",
         InvalidHrp(HrpError::Empty)),
    );

    for (s, expected_error) in invalid {
        match Parsed::new(s) {
            Err(e) => assert_eq!(e, expected_error),
            Ok(hrpstring) =>
                assert_eq!(hrpstring.validate_checksum::<Bech32m>().unwrap_err(), expected_error),
        }
    }
}
