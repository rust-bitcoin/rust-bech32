// BIP-350 test vectors.

#![cfg(feature = "alloc")]

use bech32::primitives::hrpstring::Parsed;
use bech32::segwit::{Bech32, Bech32m};

macro_rules! check_valid_bech32m {
    ($($test_name:ident, $s:literal);* $(;)?) => {
        $(
            #[test]
            fn $test_name() {
                let valid_bech32m = $s;
                let hrps = Parsed::new(valid_bech32m).unwrap();

                assert!(hrps.validate_checksum::<Bech32m>().is_ok());
                // Valid bech32m strings are by definition invalid bech32.
                assert!(hrps.validate_checksum::<Bech32>().is_err());

                // data_iter only checks the checksum length so both checksum algos work.
                let data_iter = hrps.data_iter::<Bech32>().unwrap();
                data_iter.count(); // consume whole iterator
                let data_iter = hrps.data_iter::<Bech32m>().unwrap();
                data_iter.count(); // consume whole iterator
            }
        )*
    }
}
check_valid_bech32m! {
        valid_bech32m_hrp_string_0, "A1LQFN3A";
        valid_bech32m_hrp_string_1, "a1lqfn3a";
        valid_bech32m_hrp_string_2, "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6";
        valid_bech32m_hrp_string_3, "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx";
        valid_bech32m_hrp_string_4, "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8";
        valid_bech32m_hrp_string_5, "split1checkupstagehandshakeupstreamerranterredcaperredlc445v";
        valid_bech32m_hrp_string_6, "?1v759aa";
}

macro_rules! check_valid_address_roundtrip {
    ($($test_name:ident, $addr:literal, $hrp:ident);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                use bech32::primitives::hrp::KnownHrp::*;

                bech32::segwit::verify($addr).expect("verify_any failed");

                // The test vectors include both bech32 and bech32m checksummed addresses so we
                // check both and roundtrip using the "force" function to encode using the correct
                // checksum algo.

                match bech32::segwit::decode_bech32m($addr) {
                    Ok((hrp, witver, data)) => {
                        assert_eq!(hrp, $hrp);

                        // BIP-350: No string can be simultaneously valid Bech32 and Bech32m.
                        assert!(bech32::segwit::decode_bech32($addr).is_err());

                        let encoded = bech32::segwit::encode_force_bech32m($hrp, witver, &data);
                        if encoded != $addr {
                            let got = encoded.to_uppercase();
                            assert_eq!(got, $addr)
                        }
                    },
                    Err(_) => {
                        let (hrp, witver, data) = bech32::segwit::decode_bech32($addr).expect("decode_bech32 failed");
                        assert_eq!(hrp, $hrp);

                        let encoded = bech32::segwit::encode_force_bech32($hrp, witver, &data);
                        if encoded != $addr {
                            let got = encoded.to_uppercase();
                            assert_eq!(got, $addr)
                        }
                    }
                }
            }
        )*
    }
}
// Note these test vectors include various witness versions.
check_valid_address_roundtrip! {
    bip_350_valid_address_roundtrip_0, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", Bitcoin;
    bip_350_valid_address_roundtrip_1, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", Testnet;
    bip_350_valid_address_roundtrip_2, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", Bitcoin;
    bip_350_valid_address_roundtrip_3, "BC1SW50QGDZ25J", Bitcoin;
    bip_350_valid_address_roundtrip_4, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", Bitcoin;
    bip_350_valid_address_roundtrip_5, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", Testnet;
    bip_350_valid_address_roundtrip_6, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", Testnet;
    bip_350_valid_address_roundtrip_7, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", Bitcoin;
}

macro_rules! check_invalid_address {
    ($($test_name:ident, $addr:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert!(bech32::segwit::decode_bech32m($addr).is_err(), "validation should fail for: {}", $addr);
            }
        )*
    }
}
check_invalid_address! {
    // Invalid human-readable part
    bip_350_invalid_address_0, "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut";
    // Invalid checksums (Bech32 instead of Bech32m):
    bip_350_invalid_address_1, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd";
    bip_350_invalid_address_2, "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf";
    bip_350_invalid_address_3, "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL";
    bip_350_invalid_address_4, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh";
    bip_350_invalid_address_5, "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47";
    // Invalid character in checksum
    bip_350_invalid_address_6, "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4";
    // Invalid witness version
    bip_350_invalid_address_7, "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R";
    // Invalid program length (1 byte)
    bip_350_invalid_address_8, "bc1pw5dgrnzv";
    // Invalid program length (41 bytes)
    bip_350_invalid_address_9, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav";
    // Invalid program length for witness version 0 (per BIP-141)
    bip_350_invalid_address_10, "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P";
    // Mixed case
    bip_350_invalid_address_11, "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq";
    // zero padding of more than 4 bits
    bip_350_invalid_address_12, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf";
    // Non-zero padding in 8-to-5 conversion
    // TODO: Un-comment this test and make it pass.
    // bip_350_invalid_address_13, "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j";
    // Empty data section
    bip_350_invalid_address_14, "bc1gmk9yu";
}

#[test]
fn bip_350_invalid_hrpstring() {
    use bech32::primitives::hrp::Error as HrpError;
    use bech32::primitives::hrpstring::Error;
    use bech32::primitives::hrpstring::Error::*;

    let invalid: Vec<(&str, Error)> = vec!(
        // 0x20 + 1xj0phk: HRP character out of range
        ("\u{20}1xj0phk",       // space: u{20} encodes as a single byte.
         InvalidHrp(HrpError::InvalidAsciiByte(0x20))),
        // 0x7F + 1g6xzxy: HRP character out of range
        ("\u{7F}1g6xzxy",       // delete: u{7F} encodes as a single byte.
         InvalidHrp(HrpError::InvalidAsciiByte(0x7F))),
        //
        // 0x80 + 1vctc34: HRP character out of range
        // This test vector is prevented by the Rust type system because we accept `&str` which is
        // made up of utf-8 characters, 0x80 is not a valid utf-8 character.
        //
        ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
         InvalidHrp(HrpError::TooLong(84))),
        ("qyrz8wqd2c9m",
         MissingSeparator),
        ("1qyrz8wqd2c9m",
         InvalidHrp(HrpError::Empty)),
        ("y1b0jsk6g",
         InvalidBech32Char('b')),
        ("in1muywd",
         Error::InvalidChecksumLength),
        ("mm1crxm3i",
         InvalidBech32Char('i')),
        ("au1s5cgom",
         InvalidBech32Char('o')),
        // FIXME: Is this error return acceptable for the BIP?
        // M1VUXWEZ: checksum calculated with uppercase form of HRP
        ("M1VUXWEZ",
         InvalidChecksum),
        ("1qzzfhee",
         InvalidHrp(HrpError::Empty)),
        ("1p2gdwpf",
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
