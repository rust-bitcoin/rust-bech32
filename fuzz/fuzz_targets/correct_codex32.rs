use std::collections::HashMap;

use bech32::primitives::correction::CorrectableError as _;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Checksum, Fe1024, Fe32};
use honggfuzz::fuzz;

/// The codex32 checksum algorithm, defined in BIP-93.
///
/// Used in this fuzztest because it can correct up to 4 errors, vs bech32 which
/// can correct only 1. Should exhibit more interesting behavior.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Codex32 {}

impl Checksum for Codex32 {
    type MidstateRepr = u128;
    type CorrectionField = Fe1024;
    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::_9, Fe32::_9]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 9..=16;

    const CHECKSUM_LENGTH: usize = 13;
    const CODE_LENGTH: usize = 93;
    // Copied from BIP-93
    const GENERATOR_SH: [u128; 5] = [
        0x19dc500ce73fde210,
        0x1bfae00def77fe529,
        0x1fbd920fffe7bee52,
        0x1739640bdeee3fdad,
        0x07729a039cfc75f5a,
    ];
    const TARGET_RESIDUE: u128 = 0x10ce0795c2fd1e62a;
}

static CORRECT: &[u8; 48] = b"ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw";

fn do_test(data: &[u8]) {
    if data.is_empty() || data.len() % 2 == 1 {
        return;
    }

    let mut any_actual_errors = false;
    let mut e2t = 0;
    let mut erasures = Vec::with_capacity(CORRECT.len());
    // Start with a correct string
    let mut hrpstring = *CORRECT;
    // ..then mangle it
    let mut errors = HashMap::with_capacity(data.len() / 2);
    for sl in data.chunks_exact(2) {
        let idx = usize::from(sl[0]) & 0x7f;
        if idx >= CORRECT.len() - 3 {
            return;
        }
        let offs = match Fe32::try_from(sl[1]) {
            Ok(fe) => fe,
            Err(_) => return,
        };

        hrpstring[idx + 3] =
            (Fe32::from_char(hrpstring[idx + 3].into()).unwrap() + offs).to_char() as u8;

        if errors.insert(CORRECT.len() - (idx + 3) - 1, offs).is_some() {
            return;
        }
        if sl[0] & 0x80 == 0x80 {
            // We might push "dummy" errors which are erasures that aren't actually wrong.
            // If we do this too many times, we'll exceed the singleton bound so correction
            // will fail, but as long as we're within the bound everything should "work",
            // in the sense that there will be no crashes and the error corrector will
            // just yield an error with value Q.
            erasures.push(CORRECT.len() - (idx + 3) - 1);
            e2t += 1;
            if offs != Fe32::Q {
                any_actual_errors = true;
            }
        } else if offs != Fe32::Q {
            any_actual_errors = true;
            e2t += 2;
        }
    }
    // We need _some_ errors.
    if !any_actual_errors {
        return;
    }

    let s = unsafe { core::str::from_utf8_unchecked(&hrpstring) };
    let mut correct_ctx = CheckedHrpstring::new::<Codex32>(s)
        .unwrap_err()
        .correction_context::<Codex32>()
        .unwrap();

    correct_ctx.add_erasures(&erasures);

    let iter = correct_ctx.bch_errors();
    if e2t <= 8 {
        for (idx, fe) in iter.unwrap() {
            assert_eq!(errors.remove(&idx), Some(fe));
        }
        for val in errors.values() {
            assert_eq!(*val, Fe32::Q);
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().filter(|&&c| c != b'\n').enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("8c00a10091039e0185008000831f8e0f", &mut a);
        super::do_test(&a);
    }
}
