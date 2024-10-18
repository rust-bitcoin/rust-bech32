use std::collections::HashMap;

use bech32::primitives::correction::CorrectableError as _;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Fe32};
use honggfuzz::fuzz;

// coinbase output of block 862290
static CORRECT: &[u8; 62] = b"bc1qwzrryqr3ja8w7hnja2spmkgfdcgvqwp5swz4af4ngsjecfz0w0pqud7k38";

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
    let mut correct_ctx = CheckedHrpstring::new::<Bech32>(s)
        .unwrap_err()
        .correction_context::<Bech32>()
        .unwrap();

    correct_ctx.add_erasures(&erasures);

    let iter = correct_ctx.bch_errors();
    if e2t <= 3 {
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
        extend_vec_from_hex("04010008", &mut a);
        super::do_test(&a);
    }
}
