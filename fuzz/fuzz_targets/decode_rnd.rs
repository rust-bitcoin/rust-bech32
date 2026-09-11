use bech32::primitives::decode::{CheckedHrpstring, SegwitHrpstring, UncheckedHrpstring};
use bech32::{Bech32, Bech32m, Checksum, CorrectableError};
use honggfuzz::fuzz;

// Checks that we do not crash if passed random data while decoding.
fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let _ = UncheckedHrpstring::new(&data_str);
    check_correction::<Bech32>(&data_str);
    check_correction::<Bech32m>(&data_str);
    let _ = SegwitHrpstring::new(&data_str);
}

fn check_correction<Ck: Checksum>(s: &str) {
    if let Err(err) = CheckedHrpstring::new::<Ck>(s) {
        if let Some(ctx) = err.correction_context::<Ck>() {
            if let Some(iter) = ctx.bch_errors() {
                for _ in iter {}
            }
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
    #[test]
    fn issue_290() {
        super::do_test(b"cbbc1yuglpryqdm");
        super::do_test(b"aa1aagz20up2hk8e");
    }

    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
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
        extend_vec_from_hex("39313131", &mut a);
        super::do_test(&a);
    }
}
