use bech32::primitives::decode::{CheckedHrpstring, SegwitHrpstring, UncheckedHrpstring};
use bech32::Bech32m;
use honggfuzz::fuzz;

// Checks that we do not crash if passed random data while decoding.
fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let _ = UncheckedHrpstring::new(&data_str);
    let _ = CheckedHrpstring::new::<Bech32m>(&data_str);
    let _ = SegwitHrpstring::new(&data_str);
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
