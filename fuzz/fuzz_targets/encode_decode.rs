use std::str;

use bech32::{Bech32m, Hrp};
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let hrp_end = (data[0] as usize) + 1;

    if data.len() < hrp_end {
        return;
    }

    let dp = &data[hrp_end..];

    let Ok(s) = str::from_utf8(&data[1..hrp_end]) else { return };
    let Ok(hrp) = Hrp::parse(s) else { return };
    let Ok(address) = bech32::encode::<Bech32m>(hrp, dp) else { return };

    let (hrp, data) = bech32::decode(&address).expect("should be able to decode own encoding");
    assert_eq!(bech32::encode::<Bech32m>(hrp, &data).unwrap(), address);
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
        extend_vec_from_hex("ff6c2d", &mut a);
        super::do_test(&a);
    }
}
