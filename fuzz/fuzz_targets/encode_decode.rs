extern crate bech32;

use std::convert::TryFrom;
use std::str;

use bech32::{Fe32, Hrp};

fn do_test(data: &[u8]) {
    if data.len() < 1 {
        return;
    }

    let hrp_end = (data[0] as usize) + 1;

    if data.len() < hrp_end {
        return;
    }

    let dp = data[hrp_end..]
        .iter()
        .map(|b| bech32::u5::try_from(b % 32).unwrap())
        .collect::<Vec<_>>();

    let variant = if data[0] > 0x0f {
        bech32::Variant::Bech32m
    } else {
        bech32::Variant::Bech32
    };

    match str::from_utf8(&data[1..hrp_end]) {
        Err(_) => return,
        Ok(s) => {
            match Hrp::parse(&s) {
                Err(_) => return,
                Ok(hrp) => {
                    let encoded = bech32::encode(hrp, &dp, variant).expect("failed to encode");
                    let (parsed, variant) = bech32::decode(&encoded).expect("failed to decode");

                    let hrp = parsed.hrp();
                    let data = parsed.fe32_iter().collect::<Vec<Fe32>>();

                    assert_eq!(bech32::encode(hrp, data, variant).expect("failed to encode"), encoded);
                }
            }
        }
    }
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    afl::read_stdio_bytes(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use]
extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
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
                b'A'...b'F' => b |= c - b'A' + 10,
                b'a'...b'f' => b |= c - b'a' + 10,
                b'0'...b'9' => b |= c - b'0',
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
