extern crate bech32;

use bech32::Fe32;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let decoded = bech32::decode(&data_str);
    let (parsed, variant) = match decoded {
        Ok((parsed, variant)) => (parsed, variant),
        Err(_) => return,
    };

    let hrp = parsed.hrp();
    let data = parsed.fe32_iter().collect::<Vec<Fe32>>();

    assert_eq!(bech32::encode(hrp, data, variant).expect("failed to encode"), data_str);
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
        for (idx, c) in hex.as_bytes().iter().enumerate() {
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
        extend_vec_from_hex("00000000", &mut a);
        super::do_test(&a);
    }
}
