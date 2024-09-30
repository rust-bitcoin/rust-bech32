use bech32::primitives::LfsrIter;
use bech32::Fe32;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    for ch in data {
        if *ch >= 32 {
            return;
        }
    }
    if data.is_empty() || data.len() > 1_000 {
        return;
    }

    let mut iv = Vec::with_capacity(data.len());
    for ch in data {
        iv.push(Fe32::try_from(*ch).unwrap());
    }

    for (i, d) in LfsrIter::berlekamp_massey(&iv).take(data.len()).enumerate() {
        assert_eq!(data[i], d.to_u8());
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
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
