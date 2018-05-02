# Bech32 Rust

Rust implementation of the Bech32 encoding format described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).

Bitcoin-specific address encoding is handled by the `bitcoin-bech32` crate.

## Examples
```rust
use bech32::Bech32;

let b = Bech32::new_check_data("bech32".into(), vec![0x00, 0x01, 0x02]).unwrap();
let encoded = b.to_string();
assert_eq!(encoded, "bech321qpz4nc4pe".to_string());

let c = encoded.parse::<Bech32>();
assert_eq!(b, c.unwrap());
```

If the data is already range-checked the `Bech32::new` function can be used which will never
return `Err(Error::InvalidData)`.

```rust
use bech32::{Bech32, u5, ToBase32};

// converts base256 data to base32 and adds padding if needed
let checked_data: Vec<u5> = [0xb4, 0xff, 0xa5].to_base32();

let b = Bech32::new("bech32".into(), checked_data).expect("hrp is not empty");
let encoded = b.to_string();

assert_eq!(encoded, "bech321knl623tk6v7".to_string());
```