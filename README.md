# Bech32 Rust

Rust implementation of the Bech32 encoding format described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).

Bitcoin-specific address encoding is handled by the `bitcoin-bech32` crate.

## Example
```rust
use bech32::Bech32;

let b = Bech32::new("bech32".into(), vec![0x00, 0x01, 0x02]).unwrap();
let encoded = b.to_string();
assert_eq!(encoded, "bech321qpz4nc4pe".to_string());

let c = encoded.parse::<Bech32>();
assert_eq!(b, c.unwrap());
```
