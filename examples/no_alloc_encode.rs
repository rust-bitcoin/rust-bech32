//! Shows how to decode and encode a Bitcoin address without an allocator.

use core::iter::FusedIterator;

use bech32::primitives::hrp::Hrp;
use bech32::primitives::hrpstring::Parsed;
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bech32::segwit::{Bech32, Bech32m, KnownHrp, WitnessVersion};

pub fn main() -> Result<(), bech32::segwit::Error> {
    let addr = "bc1qadx88l6juc3lhuz3dvw7frmxujxzv0ralj2y20yq6gurguqyyxxsfq5jv3";
    let (hrp_string, witness_version) = Parsed::new_with_witness_version(addr)?;
    hrp_string.validate_checksum::<Bech32>()?;
    let decoded_iter = hrp_string.data_iter::<Bech32>()?;

    assert_eq!(witness_version, WitnessVersion::V0);
    let _encoded_iter =
        encode_bech32(hrp_string.segwit_known_hrp().expect("bc is valid"), decoded_iter);

    Ok(())
}

/// Encodes hrp and data into a Bitcoin address using the bech32 checksum algorithm i.e.,
/// a segwit v0 address.
///
/// # Returns
///
/// An iterator over the characters of the address - this means no allocation is required.
pub fn encode_bech32<'d, I>(hrp: KnownHrp, data: I) -> impl Iterator<Item = char>
where
    I: ExactSizeIterator + FusedIterator + Iterator<Item = u8> + 'd,
{
    let hrp = Hrp::from(hrp);

    data.bytes_to_fes() // convert bytes to field elements in-line
        .with_witness_version(WitnessVersion::V0)
        .checksum::<Bech32>()
        .with_checksummed_hrp(hrp)
        .hrp_char(hrp)
}

/// Encodes hrp, witness_version, and data into a Bitcoin address using the bech32m checksum algorithm.
///
/// # Returns
///
/// An iterator over the characters of the address - this means no allocation is required.
pub fn encode_bech32m<'d, I>(
    hrp: KnownHrp,
    witness_version: WitnessVersion,
    data: I,
) -> impl Iterator<Item = char>
where
    I: ExactSizeIterator + FusedIterator + Iterator<Item = u8> + 'd,
{
    let hrp = Hrp::from(hrp);

    data.bytes_to_fes() // convert bytes to field elements in-line
        .with_witness_version(witness_version)
        .checksum::<Bech32m>()
        .with_checksummed_hrp(hrp)
        .hrp_char(hrp)
}
