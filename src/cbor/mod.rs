//! Helpful functionality around the `serde_cbor` crate.

use alloc::vec::Vec;
use serde::Serialize;

#[cfg_attr(tarpaulin, skip)]
mod error;
pub use error::CborError;

/// The result type for the `cbor` module.
pub type Result<T> = core::result::Result<T, CborError>;

/// Serializes an object into CBOR.
pub fn encode(object: impl Serialize) -> Result<Vec<u8>> {
    serialize(object, 0)
}

/// Serializes an object into a sequence of CBOR encoded data items.
///
/// Only works for objects that serialize to a CBOR array of at most 23 items.
pub fn encode_sequence(object: impl Serialize) -> Result<Vec<u8>> {
    // We serialize something that encodes as a CBOR array.
    // What we want is just the sequence of items, so we can omit the
    // first byte (indicating array type and length), and get the items.
    // That only works as long as we have at most 23 items, after that it
    // takes an additional byte to indicate the length.
    serialize(object, 1)
}

/// Serializes an object, returning its bytes from an offset.
fn serialize(object: impl Serialize, offset: usize) -> Result<Vec<u8>> {
    // Serialize to byte vector
    let mut v = serde_cbor::to_vec(&object)?;
    // Return everything starting from the offset
    Ok(v.drain(offset..).collect())
}

/// Deserializes a CBOR encoded object.
pub fn decode<'a, T>(bytes: &'a [u8]) -> Result<T>
where
    T: serde::Deserialize<'a>,
{
    Ok(serde_cbor::from_slice(bytes)?)
}

/// Deserializes a sequence of CBOR encoded data items into an object.
///
/// Requires a `Vec<u8>` of length `bytes` + 1 to use as a buffer and only
/// works for sequences of at most 23 items.
///
/// # Arguments
/// * `bytes` - The sequence of CBOR items.
/// * `n_items` - The number of items.
/// * `tmp_vec` - Buffer used for deserialization.
pub fn decode_sequence<'a, T>(
    bytes: &[u8],
    n_items: usize,
    tmp_vec: &'a mut Vec<u8>,
) -> Result<T>
where
    T: serde::Deserialize<'a>,
{
    // We receive a sequence of CBOR items. For parsing we need an array, so
    // start a CBOR array of the given length.
    tmp_vec.push(array_byte(n_items)?);
    // After the start byte, insert the message (sequence of CBOR items)
    tmp_vec.extend(bytes);

    // Now we can try to deserialize that
    Ok(serde_cbor::from_slice(tmp_vec)?)
}

/// Changes the given CBOR bytes from an array of n elements to a map of n / 2
/// key/value pairs.
///
/// Only works for arrays with at most 23 items.
pub fn array_to_map(bytes: &mut [u8]) -> Result<()> {
    // The 5 least significant bits are the number of elements in the array
    let n = 0b000_11111 & bytes[0];
    match n {
        _ if n > 23 => Err(CborError::TooManyItems),
        n => {
            // Change the major type and number of elements accordingly
            bytes[0] = 0b101_00000 | (n / 2);
            Ok(())
        }
    }
}

/// Changes the given CBOR bytes from a map of n key/value pairs to an array
/// of n * 2 items.
///
/// Only works for arrays with at most 23 items.
#[allow(dead_code)]
pub fn map_to_array(bytes: &mut [u8]) -> Result<()> {
    // The 5 least significant bits are the number of key/value pairs
    let n = 0b000_11111 & bytes[0];
    match n {
        _ if n * 2 > 23 => Err(CborError::TooManyItems),
        n => {
            // Change the major type and number of elements accordingly
            bytes[0] = 0b100_00000 | (n * 2);
            Ok(())
        }
    }
}

/// Returns the byte indicating the CBOR array type with the given number of
/// elements.
fn array_byte(n: usize) -> Result<u8> {
    match n {
        _ if n > 23 => Err(CborError::TooManyItems),
        // The major type for arrays is indicated by the three leftmost bits.
        // By doing bitwise OR with the number of items, we assign the
        // remaining bits for the number of elements.
        n => Ok(0b100_00000 | n as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_length() {
        assert_eq!(0x80, array_byte(0).unwrap());
        assert_eq!(0x81, array_byte(1).unwrap());
        assert_eq!(0x94, array_byte(20).unwrap());
        assert_eq!(0x97, array_byte(23).unwrap());
        assert!(array_byte(24).is_err());
    }

    const MAP_0: [u8; 1] = [0xA0];
    const ARR_0: [u8; 1] = [0x80];
    const MAP_1: [u8; 4] = [0xA1, 0x01, 0x18, 0x2A];
    const ARR_2: [u8; 4] = [0x82, 0x01, 0x18, 0x2a];
    const MAP_11: [u8; 23] = [
        0xAB, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x07, 0x01, 0x08, 0x01, 0x09, 0x01, 0x0A, 0x01, 0x0B,
        0x01,
    ];
    const ARR_22: [u8; 23] = [
        0x96, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x07, 0x01, 0x08, 0x01, 0x09, 0x01, 0x0A, 0x01, 0x0B,
        0x01,
    ];
    const MAP_12: [u8; 25] = [
        0xAC, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x07, 0x01, 0x08, 0x01, 0x09, 0x01, 0x0A, 0x01, 0x0B,
        0x01, 0x0C, 0x01,
    ];
    const ARR_24: [u8; 26] = [
        0x98, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05,
        0x01, 0x06, 0x01, 0x07, 0x01, 0x08, 0x01, 0x09, 0x01, 0x0A, 0x01,
        0x0B, 0x01, 0x0C, 0x01,
    ];

    #[test]
    fn transformations() {
        let mut map_0 = MAP_0.to_vec();
        let mut arr_0 = ARR_0.to_vec();
        map_to_array(&mut map_0).unwrap();
        array_to_map(&mut arr_0).unwrap();
        assert_eq!(&ARR_0[..], &map_0[..]);
        assert_eq!(&MAP_0[..], &arr_0[..]);

        let mut map_1 = MAP_1.to_vec();
        let mut arr_2 = ARR_2.to_vec();
        map_to_array(&mut map_1).unwrap();
        array_to_map(&mut arr_2).unwrap();
        assert_eq!(&ARR_2[..], &map_1[..]);
        assert_eq!(&MAP_1[..], &arr_2[..]);

        let mut map_11 = MAP_11.to_vec();
        let mut arr_22 = ARR_22.to_vec();
        map_to_array(&mut map_11).unwrap();
        array_to_map(&mut arr_22).unwrap();
        assert_eq!(&ARR_22[..], &map_11[..]);
        assert_eq!(&MAP_11[..], &arr_22[..]);

        let mut map_12 = MAP_12.to_vec();
        let mut arr_24 = ARR_24.to_vec();
        assert!(map_to_array(&mut map_12).is_err());
        assert!(array_to_map(&mut arr_24).is_err());
    }
}
