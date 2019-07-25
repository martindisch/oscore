use alloc::vec::Vec;
use serde::Serialize;
use serde_cbor::de::from_mut_slice;
use serde_cbor::ser::SliceWrite;
use serde_cbor::{Error, Serializer};

/// Serializes an object into CBOR.
pub fn encode(object: impl Serialize) -> Result<Vec<u8>, Error> {
    serialize(object, 0)
}

/// Serializes an object into a sequence of CBOR encoded data items.
///
/// Only works for objects that serialize to a CBOR array of at most 23 items.
pub fn encode_sequence(object: impl Serialize) -> Result<Vec<u8>, Error> {
    // We serialize something that encodes as a CBOR array.
    // What we want is just the sequence of items, so we can omit the
    // first byte (indicating array type and length), and get the items.
    // That only works as long as we have at most 23 items, after that it
    // takes an additional byte to indicate the length.
    serialize(object, 1)
}

fn serialize(object: impl Serialize, offset: usize) -> Result<Vec<u8>, Error> {
    // Initialize a buffer, as well as a writer and serializer relying on it
    let mut buf = [0u8; 128];
    let writer = SliceWrite::new(&mut buf);
    let mut serializer = Serializer::new(writer);
    // Attempt serialization and determine the length
    object.serialize(&mut serializer)?;
    let writer = serializer.into_inner();
    let size = writer.bytes_written();

    // Return the bytes from the offset the caller requested
    Ok(buf[offset..size].to_vec())
}

/// Deserializes a sequence of CBOR encoded data items into an object.
///
/// Requires a Vec<u8> to use as a buffer and only works for sequences of at
/// most 23 items.
///
/// # Arguments
/// * `bytes` - The sequence of CBOR items
/// * `n_items` - The number of items
/// * `tmp_vec` - Buffer used for deserialization
pub fn decode<'a, T>(
    bytes: &[u8],
    n_items: u8,
    tmp_vec: &'a mut Vec<u8>,
) -> Result<T, Error>
where
    T: serde::Deserialize<'a>,
{
    // We receive a sequence of CBOR items. For parsing we need an array, so
    // start a CBOR array of the given length.
    tmp_vec.push(array_byte(n_items));
    // After the start byte, insert the message (sequence of CBOR items)
    tmp_vec.extend(bytes);

    // Now we can try to deserialize that
    from_mut_slice(tmp_vec)
}

fn array_byte(n: u8) -> u8 {
    // The major type for arrays is indicated by the three leftmost bits.
    // By doing bitwise OR with the number of items, we assign the remaining
    // bits for the number of elements.
    // TODO: Error handling for more than 23 items
    0b100_00000 | n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_length() {
        assert_eq!(0x80, array_byte(0));
        assert_eq!(0x81, array_byte(1));
        assert_eq!(0x94, array_byte(20));
        assert_eq!(0x97, array_byte(23));
    }
}
