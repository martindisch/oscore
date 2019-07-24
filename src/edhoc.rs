use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_cbor::de::from_mut_slice;
use serde_cbor::ser::SliceWrite;
use serde_cbor::{Error, Serializer};

#[derive(Debug, PartialEq)]
pub struct Message1 {
    pub r#type: i32,
    pub suite: i32,
    pub x_u: Vec<u8>,
    pub c_u: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawMessage1<'a>(
    i32,
    i32,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
);

pub fn serialize_message_1(msg: &Message1) -> Result<Vec<u8>, Error> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = RawMessage1(msg.r#type, msg.suite, &msg.x_u, &msg.c_u);

    // Initialize a buffer, as well as a writer and serializer relying on it
    let mut buf = [0u8; 128];
    let writer = SliceWrite::new(&mut buf);
    let mut serializer = Serializer::new(writer);
    // Attempt serialization and determine the length
    raw_msg.serialize(&mut serializer)?;
    let writer = serializer.into_inner();
    let size = writer.bytes_written();

    // What we have now is a fixed-length CBOR array with 4 items.
    // What we want is just the sequence of items, so we can simply omit the
    // first byte (indicating array type and length), and get the items.
    Ok(buf[1..size].to_vec())
}

pub fn deserialize_message_1(msg: &[u8]) -> Result<Message1, Error> {
    // We receive a sequence of 4 CBOR items. For parsing we need an array, so
    // start a CBOR array of length 4.
    let mut cbor_arr = vec![0x84];
    // After the start byte, insert the message (sequence of CBOR items)
    cbor_arr.extend(msg);

    // Now we can try to deserialize that into our raw message format
    let raw_msg: RawMessage1 = from_mut_slice(&mut cbor_arr)?;

    // On success, just move the items into the "nice" message structure
    Ok(Message1 {
        r#type: raw_msg.0,
        suite: raw_msg.1,
        x_u: raw_msg.2.to_vec(),
        c_u: raw_msg.3.to_vec(),
    })
}

#[derive(Debug, PartialEq)]
pub struct Message2 {
    c_u: Vec<u8>,
    x_v: Vec<u8>,
    c_v: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawMessage2<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
);

pub fn serialize_message_2(msg: &Message2) -> Result<Vec<u8>, Error> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = RawMessage2(&msg.c_u, &msg.x_v, &msg.c_v, &msg.ciphertext);

    // Initialize a buffer, as well as a writer and serializer relying on it
    let mut buf = [0u8; 128];
    let writer = SliceWrite::new(&mut buf);
    let mut serializer = Serializer::new(writer);
    // Attempt serialization and determine the length
    raw_msg.serialize(&mut serializer)?;
    let writer = serializer.into_inner();
    let size = writer.bytes_written();

    // What we have now is a fixed-length CBOR array with 4 items.
    // What we want is just the sequence of items, so we can simply omit the
    // first byte (indicating array type and length), and get the items.
    Ok(buf[1..size].to_vec())
}

pub fn deserialize_message_2(msg: &[u8]) -> Result<Message2, Error> {
    // We receive a sequence of 4 CBOR items. For parsing we need an array, so
    // start a CBOR array of length 4.
    let mut cbor_arr = vec![0x84];
    // After the start byte, insert the message (sequence of CBOR items)
    cbor_arr.extend(msg);

    // Now we can try to deserialize that into our raw message format
    let raw_msg: RawMessage2 = from_mut_slice(&mut cbor_arr)?;

    // On success, just move the items into the "nice" message structure
    Ok(Message2 {
        c_u: raw_msg.0.to_vec(),
        x_v: raw_msg.1.to_vec(),
        c_v: raw_msg.2.to_vec(),
        ciphertext: raw_msg.3.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static TYPE: i32 = 1;
    static SUITE: i32 = 0;
    static C_U: [u8; 1] = [0xC3];
    static C_V: [u8; 1] = [0xC4];

    static MSG1_X_U: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];
    static MSG1_BYTES: [u8; 38] = [
        0x01, 0x00, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x41, 0xC3,
    ];

    static MSG2_X_V: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];
    static MSG2_CIPHERTEXT: [u8; 76] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
    ];
    static MSG2_BYTES: [u8; 116] = [
        0x41, 0xC3, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x41, 0xC4, 0x58, 0x4C, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
    ];

    #[test]
    fn serialize_1() {
        let original = Message1 {
            r#type: TYPE,
            suite: SUITE,
            x_u: MSG1_X_U.to_vec(),
            c_u: C_U.to_vec(),
        };
        let bytes = MSG1_BYTES.to_vec();

        assert_eq!(serialize_message_1(&original).unwrap(), bytes);
    }

    #[test]
    fn deserialize_1() {
        let original = Message1 {
            r#type: TYPE,
            suite: SUITE,
            x_u: MSG1_X_U.to_vec(),
            c_u: C_U.to_vec(),
        };
        let mut bytes = MSG1_BYTES.to_vec();

        assert_eq!(deserialize_message_1(&mut bytes).unwrap(), original);
    }

    #[test]
    #[should_panic]
    fn returns_err() {
        let bytes = vec![0xFF];
        deserialize_message_1(&bytes).unwrap();
    }

    #[test]
    fn serialize_2() {
        let original = Message2 {
            c_u: C_U.to_vec(),
            x_v: MSG2_X_V.to_vec(),
            c_v: C_V.to_vec(),
            ciphertext: MSG2_CIPHERTEXT.to_vec(),
        };
        let bytes = MSG2_BYTES.to_vec();

        assert_eq!(serialize_message_2(&original).unwrap(), bytes);
    }

    #[test]
    fn deserialize_2() {
        let original = Message2 {
            c_u: C_U.to_vec(),
            x_v: MSG2_X_V.to_vec(),
            c_v: C_V.to_vec(),
            ciphertext: MSG2_CIPHERTEXT.to_vec(),
        };
        let mut bytes = MSG2_BYTES.to_vec();

        assert_eq!(deserialize_message_2(&mut bytes).unwrap(), original);
    }
}
