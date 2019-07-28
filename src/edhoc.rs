use crate::cbor::{decode_sequence, encode_sequence};
use crate::cose::build_kdf_context;
use crate::Result;
use alloc::vec::Vec;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

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

pub fn serialize_message_1(msg: &Message1) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = RawMessage1(msg.r#type, msg.suite, &msg.x_u, &msg.c_u);

    Ok(encode_sequence(raw_msg)?)
}

pub fn deserialize_message_1(msg: &[u8]) -> Result<Message1> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let raw_msg: RawMessage1 = decode_sequence(msg, 4, &mut temp)?;

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

pub fn serialize_message_2(msg: &Message2) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = RawMessage2(&msg.c_u, &msg.x_v, &msg.c_v, &msg.ciphertext);

    Ok(encode_sequence(raw_msg)?)
}

pub fn deserialize_message_2(msg: &[u8]) -> Result<Message2> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let raw_msg: RawMessage2 = decode_sequence(msg, 4, &mut temp)?;

    // On success, just move the items into the "nice" message structure
    Ok(Message2 {
        c_u: raw_msg.0.to_vec(),
        x_v: raw_msg.1.to_vec(),
        c_v: raw_msg.2.to_vec(),
        ciphertext: raw_msg.3.to_vec(),
    })
}

pub fn edhoc_key_derivation(
    algorithm_id: &str,
    key_data_length: usize,
    other: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    // We use the ECDH shared secret as input keying material
    let ikm = secret;
    // Since we have asymmetric authentication, the salt is 0
    let salt = None;
    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = build_kdf_context(algorithm_id, key_data_length, other)?;

    // This is the extract step, resulting in the pseudorandom key (PRK)
    let h = Hkdf::<Sha256>::new(salt, &ikm);
    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; key_data_length];
    h.expand(&info, &mut okm)?;

    Ok(okm)
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

        assert_eq!(
            &MSG1_BYTES[..],
            &serialize_message_1(&original).unwrap()[..]
        );
    }

    #[test]
    fn deserialize_1() {
        let original = Message1 {
            r#type: TYPE,
            suite: SUITE,
            x_u: MSG1_X_U.to_vec(),
            c_u: C_U.to_vec(),
        };

        assert_eq!(original, deserialize_message_1(&MSG1_BYTES).unwrap());
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

        assert_eq!(
            &MSG2_BYTES[..],
            &serialize_message_2(&original).unwrap()[..]
        );
    }

    #[test]
    fn deserialize_2() {
        let original = Message2 {
            c_u: C_U.to_vec(),
            x_v: MSG2_X_V.to_vec(),
            c_v: C_V.to_vec(),
            ciphertext: MSG2_CIPHERTEXT.to_vec(),
        };

        assert_eq!(original, deserialize_message_2(&MSG2_BYTES).unwrap());
    }

    static ALG: &str = "AES-CCM-64-64-128";
    static LENGTH: usize = 16;
    static OTHER: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
    ];
    static SECRET: [u8; 32] = [
        0x32, 0x0E, 0x38, 0xF7, 0xC5, 0x8D, 0x01, 0x0B, 0xB7, 0xA8, 0x1E,
        0x38, 0x34, 0x07, 0xDD, 0x59, 0xF4, 0xAE, 0x83, 0x7A, 0x0B, 0x5C,
        0xE7, 0xB7, 0x55, 0xCF, 0x79, 0x28, 0x3A, 0x95, 0xC2, 0x68,
    ];
    static OKM: [u8; 16] = [
        70, 161, 136, 75, 243, 41, 180, 20, 17, 219, 229, 122, 100, 24, 124,
        152,
    ];

    #[test]
    fn key_derivation() {
        let okm = edhoc_key_derivation(ALG, LENGTH, &OTHER, &SECRET).unwrap();
        assert_eq!(&OKM[..], &okm[..]);

        let mut other = OTHER.to_vec();
        other[1] = 0x42;
        let okm = edhoc_key_derivation(ALG, LENGTH, &other, &SECRET).unwrap();
        assert_ne!(&OKM[..], &okm[..]);

        let mut secret = SECRET.to_vec();
        secret[1] = 0x42;
        let okm = edhoc_key_derivation(ALG, LENGTH, &OTHER, &secret).unwrap();
        assert_ne!(&OKM[..], &okm[..]);
    }
}
