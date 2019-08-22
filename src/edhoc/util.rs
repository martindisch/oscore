use aes_ccm::CcmMode;
use alloc::{string::String, vec::Vec};
use digest::{FixedOutput, Input};
use hkdf::Hkdf;
use serde_bytes::{ByteBuf, Bytes};
use sha2::Sha256;

use crate::{cbor, cose, error::Error, Result};

pub const CCM_KEY_LEN: usize = 16;
pub const CCM_NONCE_LEN: usize = 13;
pub const CCM_MAC_LEN: usize = 8;

/// EDHOC `message_1`.
#[derive(Debug, PartialEq)]
pub struct Message1 {
    pub r#type: isize,
    pub suite: isize,
    pub x_u: Vec<u8>,
    pub c_u: Vec<u8>,
}

/// Serializes EDHOC `message_1`.
pub fn serialize_message_1(msg: &Message1) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let raw_msg = (
        msg.r#type,
        msg.suite,
        Bytes::new(&msg.x_u),
        Bytes::new(&msg.c_u),
    );

    Ok(cbor::encode_sequence(raw_msg)?)
}

/// Deserializes EDHOC `message_1`.
pub fn deserialize_message_1(msg: &[u8]) -> Result<Message1> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let raw_msg: (isize, isize, ByteBuf, ByteBuf) =
        cbor::decode_sequence(msg, 4, &mut temp)?;

    // On success, just move the items into the "nice" message structure
    Ok(Message1 {
        r#type: raw_msg.0,
        suite: raw_msg.1,
        x_u: raw_msg.2.into_vec(),
        c_u: raw_msg.3.into_vec(),
    })
}

/// EDHOC `message_2`.
#[derive(Debug, PartialEq)]
pub struct Message2 {
    pub c_u: Option<Vec<u8>>,
    pub x_v: Vec<u8>,
    pub c_v: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_2`.
pub fn serialize_message_2(msg: &Message2) -> Result<Vec<u8>> {
    if msg.c_u.is_some() {
        // Case where we have U's connection identifier
        cbor::encode_sequence((
            Bytes::new(msg.c_u.as_ref().unwrap()),
            Bytes::new(&msg.x_v),
            Bytes::new(&msg.c_v),
            Bytes::new(&msg.ciphertext),
        ))
    } else {
        // Case where we don't
        cbor::encode_sequence((
            Bytes::new(&msg.x_v),
            Bytes::new(&msg.c_v),
            Bytes::new(&msg.ciphertext),
        ))
    }
}

/// Deserializes EDHOC `message_2`.
pub fn deserialize_message_2(msg: &[u8]) -> Result<Message2> {
    let mut temp = Vec::with_capacity(msg.len() + 1);
    // First, attempt to decode the variant without c_u
    if let Ok((x_v, c_v, ciphertext)) =
        cbor::decode_sequence::<(ByteBuf, ByteBuf, ByteBuf)>(msg, 3, &mut temp)
    {
        // If that worked, return the Message2 variant without it
        Ok(Message2 {
            c_u: None,
            x_v: x_v.into_vec(),
            c_v: c_v.into_vec(),
            ciphertext: ciphertext.into_vec(),
        })
    } else {
        // Otherwise, try the one with c_u
        temp.clear();
        let (c_u, x_v, c_v, ciphertext) =
            cbor::decode_sequence::<(ByteBuf, ByteBuf, ByteBuf, ByteBuf)>(
                msg, 4, &mut temp,
            )?;
        // If we managed this time, we can fill up the whole struct
        Ok(Message2 {
            c_u: Some(c_u.into_vec()),
            x_v: x_v.into_vec(),
            c_v: c_v.into_vec(),
            ciphertext: ciphertext.into_vec(),
        })
    }
}

/// EDHOC `message_3`.
#[derive(Debug, PartialEq)]
pub struct Message3 {
    pub c_v: Option<Vec<u8>>,
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_3`.
pub fn serialize_message_3(msg: &Message3) -> Result<Vec<u8>> {
    if msg.c_v.is_some() {
        // Case where we have V's connection identifier
        cbor::encode_sequence((
            Bytes::new(msg.c_v.as_ref().unwrap()),
            Bytes::new(&msg.ciphertext),
        ))
    } else {
        // Case where we don't.
        // Since we have a single element (the ciphertext), there's no need
        // to use the sequence encoder.
        cbor::encode(Bytes::new(&msg.ciphertext))
    }
}

/// Deserializes EDHOC `message_3`.
pub fn deserialize_message_3(msg: &[u8]) -> Result<Message3> {
    let mut temp = Vec::with_capacity(msg.len() + 1);
    // First, attempt to decode the variant with c_v
    if let Ok((c_v, ciphertext)) =
        cbor::decode_sequence::<(ByteBuf, ByteBuf)>(msg, 2, &mut temp)
    {
        // If that worked, return the Message3 variant with it
        Ok(Message3 {
            c_v: Some(c_v.into_vec()),
            ciphertext: ciphertext.into_vec(),
        })
    } else {
        // Otherwise, try the one without it.
        // Again, we have a single element and therefore don't use the sequence
        // decoder. The regular encoder needs to operate on a mutable
        // reference, so clone the contents.
        let mut cpy = msg.to_vec();
        let ciphertext = cbor::decode::<ByteBuf>(&mut cpy)?;
        // If we managed this time, we can return the struct without c_v
        Ok(Message3 {
            c_v: None,
            ciphertext: ciphertext.into_vec(),
        })
    }
}

/// Returns the bytes of an EDHOC error message with the given text.
pub fn build_error_message(err_msg: &str) -> Vec<u8> {
    // Build a tuple for the sequence of items
    // (type, err_msg)
    let raw_msg = (-1, err_msg);

    // Try to serialize the message. If we fail for some reason, return a
    // valid, pregenerated error message saying as much.
    cbor::encode_sequence(raw_msg).unwrap_or_else(|_| {
        vec![
            0x20, 0x78, 0x22, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x77, 0x68,
            0x69, 0x6C, 0x65, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E,
            0x67, 0x20, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x6D, 0x65, 0x73,
            0x73, 0x61, 0x67, 0x65,
        ]
    })
}

/// Returns the extracted message from the EDHOC error message.
pub fn extract_error_message(msg: &[u8]) -> Result<String> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let (_, err_msg): (isize, String) =
        cbor::decode_sequence(msg, 2, &mut temp)?;

    Ok(err_msg)
}

/// Returns `Error::Edhoc` variant containing the error message, if the given
/// message was an EDHOC error message.
///
/// Use it by passing a received message to it, before trying to parse it.
pub fn fail_on_error_message(msg: &[u8]) -> Result<()> {
    match extract_error_message(msg) {
        // If we succeed, it really is an error message
        Ok(err_msg) => Err(Error::Edhoc(err_msg)),
        // If not, then we don't have an error message
        Err(_) => Ok(()),
    }
}

/// The `EDHOC-Key-Derivation` function.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
/// * `secret` - The ECDH shared secret to use as input keying material.
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
    let info = cose::build_kdf_context(algorithm_id, key_data_length, other)?;

    // This is the extract step, resulting in the pseudorandom key (PRK)
    let h = Hkdf::<Sha256>::new(salt, &ikm);
    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; key_data_length / 8];
    h.expand(&info, &mut okm)?;

    Ok(okm)
}

/// The `EDHOC-Exporter` interface.
///
/// # Arguments
/// * `label` - Chosen by the application.
/// * `length` - The length in bytes (chosen by the application).
/// * `th_4` - TH_4.
/// * `secret` - The ECDH shared secret to use as input keying material.
pub fn edhoc_exporter(
    label: &str,
    length: usize,
    th_4: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    edhoc_key_derivation(label, 8 * length, th_4, secret)
}

/// Calculates the transcript hash of the second message.
pub fn compute_th_2(
    message_1: Vec<u8>,
    c_u: Option<&[u8]>,
    x_v: &[u8],
    c_v: &[u8],
) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items from the data
    let data_2 = if c_u.is_some() {
        // Case where we have c_u
        cbor::encode_sequence((
            Bytes::new(c_u.unwrap()),
            Bytes::new(x_v),
            Bytes::new(c_v),
        ))?
    } else {
        // Case where we don't
        cbor::encode_sequence((Bytes::new(x_v), Bytes::new(c_v)))?
    };
    // Start the sequence we'll use from message_1, which is already a sequence
    let mut seq = message_1;
    // Concatenate it with the sequence we just created
    seq.extend(data_2);
    // Wrap the new sequence in a bstr to get the input to h()
    let bstr = cbor::encode(Bytes::new(&seq))?;

    // Return the hash of this
    h(&bstr)
}

/// Calculates the transcript hash of the third message.
pub fn compute_th_3(
    th_2: &[u8],
    ciphertext_2: &[u8],
    c_v: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let seq = if c_v.is_some() {
        // Case where we have c_v
        cbor::encode_sequence((
            Bytes::new(th_2),
            Bytes::new(ciphertext_2),
            Bytes::new(c_v.unwrap()),
        ))?
    } else {
        // Case where we don't
        cbor::encode_sequence((Bytes::new(th_2), Bytes::new(ciphertext_2)))?
    };
    // Wrap the sequence in a bstr to get the input to h()
    let bstr = cbor::encode(Bytes::new(&seq))?;

    // Return the hash of this
    h(&bstr)
}

/// Calculates the final transcript hash used for the `EDHOC-Exporter`.
pub fn compute_th_4(th_3: &[u8], ciphertext_3: &[u8]) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let seq =
        cbor::encode_sequence((Bytes::new(th_3), Bytes::new(ciphertext_3)))?;
    // Wrap the sequence in a bstr to get the input to h()
    let bstr = cbor::encode(Bytes::new(&seq))?;

    // Return the hash of this
    h(&bstr)
}

/// Returns a CBOR bstr containing the hash of the input CBOR bstr.
fn h(bstr: &[u8]) -> Result<Vec<u8>> {
    let mut sha256 = Sha256::default();
    sha256.input(bstr);
    let hash: [u8; 32] = sha256.fixed_result().into();

    // Return the bstr encoding
    cbor::encode(Bytes::new(&hash))
}

/// Returns the CBOR bstr making up the plaintext of `message_i`.
pub fn build_plaintext(kid: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    // Since ID_CRED_V contains a single kid parameter, take only the bstr of
    // it. Since the signature is raw bytes, wrap it in a bstr.
    let seq = cbor::encode_sequence((Bytes::new(kid), Bytes::new(signature)))?;

    // Return the sequence wrapped in a bstr
    cbor::encode(Bytes::new(&seq))
}

/// Extracts and returns the `kid` and signature from the plaintext of
/// `message_i`.
pub fn extract_plaintext(
    mut plaintext: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Unwrap the CBOR sequence from the bstr
    let seq: ByteBuf = cbor::decode(&mut plaintext)?;
    // Extract the kid and signature from the contained sequence
    let mut temp = Vec::with_capacity(seq.len() + 1);
    let (kid, sig): (ByteBuf, ByteBuf) =
        cbor::decode_sequence(&seq, 2, &mut temp)?;

    Ok((kid.into_vec(), sig.into_vec()))
}

/// Encrypts and authenticates with AES-CCM-16-64-128.
///
/// DO NOT reuse the nonce with the same key.
pub fn aead_seal(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Prepare key & nonce. This is fine, since it's not part of the public
    // API and we can guarantee that key & nonce always have the right length.
    let mut key_arr = [0; CCM_KEY_LEN];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0; CCM_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    // Initialize CCM mode
    let ccm = CcmMode::new(&key_arr, nonce_arr, CCM_MAC_LEN)?;
    // Allocate space for ciphertext & Poly1305 tag
    let mut dst_out_ct = vec![0; plaintext.len() + CCM_MAC_LEN];
    // Encrypt and place ciphertext & tag in dst_out_ct
    ccm.generate_encrypt(&mut dst_out_ct, ad, plaintext)?;

    Ok(dst_out_ct)
}

/// Decrypts and verifies with AES-CCM-16-64-128.
pub fn aead_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Prepare key & nonce. This is fine, since it's not part of the public
    // API and we can guarantee that key & nonce always have the right length.
    let mut key_arr = [0; CCM_KEY_LEN];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0; CCM_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    // Initialize CCM mode
    let ccm = CcmMode::new(&key_arr, nonce_arr, CCM_MAC_LEN)?;
    // Allocate space for the plaintext
    let mut dst_out_pt = vec![0; ciphertext.len() - CCM_MAC_LEN];
    // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
    ccm.decrypt_verify(&mut dst_out_pt, ad, ciphertext)?;

    Ok(dst_out_pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TYPE: isize = 1;
    static SUITE: isize = 0;
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

    static MSG3_CIPHERTEXT: [u8; 76] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
    ];
    static MSG3_BYTES: [u8; 80] = [
        0x41, 0xC4, 0x58, 0x4C, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B,
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
    fn returns_err() {
        let bytes = vec![0xFF];
        assert!(deserialize_message_1(&bytes).is_err());
        assert!(deserialize_message_2(&bytes).is_err());
        assert!(deserialize_message_3(&bytes).is_err());
    }

    #[test]
    fn serialize_2() {
        let mut original = Message2 {
            c_u: Some(C_U.to_vec()),
            x_v: MSG2_X_V.to_vec(),
            c_v: C_V.to_vec(),
            ciphertext: MSG2_CIPHERTEXT.to_vec(),
        };
        assert_eq!(
            &MSG2_BYTES[..],
            &serialize_message_2(&original).unwrap()[..]
        );

        original.c_u = None;
        assert_eq!(
            &MSG2_BYTES[2..],
            &serialize_message_2(&original).unwrap()[..]
        );
    }

    #[test]
    fn deserialize_2() {
        let mut original = Message2 {
            c_u: Some(C_U.to_vec()),
            x_v: MSG2_X_V.to_vec(),
            c_v: C_V.to_vec(),
            ciphertext: MSG2_CIPHERTEXT.to_vec(),
        };
        assert_eq!(original, deserialize_message_2(&MSG2_BYTES).unwrap());

        original.c_u = None;
        assert_eq!(original, deserialize_message_2(&MSG2_BYTES[2..]).unwrap());
    }

    #[test]
    fn serialize_3() {
        let mut original = Message3 {
            c_v: Some(C_V.to_vec()),
            ciphertext: MSG3_CIPHERTEXT.to_vec(),
        };
        assert_eq!(
            &MSG3_BYTES[..],
            &serialize_message_3(&original).unwrap()[..]
        );

        original.c_v = None;
        assert_eq!(
            &MSG3_BYTES[2..],
            &serialize_message_3(&original).unwrap()[..]
        );
    }

    #[test]
    fn deserialize_3() {
        let mut original = Message3 {
            c_v: Some(C_V.to_vec()),
            ciphertext: MSG3_CIPHERTEXT.to_vec(),
        };
        assert_eq!(original, deserialize_message_3(&MSG3_BYTES).unwrap());

        original.c_v = None;
        assert_eq!(original, deserialize_message_3(&MSG3_BYTES[2..]).unwrap());
    }

    static ERR_MSG: &str = "Unicode: 助, 😀";
    static ERR_MSG_BYTES: [u8; 20] = [
        0x20, 0x72, 0x55, 0x6E, 0x69, 0x63, 0x6F, 0x64, 0x65, 0x3A, 0x20,
        0xE5, 0x8A, 0xA9, 0x2C, 0x20, 0xF0, 0x9F, 0x98, 0x80,
    ];

    #[test]
    fn build_err() {
        let err_bytes = build_error_message(ERR_MSG);
        assert_eq!(&ERR_MSG_BYTES, &err_bytes[..]);
    }

    #[test]
    fn extract_err() {
        let err_msg = extract_error_message(&ERR_MSG_BYTES).unwrap();
        assert_eq!(ERR_MSG, &err_msg);
    }

    #[test]
    fn err_catching() {
        // Don't fail when parsing something that's not an error message
        assert!(fail_on_error_message(&MSG1_BYTES).is_ok());
        let msg_2_bytes = cbor::encode(Bytes::new(&MSG3_BYTES)).unwrap();
        assert!(fail_on_error_message(&msg_2_bytes).is_ok());

        // If it is an error message, give us the correct error variant
        let msg = match fail_on_error_message(&ERR_MSG_BYTES) {
            Err(Error::Edhoc(err_msg)) => err_msg,
            _ => String::from("Not what we're looking for"),
        };
        assert_eq!(ERR_MSG, &msg);
    }

    static ALG: &str = "AES-CCM-16-64-128";
    static LENGTH: usize = 128;
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
        0x06, 0xA0, 0x53, 0x83, 0x03, 0xD8, 0x39, 0x5D, 0x1E, 0xFB, 0x90,
        0x90, 0x88, 0x03, 0x67, 0x37,
    ];

    static EXPORTER_LABEL: &str = "OSCORE Master Salt";
    static EXPORTER_LENGTH: usize = 8;
    static EXPORTER_TH_4: [u8; 7] = [0x46, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

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

    #[test]
    fn exporter() {
        let key = edhoc_exporter(
            EXPORTER_LABEL,
            EXPORTER_LENGTH,
            &EXPORTER_TH_4,
            &SECRET,
        )
        .unwrap();
        assert_eq!(
            &edhoc_key_derivation(
                EXPORTER_LABEL,
                8 * EXPORTER_LENGTH,
                &EXPORTER_TH_4,
                &SECRET
            )
            .unwrap()[..],
            &key[..]
        );
    }

    static H_INPUT: [u8; 46] = [
        0x58, 0x2C, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B,
        0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78, 0x20,
        0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F,
        0x67, 0x2E,
    ];
    static H_BSTR: [u8; 34] = [
        0x58, 0x20, 0x86, 0x9F, 0xFE, 0x82, 0xD4, 0xEA, 0x1F, 0x34, 0xB8,
        0x79, 0x73, 0xD4, 0x5D, 0x72, 0xED, 0xC1, 0x52, 0x52, 0xB1, 0xD2,
        0xB4, 0x5D, 0x1B, 0x0B, 0xC5, 0x59, 0x46, 0x3C, 0x4D, 0xF3, 0x06,
        0xEF,
    ];

    #[test]
    fn hash() {
        let bstr = h(&H_INPUT).unwrap();
        assert_eq!(&H_BSTR[..], &bstr[..]);
    }

    static TH_2_MSG1: [u8; 2] = [0x01, 0x02];
    static TH_2_C_U: [u8; 1] = [0x00];
    static TH_2_X_V: [u8; 1] = [0x01];
    static TH_2_C_V: [u8; 1] = [0x02];
    static TH_2_INPUT: [u8; 9] =
        [0x48, 0x01, 0x02, 0x41, 0x00, 0x41, 0x01, 0x41, 0x02];
    static TH_2_INPUT_SHORTER: [u8; 7] =
        [0x46, 0x01, 0x02, 0x41, 0x01, 0x41, 0x02];

    #[test]
    fn th_2() {
        let t_h = compute_th_2(
            TH_2_MSG1.to_vec(),
            Some(&TH_2_C_U),
            &TH_2_X_V,
            &TH_2_C_V,
        )
        .unwrap();
        assert_eq!(h(&TH_2_INPUT).unwrap(), t_h);

        let t_h = compute_th_2(TH_2_MSG1.to_vec(), None, &TH_2_X_V, &TH_2_C_V)
            .unwrap();
        assert_eq!(h(&TH_2_INPUT_SHORTER).unwrap(), t_h);
    }

    static TH_3_TH_2: [u8; 2] = [0x01, 0x02];
    static TH_3_CIPHERTEXT: [u8; 2] = [0x03, 0x04];
    static TH_3_C_V: [u8; 1] = [0x05];
    static TH_3_INPUT: [u8; 9] =
        [0x48, 0x42, 0x01, 0x02, 0x42, 0x03, 0x04, 0x41, 0x05];
    static TH_3_INPUT_SHORTER: [u8; 7] =
        [0x46, 0x42, 0x01, 0x02, 0x42, 0x03, 0x04];

    #[test]
    fn th_3() {
        let t_h = compute_th_3(&TH_3_TH_2, &TH_3_CIPHERTEXT, Some(&TH_3_C_V))
            .unwrap();
        assert_eq!(h(&TH_3_INPUT).unwrap(), t_h);

        let t_h = compute_th_3(&TH_3_TH_2, &TH_3_CIPHERTEXT, None).unwrap();
        assert_eq!(h(&TH_3_INPUT_SHORTER).unwrap(), t_h);
    }

    static TH_4_TH_3: [u8; 2] = [0x01, 0x02];
    static TH_4_CIPHERTEXT: [u8; 2] = [0x03, 0x04];
    static TH_4_INPUT: [u8; 7] = [0x46, 0x42, 0x01, 0x02, 0x42, 0x03, 0x04];

    #[test]
    fn th_4() {
        let t_h = compute_th_4(&TH_4_TH_3, &TH_4_CIPHERTEXT).unwrap();
        assert_eq!(h(&TH_4_INPUT).unwrap(), t_h);
    }

    static PLAINTEXT_KID: [u8; 15] = *b"bob@example.org";
    static PLAINTEXT_SIG: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    static PLAINTEXT_2: [u8; 22] = [
        0x55, 0x4F, 0x62, 0x6F, 0x62, 0x40, 0x65, 0x78, 0x61, 0x6D, 0x70,
        0x6C, 0x65, 0x2E, 0x6F, 0x72, 0x67, 0x44, 0x01, 0x02, 0x03, 0x04,
    ];

    #[test]
    fn plaintext() {
        let plaintext =
            build_plaintext(&PLAINTEXT_KID, &PLAINTEXT_SIG).unwrap();
        assert_eq!(&PLAINTEXT_2[..], &plaintext[..]);

        let (kid, sig) = extract_plaintext(plaintext).unwrap();
        assert_eq!(&PLAINTEXT_KID[..], &kid[..]);
        assert_eq!(&PLAINTEXT_SIG[..], &sig[..]);
    }

    static AEAD_SECRET_KEY: [u8; CCM_KEY_LEN] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    ];
    static AEAD_NONCE: [u8; CCM_NONCE_LEN] = [
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3,
        0xA4, 0xA5,
    ];
    static AEAD_PT: [u8; 23] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E,
    ];
    static AEAD_AD: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    #[test]
    fn aead() {
        // Check for plaintext equality
        let ct = aead_seal(&AEAD_SECRET_KEY, &AEAD_NONCE, &AEAD_PT, &AEAD_AD)
            .unwrap();
        let pt =
            aead_open(&AEAD_SECRET_KEY, &AEAD_NONCE, &ct, &AEAD_AD).unwrap();
        assert_eq!(&AEAD_PT[..], &pt[..]);

        // Check verification fail on manipulated ciphertext
        let mut ct_manip = ct.clone();
        ct_manip[2] = 0x00;
        assert!(
            aead_open(&AEAD_SECRET_KEY, &AEAD_NONCE, &ct_manip, &AEAD_AD)
                .is_err()
        );

        // Check verification fail on manipulated tag
        let mut ct_manip = ct.clone();
        ct_manip[AEAD_PT.len() + 4] = 0x00;
        assert!(
            aead_open(&AEAD_SECRET_KEY, &AEAD_NONCE, &ct_manip, &AEAD_AD)
                .is_err()
        );

        // Check verification fail on wrong AD
        let mut ad_manip = AEAD_AD.to_vec();
        ad_manip[6] = 0x00;
        assert!(
            aead_open(&AEAD_SECRET_KEY, &AEAD_NONCE, &ct, &ad_manip).is_err()
        );
    }
}
