use alloc::vec::Vec;
use hkdf::Hkdf;
use serde_bytes::Bytes;
use sha2::Sha256;

use crate::{cbor, Result};

/// The common context part of the security context.
struct CommonContext {
    master_secret: Vec<u8>,
    master_salt: Vec<u8>,
    common_iv: Vec<u8>,
}

/// The sender context part of the security context.
struct SenderContext {
    sender_id: Vec<u8>,
    sender_key: Vec<u8>,
    sender_sequence_number: u64,
}

/// The recipient context part of the security context.
struct RecipientContext {
    recipient_id: Vec<u8>,
    recipient_key: Vec<u8>,
    // We're assuming a reliable transport and therefore only store the last
    // received partial IV for simplicity
    replay_window: u64,
}

/// The security context.
pub struct SecurityContext {
    common_context: CommonContext,
    sender_context: SenderContext,
    recipient_context: RecipientContext,
}

impl SecurityContext {
    /// Creates a new `SecurityContext`.
    pub fn new(
        master_secret: Vec<u8>,
        master_salt: Vec<u8>,
        sender_id: Vec<u8>,
        recipient_id: Vec<u8>,
    ) -> Result<SecurityContext> {
        // Derive the keys and IV
        let sender_key = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&sender_id, "Key", 16)?,
            16,
        )?;
        let recipient_key = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&recipient_id, "Key", 16)?,
            16,
        )?;
        let common_iv = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&[], "IV", 13)?,
            13,
        )?;

        // Build the subcontexts
        let common_context = CommonContext {
            master_secret,
            master_salt,
            common_iv,
        };
        let sender_context = SenderContext {
            sender_id,
            sender_key,
            sender_sequence_number: 0,
        };
        let recipient_context = RecipientContext {
            recipient_id,
            recipient_key,
            replay_window: 0,
        };

        // Combine them to the final thing
        Ok(SecurityContext {
            common_context,
            sender_context,
            recipient_context,
        })
    }
}

/// Returns the CBOR encoded `info` structure.
///
/// # Arguments
/// * `id` - The sender ID or recipient ID (or empty for IV).
/// * `type` - Either "Key" or "IV".
/// * `l` - The size of the key/nonce for the AEAD, in bytes.
fn build_info(id: &[u8], r#type: &str, l: usize) -> Result<Vec<u8>> {
    // (id, id_context, alg_aead, type, L)
    let info = (Bytes::new(id), (), 10, r#type, l);
    // Return the CBOR encoded version of that
    cbor::encode(info)
}

/// Returns the derived key/IV for this `info` structure.
///
/// # Arguments
/// * `master_secret` - The master secret.
/// * `master_salt` - The master salt.
/// * `info` - The `info` structure, different for key and IV derivation.
/// * `l` - The size of the key/nonce for the AEAD used, in bytes.
fn hkdf(
    master_secret: &[u8],
    master_salt: &[u8],
    info: &[u8],
    l: usize,
) -> Result<Vec<u8>> {
    // This is the extract step, resulting in the pseudorandom key (PRK)
    let h = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; l];
    h.expand(info, &mut okm)?;

    Ok(okm)
}

/// Returns the CBOR encoded AAD array.
///
/// There's no argument for class I options, because the standard doesn't
/// define any at this point.
fn build_aad_array(request_kid: &[u8], request_piv: &[u8]) -> Result<Vec<u8>> {
    // (oscore_version, algorithms, request_kid, request_piv, options)
    let arr = (
        1,
        [10],
        Bytes::new(request_kid),
        Bytes::new(request_piv),
        Bytes::new(&[]),
    );
    // Return the CBOR encoded version of that
    cbor::encode(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_SECRET: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];
    const MASTER_SALT: [u8; 8] =
        [0x9E, 0x7C, 0xA9, 0x22, 0x23, 0x78, 0x63, 0x40];
    const SENDER_ID: [u8; 0] = [];
    const RECIPIENT_ID: [u8; 1] = [0x01];
    const INFO_SENDER_KEY: [u8; 9] =
        [0x85, 0x40, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_RECIPIENT_KEY: [u8; 10] =
        [0x85, 0x41, 0x01, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_COMMON_IV: [u8; 8] =
        [0x85, 0x40, 0xF6, 0x0A, 0x62, 0x49, 0x56, 0x0D];
    const SENDER_KEY: [u8; 16] = [
        0xF0, 0x91, 0x0E, 0xD7, 0x29, 0x5E, 0x6A, 0xD4, 0xB5, 0x4F, 0xC7,
        0x93, 0x15, 0x43, 0x02, 0xFF,
    ];
    const RECIPIENT_KEY: [u8; 16] = [
        0xFF, 0xB1, 0x4E, 0x09, 0x3C, 0x94, 0xC9, 0xCA, 0xC9, 0x47, 0x16,
        0x48, 0xB4, 0xF9, 0x87, 0x10,
    ];
    const COMMON_IV: [u8; 13] = [
        0x46, 0x22, 0xD4, 0xDD, 0x6D, 0x94, 0x41, 0x68, 0xEE, 0xFB, 0x54,
        0x98, 0x7C,
    ];

    const EXAMPLE_KID: [u8; 1] = [0x00];
    const EXAMPLE_PIV: [u8; 1] = [0x25];
    const EXAMPLE_AAD_ARR: [u8; 9] =
        [0x85, 0x01, 0x81, 0x0A, 0x41, 0x00, 0x41, 0x25, 0x40];

    const VECTOR_KID: [u8; 0] = [];
    const VECTOR_PIV: [u8; 1] = [0x14];
    const VECTOR_AAD_ARR: [u8; 8] =
        [0x85, 0x01, 0x81, 0x0A, 0x40, 0x41, 0x14, 0x40];

    #[test]
    fn info() {
        let i_sender = build_info(&SENDER_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_SENDER_KEY, &i_sender[..]);

        let i_recipient = build_info(&RECIPIENT_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_RECIPIENT_KEY, &i_recipient[..]);

        let i_iv = build_info(&[], "IV", 13).unwrap();
        assert_eq!(&INFO_COMMON_IV, &i_iv[..]);
    }

    #[test]
    fn context_derivation() {
        let security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SENDER_ID.to_vec(),
            RECIPIENT_ID.to_vec(),
        )
        .unwrap();

        assert_eq!(
            &MASTER_SECRET,
            &security_context.common_context.master_secret[..]
        );
        assert_eq!(
            &MASTER_SALT,
            &security_context.common_context.master_salt[..]
        );
        assert_eq!(&COMMON_IV, &security_context.common_context.common_iv[..]);

        assert_eq!(&SENDER_ID, &security_context.sender_context.sender_id[..]);
        assert_eq!(
            &SENDER_KEY,
            &security_context.sender_context.sender_key[..]
        );
        assert_eq!(0, security_context.sender_context.sender_sequence_number);

        assert_eq!(
            &RECIPIENT_ID,
            &security_context.recipient_context.recipient_id[..]
        );
        assert_eq!(
            &RECIPIENT_KEY,
            &security_context.recipient_context.recipient_key[..]
        );
        assert_eq!(0, security_context.recipient_context.replay_window);
    }

    #[test]
    fn aad_array() {
        let example_aad_arr =
            build_aad_array(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD_ARR, &example_aad_arr[..]);

        let vector_aad_arr =
            build_aad_array(&VECTOR_KID, &VECTOR_PIV).unwrap();
        assert_eq!(&VECTOR_AAD_ARR, &vector_aad_arr[..]);
    }
}
