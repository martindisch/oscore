use alloc::vec::Vec;
use serde_bytes::Bytes;

use crate::{cbor, Result};

/// Returns the CBOR encoded `info` structure.
///
/// # Arguments
/// * `id` - The sender ID or recipient ID (or empty for IV).
/// * `type` - Either "Key" or "IV".
/// * `l` - The size of the key/nonce for the AEAD, in bytes.
pub fn build_info(id: &[u8], r#type: &str, l: usize) -> Result<Vec<u8>> {
    // (id, id_context, alg_aead, type, L)
    let info = (Bytes::new(id), (), 10, r#type, l);
    // Return the CBOR encoded version of that
    cbor::encode(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_ID: [u8; 0] = [];
    const RECIPIENT_ID: [u8; 1] = [0x01];
    const INFO_SENDER_KEY: [u8; 9] =
        [0x85, 0x40, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_RECIPIENT_KEY: [u8; 10] =
        [0x85, 0x41, 0x01, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_COMMON_IV: [u8; 8] =
        [0x85, 0x40, 0xF6, 0x0A, 0x62, 0x49, 0x56, 0x0D];

    #[test]
    fn info() {
        let i_sender = build_info(&SENDER_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_SENDER_KEY, &i_sender[..]);

        let i_recipient = build_info(&RECIPIENT_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_RECIPIENT_KEY, &i_recipient[..]);

        let i_iv = build_info(&[], "IV", 13).unwrap();
        assert_eq!(&INFO_COMMON_IV, &i_iv[..]);
    }
}
