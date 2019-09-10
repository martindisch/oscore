use alloc::vec::Vec;
use hkdf::Hkdf;
use serde_bytes::Bytes;
use sha2::Sha256;

use crate::{cbor, Result};

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 13;
pub const MAC_LEN: usize = 8;

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

/// Returns the derived key/IV for this `info` structure.
///
/// # Arguments
/// * `master_secret` - The master secret.
/// * `master_salt` - The master salt.
/// * `info` - The `info` structure, different for key and IV derivation.
/// * `l` - The size of the key/nonce for the AEAD used, in bytes.
pub fn hkdf(
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
pub fn build_aad_array(
    request_kid: &[u8],
    request_piv: &[u8],
) -> Result<Vec<u8>> {
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

/// Returns the AAD.
pub fn build_aad(request_kid: &[u8], request_piv: &[u8]) -> Result<Vec<u8>> {
    // First we need to construct the AAD array containing our parameters
    let aad_arr = build_aad_array(request_kid, request_piv)?;
    // Then we pack it into an Encrypt0 structure
    let aad = ("Encrypt0", Bytes::new(&[]), Bytes::new(&aad_arr));
    // And return the encoding of that
    cbor::encode(aad)
}

/// Returns the value of the OSCORE option.
pub fn build_oscore_option(kid: Option<&[u8]>, piv: Option<&[u8]>) -> Vec<u8> {
    // Allocate memory for the flag byte and piv and kid
    let mut option =
        vec![0; 1 + piv.map_or(0, |p| p.len()) + kid.map_or(0, |k| k.len())];
    // If we have neither kid nor piv, our option has no value
    if option.len() == 1 {
        option.pop();
        return option;
    }

    if let Some(piv) = piv {
        // Set the partial IV length (3 least significant bits of flag byte)
        option[0] |= piv.len() as u8 & 0b0000_0111;
        // Copy in the partial IV
        option[1..=piv.len()].copy_from_slice(piv);
    }

    if let Some(kid) = kid {
        // Set the kid flag
        option[0] |= 0b0000_1000;
        // Copy in the kid
        option[1 + piv.map_or(0, |p| p.len())..].copy_from_slice(kid);
    }

    option
}

/// Returns the encoded `kid` and `piv` values, if present.
pub fn extract_oscore_option(
    value: &[u8],
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    // Handle empty option
    if value.is_empty() {
        return (None, None);
    }

    // Unpack piv if present
    let (piv, piv_len) = match value[0] & 0b0000_0111 {
        0 => (None, 0),
        n => {
            // Check if we really received enough data
            if value.len() > n as usize {
                (Some(Vec::from(&value[1..=n as usize])), n)
            } else {
                // If not, abort
                return (None, None);
            }
        }
    };
    // Unpack kid if present
    let kid = match value[0] & 0b0000_1000 {
        0 => None,
        _ => Some(Vec::from(&value[1 + piv_len as usize..])),
    };

    (kid, piv)
}

/// Returns the nonce for the AEAD.
pub fn compute_nonce(
    mut piv: &[u8],
    mut id_piv: &[u8],
    common_iv: &[u8; NONCE_LEN],
) -> [u8; NONCE_LEN] {
    // Since id_piv could be longer than it should, trim it if necessary
    if id_piv.len() > NONCE_LEN - 6 {
        id_piv = &id_piv[id_piv.len() - (NONCE_LEN - 6)..]
    }
    // Same for the piv itself
    if piv.len() > 5 {
        piv = &piv[piv.len() - 5..];
    }

    let mut nonce = [0; NONCE_LEN];
    // Left-pad the Partial IV (PIV) with zeros to exactly 5 bytes
    nonce[NONCE_LEN - piv.len()..].copy_from_slice(&piv);
    // Left-pad ID_PIV with zeros to exactly nonce length minus 6 bytes
    nonce[1 + NONCE_LEN - 6 - id_piv.len()..NONCE_LEN - 5]
        .copy_from_slice(&id_piv);
    // Add the size of the ID_PIV (a single byte S)
    nonce[0] = id_piv.len() as u8;
    // XOR with common IV
    for (b1, b2) in nonce.iter_mut().zip(common_iv.iter()) {
        *b1 ^= b2;
    }

    nonce
}

/// Returns the `piv` as a u64.
pub fn piv_to_u64(mut piv: &[u8]) -> u64 {
    // Trim piv if it's too long
    if piv.len() > 8 {
        piv = &piv[piv.len() - 8..];
    }
    // Copy piv into an appropriately sized array
    let mut piv_arr = [0; 8];
    piv_arr[8 - piv.len()..].copy_from_slice(piv);

    u64::from_be_bytes(piv_arr)
}

/// Returns the `piv` in its correct format (no leading zero bytes).
pub fn format_piv(piv: u64) -> Vec<u8> {
    // Convert the sender sequence number to its byte representation
    let bytes = piv.to_be_bytes();
    // Find the index of the first byte that is not zero
    let first_nonzero = bytes.iter().position(|&x| x != 0);
    match first_nonzero {
        // If there is one, skip leading zero bytes and return the others
        Some(n) => bytes[n..].to_vec(),
        // If there isn't, we simply return 0
        None => vec![0x00],
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_vectors::*;
    use super::*;

    #[test]
    fn info() {
        let i_sender = build_info(&CLIENT_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_CLIENT_KEY, &i_sender[..]);

        let i_recipient = build_info(&SERVER_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_SERVER_KEY, &i_recipient[..]);

        let i_iv = build_info(&[], "IV", 13).unwrap();
        assert_eq!(&INFO_COMMON_IV, &i_iv[..]);
    }

    #[test]
    fn aad_array() {
        let example_aad_arr =
            build_aad_array(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD_ARR, &example_aad_arr[..]);

        let v4_aad_arr = build_aad_array(&CLIENT_ID, &REQ_PIV).unwrap();
        assert_eq!(&REQ_AAD_ARR, &v4_aad_arr[..]);
    }

    #[test]
    fn aad() {
        let example_aad = build_aad(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD, &example_aad[..]);

        let v4_aad = build_aad(&CLIENT_ID, &REQ_PIV).unwrap();
        assert_eq!(&REQ_AAD, &v4_aad[..]);
    }

    #[test]
    fn option_encoding() {
        assert_eq!(&EX1_OPTION, &build_oscore_option(EX1_KID, EX1_PIV)[..]);
        assert_eq!(&EX2_OPTION, &build_oscore_option(EX2_KID, EX2_PIV)[..]);
        assert_eq!(&EX4_OPTION, &build_oscore_option(EX4_KID, EX4_PIV)[..]);
        assert_eq!(&EX5_OPTION, &build_oscore_option(EX5_KID, EX5_PIV)[..]);
    }

    #[test]
    fn option_decoding() {
        let (kid, piv) = extract_oscore_option(&EX1_OPTION);
        assert_eq!(EX1_KID, crate::as_deref(&kid));
        assert_eq!(EX1_PIV, crate::as_deref(&piv));

        let (kid, piv) = extract_oscore_option(&EX2_OPTION);
        assert_eq!(EX2_KID, crate::as_deref(&kid));
        assert_eq!(EX2_PIV, crate::as_deref(&piv));

        let (kid, piv) = extract_oscore_option(&EX4_OPTION);
        assert_eq!(EX4_KID, crate::as_deref(&kid));
        assert_eq!(EX4_PIV, crate::as_deref(&piv));

        let (kid, piv) = extract_oscore_option(&EX5_OPTION);
        assert_eq!(EX5_KID, crate::as_deref(&kid));
        assert_eq!(EX5_PIV, crate::as_deref(&piv));

        let (kid, piv) = extract_oscore_option(&CRASH_OPTION);
        assert_eq!(None, kid);
        assert_eq!(None, piv);
    }

    #[test]
    fn nonce() {
        assert_eq!(
            CLIENT_NONCE,
            compute_nonce(&REQ_PIV, &CLIENT_ID, &COMMON_IV)
        );
        assert_eq!(
            SERVER_NONCE,
            compute_nonce(&RES_PIV, &SERVER_ID, &COMMON_IV)
        );
        assert_eq!(
            SERVER_NONCE_LONG_PIV,
            compute_nonce(&RES_PIV, &SERVER_ID_LONG, &COMMON_IV)
        );
    }

    #[test]
    fn piv_transform() {
        let piv = [0x00];
        assert_eq!(0, piv_to_u64(&piv));

        let piv = [0x01, 0x02];
        assert_eq!(258, piv_to_u64(&piv));

        let piv = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(1, piv_to_u64(&piv));
    }

    #[test]
    fn piv_format() {
        assert_eq!([0], format_piv(0)[..]);
        assert_eq!([0xFF], format_piv(0xFF)[..]);
        assert_eq!([0x01, 0x00], format_piv(0xFF + 1)[..]);
    }
}
