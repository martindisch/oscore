// TODO: remove
#![allow(dead_code)]

use alloc::vec::Vec;
use hkdf::Hkdf;
use num_traits::FromPrimitive;
use serde_bytes::Bytes;
use sha2::Sha256;

use crate::coap::{
    packet::Packet, CoapOption, MessageClass, RequestType, ResponseType,
};
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

    /// Returns an OSCORE message based on the original CoAP message.
    pub fn protect_message(
        &self,
        coap_msg: &[u8],
        partial_iv: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the CoAP message TODO: figure out the error situation
        let mut original = Packet::from_bytes(coap_msg).unwrap();
        // Initialize a new CoAP message to store the protected parts
        let mut inner = Packet::new();

        // Move the code into the inner message
        inner.header.code = original.header.code;
        original.header.code = match original.header.code {
            // All requests get POST
            MessageClass::Request(_) => {
                MessageClass::Request(RequestType::Post)
            }
            // All responses get Changed
            MessageClass::Response(_) => {
                MessageClass::Response(ResponseType::Changed)
            }
            MessageClass::Empty => MessageClass::Empty,
            MessageClass::Reserved => MessageClass::Reserved,
        };
        // Store which options we remove from the outer message in this
        let mut moved_options = vec![];
        // Go over options, moving class E ones into the inner message
        for (number, value_list) in original.options() {
            // Abort on unimplemented optional features
            if UNSUPPORTED.contains(number) {
                // TODO: Error instead of panic
                unimplemented!("Option {}", number);
            }
            // Skip class U options
            if CLASS_U.contains(number) {
                continue;
            }

            // At this point the option is class E or undefined, so protect it
            // TODO: Better integration with coap module
            let option = CoapOption::from_usize(*number).unwrap();
            // Add it to the inner message
            inner.set_option(option, value_list.clone());
            // Remember it's been moved
            moved_options.push(option);
        }
        // Remove the moved options from the original
        for option in moved_options {
            original.clear_option(option);
        }
        // Move the payload out of the original into the new one
        inner.set_payload(original.payload);

        // Convert the message to its byte representation TODO: error handling
        let mut inner_bytes = inner.to_bytes().unwrap();
        // Remove the message ID and the token (if it exists)
        let tkl = inner.header.get_token_length();
        inner_bytes.drain(2..4 + tkl as usize);
        // Remove the first header byte
        inner_bytes.remove(0);

        // Set the inner message as the new payload TODO: encryption & stuff
        original.payload = inner_bytes;
        // Add the OSCORE option
        original.add_option(
            CoapOption::Oscore,
            build_oscore_option(
                Some(&self.sender_context.sender_id),
                // TODO: proper PIV
                Some(partial_iv),
            ),
        );

        // TODO: error handling
        Ok(original.to_bytes().unwrap())
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

/// Returns the AAD.
fn build_aad(request_kid: &[u8], request_piv: &[u8]) -> Result<Vec<u8>> {
    // First we need to construct the AAD array containing our parameters
    let aad_arr = build_aad_array(request_kid, request_piv)?;
    // Then we pack it into an Encrypt0 structure
    let aad = ("Encrypt0", Bytes::new(&[]), Bytes::new(&aad_arr));
    // And return the encoding of that
    cbor::encode(aad)
}

/// Returns the value of the OSCORE option.
fn build_oscore_option(kid: Option<&[u8]>, piv: Option<&[u8]>) -> Vec<u8> {
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
fn extract_oscore_option(value: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
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

// TODO: Better integration with improved coap module in the future
static CLASS_U: [usize; 4] = [3, 7, 35, 39];
static UNSUPPORTED: [usize; 6] = [6, 23, 27, 28, 60, 258];

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
    const EXAMPLE_AAD: [u8; 21] = [
        0x83, 0x68, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40,
        0x49, 0x85, 0x01, 0x81, 0x0A, 0x41, 0x00, 0x41, 0x25, 0x40,
    ];
    const KID: [u8; 0] = [];
    const PIV: [u8; 1] = [0x14];
    const AAD_ARR: [u8; 8] = [0x85, 0x01, 0x81, 0x0A, 0x40, 0x41, 0x14, 0x40];
    const AAD: [u8; 20] = [
        0x83, 0x68, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40,
        0x48, 0x85, 0x01, 0x81, 0x0A, 0x40, 0x41, 0x14, 0x40,
    ];

    const EX1_KID: Option<&[u8]> = Some(&[0x25]);
    const EX1_PIV: Option<&[u8]> = Some(&[0x05]);
    const EX1_OPTION: [u8; 3] = [0x09, 0x05, 0x25];
    const EX2_KID: Option<&[u8]> = Some(&[]);
    const EX2_PIV: Option<&[u8]> = Some(&[0x00]);
    const EX2_OPTION: [u8; 2] = [0x09, 0x00];
    const EX4_KID: Option<&[u8]> = None;
    const EX4_PIV: Option<&[u8]> = None;
    const EX4_OPTION: [u8; 0] = [];
    const EX5_KID: Option<&[u8]> = None;
    const EX5_PIV: Option<&[u8]> = Some(&[0x07]);
    const EX5_OPTION: [u8; 2] = [0x01, 0x07];
    const CRASH_OPTION: [u8; 2] = [0b0000_1101, 0x01];

    const UNPROTECTED: [u8; 22] = [
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    ];
    const PROTECTED: [u8; 35] = [
        0x44, 0x02, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x62, 0x09, 0x14, 0xFF,
        0x61, 0x2F, 0x10, 0x92, 0xF1, 0x77, 0x6F, 0x1C, 0x16, 0x68, 0xB3,
        0x82, 0x5E,
    ];
    const TEMP_PROTECTED: [u8; 27] = [
        0x44, 0x02, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x62, 0x09, 0x14, 0xFF,
        0x01, 0xB3, 0x74, 0x76, 0x31,
    ];

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

        let vector_aad_arr = build_aad_array(&KID, &PIV).unwrap();
        assert_eq!(&AAD_ARR, &vector_aad_arr[..]);
    }

    #[test]
    fn aad() {
        let example_aad = build_aad(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD, &example_aad[..]);

        let vector_aad = build_aad(&KID, &PIV).unwrap();
        assert_eq!(&AAD, &vector_aad[..]);
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
    fn protection() {
        let security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SENDER_ID.to_vec(),
            RECIPIENT_ID.to_vec(),
        )
        .unwrap();
        assert_eq!(
            &TEMP_PROTECTED[..],
            &security_context
                .protect_message(&UNPROTECTED, &PIV)
                .unwrap()[..]
        );
    }
}
