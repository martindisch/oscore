// TODO: remove
#![allow(dead_code)]

use aes_ccm::CcmMode;
use alloc::vec::Vec;
use hkdf::Hkdf;
use num_traits::FromPrimitive;
use serde_bytes::Bytes;
use sha2::Sha256;

use crate::coap::{
    packet::Packet, CoapOption, MessageClass, RequestType, ResponseType,
};
use crate::{cbor, Result};

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 13;
const MAC_LEN: usize = 8;

/// The common context part of the security context.
struct CommonContext {
    master_secret: Vec<u8>,
    master_salt: Vec<u8>,
    common_iv: [u8; NONCE_LEN],
}

/// The sender context part of the security context.
struct SenderContext {
    sender_id: Vec<u8>,
    sender_key: [u8; KEY_LEN],
    sender_sequence_number: u64,
}

/// The recipient context part of the security context.
struct RecipientContext {
    recipient_id: Vec<u8>,
    recipient_key: [u8; KEY_LEN],
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
        let sender_key_vec = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&sender_id, "Key", 16)?,
            16,
        )?;
        let recipient_key_vec = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&recipient_id, "Key", 16)?,
            16,
        )?;
        let common_iv_vec = hkdf(
            &master_secret,
            &master_salt,
            &build_info(&[], "IV", 13)?,
            13,
        )?;
        let mut sender_key = [0; KEY_LEN];
        sender_key.copy_from_slice(&sender_key_vec);
        let mut recipient_key = [0; KEY_LEN];
        recipient_key.copy_from_slice(&recipient_key_vec);
        let mut common_iv = [0; NONCE_LEN];
        common_iv.copy_from_slice(&common_iv_vec);

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

    /// Returns the byte representation of the partial IV.
    pub fn get_piv(&self) -> Vec<u8> {
        // Convert the sender sequence number to its byte representation
        let bytes = self.sender_context.sender_sequence_number.to_be_bytes();
        // Find the index of the first byte that is not zero
        let first_nonzero = bytes.iter().position(|&x| x != 0);
        match first_nonzero {
            // If there is one, skip leading zero bytes and return the others
            Some(n) => bytes[n..].to_vec(),
            // If there isn't, we simply return 0
            None => vec![0x00],
        }
    }

    /// Returns an OSCORE message based on the original CoAP request.
    ///
    /// # Arguments
    /// * `coap_msg` - The original CoAP message to protect.
    pub fn protect_request(&mut self, coap_msg: &[u8]) -> Result<Vec<u8>> {
        // Store piv for this execution
        let piv = self.get_piv();
        // Compute the AAD
        let aad = build_aad(&self.sender_context.sender_id, &piv)?;

        // Build nonce from own sender context
        let nonce = compute_nonce(
            &piv,
            &self.sender_context.sender_id,
            &self.common_context.common_iv,
        );

        // Encode the kid and piv in the OSCORE option
        let option = build_oscore_option(
            Some(&self.sender_context.sender_id),
            Some(&piv),
        );
        self.sender_context.sender_sequence_number += 1;

        // Use these values to protect the message
        self.protect_message(coap_msg, &aad, nonce, option)
    }

    /// Returns an OSCORE message based on the original CoAP response.
    ///
    /// # Arguments
    /// * `coap_msg` - The original CoAP message to protect.
    /// * `request_kid` - The request's `kid`.
    /// * `request_piv` - The request's `piv`.
    /// * `reuse_piv` - Whether the request's `piv` should be reused. Otherwise
    ///   the own `sender_sequence_number` will be used.
    pub fn protect_response(
        &mut self,
        coap_msg: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
        reuse_piv: bool,
    ) -> Result<Vec<u8>> {
        // Store piv for this execution
        let piv = self.get_piv();
        // Compute the AAD
        let aad = build_aad(request_kid, request_piv)?;

        // Decide on the nonce and option value
        let (nonce, option) = if reuse_piv {
            // We're reusing the request's piv:
            // Same nonce, empty OSCORE option since there's no change
            (
                compute_nonce(
                    request_piv,
                    &self.recipient_context.recipient_id,
                    &self.common_context.common_iv,
                ),
                build_oscore_option(None, None),
            )
        } else {
            // We're not reusing the request's piv:
            // Build nonce from own sender context, transmit piv but no kid
            let result = (
                compute_nonce(
                    &piv,
                    &self.sender_context.sender_id,
                    &self.common_context.common_iv,
                ),
                build_oscore_option(None, Some(&piv)),
            );
            // Since we used our sender context, increment the sequence number
            self.sender_context.sender_sequence_number += 1;
            result
        };

        // Use these values to protect the message
        self.protect_message(coap_msg, &aad, nonce, option)
    }

    /// Returns the protected OSCORE message for the given parameters.
    ///
    /// # Arguments
    /// * `coap_msg` - The original CoAP message to protect.
    /// * `aad` - The AAD for the AEAD.
    /// * `nonce` - The AEAD nonce to use.
    /// * `option` - The value of the OSCORE option.
    fn protect_message(
        &self,
        coap_msg: &[u8],
        aad: &[u8],
        nonce: [u8; NONCE_LEN],
        option: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // Parse the CoAP message TODO: figure out the error situation
        let mut original = Packet::from_bytes(coap_msg).unwrap();
        // Initialize a new CoAP message to store the protected parts
        let mut inner = Packet::new();

        // Move the code into the inner message
        inner.header.code = original.header.code;
        // Replace the outer code
        original.header.code = match original.header.code {
            // All responses get Changed
            MessageClass::Response(_) => {
                MessageClass::Response(ResponseType::Changed)
            }
            // All requests (and unknown + reserved) get POST
            _ => MessageClass::Request(RequestType::Post),
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
        // Convert the inner message to its byte representation
        // TODO: error handling
        let mut inner_bytes = inner.to_bytes().unwrap();
        // Remove the message ID and the token (if it exists)
        let tkl = inner.header.get_token_length();
        inner_bytes.drain(2..4 + tkl as usize);
        // Remove the first header byte
        inner_bytes.remove(0);

        // Encrypt the payload
        let ccm =
            CcmMode::new(&self.sender_context.sender_key, nonce, MAC_LEN)?;
        let mut ciphertext_buf = vec![0; inner_bytes.len() + MAC_LEN];
        ccm.generate_encrypt(&mut ciphertext_buf, &aad, &inner_bytes)?;
        // Set the ciphertext as the new payload
        original.payload = ciphertext_buf;

        // Add the OSCORE option
        original.add_option(CoapOption::Oscore, option);

        // TODO: error handling
        Ok(original.to_bytes().unwrap())
    }

    #[cfg(test)]
    pub fn set_sender_sequence_number(&mut self, n: u64) {
        self.sender_context.sender_sequence_number = n;
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

/// Returns the nonce for the AEAD.
fn compute_nonce(
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

// TODO: Better integration with improved coap module in the future
static CLASS_U: [usize; 4] = [3, 7, 35, 39];
static UNSUPPORTED: [usize; 6] = [6, 23, 27, 28, 60, 258];

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8613 test vectors & examples ---------------------------------------

    // AAD example

    const EXAMPLE_KID: [u8; 1] = [0x00];
    const EXAMPLE_PIV: [u8; 1] = [0x25];
    const EXAMPLE_AAD_ARR: [u8; 9] =
        [0x85, 0x01, 0x81, 0x0A, 0x41, 0x00, 0x41, 0x25, 0x40];
    const EXAMPLE_AAD: [u8; 21] = [
        0x83, 0x68, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40,
        0x49, 0x85, 0x01, 0x81, 0x0A, 0x41, 0x00, 0x41, 0x25, 0x40,
    ];

    // COSE compression (OSCORE option) examples

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

    // Test vector 1

    const MASTER_SECRET: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];
    const MASTER_SALT: [u8; 8] =
        [0x9E, 0x7C, 0xA9, 0x22, 0x23, 0x78, 0x63, 0x40];
    const CLIENT_ID: [u8; 0] = [];
    const SERVER_ID: [u8; 1] = [0x01];
    const INFO_CLIENT_KEY: [u8; 9] =
        [0x85, 0x40, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_SERVER_KEY: [u8; 10] =
        [0x85, 0x41, 0x01, 0xF6, 0x0A, 0x63, 0x4B, 0x65, 0x79, 0x10];
    const INFO_COMMON_IV: [u8; 8] =
        [0x85, 0x40, 0xF6, 0x0A, 0x62, 0x49, 0x56, 0x0D];
    const CLIENT_KEY: [u8; 16] = [
        0xF0, 0x91, 0x0E, 0xD7, 0x29, 0x5E, 0x6A, 0xD4, 0xB5, 0x4F, 0xC7,
        0x93, 0x15, 0x43, 0x02, 0xFF,
    ];
    const SERVER_KEY: [u8; 16] = [
        0xFF, 0xB1, 0x4E, 0x09, 0x3C, 0x94, 0xC9, 0xCA, 0xC9, 0x47, 0x16,
        0x48, 0xB4, 0xF9, 0x87, 0x10,
    ];
    const COMMON_IV: [u8; 13] = [
        0x46, 0x22, 0xD4, 0xDD, 0x6D, 0x94, 0x41, 0x68, 0xEE, 0xFB, 0x54,
        0x98, 0x7C,
    ];
    const CLIENT_NONCE: [u8; 13] = [
        0x46, 0x22, 0xD4, 0xDD, 0x6D, 0x94, 0x41, 0x68, 0xEE, 0xFB, 0x54,
        0x98, 0x68,
    ];
    const SERVER_NONCE: [u8; 13] = [
        0x47, 0x22, 0xD4, 0xDD, 0x6D, 0x94, 0x41, 0x69, 0xEE, 0xFB, 0x54,
        0x98, 0x7C,
    ];

    // Test vector 4 (uses context from test vector 1)

    const REQ_UNPROTECTED: [u8; 22] = [
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    ];
    const REQ_SSN: u64 = 20;
    const REQ_PIV: [u8; 1] = [0x14];
    const REQ_AAD_ARR: [u8; 8] =
        [0x85, 0x01, 0x81, 0x0A, 0x40, 0x41, 0x14, 0x40];
    const REQ_AAD: [u8; 20] = [
        0x83, 0x68, 0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40,
        0x48, 0x85, 0x01, 0x81, 0x0A, 0x40, 0x41, 0x14, 0x40,
    ];
    const REQ_PROTECTED: [u8; 35] = [
        0x44, 0x02, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x62, 0x09, 0x14, 0xFF,
        0x61, 0x2F, 0x10, 0x92, 0xF1, 0x77, 0x6F, 0x1C, 0x16, 0x68, 0xB3,
        0x82, 0x5E,
    ];

    // Test vector 7 (uses context from test vector 1 & parts from vector 4)

    const RES_UNPROTECTED: [u8; 21] = [
        0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65,
        0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ];
    const RES_SSN: u64 = 0;
    const RES_PROTECTED: [u8; 32] = [
        0x64, 0x44, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x90, 0xFF, 0xDB,
        0xAA, 0xD1, 0xE9, 0xA7, 0xE7, 0xB2, 0xA8, 0x13, 0xD3, 0xC3, 0x15,
        0x24, 0x37, 0x83, 0x03, 0xCD, 0xAF, 0xAE, 0x11, 0x91, 0x06,
    ];

    // Test vector 8 (like test vector 7, but with PIV)

    const RES_PIV: [u8; 1] = [0x00];
    const RES_PIV_PROTECTED: [u8; 34] = [
        0x64, 0x44, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x92, 0x01, 0x00,
        0xFF, 0x4D, 0x4C, 0x13, 0x66, 0x93, 0x84, 0xB6, 0x73, 0x54, 0xB2,
        0xB6, 0x17, 0x5F, 0xF4, 0xB8, 0x65, 0x8C, 0x66, 0x6A, 0x6C, 0xF8,
        0x8E,
    ];

    // Custom test vectors ----------------------------------------------------

    const CRASH_OPTION: [u8; 2] = [0b0000_1101, 0x01];
    const SERVER_NONCE_LONG_PIV: [u8; 13] = [
        0x41, 0x22, 0xD4, 0xDD, 0x6D, 0x94, 0x41, 0x69, 0xEE, 0xFB, 0x54,
        0x98, 0x7C,
    ];
    const SERVER_ID_LONG: [u8; 10] =
        [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

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
    fn context_derivation() {
        let security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            CLIENT_ID.to_vec(),
            SERVER_ID.to_vec(),
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

        assert_eq!(&CLIENT_ID, &security_context.sender_context.sender_id[..]);
        assert_eq!(
            &CLIENT_KEY,
            &security_context.sender_context.sender_key[..]
        );
        assert_eq!(0, security_context.sender_context.sender_sequence_number);

        assert_eq!(
            &SERVER_ID,
            &security_context.recipient_context.recipient_id[..]
        );
        assert_eq!(
            &SERVER_KEY,
            &security_context.recipient_context.recipient_key[..]
        );
        assert_eq!(0, security_context.recipient_context.replay_window);
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
        let mut ctx = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            CLIENT_ID.to_vec(),
            SERVER_ID.to_vec(),
        )
        .unwrap();
        assert_eq!([0], ctx.get_piv()[..]);

        ctx.set_sender_sequence_number(0xFF);
        assert_eq!([0xFF], ctx.get_piv()[..]);

        ctx.set_sender_sequence_number(0xFF + 1);
        assert_eq!([0x01, 0x00], ctx.get_piv()[..]);
    }

    #[test]
    fn protection() {
        let mut req_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            CLIENT_ID.to_vec(),
            SERVER_ID.to_vec(),
        )
        .unwrap();
        req_security_context.set_sender_sequence_number(REQ_SSN);
        assert_eq!(
            &REQ_PROTECTED[..],
            &req_security_context
                .protect_request(&REQ_UNPROTECTED)
                .unwrap()[..]
        );

        let mut res_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SERVER_ID.to_vec(),
            CLIENT_ID.to_vec(),
        )
        .unwrap();
        assert_eq!(
            &RES_PROTECTED[..],
            &res_security_context
                .protect_response(&RES_UNPROTECTED, &CLIENT_ID, &REQ_PIV, true)
                .unwrap()[..]
        );

        let mut res_piv_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SERVER_ID.to_vec(),
            CLIENT_ID.to_vec(),
        )
        .unwrap();
        assert_eq!(
            &RES_PIV_PROTECTED[..],
            &res_piv_security_context
                .protect_response(
                    &RES_UNPROTECTED,
                    &CLIENT_ID,
                    &REQ_PIV,
                    false
                )
                .unwrap()[..]
        );
    }
}
