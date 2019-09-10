use aes_ccm::CcmMode;
use alloc::vec::Vec;
use coap_lite::{CoapOption, MessageClass, Packet, RequestType, ResponseType};
use core::convert::{TryFrom, TryInto};

use super::util;
use crate::{error::Error, Result};

/// The common context part of the security context.
struct CommonContext {
    master_secret: Vec<u8>,
    master_salt: Vec<u8>,
    common_iv: [u8; util::NONCE_LEN],
}

/// The sender context part of the security context.
struct SenderContext {
    sender_id: Vec<u8>,
    sender_key: [u8; util::KEY_LEN],
    sender_sequence_number: u64,
}

/// The recipient context part of the security context.
struct RecipientContext {
    recipient_id: Vec<u8>,
    recipient_key: [u8; util::KEY_LEN],
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

// TODO: Better integration with improved coap module in the future
static CLASS_U: [usize; 4] = [3, 7, 35, 39];
static UNSUPPORTED: [usize; 6] = [6, 23, 27, 28, 60, 258];

impl SecurityContext {
    /// Creates a new `SecurityContext`.
    pub fn new(
        master_secret: Vec<u8>,
        master_salt: Vec<u8>,
        sender_id: Vec<u8>,
        recipient_id: Vec<u8>,
    ) -> Result<SecurityContext> {
        // Derive the keys and IV
        let sender_key_vec = util::hkdf(
            &master_secret,
            &master_salt,
            &util::build_info(&sender_id, "Key", 16)?,
            16,
        )?;
        let recipient_key_vec = util::hkdf(
            &master_secret,
            &master_salt,
            &util::build_info(&recipient_id, "Key", 16)?,
            16,
        )?;
        let common_iv_vec = util::hkdf(
            &master_secret,
            &master_salt,
            &util::build_info(&[], "IV", 13)?,
            13,
        )?;
        let mut sender_key = [0; util::KEY_LEN];
        sender_key.copy_from_slice(&sender_key_vec);
        let mut recipient_key = [0; util::KEY_LEN];
        recipient_key.copy_from_slice(&recipient_key_vec);
        let mut common_iv = [0; util::NONCE_LEN];
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

    /// Returns an OSCORE message based on the original CoAP request.
    ///
    /// # Arguments
    /// * `coap_msg` - The original CoAP request to protect.
    pub fn protect_request(&mut self, coap_msg: &[u8]) -> Result<Vec<u8>> {
        // Store piv for this execution
        let piv = self.get_piv();

        // Compute the AAD
        let aad = util::build_aad(&self.sender_context.sender_id, &piv)?;

        // Build nonce from own sender context
        let nonce = util::compute_nonce(
            &piv,
            &self.sender_context.sender_id,
            &self.common_context.common_iv,
        );
        // Encode the kid and piv in the OSCORE option
        let option = util::build_oscore_option(
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
    /// * `coap_msg` - The original CoAP response to protect.
    /// * `request` - The OSCORE request to which to respond. Necessary to
    ///   extract `kid` and `piv` values.
    /// * `reuse_piv` - Whether the request's `piv` should be reused. Otherwise
    ///   the own `sender_sequence_number` will be used.
    pub fn protect_response(
        &mut self,
        coap_msg: &[u8],
        request: &[u8],
        reuse_piv: bool,
    ) -> Result<Vec<u8>> {
        // Store piv for this execution
        let piv = self.get_piv();

        let request = Packet::from_bytes(request)?;
        // Extract the kid and piv from the OSCORE option
        let option = request
            .get_option(CoapOption::Oscore)
            .ok_or(Error::NoOscoreOption)?
            .front()
            .ok_or(Error::NoOscoreOption)?;
        let (request_kid, request_piv) = util::extract_oscore_option(option);
        let (request_kid, request_piv) = (
            request_kid.ok_or(Error::NoKidPiv)?,
            request_piv.ok_or(Error::NoKidPiv)?,
        );

        // Compute the AAD
        let aad = util::build_aad(&request_kid, &request_piv)?;

        // Decide on the nonce and option value
        let (nonce, option) = if reuse_piv {
            // We're reusing the request's piv:
            // Same nonce, empty OSCORE option since there's no change
            (
                util::compute_nonce(
                    &request_piv,
                    &self.recipient_context.recipient_id,
                    &self.common_context.common_iv,
                ),
                util::build_oscore_option(None, None),
            )
        } else {
            // We're not reusing the request's piv:
            // Build nonce from own sender context, transmit piv but no kid
            let result = (
                util::compute_nonce(
                    &piv,
                    &self.sender_context.sender_id,
                    &self.common_context.common_iv,
                ),
                util::build_oscore_option(None, Some(&piv)),
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
        nonce: [u8; util::NONCE_LEN],
        option: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // Parse the CoAP message
        let mut original = Packet::from_bytes(coap_msg)?;
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
            // TODO: Better integration with coap module, error handling
            let option = CoapOption::try_from(*number).unwrap();
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
        inner.payload = original.payload;
        // Convert the inner message to its byte representation
        let mut inner_bytes = inner.to_bytes()?;
        // Remove the message ID and the token (if it exists)
        let tkl = inner.header.get_token_length();
        inner_bytes.drain(2..4 + tkl as usize);
        // Remove the first header byte
        inner_bytes.remove(0);

        // Encrypt the payload
        let ccm = CcmMode::new(
            &self.sender_context.sender_key,
            nonce,
            util::MAC_LEN,
        )?;
        let mut ciphertext_buf = vec![0; inner_bytes.len() + util::MAC_LEN];
        ccm.generate_encrypt(&mut ciphertext_buf, &aad, &inner_bytes)?;
        // Set the ciphertext as the new payload
        original.payload = ciphertext_buf;

        // Add the OSCORE option
        original.add_option(CoapOption::Oscore, option);

        Ok(original.to_bytes()?)
    }

    /// Returns the original CoAP request protected in the OSCORE message.
    ///
    /// # Arguments
    /// * `oscore_msg` - The OSCORE message protecting the CoAP request.
    fn unprotect_request(&mut self, oscore_msg: &[u8]) -> Result<Vec<u8>> {
        // Parse the CoAP message
        let mut original = Packet::from_bytes(oscore_msg)?;

        // Extract the kid and piv from the OSCORE option
        let option = original
            .get_option(CoapOption::Oscore)
            .ok_or(Error::NoOscoreOption)?
            .front()
            .ok_or(Error::NoOscoreOption)?;
        let (request_kid, request_piv) = util::extract_oscore_option(option);
        let (request_kid, request_piv) = (
            request_kid.ok_or(Error::NoKidPiv)?,
            request_piv.ok_or(Error::NoKidPiv)?,
        );

        // Store which options we remove from the outer message in this
        let mut to_discard = vec![];
        // Go over options, remembering class E ones to discard
        for (number, _) in original.options() {
            // Abort on unimplemented optional features
            if UNSUPPORTED.contains(number) {
                // TODO: Error instead of panic
                unimplemented!("Option {}", number);
            }
            // Skip class U options
            if CLASS_U.contains(number) {
                continue;
            }

            // At this point the option is class E or undefined, so discard it
            // TODO: Better integration with coap module, error handling
            let option = CoapOption::try_from(*number).unwrap();
            to_discard.push(option);
        }
        // Discard class E options
        for option in to_discard {
            original.clear_option(option);
        }

        // Verify that the partial IV has not been received before
        if self.recipient_context.replay_window
            == util::piv_to_u64(&request_piv)
        {
            return Err(Error::ReplayDetected);
        }

        // Compute the AAD
        let aad = util::build_aad(&request_kid, &request_piv)?;

        // Compute the nonce
        let nonce = util::compute_nonce(
            &request_piv,
            &self.recipient_context.recipient_id,
            &self.common_context.common_iv,
        );

        // Decrypt the payload
        let ccm = CcmMode::new(
            &self.recipient_context.recipient_key,
            nonce,
            util::MAC_LEN,
        )?;
        let mut plaintext_buf =
            vec![0; original.payload.len() - util::MAC_LEN];
        ccm.decrypt_verify(&mut plaintext_buf, &aad, &original.payload)?;

        // Build a CoAP message from the bytes of the plaintext, which contain
        // the code, class E options and the payload
        // [ver_t_tkl, code, message_id, message_id]
        let mut inner = vec![0x40, plaintext_buf[0], 0x00, 0x00];
        inner.extend(&plaintext_buf[1..]);
        // Parse the CoAP message
        let inner = Packet::from_bytes(&inner)?;
        // Set the code from the inner message
        original.header.code = inner.header.code;
        // Set the options from the inner message
        for (number, value_list) in inner.options() {
            // TODO: error handling
            original
                .set_option((*number).try_into().unwrap(), value_list.clone());
        }
        // Set the payload from the inner message
        original.payload = inner.payload;

        Ok(original.to_bytes()?)
    }

    /// Returns the byte representation of the partial IV.
    fn get_piv(&self) -> Vec<u8> {
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

    #[cfg(test)]
    pub fn set_sender_sequence_number(&mut self, n: u64) {
        self.sender_context.sender_sequence_number = n;
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_vectors::*;
    use super::*;

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
                .protect_response(&RES_UNPROTECTED, &REQ_PROTECTED, true)
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
                .protect_response(&RES_UNPROTECTED, &REQ_PROTECTED, false)
                .unwrap()[..]
        );
    }

    #[test]
    fn unprotection() {
        let mut req_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SERVER_ID.to_vec(),
            CLIENT_ID.to_vec(),
        )
        .unwrap();
        assert_eq!(
            &REQ_UNPROTECTED[..],
            &req_security_context
                .unprotect_request(&REQ_PROTECTED)
                .unwrap()[..]
        );
    }
}
