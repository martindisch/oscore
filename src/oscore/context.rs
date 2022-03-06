
use aes::Aes128;
use alloc::{collections::LinkedList, vec::Vec};
use ccm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    consts::{U13, U8},
    Ccm,
};
use coap_lite::{CoapOption, MessageClass, Packet, RequestType, ResponseType};
use core::convert::TryFrom;

use super::{
    error::Error,
    util::{self, ProxyUri},
    Result,
};

/// The common context part of the security context.
struct CommonContext {
    // Master secret and salt are unused, hence not part of this
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
    replay_window: Option<u64>,
}

/// The security context.
pub struct SecurityContext {
    common_context: CommonContext,
    sender_context: SenderContext,
    recipient_context: RecipientContext,
}

/// The known class U options that have to remain public.
static CLASS_U: [CoapOption; 4] = [
    CoapOption::UriHost,
    CoapOption::UriPort,
    CoapOption::ProxyUri,
    CoapOption::ProxyScheme,
];
/// The optional options that we don't support.
static UNSUPPORTED: [CoapOption; 6] = [
    CoapOption::Observe,
    CoapOption::Block2,
    CoapOption::Block1,
    CoapOption::Size2,
    CoapOption::Size1,
    CoapOption::NoResponse,
];

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
        let common_context = CommonContext { common_iv };
        let sender_context = SenderContext {
            sender_id,
            sender_key,
            sender_sequence_number: 0,
        };
        let recipient_context = RecipientContext {
            recipient_id,
            recipient_key,
            replay_window: None,
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

        // Parse the request to which we respond
        let request = Packet::from_bytes(request)?;
        // Extract the kid and piv from its OSCORE option
        let (request_kid, request_piv) = util::extract_kid_piv(&request)?;
        // This is a request, so they need to be present
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

        // Proxy-Uri handling if it's present
        if let Some(proxy_uri) = original.get_option(CoapOption::ProxyUri) {
            // Obtain and parse it
            let proxy_uri = proxy_uri.front().ok_or(Error::InvalidProxyUri)?;
            let proxy_uri = ProxyUri::try_from(proxy_uri.as_slice())?;

            // If there's a Uri-Path or Uri-Query, add them to the options and
            // they will be protected in the next stage
            if let Some(path_list) = proxy_uri.get_path_list() {
                original.set_option(CoapOption::UriPath, path_list);
            }
            if let Some(query_list) = proxy_uri.get_query_list() {
                original.set_option(CoapOption::UriQuery, query_list);
            }

            // Compose the remaining parts into the Proxy-Uri, which will
            // remain public
            let mut uri_list = LinkedList::new();
            uri_list.push_back(proxy_uri.compose_proxy_uri());
            original.set_option(CoapOption::ProxyUri, uri_list);
        }

        // Store which options we remove from the outer message in this
        let mut moved_options = vec![];
        // Go over options, moving class E ones into the inner message
        for (number, value_list) in original.options() {
            let option = CoapOption::from(*number);

            // Abort on unimplemented optional features
            if UNSUPPORTED.contains(&option) {
                return Err(Error::UnsupportedOption(option));
            }
            // Skip class U options
            if CLASS_U.contains(&option) {
                continue;
            }

            // At this point the option is class E or undefined, so protect it
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
        let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(
            &self.sender_context.sender_key,
        ));
        let ciphertext_buf = ccm.encrypt(
            &nonce.into(),
            Payload {
                aad,
                msg: &inner_bytes,
            },
        )?;
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
    pub fn unprotect_request(&mut self, oscore_msg: &[u8]) -> Result<Vec<u8>> {
        // Parse the CoAP message
        let original = Packet::from_bytes(oscore_msg)?;
        // Extract the kid and piv from the OSCORE option
        let (request_kid, request_piv) = util::extract_kid_piv(&original)?;
        // This is a request, so they need to be present
        let (request_kid, request_piv) = (
            request_kid.ok_or(Error::NoKidPiv)?,
            request_piv.ok_or(Error::NoKidPiv)?,
        );

        // Verify that the partial IV has not been received before
        self.check_and_remember(&request_piv)?;

        // Compute the AAD
        let aad = util::build_aad(&request_kid, &request_piv)?;

        // Compute the nonce
        let nonce = util::compute_nonce(
            &request_piv,
            &self.recipient_context.recipient_id,
            &self.common_context.common_iv,
        );

        // Use these values to protect the message
        self.unprotect_message(original, &aad, nonce)
    }

    /// Returns the original CoAP response protected in the OSCORE message.
    ///
    /// # Arguments
    /// * `oscore_msg` - The OSCORE message protecting the CoAP response.
    pub fn unprotect_response(
        &mut self,
        oscore_msg: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the CoAP message
        let original = Packet::from_bytes(oscore_msg)?;
        // Attempt to extract the piv from the OSCORE option
        let (_, request_piv) = util::extract_kid_piv(&original)?;
        // If we don't reuse the request's piv, extract it from the response
        let (kid, piv) = match request_piv {
            // Using the sender's kid & piv
            Some(piv) => (&self.recipient_context.recipient_id, piv),
            // Using our kid & piv
            None => (&self.sender_context.sender_id, self.get_last_piv()),
        };

        // Compute the AAD
        let aad = util::build_aad(
            &self.sender_context.sender_id,
            &self.get_last_piv(),
        )?;

        // Compute the nonce
        let nonce =
            util::compute_nonce(&piv, kid, &self.common_context.common_iv);

        // Use these values to protect the message
        self.unprotect_message(original, &aad, nonce)
    }

    /// Returns the original CoAP message protected in the OSCORE message.
    /// # Arguments
    /// * `oscore_msg` - The OSCORE message protecting the CoAP message.
    /// * `aad` - The AAD for the AEAD.
    /// * `nonce` - The AEAD nonce to use.
    fn unprotect_message(
        &mut self,
        mut original: Packet,
        aad: &[u8],
        nonce: [u8; util::NONCE_LEN],
    ) -> Result<Vec<u8>> {
        // Store which options we remove from the outer message in this
        let mut to_discard = vec![];
        // Go over options, remembering class E ones to discard
        for (number, _) in original.options() {
            let option = CoapOption::from(*number);

            // Abort on unimplemented optional features
            if UNSUPPORTED.contains(&option) {
                return Err(Error::UnsupportedOption(option));
            }
            // Skip class U options
            if CLASS_U.contains(&option) {
                continue;
            }

            // At this point the option is class E or undefined, so discard it
            to_discard.push(option);
        }
        // Discard class E options
        for option in to_discard {
            original.clear_option(option);
        }

        // Decrypt the payload
        let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(
            &self.recipient_context.recipient_key,
        ));
        let plaintext_buf = ccm.decrypt(
            &nonce.into(),
            Payload {
                aad,
                msg: &original.payload,
            },
        )?;

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
            original.set_option((*number).into(), value_list.clone());
        }
        // Set the payload from the inner message
        original.payload = inner.payload;

        Ok(original.to_bytes()?)
    }

    /// Throws an error if the `piv` has been received before and adds it to
    /// the replay window.
    fn check_and_remember(&mut self, piv: &[u8]) -> Result<()> {
        let piv_64 = util::piv_to_u64(piv);
        if let Some(previous) = self.recipient_context.replay_window {
            if previous == piv_64 {
                #[cfg(not(feature = "no_replay"))]
                return Err(Error::ReplayDetected);
            }
        }
        // Remember it
        self.recipient_context.replay_window = Some(piv_64);

        Ok(())
    }

    /// Returns the byte representation of the partial IV.
    fn get_piv(&self) -> Vec<u8> {
        util::format_piv(self.sender_context.sender_sequence_number)
    }

    /// Returns the byte representation of the partial IV.
    fn get_last_piv(&self) -> Vec<u8> {
        util::format_piv(self.sender_context.sender_sequence_number - 1)
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
        assert_eq!(None, security_context.recipient_context.replay_window);
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
        // No need to reinitialize the security context, because the previous
        // protection didn't increment the sender sequence number
        assert_eq!(
            &RES_PIV_PROTECTED[..],
            &res_security_context
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

        let mut res_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            CLIENT_ID.to_vec(),
            SERVER_ID.to_vec(),
        )
        .unwrap();
        res_security_context.set_sender_sequence_number(REQ_SSN + 1);
        assert_eq!(
            &RES_UNPROTECTED[..],
            &res_security_context
                .unprotect_response(&RES_PROTECTED)
                .unwrap()[..]
        );
        assert_eq!(
            &RES_UNPROTECTED[..],
            &res_security_context
                .unprotect_response(&RES_PIV_PROTECTED)
                .unwrap()[..]
        );
    }

    #[test]
    fn proxying() {
        let mut req_ctx = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            CLIENT_ID.to_vec(),
            SERVER_ID.to_vec(),
        )
        .unwrap();
        let mut res_ctx = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SERVER_ID.to_vec(),
            CLIENT_ID.to_vec(),
        )
        .unwrap();

        let mut packet = Packet::new();
        packet.add_option(
            CoapOption::ProxyUri,
            "coap://example.com:9999/path/to/resource?q=1&p=2"
                .as_bytes()
                .to_vec(),
        );
        let protected_bytes = &req_ctx
            .protect_request(&packet.to_bytes().unwrap())
            .unwrap();
        let protected_coap = Packet::from_bytes(protected_bytes).unwrap();
        // Check the only unprotected options are the OSCORE option and
        // the new Proxy-Uri
        assert_eq!(2, protected_coap.options().len());
        // Check the Proxy-Uri contains only the public part
        assert_eq!(
            b"coap://example.com:9999",
            &protected_coap
                .get_option(CoapOption::ProxyUri)
                .unwrap()
                .front()
                .unwrap()[..]
        );

        let unprotected_bytes =
            &res_ctx.unprotect_request(protected_bytes).unwrap();
        let unprotected_coap = Packet::from_bytes(unprotected_bytes).unwrap();
        let mut uri_path = LinkedList::new();
        uri_path.push_back("path".as_bytes().to_vec());
        uri_path.push_back("to".as_bytes().to_vec());
        uri_path.push_back("resource".as_bytes().to_vec());
        let mut uri_query = LinkedList::new();
        uri_query.push_back("q=1".as_bytes().to_vec());
        uri_query.push_back("p=2".as_bytes().to_vec());
        assert_eq!(
            &uri_path,
            unprotected_coap.get_option(CoapOption::UriPath).unwrap()
        );
        assert_eq!(
            &uri_query,
            unprotected_coap.get_option(CoapOption::UriQuery).unwrap()
        );
    }

    #[test]
    fn replay() {
        let mut req_security_context = SecurityContext::new(
            MASTER_SECRET.to_vec(),
            MASTER_SALT.to_vec(),
            SERVER_ID.to_vec(),
            CLIENT_ID.to_vec(),
        )
        .unwrap();

        assert!(req_security_context
            .unprotect_request(&REQ_PROTECTED)
            .is_ok());
        assert!(req_security_context
            .unprotect_request(&REQ_PROTECTED)
            .is_err())
    }
}
