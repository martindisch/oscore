use alloc::vec::Vec;
use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{cbor, cose, edhoc, Result};

use edhoc::{
    util,
    util::{Message1, Message2, Message3},
};

pub struct Msg1Sender {
    u_c_u: Vec<u8>,
    u_secret: StaticSecret,
    u_x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Sender {
    pub fn new(
        c_u: &[u8],
        ecdh_secret: [u8; 32],
        auth: [u8; 64],
        kid: &[u8],
    ) -> Msg1Sender {
        // The corresponding DH secret
        let u_secret = StaticSecret::from(ecdh_secret);
        // The corresponding public key
        let u_x_u = PublicKey::from(&u_secret);

        Msg1Sender {
            u_c_u: c_u.to_vec(),
            u_secret,
            u_x_u,
            auth,
            kid: kid.to_vec(),
        }
    }

    pub fn generate_message_1(self) -> (Vec<u8>, Msg2Receiver) {
        // Encode the necessary information into the first message
        let u_msg_1 = Message1 {
            // This would be the case in CoAP, where party U can correlate
            // message_1 and message_2 with the token
            r#type: 1,
            suite: 0,
            x_u: self.u_x_u.as_bytes().to_vec(),
            c_u: self.u_c_u,
        };
        // Get CBOR sequence for message
        let u_msg_1_seq = util::serialize_message_1(&u_msg_1).unwrap();
        // Wrap it in a bstr for transmission
        let msg_1_bytes = cbor::encode(Bytes::new(&u_msg_1_seq)).unwrap();

        (
            msg_1_bytes,
            Msg2Receiver {
                u_msg_1_seq,
                u_secret: self.u_secret,
                u_x_u: self.u_x_u,
                u_msg_1,
                auth: self.auth,
                kid: self.kid,
            },
        )
    }
}

pub struct Msg1Receiver {
    v_c_v: Vec<u8>,
    v_secret: StaticSecret,
    v_x_v: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Receiver {
    pub fn new(
        c_v: &[u8],
        ecdh_secret: [u8; 32],
        auth: [u8; 64],
        kid: &[u8],
    ) -> Msg1Receiver {
        // The corresponding DH secret
        let v_secret = StaticSecret::from(ecdh_secret);
        // The corresponding public key
        let v_x_v = PublicKey::from(&v_secret);

        Msg1Receiver {
            v_c_v: c_v.to_vec(),
            v_secret,
            v_x_v,
            auth,
            kid: kid.to_vec(),
        }
    }

    pub fn handle_message_1(self, msg_1: &mut [u8]) -> Msg2Sender {
        // Unwrap sequence from bstr
        let v_msg_1_seq: ByteBuf = cbor::decode(msg_1).unwrap();
        // Decode the first message
        let v_msg_1 = util::deserialize_message_1(&v_msg_1_seq).unwrap();
        // Verify that the selected suite is supported
        if v_msg_1.suite != 0 {
            unimplemented!("Other cipher suites");
        }
        // Use U's public key to generate the ephemeral shared secret
        let mut v_x_u_bytes = [0; 32];
        v_x_u_bytes.copy_from_slice(&v_msg_1.x_u[..32]);
        let v_u_public = x25519_dalek::PublicKey::from(v_x_u_bytes);
        let v_shared_secret = self.v_secret.diffie_hellman(&v_u_public);

        Msg2Sender {
            v_msg_1,
            v_x_v: self.v_x_v,
            v_msg_1_seq: v_msg_1_seq.into_vec(),
            v_shared_secret,
            v_c_v: self.v_c_v,
            auth: self.auth,
            kid: self.kid,
        }
    }
}

pub struct Msg2Sender {
    v_msg_1: Message1,
    v_x_v: PublicKey,
    v_c_v: Vec<u8>,
    v_msg_1_seq: Vec<u8>,
    v_shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg2Sender {
    pub fn generate_message_2(self) -> (Vec<u8>, Msg3Receiver) {
        // Determine whether to include c_u in message_2 or not
        let v_c_u =
            if self.v_msg_1.r#type % 4 == 1 || self.v_msg_1.r#type % 4 == 3 {
                None
            } else {
                Some(self.v_msg_1.c_u.clone())
            };

        // Build the COSE header map identifying the public authentication key
        let v_id_cred_v = cose::build_id_cred_x(&self.kid).unwrap();
        // Build the COSE_Key containing our ECDH public key
        let v_cred_v =
            cose::serialize_cose_key(self.v_x_v.as_bytes(), &self.kid)
                .unwrap();
        // Compute TH_2
        let v_th_2 = util::compute_th_2(
            &self.v_msg_1_seq,
            as_deref(&v_c_u),
            self.v_x_v.as_bytes(),
            &self.v_c_v,
        )
        .unwrap();
        // Sign it
        let v_sig =
            cose::sign(&v_id_cred_v, &v_th_2, &v_cred_v, &self.auth).unwrap();

        // Derive K_2
        let v_k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &v_th_2,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_2
        let v_iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &v_th_2,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();

        // Put together the plaintext for the encryption
        let v_plaintext = util::build_plaintext(&self.kid, &v_sig).unwrap();
        // Compute the associated data
        let v_ad = cose::build_ad(&v_th_2).unwrap();
        // Get the ciphertext
        let v_ciphertext =
            util::aead_seal(&v_k_2, &v_iv_2, &v_plaintext, &v_ad).unwrap();

        // Produce message_2
        let v_msg_2 = Message2 {
            c_u: v_c_u,
            x_v: self.v_x_v.as_bytes().to_vec(),
            c_v: self.v_c_v.to_vec(),
            ciphertext: v_ciphertext,
        };
        // Get CBOR sequence for message
        let v_msg_2_seq = util::serialize_message_2(&v_msg_2).unwrap();
        // Wrap it in a bstr for transmission
        let msg_2_bytes = cbor::encode(Bytes::new(&v_msg_2_seq)).unwrap();

        (
            msg_2_bytes,
            Msg3Receiver {
                v_th_2,
                v_msg_1: self.v_msg_1,
                v_msg_2,
                v_shared_secret: self.v_shared_secret,
            },
        )
    }
}

pub struct Msg2Receiver {
    u_msg_1_seq: Vec<u8>,
    u_secret: StaticSecret,
    u_x_u: PublicKey,
    u_msg_1: Message1,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg2Receiver {
    pub fn handle_message_2(
        self,
        msg_2: &mut [u8],
        v_public: [u8; 32],
    ) -> Msg3Sender {
        // Unwrap sequence from bstr
        let u_msg_2_seq: ByteBuf = cbor::decode(msg_2).unwrap();
        // Check if we don't have an error message
        util::fail_on_error_message(&u_msg_2_seq).unwrap();
        // Decode the second message
        let u_msg_2 = util::deserialize_message_2(&u_msg_2_seq).unwrap();

        // Use V's public key to generate the ephemeral shared secret
        let mut u_x_v_bytes = [0; 32];
        u_x_v_bytes.copy_from_slice(&u_msg_2.x_v[..32]);
        let u_v_public = x25519_dalek::PublicKey::from(u_x_v_bytes);
        let u_shared_secret = self.u_secret.diffie_hellman(&u_v_public);

        // Compute TH_2
        let u_th_2 = util::compute_th_2(
            &self.u_msg_1_seq,
            as_deref(&u_msg_2.c_u),
            &u_msg_2.x_v,
            &u_msg_2.c_v,
        )
        .unwrap();

        // Derive K_2
        let u_k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &u_th_2,
            u_shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_2
        let u_iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &u_th_2,
            u_shared_secret.as_bytes(),
        )
        .unwrap();

        // Compute the associated data
        let u_ad = cose::build_ad(&u_th_2).unwrap();
        // Decrypt and verify the ciphertext
        let mut u_plaintext =
            util::aead_open(&u_k_2, &u_iv_2, &u_msg_2.ciphertext, &u_ad)
                .unwrap();
        // Fetch the contents of the plaintext
        let (u_v_kid, u_v_sig) =
            util::extract_plaintext(&mut u_plaintext).unwrap();

        // Build the COSE header map identifying the public authentication key
        // of V
        let u_id_cred_v = cose::build_id_cred_x(&u_v_kid).unwrap();
        // Build the COSE_Key containing V's ECDH public key
        let u_cred_v =
            cose::serialize_cose_key(&u_msg_2.x_v, &u_v_kid).unwrap();
        // Verify the signed data from Party V
        cose::verify(&u_id_cred_v, &u_th_2, &u_cred_v, &v_public, &u_v_sig)
            .unwrap();

        Msg3Sender {
            u_th_2,
            u_x_u: self.u_x_u,
            u_msg_1: self.u_msg_1,
            u_msg_2,
            u_shared_secret,
            auth: self.auth,
            kid: self.kid,
        }
    }
}

pub struct Msg3Sender {
    u_th_2: Vec<u8>,
    u_x_u: PublicKey,
    u_msg_1: Message1,
    u_msg_2: Message2,
    u_shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg3Sender {
    pub fn generate_message_3(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Determine whether to include c_v in message_3 or not
        let u_c_v =
            if self.u_msg_1.r#type % 4 == 2 || self.u_msg_1.r#type % 4 == 3 {
                None
            } else {
                Some(self.u_msg_2.c_v.to_vec())
            };

        // Build the COSE header map identifying the public authentication key
        let u_id_cred_u = cose::build_id_cred_x(&self.kid).unwrap();
        // Build the COSE_Key containing our ECDH public key
        let u_cred_u =
            cose::serialize_cose_key(self.u_x_u.as_bytes(), &self.kid)
                .unwrap();
        // Compute TH_3
        let u_th_3 = util::compute_th_3(
            &self.u_th_2,
            &self.u_msg_2.ciphertext,
            as_deref(&u_c_v),
        )
        .unwrap();
        // Sign it
        let u_sig =
            cose::sign(&u_id_cred_u, &u_th_3, &u_cred_u, &self.auth).unwrap();

        // Derive K_3
        let u_k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &u_th_3,
            self.u_shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_3
        let u_iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &u_th_3,
            self.u_shared_secret.as_bytes(),
        )
        .unwrap();

        // Put together the plaintext for the encryption
        let u_plaintext = util::build_plaintext(&self.kid, &u_sig).unwrap();
        // Compute the associated data
        let u_ad = cose::build_ad(&u_th_3).unwrap();
        // Get the ciphertext
        let u_ciphertext =
            util::aead_seal(&u_k_3, &u_iv_3, &u_plaintext, &u_ad).unwrap();

        // Produce message_3
        let u_msg_3 = Message3 {
            c_v: u_c_v,
            ciphertext: u_ciphertext,
        };
        // Get CBOR sequence for message
        let u_msg_3_seq = util::serialize_message_3(&u_msg_3).unwrap();
        // Wrap it in a bstr for transmission
        let msg_3_bytes = cbor::encode(Bytes::new(&u_msg_3_seq)).unwrap();

        // Derive values for the OSCORE context
        let u_th_4 = util::compute_th_4(&u_th_3, &u_msg_3.ciphertext).unwrap();
        let u_master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &u_th_4,
            self.u_shared_secret.as_bytes(),
        )
        .unwrap();
        let u_master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &u_th_4,
            self.u_shared_secret.as_bytes(),
        )
        .unwrap();

        (msg_3_bytes, u_master_secret, u_master_salt)
    }
}

pub struct Msg3Receiver {
    v_th_2: Vec<u8>,
    v_msg_1: Message1,
    v_msg_2: Message2,
    v_shared_secret: SharedSecret,
}

impl Msg3Receiver {
    pub fn handle_message_3(
        &self,
        msg_3: &mut [u8],
        u_public: [u8; 32],
    ) -> (Vec<u8>, Vec<u8>) {
        // Unwrap sequence from bstr
        let v_msg_3_seq: ByteBuf = cbor::decode(msg_3).unwrap();
        // Check if we don't have an error message
        util::fail_on_error_message(&v_msg_3_seq).unwrap();
        // Decode the third message
        let v_msg_3 = util::deserialize_message_3(&v_msg_3_seq).unwrap();

        // Compute TH_3
        let v_th_3 = util::compute_th_3(
            &self.v_th_2,
            &self.v_msg_2.ciphertext,
            as_deref(&v_msg_3.c_v),
        )
        .unwrap();

        // Derive K_3
        let v_k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &v_th_3,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_3
        let v_iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &v_th_3,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();

        // Compute the associated data
        let v_ad = cose::build_ad(&v_th_3).unwrap();
        // Decrypt and verify the ciphertext
        let mut v_plaintext =
            util::aead_open(&v_k_3, &v_iv_3, &v_msg_3.ciphertext, &v_ad)
                .unwrap();
        // Fetch the contents of the plaintext
        let (v_u_kid, v_u_sig) =
            util::extract_plaintext(&mut v_plaintext).unwrap();

        // Build the COSE header map identifying the public authentication key
        // of U
        let v_id_cred_u = cose::build_id_cred_x(&v_u_kid).unwrap();
        // Build the COSE_Key containing U's ECDH public key
        let v_cred_u =
            cose::serialize_cose_key(&self.v_msg_1.x_u, &v_u_kid).unwrap();
        // Verify the signed data from Party U
        cose::verify(&v_id_cred_u, &v_th_3, &v_cred_u, &u_public, &v_u_sig)
            .unwrap();

        // Derive values for the OSCORE context
        let v_th_4 = util::compute_th_4(&v_th_3, &v_msg_3.ciphertext).unwrap();
        let v_master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &v_th_4,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();
        let v_master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &v_th_4,
            self.v_shared_secret.as_bytes(),
        )
        .unwrap();

        (v_master_secret, v_master_salt)
    }
}

/// Converts from `&Option<T>` to `Option<&T::Target>`.
///
/// Leaves the original Option in-place, creating a new one with a reference
/// to the original one, additionally coercing the contents via `Deref`.
///
/// This is extracted from the `inner_deref` feature of unstable Rust
/// (https://github.com/rust-lang/rust/issues/50264) and can be removed, as
/// soon as the feature becomes stable.
fn as_deref<T: core::ops::Deref>(option: &Option<T>) -> Option<&T::Target> {
    option.as_ref().map(|t| t.deref())
}
