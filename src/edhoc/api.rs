use alloc::vec::Vec;
use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{cbor, cose, edhoc, Result};

use edhoc::{
    util,
    util::{Message1, Message2, Message3},
};

pub struct Msg1Sender {
    c_u: Vec<u8>,
    secret: StaticSecret,
    x_u: PublicKey,
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
        let secret = StaticSecret::from(ecdh_secret);
        // The corresponding public key
        let x_u = PublicKey::from(&secret);

        Msg1Sender {
            c_u: c_u.to_vec(),
            secret,
            x_u,
            auth,
            kid: kid.to_vec(),
        }
    }

    pub fn generate_message_1(self, r#type: isize) -> (Vec<u8>, Msg2Receiver) {
        // Encode the necessary information into the first message
        let msg_1 = Message1 {
            // This would be the case in CoAP, where party U can correlate
            // message_1 and message_2 with the token
            r#type,
            suite: 0,
            x_u: self.x_u.as_bytes().to_vec(),
            c_u: self.c_u,
        };
        // Get CBOR sequence for message
        let msg_1_seq = util::serialize_message_1(&msg_1).unwrap();
        // Wrap it in a bstr for transmission
        let msg_1_bytes = cbor::encode(Bytes::new(&msg_1_seq)).unwrap();

        (
            msg_1_bytes,
            Msg2Receiver {
                msg_1_seq,
                secret: self.secret,
                x_u: self.x_u,
                msg_1,
                auth: self.auth,
                kid: self.kid,
            },
        )
    }
}

pub struct Msg1Receiver {
    c_v: Vec<u8>,
    secret: StaticSecret,
    x_v: PublicKey,
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
        let secret = StaticSecret::from(ecdh_secret);
        // The corresponding public key
        let x_v = PublicKey::from(&secret);

        Msg1Receiver {
            c_v: c_v.to_vec(),
            secret,
            x_v,
            auth,
            kid: kid.to_vec(),
        }
    }

    pub fn handle_message_1(self, msg_1: &mut [u8]) -> Msg2Sender {
        // Unwrap sequence from bstr
        let msg_1_seq: ByteBuf = cbor::decode(msg_1).unwrap();
        // Decode the first message
        let msg_1 = util::deserialize_message_1(&msg_1_seq).unwrap();
        // Verify that the selected suite is supported
        if msg_1.suite != 0 {
            unimplemented!("Other cipher suites");
        }
        // Use U's public key to generate the ephemeral shared secret
        let mut x_u_bytes = [0; 32];
        x_u_bytes.copy_from_slice(&msg_1.x_u[..32]);
        let u_public = x25519_dalek::PublicKey::from(x_u_bytes);
        let shared_secret = self.secret.diffie_hellman(&u_public);

        Msg2Sender {
            msg_1,
            x_v: self.x_v,
            msg_1_seq: msg_1_seq.into_vec(),
            shared_secret,
            c_v: self.c_v,
            auth: self.auth,
            kid: self.kid,
        }
    }
}

pub struct Msg2Sender {
    msg_1: Message1,
    x_v: PublicKey,
    c_v: Vec<u8>,
    msg_1_seq: Vec<u8>,
    shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg2Sender {
    pub fn generate_message_2(self) -> (Vec<u8>, Msg3Receiver) {
        // Determine whether to include c_u in message_2 or not
        let c_u = if self.msg_1.r#type % 4 == 1 || self.msg_1.r#type % 4 == 3 {
            None
        } else {
            Some(self.msg_1.c_u.clone())
        };

        // Build the COSE header map identifying the public authentication key
        let id_cred_v = cose::build_id_cred_x(&self.kid).unwrap();
        // Build the COSE_Key containing our ECDH public key
        let cred_v =
            cose::serialize_cose_key(self.x_v.as_bytes(), &self.kid).unwrap();
        // Compute TH_2
        let th_2 = util::compute_th_2(
            &self.msg_1_seq,
            as_deref(&c_u),
            self.x_v.as_bytes(),
            &self.c_v,
        )
        .unwrap();
        // Sign it
        let sig = cose::sign(&id_cred_v, &th_2, &cred_v, &self.auth).unwrap();

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_2,
            self.shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_2,
            self.shared_secret.as_bytes(),
        )
        .unwrap();

        // Put together the plaintext for the encryption
        let plaintext = util::build_plaintext(&self.kid, &sig).unwrap();
        // Compute the associated data
        let ad = cose::build_ad(&th_2).unwrap();
        // Get the ciphertext
        let ciphertext =
            util::aead_seal(&k_2, &iv_2, &plaintext, &ad).unwrap();

        // Produce message_2
        let msg_2 = Message2 {
            c_u: c_u,
            x_v: self.x_v.as_bytes().to_vec(),
            c_v: self.c_v.to_vec(),
            ciphertext: ciphertext,
        };
        // Get CBOR sequence for message
        let msg_2_seq = util::serialize_message_2(&msg_2).unwrap();
        // Wrap it in a bstr for transmission
        let msg_2_bytes = cbor::encode(Bytes::new(&msg_2_seq)).unwrap();

        (
            msg_2_bytes,
            Msg3Receiver {
                th_2,
                msg_1: self.msg_1,
                msg_2,
                shared_secret: self.shared_secret,
            },
        )
    }
}

pub struct Msg2Receiver {
    msg_1_seq: Vec<u8>,
    secret: StaticSecret,
    x_u: PublicKey,
    msg_1: Message1,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg2Receiver {
    pub fn extract_peer_kid(
        self,
        msg_2: &mut [u8],
    ) -> (Vec<u8>, Msg2Verifier) {
        // Unwrap sequence from bstr
        let msg_2_seq: ByteBuf = cbor::decode(msg_2).unwrap();
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_2_seq).unwrap();
        // Decode the second message
        let msg_2 = util::deserialize_message_2(&msg_2_seq).unwrap();

        // Use V's public key to generate the ephemeral shared secret
        let mut x_v_bytes = [0; 32];
        x_v_bytes.copy_from_slice(&msg_2.x_v[..32]);
        let v_public = x25519_dalek::PublicKey::from(x_v_bytes);
        let shared_secret = self.secret.diffie_hellman(&v_public);

        // Compute TH_2
        let th_2 = util::compute_th_2(
            &self.msg_1_seq,
            as_deref(&msg_2.c_u),
            &msg_2.x_v,
            &msg_2.c_v,
        )
        .unwrap();

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_2,
            shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_2,
            shared_secret.as_bytes(),
        )
        .unwrap();

        // Compute the associated data
        let ad = cose::build_ad(&th_2).unwrap();
        // Decrypt and verify the ciphertext
        let mut plaintext =
            util::aead_open(&k_2, &iv_2, &msg_2.ciphertext, &ad).unwrap();
        // Fetch the contents of the plaintext
        let (v_kid, v_sig) = util::extract_plaintext(&mut plaintext).unwrap();
        // Copy to keep for yourself
        let v_kid_cpy = v_kid.clone();

        (
            v_kid_cpy,
            Msg2Verifier {
                th_2,
                x_u: self.x_u,
                msg_1: self.msg_1,
                msg_2,
                shared_secret,
                auth: self.auth,
                kid: self.kid,
                v_sig,
                v_kid,
            },
        )
    }
}

pub struct Msg2Verifier {
    th_2: Vec<u8>,
    x_u: PublicKey,
    msg_1: Message1,
    msg_2: Message2,
    shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
    v_sig: Vec<u8>,
    v_kid: Vec<u8>,
}

impl Msg2Verifier {
    pub fn verify_message_2(self, v_public: &[u8]) -> Msg3Sender {
        // Build the COSE header map identifying the public authentication key
        // of V
        let id_cred_v = cose::build_id_cred_x(&self.v_kid).unwrap();
        // Build the COSE_Key containing V's ECDH public key
        let cred_v =
            cose::serialize_cose_key(&self.msg_2.x_v, &self.v_kid).unwrap();
        // Verify the signed data from Party V
        cose::verify(&id_cred_v, &self.th_2, &cred_v, v_public, &self.v_sig)
            .unwrap();

        Msg3Sender {
            th_2: self.th_2,
            x_u: self.x_u,
            msg_1: self.msg_1,
            msg_2: self.msg_2,
            shared_secret: self.shared_secret,
            auth: self.auth,
            kid: self.kid,
        }
    }
}

pub struct Msg3Sender {
    th_2: Vec<u8>,
    x_u: PublicKey,
    msg_1: Message1,
    msg_2: Message2,
    shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg3Sender {
    pub fn generate_message_3(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Determine whether to include c_v in message_3 or not
        let c_v = if self.msg_1.r#type % 4 == 2 || self.msg_1.r#type % 4 == 3 {
            None
        } else {
            Some(self.msg_2.c_v.to_vec())
        };

        // Build the COSE header map identifying the public authentication key
        let id_cred_u = cose::build_id_cred_x(&self.kid).unwrap();
        // Build the COSE_Key containing our ECDH public key
        let cred_u =
            cose::serialize_cose_key(self.x_u.as_bytes(), &self.kid).unwrap();
        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.th_2,
            &self.msg_2.ciphertext,
            as_deref(&c_v),
        )
        .unwrap();
        // Sign it
        let sig = cose::sign(&id_cred_u, &th_3, &cred_u, &self.auth).unwrap();

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_3,
            self.shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_3,
            self.shared_secret.as_bytes(),
        )
        .unwrap();

        // Put together the plaintext for the encryption
        let plaintext = util::build_plaintext(&self.kid, &sig).unwrap();
        // Compute the associated data
        let ad = cose::build_ad(&th_3).unwrap();
        // Get the ciphertext
        let ciphertext =
            util::aead_seal(&k_3, &iv_3, &plaintext, &ad).unwrap();

        // Produce message_3
        let msg_3 = Message3 { c_v, ciphertext };
        // Get CBOR sequence for message
        let msg_3_seq = util::serialize_message_3(&msg_3).unwrap();
        // Wrap it in a bstr for transmission
        let msg_3_bytes = cbor::encode(Bytes::new(&msg_3_seq)).unwrap();

        // Derive values for the OSCORE context
        let th_4 = util::compute_th_4(&th_3, &msg_3.ciphertext).unwrap();
        let master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &th_4,
            self.shared_secret.as_bytes(),
        )
        .unwrap();
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.shared_secret.as_bytes(),
        )
        .unwrap();

        (msg_3_bytes, master_secret, master_salt)
    }
}

pub struct Msg3Receiver {
    th_2: Vec<u8>,
    msg_1: Message1,
    msg_2: Message2,
    shared_secret: SharedSecret,
}

impl Msg3Receiver {
    pub fn extract_peer_kid(
        self,
        msg_3: &mut [u8],
    ) -> (Vec<u8>, Msg3Verifier) {
        // Unwrap sequence from bstr
        let msg_3_seq: ByteBuf = cbor::decode(msg_3).unwrap();
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_3_seq).unwrap();
        // Decode the third message
        let msg_3 = util::deserialize_message_3(&msg_3_seq).unwrap();

        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.th_2,
            &self.msg_2.ciphertext,
            as_deref(&msg_3.c_v),
        )
        .unwrap();

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_3,
            self.shared_secret.as_bytes(),
        )
        .unwrap();
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_3,
            self.shared_secret.as_bytes(),
        )
        .unwrap();

        // Compute the associated data
        let ad = cose::build_ad(&th_3).unwrap();
        // Decrypt and verify the ciphertext
        let mut plaintext =
            util::aead_open(&k_3, &iv_3, &msg_3.ciphertext, &ad).unwrap();
        // Fetch the contents of the plaintext
        let (u_kid, u_sig) = util::extract_plaintext(&mut plaintext).unwrap();
        // Copy to keep for yourself
        let u_kid_cpy = u_kid.clone();

        (
            u_kid_cpy,
            Msg3Verifier {
                msg_1: self.msg_1,
                shared_secret: self.shared_secret,
                u_sig,
                u_kid,
                th_3,
                msg_3,
            },
        )
    }
}

pub struct Msg3Verifier {
    msg_1: Message1,
    shared_secret: SharedSecret,
    u_sig: Vec<u8>,
    u_kid: Vec<u8>,
    th_3: Vec<u8>,
    msg_3: Message3,
}

impl Msg3Verifier {
    pub fn verify_message_3(self, u_public: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Build the COSE header map identifying the public authentication key
        // of U
        let id_cred_u = cose::build_id_cred_x(&self.u_kid).unwrap();
        // Build the COSE_Key containing U's ECDH public key
        let cred_u =
            cose::serialize_cose_key(&self.msg_1.x_u, &self.u_kid).unwrap();
        // Verify the signed data from Party U
        cose::verify(&id_cred_u, &self.th_3, &cred_u, &u_public, &self.u_sig)
            .unwrap();

        // Derive values for the OSCORE context
        let th_4 =
            util::compute_th_4(&self.th_3, &self.msg_3.ciphertext).unwrap();
        let master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &th_4,
            self.shared_secret.as_bytes(),
        )
        .unwrap();
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.shared_secret.as_bytes(),
        )
        .unwrap();

        (master_secret, master_salt)
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
