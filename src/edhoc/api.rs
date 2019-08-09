use alloc::vec::Vec;
use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{cbor, cose, edhoc, Result};

use edhoc::{
    util,
    util::{Message1, Message2, Message3},
};

// Party U constructs ---------------------------------------------------------

pub struct Msg1Sender {
    c_u: Vec<u8>,
    secret: StaticSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Sender {
    pub fn new(
        c_u: Vec<u8>,
        ecdh_secret: [u8; 32],
        auth: [u8; 64],
        kid: Vec<u8>,
    ) -> Msg1Sender {
        // From the secret bytes, create the DH secret
        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_u = PublicKey::from(&secret);

        Msg1Sender {
            c_u,
            secret,
            x_u,
            auth,
            kid,
        }
    }

    pub fn generate_message_1(
        self,
        r#type: isize,
    ) -> Result<(Vec<u8>, Msg2Receiver)> {
        // Encode the necessary information into the first message
        let msg_1 = Message1 {
            r#type,
            suite: 0,
            x_u: self.x_u.as_bytes().to_vec(),
            c_u: self.c_u,
        };
        // Get CBOR sequence for message
        let msg_1_seq = util::serialize_message_1(&msg_1)?;
        // Wrap it in a bstr for transmission
        let msg_1_bytes = cbor::encode(Bytes::new(&msg_1_seq))?;

        Ok((
            msg_1_bytes,
            Msg2Receiver {
                secret: self.secret,
                x_u: self.x_u,
                auth: self.auth,
                kid: self.kid,
                msg_1_seq,
                msg_1,
            },
        ))
    }
}

pub struct Msg2Receiver {
    secret: StaticSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
    msg_1: Message1,
}

impl Msg2Receiver {
    pub fn extract_peer_kid(
        self,
        mut msg_2: Vec<u8>,
    ) -> Result<(Vec<u8>, Msg2Verifier)> {
        // Unwrap sequence from bstr
        let msg_2_seq: ByteBuf = cbor::decode(&mut msg_2)?;
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_2_seq)?;
        // Decode the second message
        let msg_2 = util::deserialize_message_2(&msg_2_seq)?;

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
        )?;

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_2,
            shared_secret.as_bytes(),
        )?;
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_2,
            shared_secret.as_bytes(),
        )?;

        // Compute the associated data
        let ad = cose::build_ad(&th_2)?;
        // Decrypt and verify the ciphertext
        let mut plaintext =
            util::aead_open(&k_2, &iv_2, &msg_2.ciphertext, &ad)?;
        // Fetch the contents of the plaintext
        let (v_kid, v_sig) = util::extract_plaintext(&mut plaintext)?;
        // Copy this, since we need to return one and keep one
        let v_kid_cpy = v_kid.clone();

        Ok((
            v_kid_cpy,
            Msg2Verifier {
                shared_secret,
                x_u: self.x_u,
                auth: self.auth,
                kid: self.kid,
                msg_1: self.msg_1,
                msg_2,
                th_2,
                v_kid,
                v_sig,
            },
        ))
    }
}

pub struct Msg2Verifier {
    shared_secret: SharedSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1: Message1,
    msg_2: Message2,
    th_2: Vec<u8>,
    v_kid: Vec<u8>,
    v_sig: Vec<u8>,
}

impl Msg2Verifier {
    pub fn verify_message_2(self, v_public: &[u8]) -> Result<Msg3Sender> {
        // Build the COSE header map identifying the public authentication key
        // of V
        let id_cred_v = cose::build_id_cred_x(&self.v_kid)?;
        // Build the COSE_Key containing V's ECDH public key
        let cred_v = cose::serialize_cose_key(&self.msg_2.x_v, &self.v_kid)?;
        // Verify the signed data from Party V
        cose::verify(&id_cred_v, &self.th_2, &cred_v, v_public, &self.v_sig)?;

        Ok(Msg3Sender {
            shared_secret: self.shared_secret,
            x_u: self.x_u,
            auth: self.auth,
            kid: self.kid,
            msg_1: self.msg_1,
            msg_2: self.msg_2,
            th_2: self.th_2,
        })
    }
}

pub struct Msg3Sender {
    shared_secret: SharedSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1: Message1,
    msg_2: Message2,
    th_2: Vec<u8>,
}

impl Msg3Sender {
    pub fn generate_message_3(self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        // Determine whether to include c_v in message_3 or not
        let c_v = if self.msg_1.r#type % 4 == 2 || self.msg_1.r#type % 4 == 3 {
            None
        } else {
            Some(self.msg_2.c_v)
        };

        // Build the COSE header map identifying the public authentication key
        let id_cred_u = cose::build_id_cred_x(&self.kid)?;
        // Build the COSE_Key containing our ECDH public key
        let cred_u = cose::serialize_cose_key(self.x_u.as_bytes(), &self.kid)?;
        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.th_2,
            &self.msg_2.ciphertext,
            as_deref(&c_v),
        )?;
        // Sign it
        let sig = cose::sign(&id_cred_u, &th_3, &cred_u, &self.auth)?;

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;

        // Put together the plaintext for the encryption
        let plaintext = util::build_plaintext(&self.kid, &sig)?;
        // Compute the associated data
        let ad = cose::build_ad(&th_3)?;
        // Get the ciphertext
        let ciphertext = util::aead_seal(&k_3, &iv_3, &plaintext, &ad)?;

        // Produce message_3
        let msg_3 = Message3 { c_v, ciphertext };
        // Get CBOR sequence for message
        let msg_3_seq = util::serialize_message_3(&msg_3)?;
        // Wrap it in a bstr for transmission
        let msg_3_bytes = cbor::encode(Bytes::new(&msg_3_seq))?;

        // Derive values for the OSCORE context
        let th_4 = util::compute_th_4(&th_3, &msg_3.ciphertext)?;
        let master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &th_4,
            self.shared_secret.as_bytes(),
        )?;
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.shared_secret.as_bytes(),
        )?;

        Ok((msg_3_bytes, master_secret, master_salt))
    }
}

// Party V constructs ---------------------------------------------------------

pub struct Msg1Receiver {
    c_v: Vec<u8>,
    secret: StaticSecret,
    x_v: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Receiver {
    pub fn new(
        c_v: Vec<u8>,
        ecdh_secret: [u8; 32],
        auth: [u8; 64],
        kid: Vec<u8>,
    ) -> Msg1Receiver {
        // From the secret bytes, create the DH secret
        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_v = PublicKey::from(&secret);

        Msg1Receiver {
            c_v,
            secret,
            x_v,
            auth,
            kid,
        }
    }

    pub fn handle_message_1(self, mut msg_1: Vec<u8>) -> Result<Msg2Sender> {
        // Unwrap sequence from bstr
        let msg_1_seq: ByteBuf = cbor::decode(&mut msg_1)?;
        // Decode the first message
        let msg_1 = util::deserialize_message_1(&msg_1_seq)?;
        // Verify that the selected suite is supported
        // TODO: Return error instead of panicking
        if msg_1.suite != 0 {
            unimplemented!("Other cipher suites");
        }
        // Use U's public key to generate the ephemeral shared secret
        let mut x_u_bytes = [0; 32];
        x_u_bytes.copy_from_slice(&msg_1.x_u[..32]);
        let u_public = x25519_dalek::PublicKey::from(x_u_bytes);
        let shared_secret = self.secret.diffie_hellman(&u_public);

        Ok(Msg2Sender {
            c_v: self.c_v,
            shared_secret,
            x_v: self.x_v,
            auth: self.auth,
            kid: self.kid,
            msg_1_seq: msg_1_seq.into_vec(),
            msg_1,
        })
    }
}

pub struct Msg2Sender {
    c_v: Vec<u8>,
    shared_secret: SharedSecret,
    x_v: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
    msg_1: Message1,
}

impl Msg2Sender {
    pub fn generate_message_2(self) -> Result<(Vec<u8>, Msg3Receiver)> {
        // Determine whether to include c_u in message_2 or not
        let c_u = if self.msg_1.r#type % 4 == 1 || self.msg_1.r#type % 4 == 3 {
            None
        } else {
            Some(self.msg_1.c_u.clone())
        };

        // Build the COSE header map identifying the public authentication key
        let id_cred_v = cose::build_id_cred_x(&self.kid)?;
        // Build the COSE_Key containing our ECDH public key
        let cred_v = cose::serialize_cose_key(self.x_v.as_bytes(), &self.kid)?;
        // Compute TH_2
        let th_2 = util::compute_th_2(
            &self.msg_1_seq,
            as_deref(&c_u),
            self.x_v.as_bytes(),
            &self.c_v,
        )?;
        // Sign it
        let sig = cose::sign(&id_cred_v, &th_2, &cred_v, &self.auth)?;

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_2,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_2,
            self.shared_secret.as_bytes(),
        )?;

        // Put together the plaintext for the encryption
        let plaintext = util::build_plaintext(&self.kid, &sig)?;
        // Compute the associated data
        let ad = cose::build_ad(&th_2)?;
        // Get the ciphertext
        let ciphertext = util::aead_seal(&k_2, &iv_2, &plaintext, &ad)?;

        // Produce message_2
        let msg_2 = Message2 {
            c_u: c_u,
            x_v: self.x_v.as_bytes().to_vec(),
            c_v: self.c_v,
            ciphertext: ciphertext,
        };
        // Get CBOR sequence for message
        let msg_2_seq = util::serialize_message_2(&msg_2)?;
        // Wrap it in a bstr for transmission
        let msg_2_bytes = cbor::encode(Bytes::new(&msg_2_seq))?;

        Ok((
            msg_2_bytes,
            Msg3Receiver {
                shared_secret: self.shared_secret,
                msg_1: self.msg_1,
                msg_2,
                th_2,
            },
        ))
    }
}

pub struct Msg3Receiver {
    shared_secret: SharedSecret,
    msg_1: Message1,
    msg_2: Message2,
    th_2: Vec<u8>,
}

impl Msg3Receiver {
    pub fn extract_peer_kid(
        self,
        mut msg_3: Vec<u8>,
    ) -> Result<(Vec<u8>, Msg3Verifier)> {
        // Unwrap sequence from bstr
        let msg_3_seq: ByteBuf = cbor::decode(&mut msg_3)?;
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_3_seq)?;
        // Decode the third message
        let msg_3 = util::deserialize_message_3(&msg_3_seq)?;

        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.th_2,
            &self.msg_2.ciphertext,
            as_deref(&msg_3.c_v),
        )?;

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            256,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            96,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;

        // Compute the associated data
        let ad = cose::build_ad(&th_3)?;
        // Decrypt and verify the ciphertext
        let mut plaintext =
            util::aead_open(&k_3, &iv_3, &msg_3.ciphertext, &ad)?;
        // Fetch the contents of the plaintext
        let (u_kid, u_sig) = util::extract_plaintext(&mut plaintext)?;
        // Copy this, since we need to return one and keep one
        let u_kid_cpy = u_kid.clone();

        Ok((
            u_kid_cpy,
            Msg3Verifier {
                shared_secret: self.shared_secret,
                msg_1: self.msg_1,
                msg_3,
                th_3,
                u_kid,
                u_sig,
            },
        ))
    }
}

pub struct Msg3Verifier {
    shared_secret: SharedSecret,
    msg_1: Message1,
    msg_3: Message3,
    th_3: Vec<u8>,
    u_kid: Vec<u8>,
    u_sig: Vec<u8>,
}

impl Msg3Verifier {
    pub fn verify_message_3(
        self,
        u_public: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Build the COSE header map identifying the public authentication key
        // of U
        let id_cred_u = cose::build_id_cred_x(&self.u_kid)?;
        // Build the COSE_Key containing U's ECDH public key
        let cred_u = cose::serialize_cose_key(&self.msg_1.x_u, &self.u_kid)?;
        // Verify the signed data from Party U
        cose::verify(&id_cred_u, &self.th_3, &cred_u, &u_public, &self.u_sig)?;

        // Derive values for the OSCORE context
        let th_4 = util::compute_th_4(&self.th_3, &self.msg_3.ciphertext)?;
        let master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            32,
            &th_4,
            self.shared_secret.as_bytes(),
        )?;
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.shared_secret.as_bytes(),
        )?;

        Ok((master_secret, master_salt))
    }
}

// Common functionality -------------------------------------------------------

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
