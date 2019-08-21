use alloc::vec::Vec;
use core::result::Result;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use super::{
    error::{EarlyError, OwnError, OwnOrPeerError},
    util,
    util::{Message1, Message2, Message3},
};
use crate::{cose, error::Error};

// Party U constructs ---------------------------------------------------------

/// Generates the first message.
pub struct Msg1Sender {
    c_u: Vec<u8>,
    secret: StaticSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Sender {
    /// Initializes a new `Msg1Sender`.
    ///
    /// # Arguments
    /// * `c_u` - The chosen connection identifier.
    /// * `ecdh_secret` - The ECDH secret to use for this protocol run.
    /// * `auth` - The ed25519 authentication key pair. First 32 bytes are the
    ///   secret key, the other 32 bytes the public key.
    /// * `kid` - The key ID by which the other party is able to retrieve the
    ///   public key corresponding to `auth`.
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

    /// Returns the bytes of the first message.
    ///
    /// # Arguments
    /// * `type` - type = 0 is used when there is no external correlation
    ///   mechanism. type = 1 is used when there is an external correlation
    ///   mechanism (e.g. the Token in CoAP) that enables Party U to correlate
    ///   `message_1` and `message_2`. type = 2 is used when there is an
    ///   external correlation mechanism that enables Party V to correlate
    ///   `message_2` and `message_3`. type = 3 is used when there is an
    ///   external correlation mechanism that enables the parties to correlate
    ///   all the messages.
    pub fn generate_message_1(
        self,
        r#type: isize,
    ) -> Result<(Vec<u8>, Msg2Receiver), EarlyError> {
        // Encode the necessary information into the first message
        let msg_1 = Message1 {
            r#type,
            suite: 0,
            x_u: self.x_u.as_bytes().to_vec(),
            c_u: self.c_u,
        };
        // Get CBOR sequence for message
        let msg_1_seq = util::serialize_message_1(&msg_1)?;
        // Copy for returning
        let msg_1_bytes = msg_1_seq.clone();

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

/// Processes the second message.
pub struct Msg2Receiver {
    secret: StaticSecret,
    x_u: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
    msg_1: Message1,
}

impl Msg2Receiver {
    /// Returns the key ID of the other party's public authentication key.
    pub fn extract_peer_kid(
        self,
        msg_2: Vec<u8>,
    ) -> Result<(Vec<u8>, Msg2Verifier), OwnOrPeerError> {
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_2)?;
        // Decode the second message
        let msg_2 = util::deserialize_message_2(&msg_2)?;

        // Use V's public key to generate the ephemeral shared secret
        let mut x_v_bytes = [0; 32];
        x_v_bytes.copy_from_slice(&msg_2.x_v[..32]);
        let v_public = x25519_dalek::PublicKey::from(x_v_bytes);
        let shared_secret = self.secret.diffie_hellman(&v_public);

        // Compute TH_2
        let th_2 = util::compute_th_2(
            self.msg_1_seq,
            as_deref(&msg_2.c_u),
            &msg_2.x_v,
            &msg_2.c_v,
        )?;

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            util::CCM_KEY_LEN * 8,
            &th_2,
            shared_secret.as_bytes(),
        )?;
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
            &th_2,
            shared_secret.as_bytes(),
        )?;

        // Compute the associated data
        let ad = cose::build_ad(&th_2)?;
        // Decrypt and verify the ciphertext
        let plaintext = util::aead_open(&k_2, &iv_2, &msg_2.ciphertext, &ad)?;
        // Fetch the contents of the plaintext
        let (v_kid, v_sig) = util::extract_plaintext(plaintext)?;
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

/// Verifies the second message.
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
    /// Checks the authenticity of the second message with the other party's
    /// public authentication key.
    pub fn verify_message_2(
        self,
        v_public: &[u8],
    ) -> Result<Msg3Sender, OwnError> {
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

/// Generates the third message and returns the OSCORE context.
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
    /// Returns the bytes of the third message, as well as the OSCORE master
    /// secret and the OSCORE master salt.
    pub fn generate_message_3(
        self,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), OwnError> {
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
            util::CCM_KEY_LEN * 8,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
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

        Ok((msg_3_seq, master_secret, master_salt))
    }
}

// Party V constructs ---------------------------------------------------------

/// Handles the first message.
pub struct Msg1Receiver {
    c_v: Vec<u8>,
    secret: StaticSecret,
    x_v: PublicKey,
    auth: [u8; 64],
    kid: Vec<u8>,
}

impl Msg1Receiver {
    /// Initializes a new `Msg1Receiver`.
    ///
    /// # Arguments
    /// * `c_v` - The chosen connection identifier.
    /// * `ecdh_secret` - The ECDH secret to use for this protocol run.
    /// * `auth` - The ed25519 authentication key pair. First 32 bytes are the
    ///   secret key, the other 32 bytes the public key.
    /// * `kid` - The key ID by which the other party is able to retrieve the
    ///   public key corresponding to `auth`.
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

    /// Processes the first message.
    pub fn handle_message_1(
        self,
        msg_1: Vec<u8>,
    ) -> Result<Msg2Sender, OwnError> {
        // Alias this
        let msg_1_seq = msg_1;
        // Decode the first message
        let msg_1 = util::deserialize_message_1(&msg_1_seq)?;
        // Verify that the selected suite is supported
        if msg_1.suite != 0 {
            Err(Error::UnsupportedSuite)?;
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
            msg_1_seq,
            msg_1,
        })
    }
}

/// Generates the second message.
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
    /// Returns the bytes of the second message.
    pub fn generate_message_2(
        self,
    ) -> Result<(Vec<u8>, Msg3Receiver), OwnError> {
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
            self.msg_1_seq,
            as_deref(&c_u),
            self.x_v.as_bytes(),
            &self.c_v,
        )?;
        // Sign it
        let sig = cose::sign(&id_cred_v, &th_2, &cred_v, &self.auth)?;

        // Derive K_2
        let k_2 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            util::CCM_KEY_LEN * 8,
            &th_2,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_2
        let iv_2 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
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

        Ok((
            msg_2_seq,
            Msg3Receiver {
                shared_secret: self.shared_secret,
                msg_1: self.msg_1,
                msg_2,
                th_2,
            },
        ))
    }
}

/// Processes the third message.
pub struct Msg3Receiver {
    shared_secret: SharedSecret,
    msg_1: Message1,
    msg_2: Message2,
    th_2: Vec<u8>,
}

impl Msg3Receiver {
    /// Returns the key ID of the other party's public authentication key.
    pub fn extract_peer_kid(
        self,
        msg_3: Vec<u8>,
    ) -> Result<(Vec<u8>, Msg3Verifier), OwnOrPeerError> {
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_3)?;
        // Decode the third message
        let msg_3 = util::deserialize_message_3(&msg_3)?;

        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.th_2,
            &self.msg_2.ciphertext,
            as_deref(&msg_3.c_v),
        )?;

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            &"ChaCha20/Poly1305",
            util::CCM_KEY_LEN * 8,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            &"IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
            &th_3,
            self.shared_secret.as_bytes(),
        )?;

        // Compute the associated data
        let ad = cose::build_ad(&th_3)?;
        // Decrypt and verify the ciphertext
        let plaintext = util::aead_open(&k_3, &iv_3, &msg_3.ciphertext, &ad)?;
        // Fetch the contents of the plaintext
        let (u_kid, u_sig) = util::extract_plaintext(plaintext)?;
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

/// Verifies the third message and returns the OSCORE context.
pub struct Msg3Verifier {
    shared_secret: SharedSecret,
    msg_1: Message1,
    msg_3: Message3,
    th_3: Vec<u8>,
    u_kid: Vec<u8>,
    u_sig: Vec<u8>,
}

impl Msg3Verifier {
    /// Checks the authenticity of the third message with the other party's
    /// public authentication key and returns the OSCORE master secret and the
    /// OSCORE master Salt.
    pub fn verify_message_3(
        self,
        u_public: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OwnError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    static REF_BYTES: [u8; 3] = [0x01, 0x02, 0x03];

    #[test]
    fn deref() {
        let orig = Some(REF_BYTES.to_vec());
        let derefed = as_deref(&orig).unwrap();
        assert_eq!(&REF_BYTES, derefed);
    }

    static U_PRIV: [u8; 32] = [
        144, 115, 162, 206, 225, 72, 94, 30, 253, 17, 9, 171, 183, 84, 94, 17,
        170, 82, 95, 72, 77, 44, 124, 143, 102, 139, 156, 120, 63, 2, 27, 70,
    ];
    static U_C_U: [u8; 7] = *b"Party U";
    static U_AUTH: [u8; 64] = [
        0x76, 0x9E, 0x0B, 0xE0, 0xF4, 0x30, 0x9A, 0x6D, 0x6D, 0x6E, 0xC7,
        0x8D, 0x61, 0xE0, 0xFB, 0xCF, 0x48, 0x3C, 0x8D, 0xE4, 0x2C, 0x39,
        0x30, 0xD0, 0x4A, 0x4B, 0xA9, 0x17, 0x8F, 0x6C, 0xA7, 0x0F, 0xB3,
        0x94, 0x7F, 0x71, 0xA5, 0xCC, 0xA4, 0xF1, 0xD2, 0xA3, 0x42, 0xAE,
        0x62, 0x24, 0x17, 0x5E, 0x83, 0x77, 0x49, 0x34, 0x7E, 0x54, 0x21,
        0x8C, 0x35, 0xED, 0x0C, 0xC8, 0x0A, 0x26, 0x69, 0x79,
    ];
    static U_PUBLIC: [u8; 32] = [
        0xB3, 0x94, 0x7F, 0x71, 0xA5, 0xCC, 0xA4, 0xF1, 0xD2, 0xA3, 0x42,
        0xAE, 0x62, 0x24, 0x17, 0x5E, 0x83, 0x77, 0x49, 0x34, 0x7E, 0x54,
        0x21, 0x8C, 0x35, 0xED, 0x0C, 0xC8, 0x0A, 0x26, 0x69, 0x79,
    ];
    static U_KID: [u8; 17] = *b"alice@example.org";

    static V_PRIV: [u8; 32] = [
        16, 165, 169, 23, 227, 139, 247, 13, 53, 60, 173, 235, 46, 22, 199,
        69, 54, 240, 59, 183, 80, 23, 70, 121, 195, 57, 176, 97, 255, 171,
        154, 93,
    ];
    static V_C_V: [u8; 7] = *b"Party V";
    static V_AUTH: [u8; 64] = [
        0xBB, 0x5A, 0x16, 0x81, 0xBB, 0x9B, 0xC3, 0x12, 0x67, 0x8F, 0x53,
        0xD3, 0x14, 0x7F, 0xFF, 0x83, 0xF9, 0x56, 0xDB, 0x1F, 0xC6, 0xF4,
        0x35, 0xA8, 0xDF, 0xB6, 0xB1, 0x0A, 0xA7, 0x1E, 0xFA, 0x1C, 0x88,
        0x3D, 0x9F, 0x20, 0xAF, 0x73, 0xF7, 0x8E, 0xD2, 0x94, 0x78, 0xE4,
        0x16, 0x51, 0x4B, 0x88, 0x57, 0x19, 0x64, 0x3B, 0x63, 0xC5, 0x81,
        0xFD, 0x8B, 0x57, 0xDD, 0x3A, 0xC8, 0x01, 0x1A, 0xC6,
    ];
    static V_PUBLIC: [u8; 32] = [
        0x88, 0x3D, 0x9F, 0x20, 0xAF, 0x73, 0xF7, 0x8E, 0xD2, 0x94, 0x78,
        0xE4, 0x16, 0x51, 0x4B, 0x88, 0x57, 0x19, 0x64, 0x3B, 0x63, 0xC5,
        0x81, 0xFD, 0x8B, 0x57, 0xDD, 0x3A, 0xC8, 0x01, 0x1A, 0xC6,
    ];
    static V_KID: [u8; 15] = *b"bob@example.org";

    fn successful_run(r#type: isize) {
        // Party U ------------------------------------------------------------
        let msg1_sender =
            Msg1Sender::new(U_C_U.to_vec(), U_PRIV, U_AUTH, U_KID.to_vec());
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(r#type).unwrap();

        // Party V ------------------------------------------------------------
        let msg1_receiver =
            Msg1Receiver::new(V_C_V.to_vec(), V_PRIV, V_AUTH, V_KID.to_vec());
        let msg2_sender = msg1_receiver.handle_message_1(msg1_bytes).unwrap();
        let (msg2_bytes, msg3_receiver) =
            msg2_sender.generate_message_2().unwrap();

        // Party U ------------------------------------------------------------
        let (_v_kid, msg2_verifier) =
            msg2_receiver.extract_peer_kid(msg2_bytes).unwrap();
        let msg3_sender = msg2_verifier.verify_message_2(&V_PUBLIC).unwrap();
        let (msg3_bytes, u_master_secret, u_master_salt) =
            msg3_sender.generate_message_3().unwrap();

        // Party V ------------------------------------------------------------
        let (_u_kid, msg3_verifier) =
            msg3_receiver.extract_peer_kid(msg3_bytes).unwrap();
        let (v_master_secret, v_master_salt) =
            msg3_verifier.verify_message_3(&U_PUBLIC).unwrap();

        // Verification -------------------------------------------------------
        assert_eq!(u_master_secret, v_master_secret);
        assert_eq!(u_master_salt, v_master_salt);
    }

    #[test]
    fn normal_run() {
        successful_run(0);
        successful_run(1);
        successful_run(2);
        successful_run(3);
    }

    static SUITE_MSG: [u8; 27] = [
        0x20, 0x78, 0x18, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73,
        0x75, 0x69, 0x74, 0x65, 0x20, 0x75, 0x6E, 0x73, 0x75, 0x70, 0x70,
        0x6F, 0x72, 0x74, 0x65, 0x64,
    ];

    #[test]
    fn unsupported_suite() {
        // Party U ------------------------------------------------------------
        let msg1_sender =
            Msg1Sender::new(U_C_U.to_vec(), U_PRIV, U_AUTH, U_KID.to_vec());
        let (mut msg1_bytes, _) = msg1_sender.generate_message_1(1).unwrap();
        // Change the suite
        msg1_bytes[1] = 0x01;

        // Party V ------------------------------------------------------------
        let msg1_receiver =
            Msg1Receiver::new(V_C_V.to_vec(), V_PRIV, V_AUTH, V_KID.to_vec());
        let _ = match msg1_receiver.handle_message_1(msg1_bytes) {
            Err(OwnError(b)) => assert_eq!(&SUITE_MSG, &b[..]),
            Ok(_) => panic!("Should have resulted in a suite error"),
        };
    }

    static CBOR_MSG: [u8; 23] = [
        0x20, 0x75, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x70, 0x72, 0x6F,
        0x63, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x42, 0x4F,
        0x52,
    ];

    #[test]
    fn only_own_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender =
            Msg1Sender::new(U_C_U.to_vec(), U_PRIV, U_AUTH, U_KID.to_vec());
        let (mut msg1_bytes, _) = msg1_sender.generate_message_1(1).unwrap();
        // Garble the message
        msg1_bytes[0] = 0xFF;

        // Party V ------------------------------------------------------------
        let msg1_receiver =
            Msg1Receiver::new(V_C_V.to_vec(), V_PRIV, V_AUTH, V_KID.to_vec());
        let _ = match msg1_receiver.handle_message_1(msg1_bytes) {
            Err(OwnError(b)) => assert_eq!(&CBOR_MSG, &b[..]),
            Ok(_) => panic!("Should have resulted in a CBOR error"),
        };
    }

    #[test]
    fn both_own_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender =
            Msg1Sender::new(U_C_U.to_vec(), U_PRIV, U_AUTH, U_KID.to_vec());
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(1).unwrap();

        // Party V ------------------------------------------------------------
        let msg1_receiver =
            Msg1Receiver::new(V_C_V.to_vec(), V_PRIV, V_AUTH, V_KID.to_vec());
        let msg2_sender = msg1_receiver.handle_message_1(msg1_bytes).unwrap();
        let (mut msg2_bytes, _) = msg2_sender.generate_message_2().unwrap();
        // Garble the message
        msg2_bytes[0] = 0xFF;

        // Party U ------------------------------------------------------------
        match msg2_receiver.extract_peer_kid(msg2_bytes) {
            Err(OwnOrPeerError::PeerError(_)) => {
                panic!("Should have resulted in a CBOR error")
            }
            Err(OwnOrPeerError::OwnError(b)) => assert_eq!(&CBOR_MSG, &b[..]),
            Ok(_) => panic!("Should have resulted in a CBOR error"),
        };
    }

    #[test]
    fn both_peer_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender =
            Msg1Sender::new(U_C_U.to_vec(), U_PRIV, U_AUTH, U_KID.to_vec());
        let (mut msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(1).unwrap();
        // Garble the message
        msg1_bytes[0] = 0xFF;

        // Party V ------------------------------------------------------------
        let msg1_receiver =
            Msg1Receiver::new(V_C_V.to_vec(), V_PRIV, V_AUTH, V_KID.to_vec());
        // Extract the error message to send
        let msg2_err_bytes = match msg1_receiver.handle_message_1(msg1_bytes) {
            Ok(_) => panic!("Should have resulted in a CBOR error"),
            Err(OwnError(b)) => b,
        };

        // Party U ------------------------------------------------------------
        match msg2_receiver.extract_peer_kid(msg2_err_bytes) {
            Err(OwnOrPeerError::PeerError(s)) => {
                assert_eq!("Error processing CBOR", &s);
            }
            Err(OwnOrPeerError::OwnError(_)) => {
                panic!("Should have resulted in a peer error")
            }
            Ok(_) => panic!("Should have resulted in a peer error"),
        };
    }
}
