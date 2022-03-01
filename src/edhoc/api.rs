//! Structs used in the API.

use alloc::vec::Vec;
use core::result::Result;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret, EphemeralSecret};
use eui::{Eui64};
use super::{
    cose,
    error::{EarlyError, Error, OwnError, OwnOrPeerError},
    util::{self, Message1, Message2, Message3},
};


// Constants given by cipher suite 3:
static HASH_OUTPUT_LENGTH : usize = 32;
// Party U constructs ---------------------------------------------------------

/// The structure providing all operations for Party U.
pub struct PartyU<S: PartyUState>(pub S);

// Necessary stuff for session types
pub trait PartyUState {}
impl PartyUState for Msg1Sender {}
impl PartyUState for Msg2Receiver {}
impl PartyUState for Msg2Verifier {}
//impl PartyUState for Msg3Sender {}
pub struct Msg1Sender {
    c_i: Vec<u8>,
    pub secret: StaticSecret,
    pub x_i: PublicKey,
    static_secret: StaticSecret,
    static_public: PublicKey,
    pub APPEUI : Eui64,
    kid: Vec<u8>,
}

impl PartyU<Msg1Sender> {
    /// Creates a new `PartyU` ready to build the first message.
    ///
    /// # Arguments
    /// * `c_u` - The chosen connection identifier.
    /// * `ecdh_secret` - The ECDH secret to use for this protocol run. Ephemeral
    /// * `stat_priv` - The private ed25519 authentication key.
    /// * `stat_public` - The public ed25519 authentication key.
    /// * `APPEUI` - MAC adress of server
    /// * `kid` - The key ID by which the other party is able to retrieve
    ///   `stat_public`, which is called 'ID_cred_x in edho 14 .
    pub fn new(
        c_i: Vec<u8>,
        ecdh_secret: [u8; 32],
        stat_priv: StaticSecret,
        stat_pub: PublicKey,
        APPEUI : Eui64,
        kid: Vec<u8>,
    ) -> PartyU<Msg1Sender> {

        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_i = PublicKey::from(&secret);

        // Combine the authentication key pair for convenience
         PartyU(Msg1Sender {
            c_i,
            secret,
            x_i,
            static_secret:stat_priv,
            static_public:stat_pub,
            APPEUI,
            kid,
        })
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
        suites: isize,
    ) -> Result<(Vec<u8>, PartyU<Msg2Receiver>), EarlyError> {
        // Encode the necessary informati'on into the first message
        let msg_1 = Message1 {
            r#type,
            suite: suites,
            x_i: self.0.x_i.as_bytes().to_vec(), // sending PK as vector
            c_i: self.0.c_i,
        };
        // Get CBOR sequence for message
        let msg_1_seq = util::serialize_message_1(&msg_1)?;
        // Copy for returning
        let msg_1_bytes = msg_1_seq.clone();

        Ok((
            msg_1_bytes,
            PartyU(Msg2Receiver {
                i_ecdh_ephemeralsecret: self.0.secret,
                stat_priv: self.0.static_secret,
                stat_pub: self.0.static_public,
      //          auth: self.0.auth,
                kid: self.0.kid,
                msg_1_seq,
                msg_1,
            }),
        ))
    }
}
/// Contains the state to receive the second message.
pub struct Msg2Receiver {
    i_ecdh_ephemeralsecret: StaticSecret,
    stat_priv : StaticSecret,
    stat_pub : PublicKey,
    kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
    msg_1: Message1,
}



impl PartyU<Msg2Receiver> {
    /// Returns the key ID of the other party's public authentication key, and the state for verification 
    pub fn unpack_message_2_return_kid(
        self,
        msg_2: Vec<u8>,
    ) -> Result<(Vec<u8>, PartyU<Msg2Verifier>), OwnOrPeerError> {

        util::fail_on_error_message(&msg_2)?;


        let msg_2 = util::deserialize_message_2(&msg_2)?;

        // cosntructing ephemeral keypair


        // Constructing shared secret for initiator 
        let mut x_r_bytes = [0; 32];
        x_r_bytes.copy_from_slice(&msg_2.ephemeral_key_r[..32]);
        let r_public = x25519_dalek::PublicKey::from(x_r_bytes);


       let shared_secret_0 = self.0.i_ecdh_ephemeralsecret.diffie_hellman(&r_public);
 
        let msg_1_seq_cpy = self.0.msg_1_seq.clone();

        // reconstructing Keystream2
        let th_2 = util::compute_th_2(self.0.msg_1_seq, &msg_2.c_r, r_public)?;
        let (prk_2e,prk_2e_hkdf) = util::derivePRK(None, shared_secret_0.as_bytes())?;


        let prk_2e_hkdf_cpy = prk_2e_hkdf.clone();
        let Keystream2 = util::createKEYSTREAMWithExpand(prk_2e_hkdf, &th_2, msg_2.ciphertext2.len(), "KEYSTREAM_2")?;
        
        let decryptedlaintext = util::xor(&Keystream2, &msg_2.ciphertext2)?;

        let (r_kid,mac_2 ) = util::extract_plaintext(decryptedlaintext)?;

        let r_kid_cpy = r_kid.clone();

        Ok((
            r_kid,
            PartyU(Msg2Verifier {
                i_ecdh_ephemeralsecret : self.0.i_ecdh_ephemeralsecret,
                shared_secret_0 : shared_secret_0,
                stat_priv: self.0.stat_priv,
                stat_pub : self.0.stat_pub,
                kid: self.0.kid,
                msg_1: self.0.msg_1,
                msg_1_seq: msg_1_seq_cpy,
                msg_2: msg_2,
                mac_2: mac_2,
                prk_2e: prk_2e,
                prk_2e_hkdf: prk_2e_hkdf_cpy,
                th_2: th_2,
                r_kid :r_kid_cpy,

    

            }),
        ))

    }
}



/// Contains the state to verify the second message.
pub struct Msg2Verifier {
    i_ecdh_ephemeralsecret : StaticSecret,
    shared_secret_0: SharedSecret,
    stat_priv : StaticSecret,
    stat_pub : PublicKey,
    kid: Vec<u8>,
    msg_1: Message1,
    msg_1_seq : Vec<u8>,
    msg_2: Message2,
    mac_2: Vec<u8>,
    prk_2e : Vec<u8>,
    prk_2e_hkdf : hkdf::Hkdf<sha2::Sha256>,
    th_2: Vec<u8>,
    r_kid: Vec<u8>,
}


impl PartyU<Msg2Verifier> {
    /// Checks the authenticity of the second message with the other party's
    /// public authentication key.
    pub fn verify_message_2(
        self,
        i_public_static_bytes: &[u8],
    ) -> Result<u8, OwnError> {

        // build cred_x and id_cred_x (for responder party)
        let id_cred_r = cose::build_id_cred_x(&self.0.r_kid)?;
        let cred_r = cose::serialize_cred_x(i_public_static_bytes,&self.0.r_kid )?; 


        // Generating static public key of initiator
        let mut statkey_i_bytes = [0; 32];
        statkey_i_bytes.copy_from_slice(&i_public_static_bytes[..32]);
        let i_public_static = x25519_dalek::PublicKey::from(statkey_i_bytes);

        // Generating shared secret 1 for initiator

        let shared_secret_1 = self.0.i_ecdh_ephemeralsecret.diffie_hellman(&i_public_static);

        // generating prk_3

        let (_,PRK_3e2m_hkdf) = util::derivePRK(Some(&self.0.prk_2e),shared_secret_1.as_bytes())?;

        // transscript hash:
    //    let th_2 = util::compute_th_2(self.0.msg_1_seq, &self.0.c_r, self.0.x_r)?;


      //  let MAC_2 = util::createMACWithExpand(PRK_3e2m_hkdf, util::HASHFUNC_OUTPUT_LEN_BYTES, &th_2, "MAC_2", id_cred_r, cred_r)?;

        





      //  println!("{:?}",id_cred_r );

        // Build the COSE header map identifying the public authentication key
        // of V
     /*   let id_cred_v = cose::build_id_cred_x(&self.0.v_kid)?;
        // Build the COSE_Key containing V's public authentication key
        let cred_v = cose::serialize_cose_key(v_public)?;
        // Verify the signed data from Party V
        cose::verify(
            &id_cred_v,
            &self.0.th_2,
            &cred_v,
            v_public,
            &self.0.v_sig,
        )?;

        Ok(PartyU(Msg3Sender {
            shared_secret: self.0.shared_secret,
            auth: self.0.auth,
            kid: self.0.kid,
            msg_1: self.0.msg_1,
            msg_2: self.0.msg_2,
            th_2: self.0.th_2,
        }))*/

        Ok(199)
    }
}
/*
/// Contains the state to build the third message.
pub struct Msg3Sender {
    shared_secret: SharedSecret,
    auth: [u8; 64],
    kid: Vec<u8>,
    msg_1: Message1,
    msg_2: Message2,
    th_2: Vec<u8>,
}

impl PartyU<Msg3Sender> {
    /// Returns the bytes of the third message, as well as the OSCORE master
    /// secret and the OSCORE master salt.
    #[allow(clippy::type_complexity)]
    pub fn generate_message_3(
        self,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), OwnError> {
        // Determine whether to include c_v in message_3 or not
        let c_v =
            if self.0.msg_1.r#type % 4 == 2 || self.0.msg_1.r#type % 4 == 3 {
                None
            } else {
                Some(self.0.msg_2.c_v)
            };

        // Build the COSE header map identifying the public authentication key
        let id_cred_u = cose::build_id_cred_x(&self.0.kid)?;
        // Build the COSE_Key containing our public authentication key
        let cred_u = cose::serialize_cose_key(&self.0.auth[32..])?;
        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.0.th_2,
            &self.0.msg_2.ciphertext,
            c_v.as_deref(),
        )?;
        // Sign it
        let sig = cose::sign(&id_cred_u, &th_3, &cred_u, &self.0.auth)?;

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            "10",
            util::CCM_KEY_LEN * 8,
            &th_3,
            self.0.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            "IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
            &th_3,
            self.0.shared_secret.as_bytes(),
        )?;

        // Put together the plaintext for the encryption
        let plaintext = util::build_plaintext(&self.0.kid, &sig)?;
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
            util::CCM_KEY_LEN,
            &th_4,
            self.0.shared_secret.as_bytes(),
        )?;
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.0.shared_secret.as_bytes(),
        )?;

        Ok((msg_3_seq, master_secret, master_salt))
    }
}
*/
// Party V constructs ---------------------------------------------------------

/// The structure providing all operations for Party V.
pub struct PartyV<S: PartyVState>(pub S);
// Necessary stuff for session types
pub trait PartyVState {}
impl PartyVState for Msg1Receiver {}
impl PartyVState for Msg2Sender {}
impl PartyVState for Msg3Receiver {}
//impl PartyVState for Msg3Verifier {}

/// Contains the state to receive the first message.
/// 
pub struct Msg1Receiver {
    secret: StaticSecret,
    x_r: PublicKey,
    stat_priv: StaticSecret,
    stat_pub: PublicKey,
    kid: Vec<u8>,
}

impl PartyV<Msg1Receiver> {
    /// Creates a new `PartyV` ready to receive the first message.
    ///
    /// # Arguments
    /// * `c_v` - The chosen connection identifier.
    /// * `ecdh_secret` - The ECDH secret to use for this protocol run.
    /// * `auth_private` - The private ed25519 authentication key.
    /// * `auth_public` - The public ed25519 authentication key.
    /// * `kid` - The key ID by which the other party is able to retrieve
    ///   `auth_public`.
    pub fn new(
        ecdh_secret: [u8; 32],
        stat_priv: StaticSecret,
        stat_pub: PublicKey,
        kid: Vec<u8>,
    ) -> PartyV<Msg1Receiver> {
        // From the secret bytes, create the DH secret
        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_r = PublicKey::from(&secret);
        // Combine the authentication key pair for convenience

        PartyV(Msg1Receiver {
            secret,
            x_r,
            stat_priv,
            stat_pub,
            kid,
        })
    }

    /// Processes the first message.
    pub fn handle_message_1(
        self,
        msg_1: Vec<u8>,
    ) -> Result<PartyV<Msg2Sender>, OwnError> {
        // Alias this
        let msg_1_seq = msg_1;
        // Decode the first message
        let msg_1 = util::deserialize_message_1(&msg_1_seq)?;

        // Verify that the selected suite is supported
        
        if msg_1.suite != 3 {
            #[allow(clippy::try_err)]
            Err(Error::UnsupportedSuite)?;
        }
        let c_r = msg_1.c_i.iter().map(|x| x + 1).collect();

        // Use U's public key to generate the ephemeral shared secret
        let mut x_i_bytes = [0; 32];
        x_i_bytes.copy_from_slice(&msg_1.x_i[..32]);
        let i_public = x25519_dalek::PublicKey::from(x_i_bytes);

        // generating shared secret at responder
        let shared_secret_0 = self.0.secret.diffie_hellman(&i_public);

        let r_public_copy = i_public.clone();
        
        let shared_secret_1 = self.0.stat_priv.diffie_hellman(&r_public_copy);

        Ok(PartyV(Msg2Sender {
            c_r: c_r,
            shared_secret_0,
            shared_secret_1,
            x_r: self.0.x_r,
            stat_priv: self.0.stat_priv,
            stat_pub: self.0.stat_pub,
            R_kid: self.0.kid,
            msg_1_seq,
            msg_1,
        }))
    }
}

/// Contains the state to build the second message.
///  shared_secret_0 : the first shared secret created from ephemeral keys only
/// shared_secret_1 : The second shared secret, created only from I's public ephemeral key, and R's private static key
/// shared_secret_2 : the third shared secret, created only from I's public static key, and I's private ephemeral key
/// (this is from the side of I)
pub struct Msg2Sender {
    c_r: Vec<u8>,
    shared_secret_0: SharedSecret,
    shared_secret_1: SharedSecret,
    x_r: PublicKey,
    stat_priv: StaticSecret,
    stat_pub : PublicKey,
    R_kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
    msg_1: Message1,
}

impl PartyV<Msg2Sender> {
    /// Returns the bytes of the second message.
    pub fn generate_message_2(
        self,
    ) -> Result<(Vec<u8>, PartyV<Msg3Receiver>),OwnOrPeerError> {

            // first we need to build the id_cred_r from the kid
            let id_cred_r = cose::build_id_cred_x(&self.0.R_kid)?;

            // We now build the cred_x using the public key, and kid value
            let cred_r = cose::serialize_cred_x(&self.0.stat_pub.to_bytes(),&self.0.R_kid )?; 

            let th_2 = util::compute_th_2(self.0.msg_1_seq, &self.0.c_r, self.0.x_r)?;

         
            let (prk_2e,PRK_2e_hkdf) = util::derivePRK(None, self.0.shared_secret_0.as_bytes())?;

            let (_,PRK_3e2m_hkdf) = util::derivePRK(Some(&prk_2e),self.0.shared_secret_1.as_bytes())?;


            let MAC_2 = util::createMACWithExpand(PRK_3e2m_hkdf, util::HASHFUNC_OUTPUT_LEN_BYTES, &th_2, "MAC_2", id_cred_r, cred_r)?;


            let PlaintextEncoded = util::build_plaintext(&self.0.R_kid, &MAC_2)?;


            let Keystream2 = util::createKEYSTREAMWithExpand(PRK_2e_hkdf, &th_2, PlaintextEncoded.len(), "KEYSTREAM_2")?;

            let ciphertext_2 = util::xor(&Keystream2, &PlaintextEncoded)?;

        //    println!("coneection identiy: {:?}", self.0.c_r);

        //    println!("cipertext: {:?}", ciphertext_2);

            let msg2 = Message2 {
                ephemeral_key_r : self.0.x_r.as_bytes().to_vec(),
                c_r : self.0.c_r,
                ciphertext2: ciphertext_2,
            };

            let msg2_seq = util::serialize_message_2(&msg2)?;

            Ok((msg2_seq, 
                PartyV(Msg3Receiver {
                    shared_secret_0: self.0.shared_secret_0,
                    shared_secret_1: self.0.shared_secret_1,
                    msg_2 : msg2,
                    th_2 : th_2,
                }),
            ))

        
    }
}

/// Contains the state to receive the third message.
pub struct Msg3Receiver {
    shared_secret_0: SharedSecret,
    shared_secret_1 : SharedSecret,
    msg_2: Message2,
    th_2: Vec<u8>,
}
/*
impl PartyV<Msg3Receiver> {
    /// Returns the key ID of the other party's public authentication key.
    pub fn extract_peer_kid(
        self,
        msg_3: Vec<u8>,
    ) -> Result<(Vec<u8>, PartyV<Msg3Verifier>), OwnOrPeerError> {
        // Check if we don't have an error message
        util::fail_on_error_message(&msg_3)?;
        // Decode the third message
        let msg_3 = util::deserialize_message_3(&msg_3)?;

        // Compute TH_3
        let th_3 = util::compute_th_3(
            &self.0.th_2,
            &self.0.msg_2.ciphertext,
            msg_3.c_v.as_deref(),
        )?;

        // Derive K_3
        let k_3 = util::edhoc_key_derivation(
            "10",
            util::CCM_KEY_LEN * 8,
            &th_3,
            self.0.shared_secret.as_bytes(),
        )?;
        // Derive IV_3
        let iv_3 = util::edhoc_key_derivation(
            "IV-GENERATION",
            util::CCM_NONCE_LEN * 8,
            &th_3,
            self.0.shared_secret.as_bytes(),
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
            PartyV(Msg3Verifier {
                shared_secret: self.0.shared_secret,
                msg_3,
                th_3,
                u_kid,
                u_sig,
            }),
        ))
    }
}

/// Contains the state to verify the third message.
pub struct Msg3Verifier {
    shared_secret: SharedSecret,
    msg_3: Message3,
    th_3: Vec<u8>,
    u_kid: Vec<u8>,
    u_sig: Vec<u8>,
}

impl PartyV<Msg3Verifier> {
    /// Checks the authenticity of the third message with the other party's
    /// public authentication key and returns the OSCORE master secret and the
    /// OSCORE master Salt.
    pub fn verify_message_3(
        self,
        u_public: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OwnError> {
        // Build the COSE header map identifying the public authentication key
        // of U
        let id_cred_u = cose::build_id_cred_x(&self.0.u_kid)?;
        // Build the COSE_Key containing U's public authentication key
        let cred_u = cose::serialize_cose_key(u_public)?;
        // Verify the signed data from Party U
        cose::verify(
            &id_cred_u,
            &self.0.th_3,
            &cred_u,
            u_public,
            &self.0.u_sig,
        )?;

        // Derive values for the OSCORE context
        let th_4 = util::compute_th_4(&self.0.th_3, &self.0.msg_3.ciphertext)?;
        let master_secret = util::edhoc_exporter(
            "OSCORE Master Secret",
            util::CCM_KEY_LEN,
            &th_4,
            self.0.shared_secret.as_bytes(),
        )?;
        let master_salt = util::edhoc_exporter(
            "OSCORE Master Salt",
            8,
            &th_4,
            self.0.shared_secret.as_bytes(),
        )?;

        Ok((master_secret, master_salt))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_vectors::*;
    use super::*;

    const SUITE_MSG: [u8; 27] = [
        0x20, 0x78, 0x18, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73,
        0x75, 0x69, 0x74, 0x65, 0x20, 0x75, 0x6E, 0x73, 0x75, 0x70, 0x70,
        0x6F, 0x72, 0x74, 0x65, 0x64,
    ];
    const CBOR_MSG: [u8; 23] = [
        0x20, 0x75, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x70, 0x72, 0x6F,
        0x63, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x42, 0x4F,
        0x52,
    ];

    fn successful_run(r#type: isize) -> (Vec<u8>, Vec<u8>) {
        // Party U ------------------------------------------------------------
        let msg1_sender = PartyU::new(
            C_U.to_vec(),
            EPH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(r#type).unwrap();

        // Party V ------------------------------------------------------------

        let msg1_receiver = PartyV::new(
            C_V.to_vec(),
            EPH_V_PRIVATE,
            &AUTH_V_PRIVATE,
            &AUTH_V_PUBLIC,
            KID_V.to_vec(),
        );
        let msg2_sender = msg1_receiver.handle_message_1(msg1_bytes).unwrap();
        let (msg2_bytes, msg3_receiver) =
            msg2_sender.generate_message_2().unwrap();

        // Party U ------------------------------------------------------------
        let (_v_kid, msg2_verifier) =
            msg2_receiver.extract_peer_kid(msg2_bytes).unwrap();
        let msg3_sender =
            msg2_verifier.verify_message_2(&AUTH_V_PUBLIC).unwrap();
        let (msg3_bytes, u_master_secret, u_master_salt) =
            msg3_sender.generate_message_3().unwrap();

        // Party V ------------------------------------------------------------
        let (_u_kid, msg3_verifier) =
            msg3_receiver.extract_peer_kid(msg3_bytes).unwrap();
        let (v_master_secret, v_master_salt) =
            msg3_verifier.verify_message_3(&AUTH_U_PUBLIC).unwrap();

        // Verification -------------------------------------------------------
        assert_eq!(u_master_secret, v_master_secret);
        assert_eq!(u_master_salt, v_master_salt);

        (u_master_secret, u_master_salt)
    }

    #[test]
    fn normal_run() {
        // Using the same parameters as test vectors, should give same results
        let (master_secret, master_salt) = successful_run(1);
        assert_eq!(&MASTER_SECRET, &master_secret[..]);
        assert_eq!(&MASTER_SALT, &master_salt[..]);

        // These just need to end up successful
        successful_run(0);
        successful_run(2);
        successful_run(3);
    }

    #[test]
    fn unsupported_suite() {
        // Party U ------------------------------------------------------------

        let msg1_sender = PartyU::new(
            C_U.to_vec(),
            AUTH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (mut msg1_bytes, _) = msg1_sender.generate_message_1(1).unwrap();
        // Change the suite
        msg1_bytes[1] = 0x01;

        // Party V ------------------------------------------------------------
        let msg1_receiver = PartyV::new(
            C_V.to_vec(),
            AUTH_V_PRIVATE,
            &AUTH_V_PRIVATE,
            &AUTH_V_PUBLIC,
            KID_V.to_vec(),
        );
        let _ = match msg1_receiver.handle_message_1(msg1_bytes) {
            Err(OwnError(b)) => assert_eq!(&SUITE_MSG, &b[..]),
            Ok(_) => panic!("Should have resulted in a suite error"),
        };
    }

    #[test]
    fn only_own_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender = PartyU::new(
            C_U.to_vec(),
            AUTH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (mut msg1_bytes, _) = msg1_sender.generate_message_1(1).unwrap();
        // Garble the message
        msg1_bytes[0] = 0xFF;

        // Party V ------------------------------------------------------------
        let msg1_receiver = PartyV::new(
            C_V.to_vec(),
            AUTH_V_PRIVATE,
            &AUTH_V_PRIVATE,
            &AUTH_V_PUBLIC,
            KID_V.to_vec(),
        );
        let _ = match msg1_receiver.handle_message_1(msg1_bytes) {
            Err(OwnError(b)) => assert_eq!(&CBOR_MSG, &b[..]),
            Ok(_) => panic!("Should have resulted in a CBOR error"),
        };
    }

    #[test]
    fn both_own_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender = PartyU::new(
            C_U.to_vec(),
            AUTH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(1).unwrap();

        // Party V ------------------------------------------------------------
        let msg1_receiver = PartyV::new(
            C_V.to_vec(),
            AUTH_V_PRIVATE,
            &AUTH_V_PRIVATE,
            &AUTH_V_PUBLIC,
            KID_V.to_vec(),
        );
        let msg2_sender = msg1_receiver.handle_message_1(msg1_bytes).unwrap();
        let (mut msg2_bytes, _) = msg2_sender.generate_message_2().unwrap();
        // Garble the message
        msg2_bytes[0] = 0xFF;

        // Party U ------------------------------------------------------------
        match msg2_receiver.extract_peer_kid(msg2_bytes) {
            Err(OwnOrPeerError::OwnError(b)) => assert_eq!(&CBOR_MSG, &b[..]),
            _ => panic!("Should have resulted in a CBOR error"),
        };
    }

    #[test]
    fn both_peer_error() {
        // Party U ------------------------------------------------------------
        let msg1_sender = PartyU::new(
            C_U.to_vec(),
            AUTH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (mut msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(1).unwrap();
        // Garble the message
        msg1_bytes[0] = 0xFF;

        // Party V ------------------------------------------------------------
        let msg1_receiver = PartyV::new(
            C_V.to_vec(),
            AUTH_V_PRIVATE,
            &AUTH_V_PRIVATE,
            &AUTH_V_PUBLIC,
            KID_V.to_vec(),
        );
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
            _ => panic!("Should have resulted in a peer error"),
        };
    }

    /// This is here to test that the ECDH library we use complies with the
    /// test vectors.
    #[test]
    fn shared_secret() {
        let mut eph_u_private = [0; 32];
        eph_u_private.copy_from_slice(&EPH_U_PRIVATE);
        let u_priv = StaticSecret::from(eph_u_private);
        let mut eph_v_private = [0; 32];
        eph_v_private.copy_from_slice(&EPH_V_PRIVATE);
        let v_priv = StaticSecret::from(eph_v_private);

        let u_pub = PublicKey::from(&u_priv);
        assert_eq!(&X_U, u_pub.as_bytes());
        let v_pub = PublicKey::from(&v_priv);
        assert_eq!(&X_V, v_pub.as_bytes());

        assert_eq!(&SHARED_SECRET, u_priv.diffie_hellman(&v_pub).as_bytes());
        assert_eq!(&SHARED_SECRET, v_priv.diffie_hellman(&u_pub).as_bytes());
    }
}
*/

