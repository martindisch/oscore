//! Structs used in the API.

use alloc::vec::Vec;
use core::result::Result;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use super::{
    cose,
    error::{EarlyError, Error, OwnError, OwnOrPeerError},
    util::{self, Message1, Message2, Message3,Message4},
};


// Party U constructs ---------------------------------------------------------

/// The structure providing all operations for Party U.
pub struct PartyI<S: PartyIState>(pub S);

// Necessary stuff for session types
pub trait PartyIState {}
impl PartyIState for Msg1Sender {}
impl PartyIState for Msg2Receiver {}
impl PartyIState for Msg2Verifier {}
impl PartyIState for Msg3Sender {}
impl PartyIState for Msg4ReceiveVerify {}



pub struct Msg1Sender {
    c_i: Vec<u8>,
    pub secret: StaticSecret,
    pub x_i: PublicKey,
    static_secret: StaticSecret,
    static_public: PublicKey,
    kid: Vec<u8>,
}

impl PartyI<Msg1Sender> {
    /// Creates a new `PartyI` ready to build the first message.
    ///
    /// # Arguments
    /// * `c_u` - The chosen connection identifier.
    /// * `ecdh_secret` - The ECDH secret to use for this protocol run. Ephemeral
    /// * `stat_priv` - The private ed25519derivePRKauthentication key.
    /// * `APPEUI` - MAC adress of server
    /// * `kid` - The key ID by which the other party is able to retrieve
    ///   `stat_public`, which is called 'id_cred_x in edho 14 .
    pub fn new(
        c_i: Vec<u8>,
        ecdh_secret: [u8; 32],
        stat_priv: StaticSecret,
        stat_pub: PublicKey,
        kid: Vec<u8>,
    ) -> PartyI<Msg1Sender> {

        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_i = PublicKey::from(&secret);

        // Combine the authentication key pair for convenience
         PartyI(Msg1Sender {
            c_i,
            secret,
            x_i,
            static_secret:stat_priv,
            static_public:stat_pub,
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
    ) -> Result<(Vec<u8>, PartyI<Msg2Receiver>), EarlyError> {
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
            PartyI(Msg2Receiver {
                i_ecdh_ephemeralsecret: self.0.secret,
                stat_priv: self.0.static_secret,
                stat_pub: self.0.static_public,
      //          auth: self.0.auth,
                kid: self.0.kid,
                msg_1_seq,
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
}



impl PartyI<Msg2Receiver> {
    /// Returns the key ID of the other party's public authentication key, and the state for verification 
    pub fn unpack_message_2_return_kid(
        self,
        msg_2: Vec<u8>,
    ) -> Result<(Vec<u8>, PartyI<Msg2Verifier>), OwnOrPeerError> {

        util::fail_on_error_message(&msg_2)?;


        let msg_2 = util::deserialize_message_2(&msg_2)?;

        // cosntructing ephemeral keypair


        // Constructing shared secret for initiator 
        let mut x_r_bytes = [0; 32];
        x_r_bytes.copy_from_slice(&msg_2.ephemeral_key_r[..32]);
        let r_public = x25519_dalek::PublicKey::from(x_r_bytes);


       let shared_secret_0 = self.0.i_ecdh_ephemeralsecret.diffie_hellman(&r_public);
 

        // reconstructing keystream2
        let th_2 = util::compute_th_2(self.0.msg_1_seq, &msg_2.c_r, r_public)?;
        let (prk_2e,prk_2e_hkdf) = util::derive_prk(None, shared_secret_0.as_bytes())?;


        let keystream2 = util::generic_expand(prk_2e_hkdf, 
                                                        &th_2, msg_2.ciphertext2.len(), 
                                                        "KEYSTREAM_2"
                                                        ,false)?;
        let decryptedlaintext = util::xor(&keystream2, &msg_2.ciphertext2)?;

        let (r_kid,mac_2 ) = util::extract_plaintext(decryptedlaintext)?;

        let r_kid_cpy = r_kid.clone();

        Ok((
            r_kid,
            PartyI(Msg2Verifier {
                i_ecdh_ephemeralsecret : self.0.i_ecdh_ephemeralsecret,
                stat_priv: self.0.stat_priv,
                stat_pub : self.0.stat_pub,
                kid: self.0.kid,
  
                msg_2: msg_2,
                mac_2: mac_2,
                prk_2e: prk_2e,
                th_2: th_2,
                r_kid :r_kid_cpy,
                r_ephemeral_pk: r_public,

            

            }),
        ))

    }
}



/// Contains the state to verify the second message.
pub struct Msg2Verifier {
    i_ecdh_ephemeralsecret : StaticSecret,
    stat_priv : StaticSecret,
    stat_pub : PublicKey,
    kid: Vec<u8>,

    msg_2: Message2,
    mac_2: Vec<u8>,
    prk_2e : Vec<u8>,
    th_2: Vec<u8>,
    r_kid: Vec<u8>,
    r_ephemeral_pk : PublicKey,
}


impl PartyI<Msg2Verifier> {
    /// Checks the authenticity of the second message with the other party's
    /// public authentication key.
    pub fn verify_message_2(
        self,
        r_public_static_bytes: &[u8],
    ) -> Result<PartyI<Msg3Sender>, OwnError> {

        // build cred_x and id_cred_x (for responder party)
        let id_cred_r = cose::build_id_cred_x(&self.0.r_kid)?;
        let cred_r = cose::serialize_cred_x(r_public_static_bytes,&self.0.r_kid )?; 


        // Generating static public key of initiator
        let mut statkey_r_bytes = [0; 32];
        statkey_r_bytes.copy_from_slice(&r_public_static_bytes[..32]);
        let r_public_static = x25519_dalek::PublicKey::from(statkey_r_bytes);

        // Generating shared secret 1 for initiator

        let shared_secret_1 = self.0.i_ecdh_ephemeralsecret.diffie_hellman(&r_public_static);

        // generating prk_3

        let (prk_3em,prk_3e2m_hkdf) = util::derive_prk(Some(&self.0.prk_2e)
            ,shared_secret_1.as_bytes())?;

        let prk_3e2m_hkdf_cpy = prk_3e2m_hkdf.clone();




        let mac_2 = util::create_macwith_expand(prk_3e2m_hkdf, 
            util::HASHFUNC_OUTPUT_LEN_BITS, 
            &self.0.th_2, 
            "mac_2", 
            id_cred_r, 
            cred_r)?;

        if self.0.mac_2 != mac_2{
            Err(Error::BadMac)?;
        }

        Ok(PartyI(Msg3Sender{
            i_stat_priv : self.0.stat_priv,
            i_stat_pub : self.0.stat_pub,
            r_ephemeral_pk: self.0.r_ephemeral_pk,
            i_kid : self.0.kid,
            msg_2 : self.0.msg_2,
            th_2 : self.0.th_2,
            prk_3e2m_hkdf : prk_3e2m_hkdf_cpy,
            prk_3e2m : prk_3em
        }))
    }
}

/// Contains the state to build the third message.
pub struct Msg3Sender {
    i_stat_priv : StaticSecret,
    i_stat_pub : PublicKey,

    r_ephemeral_pk : PublicKey, 
    i_kid: Vec<u8>,
    msg_2: Message2,
    th_2: Vec<u8>,
    prk_3e2m_hkdf :  hkdf::Hkdf<sha2::Sha256>,
    prk_3e2m : Vec<u8>,

}

impl PartyI<Msg3Sender> {
    /// Returns the bytes of the third message, as well as the OSCORE master
    /// secret and the OSCORE master salt.
    pub fn generate_message_3(
        self,
    ) -> Result<(PartyI<Msg4ReceiveVerify>,Vec<u8>), OwnError> {

        //first making necessary copies:

        let prk_3e2m_hkdf_cpy1 = self.0.prk_3e2m_hkdf.clone();
        let prk_3e2m_hkdf_cpy2 = self.0.prk_3e2m_hkdf.clone();
        // Build the COSE header map identifying the public authentication key
        let id_cred_i = cose::build_id_cred_x(&self.0.i_kid)?;
        // Build the COSE_Key containing our public authentication key
        let cred_i = cose::serialize_cred_x(&self.0.i_stat_pub.to_bytes(), &self.0.i_kid)?;

        let shared_secret_2 = self.0.i_stat_priv.diffie_hellman(&self.0.r_ephemeral_pk);
        
        
        // transcript hash 3

        let th_3 = util::compute_th_3(
            &self.0.th_2, 
            &self.0.msg_2.ciphertext2)?;

            
        let (prk_4x3m,_prk_4x3m_hkdf) = util::derive_prk(
            Some(&self.0.prk_3e2m),
             shared_secret_2.as_bytes())?;

        let mac_3 = util::create_macwith_expand(
            self.0.prk_3e2m_hkdf, 
            util::HASHFUNC_OUTPUT_LEN_BITS, 
            &th_3,  
            "MAC_3",
             id_cred_i, 
             cred_i)?;

        
        let k_3 = util::generic_expand(
            prk_3e2m_hkdf_cpy1, 
            &th_3, 
            util::CCM_KEY_LEN,
            "K_3",
            true)?;
            
        let iv_3 = util::generic_expand(
            prk_3e2m_hkdf_cpy2, 
            &th_3, 
            util::CCM_NONCE_LEN,
            "IV_3",
             true)?;
        let p = util::build_plaintext(&self.0.i_kid, &mac_3)?;

        let ad = cose::build_ad(&th_3)?;

        // Constructing ciphertext:
        let ciphertext_3 = util::aead_seal(&k_3, &iv_3, &p, &ad)?;

        let ciphertext_3_cpy = ciphertext_3.clone();
        let msg_3 = Message3 {ciphertext: ciphertext_3};
        let msg_3_seq = util::serialize_message_3(&msg_3)?;



        // now computing the values needed for sck and rck
        let th_4 = util::compute_th_4(&th_3, &ciphertext_3_cpy)?;


        let master_secret = util::edhoc_exporter(
            "OSCORE_Master_Secret",
            util::CCM_KEY_LEN / 8, //going from bits to bytes
            &th_4,
            &prk_4x3m,
        )?;

        let master_salt = util::edhoc_exporter(
            "OSCORE_Master_Salt",
            util::SALT_LENGTH / 8,//going from bits to bytes
            &th_4,
            &prk_4x3m,
        )?;

        Ok((PartyI(Msg4ReceiveVerify {
            prk_4x3m : prk_4x3m,
            th_4 : th_4,
            master_salt : master_salt,
            master_secret: master_secret
        }),msg_3_seq))
    }
}


pub struct Msg4ReceiveVerify {
    prk_4x3m : Vec<u8>,
    th_4 : Vec<u8>,
    master_secret : Vec<u8>,
    master_salt : Vec<u8>,
}

impl PartyI<Msg4ReceiveVerify> {
    pub fn receive_message_4(
        self,
        msg4_seq : Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), OwnOrPeerError> {


        util::fail_on_error_message(&msg4_seq)?;
        let msg4 = util::deserialize_message_4(&msg4_seq)?;


        let k_4 = util::edhoc_exporter(
            "EDHOC_K_4",
            util::CCM_KEY_LEN , //going from bits to bytes
            &self.0.th_4,
            &self.0.prk_4x3m,
        )?;

        let iv_4 = util::edhoc_exporter(
            "EDHOC_IV_4",
            util::CCM_NONCE_LEN , //going from bits to bytes
            &self.0.th_4,
            &self.0.prk_4x3m,
        )?;
        let ad = cose::build_ad(&self.0.th_4)?;

        let plaintext = util::aead_open(&k_4, &iv_4, &msg4.ciphertext, &ad)?;


        if plaintext.len() != 0{
            Err(Error::Aead)?;
        }


        let sck = util::edhoc_exporter(
            "SCK", 
            32, 
            &self.0.master_salt, 
            &self.0.master_secret)?;

        let rck = util::edhoc_exporter(
            "RCK", 
            32, 
            &self.0.master_salt, 
            &self.0.master_secret)?;





        Ok((sck,rck))
    }

}
// Party V constructs ---------------------------------------------------------

/// The structure providing all operations for Party V.
pub struct PartyR<S: PartyRState>(pub S);
// Necessary stuff for session types
pub trait PartyRState {}
impl PartyRState for Msg1Receiver {}
impl PartyRState for Msg2Sender {}
impl PartyRState for Msg3Receiver {}
impl PartyRState for Msg4Sender {}

/// Contains the state to receive the first message.
/// 
pub struct Msg1Receiver {
    secret: StaticSecret,
    x_r: PublicKey,
    stat_priv: StaticSecret,
    stat_pub: PublicKey,
    kid: Vec<u8>,
}

impl PartyR<Msg1Receiver> {
    /// Creates a new `PartyR` ready to receive the first message.
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
    ) -> PartyR<Msg1Receiver> {
        // From the secret bytes, create the DH secret
        let secret = StaticSecret::from(ecdh_secret);
        // and from that build the corresponding public key
        let x_r = PublicKey::from(&secret);
        // Combine the authentication key pair for convenience

        PartyR(Msg1Receiver {
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
    ) -> Result<PartyR<Msg2Sender>, OwnError> {
        // Alias this
        let msg_1_seq = msg_1;
        // Decode the first message
        let msg_1 = util::deserialize_message_1(&msg_1_seq)?;

        // Verify that the selected suite is supported
        
        if msg_1.suite != 3 {
            Err(Error::UnsupportedSuite)?;
        }
        let c_r = msg_1.c_i.iter().map(|x| x + 1).collect();

        // Use U's public key to generate the ephemeral shared secret
        let mut x_i_bytes = [0; 32];
        x_i_bytes.copy_from_slice(&msg_1.x_i[..32]);
        let i_public = x25519_dalek::PublicKey::from(x_i_bytes);

        // generating shared secret at responder
        let shared_secret_0 = self.0.secret.diffie_hellman(&i_public);

        let i_public_cpy = i_public.clone();
        
        let shared_secret_1 = self.0.stat_priv.diffie_hellman(&i_public_cpy);



        Ok(PartyR(Msg2Sender {
            c_r: c_r,
            ecdh_r_secret : self.0.secret,
            shared_secret_0,
            shared_secret_1,
            x_r: self.0.x_r,
            stat_pub: self.0.stat_pub,
            r_kid: self.0.kid,
            msg_1_seq,
        }))
    }
}

/// Contains the state to build the second message.
///  shared_secret_0 : the first shared secret created from ephemeral keys only
/// shared_secret_1 : The second shared secret, created only from I's  ephemeral key,R and static key
/// shared_secret_2 : the third shared secret, created only from I's  static key, and R's ephemeral key
/// (this is from the side of I)
pub struct Msg2Sender {
    c_r: Vec<u8>,
    ecdh_r_secret: StaticSecret,
    shared_secret_0: SharedSecret,
    shared_secret_1: SharedSecret,
    x_r: PublicKey,
    stat_pub : PublicKey,
    r_kid: Vec<u8>,
    msg_1_seq: Vec<u8>,
}

impl PartyR<Msg2Sender> {
    /// Returns the bytes of the second message.
    pub fn generate_message_2(
        self,
    ) -> Result<(Vec<u8>, PartyR<Msg3Receiver>),OwnOrPeerError> {

            // first we need to build the id_cred_r from the kid
            let id_cred_r = cose::build_id_cred_x(&self.0.r_kid)?;

            // We now build the cred_x using the public key, and kid value
            let cred_r = cose::serialize_cred_x(&self.0.stat_pub.to_bytes(),&self.0.r_kid )?; 

            let th_2 = util::compute_th_2(self.0.msg_1_seq, &self.0.c_r, self.0.x_r)?;

            
            let (prk_2e,prk_2e_hkdf) = util::derive_prk(None, self.0.shared_secret_0.as_bytes())?;

            let (prk_3e2m,prk_3e2m_hkdf) = util::derive_prk(Some(&prk_2e),self.0.shared_secret_1.as_bytes())?;

            let prk_3e2m_hkdf_cpy = prk_3e2m_hkdf.clone();
            let mac_2 = util::create_macwith_expand(prk_3e2m_hkdf, util::HASHFUNC_OUTPUT_LEN_BITS, &th_2, "mac_2", id_cred_r, cred_r)?;

            let plaintext_encoded = util::build_plaintext(&self.0.r_kid, &mac_2)?;


            let keystream2 = util::generic_expand(
                prk_2e_hkdf, 
                &th_2, 
                plaintext_encoded.len(), 
                "KEYSTREAM_2",
                false)?;

            let ciphertext_2 = util::xor(&keystream2, &plaintext_encoded)?;



            let msg2 = Message2 {
                ephemeral_key_r : self.0.x_r.as_bytes().to_vec(),
                c_r : self.0.c_r,
                ciphertext2: ciphertext_2,
            };

            let msg2_seq = util::serialize_message_2(&msg2)?;

            Ok((msg2_seq, 
                PartyR(Msg3Receiver {
                    r_ecdh_secret: self.0.ecdh_r_secret,
                    prk_3e2m_hkdf : prk_3e2m_hkdf_cpy,
                    prk_3e2m : prk_3e2m,
                    msg_2 : msg2,
                    th_2 : th_2,
                }),
            ))

        
    }
}

/// Contains the state to receive the third message.
pub struct Msg3Receiver {
    r_ecdh_secret : StaticSecret,
    prk_3e2m_hkdf  : hkdf::Hkdf<sha2::Sha256>,
    prk_3e2m : Vec<u8>,
    msg_2: Message2,
    th_2: Vec<u8>,
}

impl PartyR<Msg3Receiver> {
    /// Returns the key ID of the other party's public authentication key.
    pub fn handle_message_3(
        self,
        msg_3_seq: Vec<u8>,
        i_public_static_bytes: &[u8],
    ) -> Result<(PartyR<Msg4Sender>, Vec<u8>, Vec<u8>), OwnOrPeerError> {
        util::fail_on_error_message(&msg_3_seq)?;
        // first, relevant copies:
        let prk_3e2m_hkdf_cpy1 = self.0.prk_3e2m_hkdf.clone();
        let prk_3e2m_hkdf_cpy2 = self.0.prk_3e2m_hkdf.clone();

        // Check if we don't have an error message
        
        // Decode the third message

        let msg_3 = util::deserialize_message_3(&msg_3_seq)?;

                // Generating static public key of initiator
        let mut statkey_i_bytes = [0; 32];
        statkey_i_bytes.copy_from_slice(&i_public_static_bytes[..32]);
        let i_public_static = x25519_dalek::PublicKey::from(statkey_i_bytes);
        
        let shared_secret_2 = self.0.r_ecdh_secret.diffie_hellman(&i_public_static);

        let th_3 = util::compute_th_3(
            &self.0.th_2, 
            &self.0.msg_2.ciphertext2)?;


        let k_3 = util::generic_expand(
            self.0.prk_3e2m_hkdf, 
            &th_3, 
            util::CCM_KEY_LEN,
            "K_3_",
            true)?;
        let iv_3 = util::generic_expand(
            prk_3e2m_hkdf_cpy1, 
            &th_3, 
            util::CCM_NONCE_LEN,
            "IV_3",
            true)?;
        
        let ad = cose::build_ad(&th_3)?;

        let p = util::aead_open(
            &k_3, 
            &iv_3, 
            &msg_3.ciphertext, 
            &ad)?;

        let (r_kid, mac3) = util::extract_plaintext(p)?;

        let id_cred_i = cose::build_id_cred_x(&r_kid)?;

        let cred_i = cose::serialize_cred_x(&i_public_static.to_bytes(), &r_kid)?;
      
      
        let mac_3_initiator = util::create_macwith_expand(
            prk_3e2m_hkdf_cpy2, 
            util::HASHFUNC_OUTPUT_LEN_BITS, 
            &th_3,  
            "MAC_3",
             id_cred_i, 
             cred_i)?;


        if mac_3_initiator != mac3{
            Err(Error::BadMac)?;
            }
        // now computing the values needed for sck and rck
        let th_4 = util::compute_th_4(&th_3, &msg_3.ciphertext)?;

        let (prk_4x3m,_prk_4x3m_hkdf) = util::derive_prk(
            Some(&self.0.prk_3e2m),
             shared_secret_2.as_bytes())?;

       

        let master_secret = util::edhoc_exporter(
            "OSCORE_Master_Secret",
            util::CCM_KEY_LEN / 8, //going from bits to bytes
            &th_4,
            &prk_4x3m,
        )?;

        let master_salt = util::edhoc_exporter(
            "OSCORE_Master_Salt",
            util::SALT_LENGTH / 8,//going from bits to bytes
            &th_4,
            &prk_4x3m,
        )?;

        let sck = util::edhoc_exporter(
            "SCK", 
            32, 
            &master_salt, 
            &master_secret)?;

        let rck = util::edhoc_exporter(
            "RCK", 
            32, 
            &master_salt, 
            &master_secret)?;

        Ok((PartyR(Msg4Sender{
            prk_4x3m : prk_4x3m,
            th_4 : th_4,
        }),
        sck,
        rck))
    }
}

/// Contains the state to verify the third message.
pub struct Msg4Sender {
    prk_4x3m : Vec<u8>,
    th_4 : Vec<u8>,
}


impl PartyR<Msg4Sender> {
    pub fn generate_message_4(
        self,
    ) -> Result< Vec<u8>, OwnOrPeerError> {


        let k_4 = util::edhoc_exporter(
            "EDHOC_K_4",
            util::CCM_KEY_LEN , //going from bits to bytes
            &self.0.th_4,
            &self.0.prk_4x3m,
        )?;

        let iv_4 = util::edhoc_exporter(
            "EDHOC_IV_4",
            util::CCM_NONCE_LEN , //going from bits to bytes
            &self.0.th_4,
            &self.0.prk_4x3m,
        )?;


        let ad = cose::build_ad(&self.0.th_4)?;



        let ciphertext_4 = util::aead_seal(&k_4, &iv_4, "".as_bytes(), &ad)?;
        let msg4 = Message4 {
            ciphertext : ciphertext_4,
        };
        let msg4_seq = util::serialize_message_4(&msg4)?;

        Ok(msg4_seq)
    }
}
/*
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
        let msg1_sender = PartyI::new(
            C_U.to_vec(),
            EPH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(r#type).unwrap();

        // Party V ------------------------------------------------------------

        let msg1_receiver = PartyR::new(
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

        let msg1_sender = PartyI::new(
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
        let msg1_receiver = PartyR::new(
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
        let msg1_sender = PartyI::new(
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
        let msg1_receiver = PartyR::new(
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
        let msg1_sender = PartyI::new(
            C_U.to_vec(),
            AUTH_U_PRIVATE,
            &AUTH_U_PRIVATE,
            &AUTH_U_PUBLIC,
            KID_U.to_vec(),
        );
        let (msg1_bytes, msg2_receiver) =
            msg1_sender.generate_message_1(1).unwrap();

        // Party V ------------------------------------------------------------
        let msg1_receiver = PartyR::new(
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
        let msg1_sender = PartyI::new(
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
        let msg1_receiver = PartyR::new(
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

