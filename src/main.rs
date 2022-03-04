//#![no_std]

use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
};
use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek::{PublicKey,StaticSecret};

use rand_core::{OsRng,};


const SUITE_I: isize = 3;
const METHOD_TYPE_I : isize = 0;
fn main() {



    /*
    Parti I generate message 1
    */


    let i_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let i_static_pub = PublicKey::from(&i_static_priv);


    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut r : StdRng = StdRng::from_entropy();
    let i_priv = r.gen::<[u8;32]>();
    
    // Choose a connection identifier
    let i_c_i = [0x1].to_vec();


    let i_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyI::new(i_c_i, i_priv, i_static_priv, i_static_pub, i_kid);

    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();




  //  let msg_1_struct : Message1= util::deserialize_message_1(&msg1_bytes).unwrap();

    /*
    /// Party R handle message 1
    */

    let r_static_priv : StaticSecret  = StaticSecret::new(OsRng);
    let r_static_pub = PublicKey::from(&r_static_priv);


    let r_kid = [0xA3].to_vec();

    // create keying material

    let mut r2 : StdRng = StdRng::from_entropy();
    let r_priv = r2.gen::<[u8;32]>();

    let msg1_receiver =
       PartyR::new(r_priv, r_static_priv, r_static_pub, r_kid);
       
    let msg2_sender = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        },
        Ok(val) => val,
    };

    // generated shared secret for responder:
    // println!("{:?}", msg2_sender.0.shared_secret.to_bytes());

    /*
    Responder gør sig klar til at lave message 2.
    */

    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };


    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 2, and then generating message 3, and the rck/sck
    ///////////////////////////////////////////////////////////////////// */
    

    // unpacking message, and getting kid, which we in a realworld situation would use to lookup our key
    let  (r_kid ,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2_bytes){
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    println!("initiator unpacked responders kid: {:?}", r_kid);

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
        Ok(val) => val, };

        let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3() {
            Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
            Ok(val) => val,
        };

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */
    
    let tup3 = msg3_receiver.handle_message_3(msg3_bytes,&i_static_pub.as_bytes().to_vec());

    let (msg4sender, r_sck,r_rck) = match tup3 {
            Ok(v) => v,
            Err(e) =>panic!("panicking in handling message 3 {}", e),
        };

        let msg4_bytes =
        match msg4sender.generate_message_4() {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };
    

        /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 4, and generati  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (i_sck, i_rck) =
    match msg4_receiver_verifier.receive_message_4(msg4_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    println!("Initiator completed handshake and made chan keys");

    println!("sck {:?}", i_sck);
    println!("rck {:?}", i_rck);
    println!("Responder completed handshake and made chan keys");

    println!("sck {:?}", r_sck);
    println!("rck {:?}", r_rck);

/*
        let (_v_kid, msg2_verifier) =
        // This is a case where we could receive an error message (just abort
        // then), or cause an error (send it to the peer)
        match msg2_receiver.extract_peer_kid(msg2_bytes) {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };
    //println!("{:?}", n);
*/
    /*

    let v1: Vec<u8> = vec![0, 1, 2, 3];
    let v2: Vec<u8> = vec![5, 6, 7, 8];

    let v3 = xor(&v1, &v2);

    println!("v1: {:?}", v1);

    println!("v2: {:?}", v2);

    println!("v3: {:?}", v3);


    let v1_ = xor(&v1,&v3);


    println!("v1_prime: {:?}", v1_);*/


  //  println!("{:?}", n)
/*
    println!("{:?}", hexstring(&msg1Byt));


    let msgdeserial = util::deserialize_message_1(&msg1Byt);


    let 

    println!("{:?}", msgdeserial);
*/
    // XOR with common IV
   // for (b1, b2) in nonce.iter_mut().zip(common_iv.iter()) {
   //     *b1 ^= b2;
   // }
     
    /*
    // Party V ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by V
    let v_priv = [
        0x17, 0xCD, 0xC7, 0xBC, 0xA3, 0xF2, 0xA0, 0xBD, 0xA6, 0x0C, 0x6D,
        0xE5, 0xB9, 0x6F, 0x82, 0xA3, 0x62, 0x39, 0xB4, 0x4B, 0xDE, 0x39,
        0x7A, 0x38, 0x62, 0xD5, 0x29, 0xBA, 0x8B, 0x3D, 0x7C, 0x62,
    ];
    // Choose a connection identifier
    let v_c_v = [0xC4].to_vec();
    // This is the keypair used to authenticate.
    // U must have the public key.
    let v_auth_priv = [
        0x74, 0x56, 0xB3, 0xA3, 0xE5, 0x8D, 0x8D, 0x26, 0xDD, 0x36, 0xBC,
        0x75, 0xD5, 0x5B, 0x88, 0x63, 0xA8, 0x5D, 0x34, 0x72, 0xF4, 0xA0,
        0x1F, 0x02, 0x24, 0x62, 0x1B, 0x1C, 0xB8, 0x16, 0x6D, 0xA9,
    ];
    let v_kid = [0xA3].to_vec();

    let msg1_receiver =
        PartyR::new(v_c_v, v_priv, &v_auth_priv, &v_auth_pub, v_kid);
    // This is a case where we could cause an error, which we'd send to the
    // other party

*/
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
