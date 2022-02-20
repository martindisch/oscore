use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyU, PartyV,
    util::{self, deserialize_message_1, Message1},
};
use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek::{EphemeralSecret, PublicKey,StaticSecret};
use eui::{Eui64};

use rand_core::{RngCore, OsRng, CryptoRng,};


const suite_I: isize = 3;
const methodType_I : isize = 0;

fn main() {


    /*
    Parti I generate message 1
    */

    let APPEUI : Eui64 =  Eui64::from(85204980412143); // completely random mac adress (should be on device)


    let i_static_priv : EphemeralSecret  = EphemeralSecret::new(OsRng);
    let i_static_pub = PublicKey::from(&i_static_priv);


    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut r : StdRng = StdRng::from_entropy();
    let i_priv = r.gen::<[u8;32]>();
    
    // Choose a connection identifier
    let i_c_i = [0x1];

    let clone = i_c_i.clone();

    let i_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyU::new(i_c_i, i_priv, i_static_priv, i_static_pub,APPEUI, i_kid);

    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(methodType_I, suite_I).unwrap();




  //  let msg_1_struct : Message1= util::deserialize_message_1(&msg1_bytes).unwrap();

    /*
    /// Party R handle message 1
    */

    let DEVEUI : Eui64 =  Eui64::from(28945057161291); 
    let r_static_priv : EphemeralSecret  = EphemeralSecret::new(OsRng);
    let r_static_pub = PublicKey::from(&r_static_priv);

    // Choose a connection identifier and kid
    let r_c_i = [0x2];

    let r_kid = [0xA3].to_vec();

    // create keying material

    let mut r2 : StdRng = StdRng::from_entropy();
    let r_priv = r2.gen::<[u8;32]>();

    let msg1_receiver =
       PartyV::new(r_c_i, r_priv, r_static_priv, r_static_pub, r_kid);
       

    let msg2_sender = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            let s = std::str::from_utf8(&b).unwrap().to_string();
            panic!("{}", s)
        },
        Ok(val) => val,
    };

    // generated shared secret for responder:
    // println!("{:?}", msg2_sender.0.shared_secret.to_bytes());


    /*
    Responder gør sig klar til at lave message 2.
    */

    let n = msg2_sender.generate_message_2();


     
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
        PartyV::new(v_c_v, v_priv, &v_auth_priv, &v_auth_pub, v_kid);
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
