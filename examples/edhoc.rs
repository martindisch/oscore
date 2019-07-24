use oscore::edhoc::Message1;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // Party U ----------------------------------------------------------------

    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let u_priv = [
        144, 115, 162, 206, 225, 72, 94, 30, 253, 17, 9, 171, 183, 84, 94, 17,
        170, 82, 95, 72, 77, 44, 124, 143, 102, 139, 156, 120, 63, 2, 27, 70,
    ];
    // The corresponding DH secret
    let u_secret = StaticSecret::from(u_priv);
    // The corresponding public key
    let u_x_u = PublicKey::from(&u_secret);

    // Encode the necessary information into the first message
    let u_msg_1 = Message1 {
        r#type: 0,
        suite: 0,
        x_u: u_x_u.as_bytes().to_vec(),
        c_u: b"Party U".to_vec(),
    };
    let msg_1_bytes = oscore::edhoc::serialize_message_1(&u_msg_1).unwrap();

    // Party V ----------------------------------------------------------------

    // Decode the first message
    let v_msg_1 = oscore::edhoc::deserialize_message_1(&msg_1_bytes).unwrap();
    // Verify that the selected suite is supported
    if v_msg_1.suite != 0 {
        unimplemented!("Other cipher suites");
    }

    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let v_priv = [
        16, 165, 169, 23, 227, 139, 247, 13, 53, 60, 173, 235, 46, 22, 199,
        69, 54, 240, 59, 183, 80, 23, 70, 121, 195, 57, 176, 97, 255, 171,
        154, 93,
    ];
    // The corresponding DH secret
    let v_secret = StaticSecret::from(v_priv);
    // The corresponding public key
    let v_x_v = PublicKey::from(&v_secret);
}
