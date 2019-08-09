use oscore::edhoc::{Msg1Receiver, Msg1Sender};

fn main() {
    // TODO: An EDHOC error message should be sent to the other party whenever
    // an operation fails and the protocol is abandoned.

    let v_public = [
        0x88, 0x3D, 0x9F, 0x20, 0xAF, 0x73, 0xF7, 0x8E, 0xD2, 0x94, 0x78,
        0xE4, 0x16, 0x51, 0x4B, 0x88, 0x57, 0x19, 0x64, 0x3B, 0x63, 0xC5,
        0x81, 0xFD, 0x8B, 0x57, 0xDD, 0x3A, 0xC8, 0x01, 0x1A, 0xC6,
    ];
    let u_public = [
        0xB3, 0x94, 0x7F, 0x71, 0xA5, 0xCC, 0xA4, 0xF1, 0xD2, 0xA3, 0x42,
        0xAE, 0x62, 0x24, 0x17, 0x5E, 0x83, 0x77, 0x49, 0x34, 0x7E, 0x54,
        0x21, 0x8C, 0x35, 0xED, 0x0C, 0xC8, 0x0A, 0x26, 0x69, 0x79,
    ];

    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let u_priv = [
        144, 115, 162, 206, 225, 72, 94, 30, 253, 17, 9, 171, 183, 84, 94, 17,
        170, 82, 95, 72, 77, 44, 124, 143, 102, 139, 156, 120, 63, 2, 27, 70,
    ];
    // Choose a connection identifier
    let u_c_u = b"Party U".to_vec();
    // This is the keypair used to authenticate.
    // V must have the public key.
    let u_auth = [
        0x76, 0x9E, 0x0B, 0xE0, 0xF4, 0x30, 0x9A, 0x6D, 0x6D, 0x6E, 0xC7,
        0x8D, 0x61, 0xE0, 0xFB, 0xCF, 0x48, 0x3C, 0x8D, 0xE4, 0x2C, 0x39,
        0x30, 0xD0, 0x4A, 0x4B, 0xA9, 0x17, 0x8F, 0x6C, 0xA7, 0x0F, 0xB3,
        0x94, 0x7F, 0x71, 0xA5, 0xCC, 0xA4, 0xF1, 0xD2, 0xA3, 0x42, 0xAE,
        0x62, 0x24, 0x17, 0x5E, 0x83, 0x77, 0x49, 0x34, 0x7E, 0x54, 0x21,
        0x8C, 0x35, 0xED, 0x0C, 0xC8, 0x0A, 0x26, 0x69, 0x79,
    ];
    let u_kid = b"alice@example.org".to_vec();

    let msg1_sender = Msg1Sender::new(u_c_u, u_priv, u_auth, u_kid);
    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        msg1_sender.generate_message_1(1).unwrap();

    // Party V ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by V
    let v_priv = [
        16, 165, 169, 23, 227, 139, 247, 13, 53, 60, 173, 235, 46, 22, 199,
        69, 54, 240, 59, 183, 80, 23, 70, 121, 195, 57, 176, 97, 255, 171,
        154, 93,
    ];
    // Choose a connection identifier
    let v_c_v = b"Party V".to_vec();
    // This is the keypair used to authenticate.
    // U must have the public key.
    let v_auth = [
        0xBB, 0x5A, 0x16, 0x81, 0xBB, 0x9B, 0xC3, 0x12, 0x67, 0x8F, 0x53,
        0xD3, 0x14, 0x7F, 0xFF, 0x83, 0xF9, 0x56, 0xDB, 0x1F, 0xC6, 0xF4,
        0x35, 0xA8, 0xDF, 0xB6, 0xB1, 0x0A, 0xA7, 0x1E, 0xFA, 0x1C, 0x88,
        0x3D, 0x9F, 0x20, 0xAF, 0x73, 0xF7, 0x8E, 0xD2, 0x94, 0x78, 0xE4,
        0x16, 0x51, 0x4B, 0x88, 0x57, 0x19, 0x64, 0x3B, 0x63, 0xC5, 0x81,
        0xFD, 0x8B, 0x57, 0xDD, 0x3A, 0xC8, 0x01, 0x1A, 0xC6,
    ];
    let v_kid = b"bob@example.org".to_vec();

    let msg1_receiver = Msg1Receiver::new(v_c_v, v_priv, v_auth, v_kid);
    let msg2_sender = msg1_receiver.handle_message_1(msg1_bytes).unwrap();
    let (msg2_bytes, msg3_receiver) =
        msg2_sender.generate_message_2().unwrap();

    // Party U ----------------------------------------------------------------
    let (v_kid, msg2_verifier) =
        msg2_receiver.extract_peer_kid(msg2_bytes).unwrap();
    let msg3_sender = msg2_verifier.verify_message_2(&v_public).unwrap();
    let (msg3_bytes, u_master_secret, u_master_salt) =
        msg3_sender.generate_message_3().unwrap();

    // Party V ----------------------------------------------------------------
    let (u_kid, msg3_verifier) =
        msg3_receiver.extract_peer_kid(msg3_bytes).unwrap();
    let (v_master_secret, v_master_salt) =
        msg3_verifier.verify_message_3(&u_public).unwrap();

    // Party U ----------------------------------------------------------------
    // It's possible that Party V failed verification of message_3, in which
    // case it sends an EDHOC error message.
    // Technically, Party U would have to be ready to receive this message and
    // invalidate any protocol state.

    // Verification -----------------------------------------------------------
    assert_eq!(u_master_secret, v_master_secret);
    assert_eq!(u_master_salt, v_master_salt);

    println!(
        "OSCORE Context established.\n\
         Master Secret:\n{}\n\
         Master Salt:\n{}",
        hexstring(&u_master_secret),
        hexstring(&u_master_salt)
    );
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
