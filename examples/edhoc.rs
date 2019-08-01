use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek::{PublicKey, StaticSecret};

use oscore::edhoc::{Message1, Message2};

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
    // Get CBOR sequence for message
    let u_msg_1_seq = oscore::edhoc::serialize_message_1(&u_msg_1).unwrap();
    // Wrap it in a bstr for transmission
    let mut msg_1_bytes =
        oscore::cbor::encode(Bytes::new(&u_msg_1_seq)).unwrap();

    // Party V ----------------------------------------------------------------

    // Unwrap sequence from bstr
    let v_msg_1_seq: ByteBuf = oscore::cbor::decode(&mut msg_1_bytes).unwrap();
    // Decode the first message
    let v_msg_1 = oscore::edhoc::deserialize_message_1(&v_msg_1_seq).unwrap();
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
    // Use U's public key to generate the ephemeral shared secret
    let mut v_x_u_bytes = [0; 32];
    v_x_u_bytes.copy_from_slice(&v_msg_1.x_u[..32]);
    let v_u_public = x25519_dalek::PublicKey::from(v_x_u_bytes);
    let v_shared_secret = v_secret.diffie_hellman(&v_u_public);

    // This is the keypair used to authenticate. U must have the public key.
    let v_auth = [
        0xBB, 0x5A, 0x16, 0x81, 0xBB, 0x9B, 0xC3, 0x12, 0x67, 0x8F, 0x53,
        0xD3, 0x14, 0x7F, 0xFF, 0x83, 0xF9, 0x56, 0xDB, 0x1F, 0xC6, 0xF4,
        0x35, 0xA8, 0xDF, 0xB6, 0xB1, 0x0A, 0xA7, 0x1E, 0xFA, 0x1C, 0x88,
        0x3D, 0x9F, 0x20, 0xAF, 0x73, 0xF7, 0x8E, 0xD2, 0x94, 0x78, 0xE4,
        0x16, 0x51, 0x4B, 0x88, 0x57, 0x19, 0x64, 0x3B, 0x63, 0xC5, 0x81,
        0xFD, 0x8B, 0x57, 0xDD, 0x3A, 0xC8, 0x01, 0x1A, 0xC6,
    ];

    // Some general information for this party
    let v_kid = b"bob@example.org";
    let v_c_v = b"Party V";

    // Build the COSE header map identifying the public authentication key
    let v_id_cred_v = oscore::cose::build_id_cred_x(v_kid).unwrap();
    // Build the COSE_Key containing our ECDH public key
    let v_cred_v =
        oscore::cose::serialize_cose_key(v_x_v.as_bytes(), v_kid).unwrap();
    // Compute TH_2
    let v_th_2 = oscore::edhoc::compute_th_2(
        &v_msg_1_seq,
        &v_msg_1.c_u,
        v_x_v.as_bytes(),
        v_c_v,
    )
    .unwrap();
    // Sign it
    let v_sig =
        oscore::cose::sign(&v_id_cred_v, &v_th_2, &v_cred_v, &v_auth).unwrap();

    // Derive K_2
    let v_k_2 = oscore::edhoc::edhoc_key_derivation(
        &"ChaCha20/Poly1305",
        256,
        &v_th_2,
        v_shared_secret.as_bytes(),
    )
    .unwrap();
    // Derive IV_2
    let v_iv_2 = oscore::edhoc::edhoc_key_derivation(
        &"IV-GENERATION",
        96,
        &v_th_2,
        v_shared_secret.as_bytes(),
    )
    .unwrap();

    // Put together the plaintext for the encryption
    let v_plaintext = oscore::edhoc::build_plaintext_2(v_kid, &v_sig).unwrap();
    // Compute the associated data
    let v_ad = oscore::cose::build_ad(&v_th_2).unwrap();
    // Get the ciphertext
    let v_ciphertext =
        oscore::edhoc::aead_seal(&v_k_2, &v_iv_2, &v_plaintext, &v_ad)
            .unwrap();

    // Produce message_2
    let v_msg_2 = Message2 {
        c_u: v_msg_1.c_u.clone(),
        x_v: v_x_v.as_bytes().to_vec(),
        c_v: v_c_v.to_vec(),
        ciphertext: v_ciphertext,
    };
    // Get CBOR sequence for message
    let v_msg_2_seq = oscore::edhoc::serialize_message_2(&v_msg_2).unwrap();
    // Wrap it in a bstr for transmission
    let mut msg_2_bytes =
        oscore::cbor::encode(Bytes::new(&v_msg_2_seq)).unwrap();
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
