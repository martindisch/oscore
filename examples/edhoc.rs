use serde_bytes::{ByteBuf, Bytes};
use x25519_dalek::{PublicKey, StaticSecret};

use oscore::{
    cbor, cose, edhoc,
    edhoc::{Message1, Message2, Message3},
};

fn main() {
    // TODO: An EDHOC error message should be sent to the other party whenever
    // an operation fails and the protocol is abandoned.

    // Party U ----------------------------------------------------------------
    // Some general information for this party
    let u_kid = b"alice@example.org";
    let u_c_u = b"Party U";

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
        // This would be the case in CoAP, where party U can correlate
        // message_1 and message_2 with the token
        r#type: 1,
        suite: 0,
        x_u: u_x_u.as_bytes().to_vec(),
        c_u: u_c_u.to_vec(),
    };
    // Get CBOR sequence for message
    let u_msg_1_seq = edhoc::serialize_message_1(&u_msg_1).unwrap();
    // Wrap it in a bstr for transmission
    let mut msg_1_bytes = cbor::encode(Bytes::new(&u_msg_1_seq)).unwrap();

    // Party V ----------------------------------------------------------------
    // Some general information for this party
    let v_kid = b"bob@example.org";
    let v_c_v = b"Party V";

    // Unwrap sequence from bstr
    let v_msg_1_seq: ByteBuf = cbor::decode(&mut msg_1_bytes).unwrap();
    // Decode the first message
    let v_msg_1 = edhoc::deserialize_message_1(&v_msg_1_seq).unwrap();
    // Verify that the selected suite is supported
    if v_msg_1.suite != 0 {
        unimplemented!("Other cipher suites");
    }

    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by V
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

    // Build the COSE header map identifying the public authentication key
    let v_id_cred_v = cose::build_id_cred_x(v_kid).unwrap();
    // Build the COSE_Key containing our ECDH public key
    let v_cred_v = cose::serialize_cose_key(v_x_v.as_bytes(), v_kid).unwrap();
    // Compute TH_2
    let v_th_2 = edhoc::compute_th_2(
        &v_msg_1_seq,
        // TODO:
        Some(&v_msg_1.c_u),
        v_x_v.as_bytes(),
        v_c_v,
    )
    .unwrap();
    // Sign it
    let v_sig = cose::sign(&v_id_cred_v, &v_th_2, &v_cred_v, &v_auth).unwrap();

    // Derive K_2
    let v_k_2 = edhoc::edhoc_key_derivation(
        &"ChaCha20/Poly1305",
        256,
        &v_th_2,
        v_shared_secret.as_bytes(),
    )
    .unwrap();
    // Derive IV_2
    let v_iv_2 = edhoc::edhoc_key_derivation(
        &"IV-GENERATION",
        96,
        &v_th_2,
        v_shared_secret.as_bytes(),
    )
    .unwrap();

    // Put together the plaintext for the encryption
    let v_plaintext = edhoc::build_plaintext(v_kid, &v_sig).unwrap();
    // Compute the associated data
    let v_ad = cose::build_ad(&v_th_2).unwrap();
    // Get the ciphertext
    let v_ciphertext =
        edhoc::aead_seal(&v_k_2, &v_iv_2, &v_plaintext, &v_ad).unwrap();

    // Determine whether to include c_u or not
    let v_c_u = if v_msg_1.r#type % 4 == 1 || v_msg_1.r#type % 4 == 3 {
        None
    } else {
        Some(v_msg_1.c_u.clone())
    };
    // Produce message_2
    let v_msg_2 = Message2 {
        c_u: v_c_u,
        x_v: v_x_v.as_bytes().to_vec(),
        c_v: v_c_v.to_vec(),
        ciphertext: v_ciphertext,
    };
    // Get CBOR sequence for message
    let v_msg_2_seq = edhoc::serialize_message_2(&v_msg_2).unwrap();
    // Wrap it in a bstr for transmission
    let mut msg_2_bytes = cbor::encode(Bytes::new(&v_msg_2_seq)).unwrap();

    // Party U ----------------------------------------------------------------
    // Unwrap sequence from bstr
    let u_msg_2_seq: ByteBuf = cbor::decode(&mut msg_2_bytes).unwrap();
    // Check if we don't have an error message
    edhoc::fail_on_error_message(&u_msg_2_seq).unwrap();
    // Decode the second message
    let u_msg_2 = edhoc::deserialize_message_2(&u_msg_2_seq).unwrap();

    // Use V's public key to generate the ephemeral shared secret
    let mut u_x_v_bytes = [0; 32];
    u_x_v_bytes.copy_from_slice(&u_msg_2.x_v[..32]);
    let u_v_public = x25519_dalek::PublicKey::from(u_x_v_bytes);
    let u_shared_secret = u_secret.diffie_hellman(&u_v_public);

    // Compute TH_2
    let u_th_2 = edhoc::compute_th_2(
        &u_msg_1_seq,
        // TODO:
        Some(&u_msg_1.c_u),
        &u_msg_2.x_v,
        &u_msg_2.c_v,
    )
    .unwrap();

    // Derive K_2
    let u_k_2 = edhoc::edhoc_key_derivation(
        &"ChaCha20/Poly1305",
        256,
        &u_th_2,
        u_shared_secret.as_bytes(),
    )
    .unwrap();
    // Derive IV_2
    let u_iv_2 = edhoc::edhoc_key_derivation(
        &"IV-GENERATION",
        96,
        &u_th_2,
        u_shared_secret.as_bytes(),
    )
    .unwrap();

    // Compute the associated data
    let u_ad = cose::build_ad(&u_th_2).unwrap();
    // Decrypt and verify the ciphertext
    let mut u_plaintext =
        edhoc::aead_open(&u_k_2, &u_iv_2, &u_msg_2.ciphertext, &u_ad).unwrap();
    // Fetch the contents of the plaintext
    let (u_v_kid, u_v_sig) =
        edhoc::extract_plaintext(&mut u_plaintext).unwrap();

    // Build the COSE header map identifying the public authentication key of V
    let u_id_cred_v = cose::build_id_cred_x(&u_v_kid).unwrap();
    // Build the COSE_Key containing V's ECDH public key
    let u_cred_v = cose::serialize_cose_key(&u_msg_2.x_v, &u_v_kid).unwrap();
    // Verify the signed data from Party V
    cose::verify(&u_id_cred_v, &u_th_2, &u_cred_v, &v_auth[32..], &u_v_sig)
        .unwrap();

    // This is the keypair used to authenticate. V must have the public key.
    let u_auth = [
        0x76, 0x9E, 0x0B, 0xE0, 0xF4, 0x30, 0x9A, 0x6D, 0x6D, 0x6E, 0xC7,
        0x8D, 0x61, 0xE0, 0xFB, 0xCF, 0x48, 0x3C, 0x8D, 0xE4, 0x2C, 0x39,
        0x30, 0xD0, 0x4A, 0x4B, 0xA9, 0x17, 0x8F, 0x6C, 0xA7, 0x0F, 0xB3,
        0x94, 0x7F, 0x71, 0xA5, 0xCC, 0xA4, 0xF1, 0xD2, 0xA3, 0x42, 0xAE,
        0x62, 0x24, 0x17, 0x5E, 0x83, 0x77, 0x49, 0x34, 0x7E, 0x54, 0x21,
        0x8C, 0x35, 0xED, 0x0C, 0xC8, 0x0A, 0x26, 0x69, 0x79,
    ];

    // Build the COSE header map identifying the public authentication key
    let u_id_cred_u = cose::build_id_cred_x(u_kid).unwrap();
    // Build the COSE_Key containing our ECDH public key
    let u_cred_u = cose::serialize_cose_key(u_x_u.as_bytes(), u_kid).unwrap();
    // Compute TH_3
    let u_th_3 =
        // TODO:
        edhoc::compute_th_3(&u_th_2, &u_msg_2.ciphertext, Some(&u_msg_2.c_v))
            .unwrap();
    // Sign it
    let u_sig = cose::sign(&u_id_cred_u, &u_th_3, &u_cred_u, &u_auth).unwrap();

    // Derive K_3
    let u_k_3 = edhoc::edhoc_key_derivation(
        &"ChaCha20/Poly1305",
        256,
        &u_th_3,
        u_shared_secret.as_bytes(),
    )
    .unwrap();
    // Derive IV_3
    let u_iv_3 = edhoc::edhoc_key_derivation(
        &"IV-GENERATION",
        96,
        &u_th_3,
        u_shared_secret.as_bytes(),
    )
    .unwrap();

    // Put together the plaintext for the encryption
    let u_plaintext = edhoc::build_plaintext(u_kid, &u_sig).unwrap();
    // Compute the associated data
    let u_ad = cose::build_ad(&u_th_3).unwrap();
    // Get the ciphertext
    let u_ciphertext =
        edhoc::aead_seal(&u_k_3, &u_iv_3, &u_plaintext, &u_ad).unwrap();

    // Determine whether to include c_v or not
    let u_c_v = if u_msg_1.r#type % 4 == 2 || u_msg_1.r#type % 4 == 3 {
        None
    } else {
        Some(u_msg_2.c_v.to_vec())
    };
    // Produce message_3
    let u_msg_3 = Message3 {
        c_v: u_c_v,
        ciphertext: u_ciphertext,
    };
    // Get CBOR sequence for message
    let u_msg_3_seq = edhoc::serialize_message_3(&u_msg_3).unwrap();
    // Wrap it in a bstr for transmission
    let mut msg_3_bytes = cbor::encode(Bytes::new(&u_msg_3_seq)).unwrap();

    // Derive values for the OSCORE context
    let u_th_4 = edhoc::compute_th_4(&u_th_3, &u_msg_3.ciphertext).unwrap();
    let u_master_secret = edhoc::edhoc_exporter(
        "OSCORE Master Secret",
        32,
        &u_th_4,
        u_shared_secret.as_bytes(),
    )
    .unwrap();
    let u_master_salt = edhoc::edhoc_exporter(
        "OSCORE Master Salt",
        8,
        &u_th_4,
        u_shared_secret.as_bytes(),
    )
    .unwrap();

    // Party V ----------------------------------------------------------------
    // Unwrap sequence from bstr
    let v_msg_3_seq: ByteBuf = cbor::decode(&mut msg_3_bytes).unwrap();
    // Check if we don't have an error message
    edhoc::fail_on_error_message(&v_msg_3_seq).unwrap();
    // Decode the third message
    let v_msg_3 = edhoc::deserialize_message_3(&v_msg_3_seq).unwrap();

    // Compute TH_3
    let v_th_3 =
        // TODO:
        edhoc::compute_th_3(&v_th_2, &v_msg_2.ciphertext, Some(&v_msg_2.c_v))
            .unwrap();

    // Derive K_3
    let v_k_3 = edhoc::edhoc_key_derivation(
        &"ChaCha20/Poly1305",
        256,
        &v_th_3,
        v_shared_secret.as_bytes(),
    )
    .unwrap();
    // Derive IV_3
    let v_iv_3 = edhoc::edhoc_key_derivation(
        &"IV-GENERATION",
        96,
        &v_th_3,
        v_shared_secret.as_bytes(),
    )
    .unwrap();

    // Compute the associated data
    let v_ad = cose::build_ad(&v_th_3).unwrap();
    // Decrypt and verify the ciphertext
    let mut v_plaintext =
        edhoc::aead_open(&v_k_3, &v_iv_3, &v_msg_3.ciphertext, &v_ad).unwrap();
    // Fetch the contents of the plaintext
    let (v_u_kid, v_u_sig) =
        edhoc::extract_plaintext(&mut v_plaintext).unwrap();

    // Build the COSE header map identifying the public authentication key of U
    let v_id_cred_u = cose::build_id_cred_x(&v_u_kid).unwrap();
    // Build the COSE_Key containing U's ECDH public key
    let v_cred_u = cose::serialize_cose_key(&v_msg_1.x_u, &v_u_kid).unwrap();
    // Verify the signed data from Party U
    cose::verify(&v_id_cred_u, &v_th_3, &v_cred_u, &u_auth[32..], &v_u_sig)
        .unwrap();

    // Derive values for the OSCORE context
    let v_th_4 = edhoc::compute_th_4(&v_th_3, &v_msg_3.ciphertext).unwrap();
    let v_master_secret = edhoc::edhoc_exporter(
        "OSCORE Master Secret",
        32,
        &v_th_4,
        v_shared_secret.as_bytes(),
    )
    .unwrap();
    let v_master_salt = edhoc::edhoc_exporter(
        "OSCORE Master Salt",
        8,
        &v_th_4,
        v_shared_secret.as_bytes(),
    )
    .unwrap();

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
