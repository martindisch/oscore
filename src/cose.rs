use alloc::vec::Vec;
use ed25519_dalek::{Keypair, Signature};
use serde_bytes::Bytes;
use sha2::Sha512;

use crate::{cbor, Result};

/// Returns the signature from signing the `Sig_structure` of the given data.
///
/// # Arguments
/// * `id_cred_x` - The CBOR encoded header map identifying a public
///   authentication key, e.g. `{ 4 : h'1111' }`.
/// * `th_i` - The bstr wrapped transcript hash.
/// * `cred_x` - CBOR encoded `COSE_Key`.
/// * `keypair_bytes` - The ed25519 authentication key pair. First 32 bytes are
///   the secret key, the other 32 bytes the public key.
pub fn sign(
    id_cred_x: &[u8],
    th_i: &[u8],
    cred_x: &[u8],
    keypair_bytes: &[u8],
) -> Result<[u8; 64]> {
    let to_be_signed = build_to_be_signed(id_cred_x, th_i, cred_x)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)?;
    let signature = keypair.sign::<Sha512>(&to_be_signed);

    Ok(signature.to_bytes())
}

/// Checks if the signature was made on a `Sig_structure` of the given data,
/// with the given key.
///
/// # Arguments
/// * `id_cred_x` - The CBOR encoded header map identifying a public
///   authentication key, e.g. `{ 4 : h'1111' }`.
/// * `th_i` - The bstr wrapped transcript hash.
/// * `cred_x` - CBOR encoded `COSE_Key`.
/// * `public_key` - The ed25519 public key of the pair used for the signature.
/// * `signature` - The ed25519 signature.
pub fn verify(
    id_cred_x: &[u8],
    th_i: &[u8],
    cred_x: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<()> {
    let to_be_signed = build_to_be_signed(id_cred_x, th_i, cred_x)?;
    let public_key = ed25519_dalek::PublicKey::from_bytes(public_key)?;
    let signature = Signature::from_bytes(signature)?;

    Ok(public_key.verify::<Sha512>(&to_be_signed, &signature)?)
}

/// Returns the COSE `Sig_structure` used as input to the signature algorithm.
fn build_to_be_signed(
    id_cred_x: &[u8],
    th_i: &[u8],
    cred_x: &[u8],
) -> Result<Vec<u8>> {
    // Create the Sig_structure
    let sig_struct = (
        "Signature1",
        Bytes::new(id_cred_x), // protected
        0,                     // placeholder 1 (external_aad)
        0,                     // placeholder 2 (payload)
    );
    // Encode it to a CBOR array
    let mut sig_arr = cbor::encode(&sig_struct)?;
    // Remove the placeholder items
    sig_arr.truncate(sig_arr.len() - 2);
    // Insert the remaining two items that are already in their CBOR encoding
    sig_arr.extend(th_i); // external_aad
    sig_arr.extend(cred_x); // payload

    Ok(sig_arr)
}

/// Returns a CBOR encoded `COSE_KDF_Context`.
///
/// This is used as the info input for the HKDF-Expand step.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
pub fn build_kdf_context(
    algorithm_id: &str,
    key_data_length: usize,
    other: &[u8],
) -> Result<Vec<u8>> {
    // (keyDataLength, protected, other)
    let supp_pub_info = (key_data_length, Bytes::new(&[]), Bytes::new(other));
    // (AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo)
    let cose_kdf_context = (algorithm_id, [(); 3], [(); 3], supp_pub_info);

    cbor::encode(cose_kdf_context)
}

/// An Octet Key Pair (OKP) `COSE_Key`.
#[derive(Debug, PartialEq)]
pub struct CoseKey {
    kty: usize,
    crv: usize,
    x: Vec<u8>,
}

/// Returns the CBOR encoded `COSE_Key` for the given data.
///
/// This is specific to our use case where we only have Ed25519 public keys,
/// which are Octet Key Pairs (OKP) in COSE and represented as a single
/// x-coordinate.
pub fn serialize_cose_key(x: &[u8]) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the COSE_Key.
    // (kty key, kty value, crv key, crv value,
    //  x-coordinate key, x-coordinate value)
    let raw_key = (1, 1, -1, 6, -2, Bytes::new(x));
    // Get the byte representation of it
    let mut bytes = cbor::encode(raw_key)?;
    // This is a CBOR array, but we want a map
    cbor::array_to_map(&mut bytes)?;

    Ok(bytes)
}

/// Returns the COSE header map for the given `kid`.
pub fn build_id_cred_x(kid: &[u8]) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the COSE header map.
    // (kid key, kid value)
    let id_cred_x = (4, Bytes::new(kid));
    // Get the byte representation of it
    let mut bytes = cbor::encode(id_cred_x)?;
    // This is a CBOR array, but we want a map
    cbor::array_to_map(&mut bytes)?;

    Ok(bytes)
}

/// Returns the `COSE_Encrypt0` structure used as associated data in the AEAD.
pub fn build_ad(th_i: &[u8]) -> Result<Vec<u8>> {
    cbor::encode(("Encrypt0", Bytes::new(&[]), Bytes::new(th_i)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    #[test]
    fn to_be_signed() {
        let to_be_signed =
            build_to_be_signed(&ID_CRED_V, &TH_2, &CRED_V).unwrap();
        assert_eq!(&M_V[..], &to_be_signed[..]);
    }

    #[test]
    fn signature_same() {
        let signature = sign(
            &ID_CRED_V,
            &TH_2,
            &CRED_V,
            &build_keypair(&AUTH_V_PRIVATE, &AUTH_V_PUBLIC),
        )
        .unwrap();
        assert_eq!(&V_SIG[..], &signature[..]);
    }

    #[test]
    fn signature_verifies() {
        let signature = sign(
            &ID_CRED_V,
            &TH_2,
            &CRED_V,
            &build_keypair(&AUTH_V_PRIVATE, &AUTH_V_PUBLIC),
        )
        .unwrap();
        assert!(verify(
            &ID_CRED_V,
            &TH_2,
            &CRED_V,
            &AUTH_V_PUBLIC,
            &signature
        )
        .is_ok());

        let mut cred_x_changed = CRED_V.to_vec();
        cred_x_changed[1] = 0x44;
        assert!(verify(
            &ID_CRED_V,
            &TH_2,
            &cred_x_changed,
            &AUTH_V_PUBLIC,
            &signature
        )
        .is_err());
    }

    const ALG1: &str = "IV-GENERATION";
    const ALG2: &str = "AES-CCM-16-64-128";
    const LEN1: usize = 104;
    const LEN2: usize = 128;
    const OTHER: [u8; 2] = [0xAA, 0xAA];
    const CONTEXT1: [u8; 30] = [
        0x84, 0x6D, 0x49, 0x56, 0x2D, 0x47, 0x45, 0x4E, 0x45, 0x52, 0x41,
        0x54, 0x49, 0x4F, 0x4E, 0x83, 0xF6, 0xF6, 0xF6, 0x83, 0xF6, 0xF6,
        0xF6, 0x83, 0x18, 0x68, 0x40, 0x42, 0xAA, 0xAA,
    ];
    const CONTEXT2: [u8; 34] = [
        0x84, 0x71, 0x41, 0x45, 0x53, 0x2D, 0x43, 0x43, 0x4D, 0x2D, 0x31,
        0x36, 0x2D, 0x36, 0x34, 0x2D, 0x31, 0x32, 0x38, 0x83, 0xF6, 0xF6,
        0xF6, 0x83, 0xF6, 0xF6, 0xF6, 0x83, 0x18, 0x80, 0x40, 0x42, 0xAA,
        0xAA,
    ];

    #[test]
    fn context_generation() {
        let context_bytes = build_kdf_context(ALG1, LEN1, &OTHER).unwrap();
        assert_eq!(&CONTEXT1[..], &context_bytes[..]);

        let context_bytes = build_kdf_context(ALG2, LEN2, &OTHER).unwrap();
        assert_eq!(&CONTEXT2[..], &context_bytes[..]);
    }

    #[test]
    fn key_encode() {
        assert_eq!(
            &CRED_U[..],
            &serialize_cose_key(&AUTH_U_PUBLIC).unwrap()[..]
        );
        assert_eq!(
            &CRED_V[..],
            &serialize_cose_key(&AUTH_V_PUBLIC).unwrap()[..]
        );
    }

    #[test]
    fn encode_id_cred_x() {
        let bytes = build_id_cred_x(&KID_U).unwrap();
        assert_eq!(&ID_CRED_U[..], &bytes[..]);
        let bytes = build_id_cred_x(&KID_V).unwrap();
        assert_eq!(&ID_CRED_V[..], &bytes[..]);
    }

    const ENCRYPT_0_TH: [u8; 3] = [0x01, 0x02, 0x03];
    const ENCRYPT_0: [u8; 15] = [
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30, 0x40,
        0x43, 0x01, 0x02, 0x03,
    ];

    #[test]
    fn encrypt_0() {
        assert_eq!(&ENCRYPT_0[..], &build_ad(&ENCRYPT_0_TH).unwrap()[..]);
    }
}
