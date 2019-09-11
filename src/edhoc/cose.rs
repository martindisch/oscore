use alloc::vec::Vec;
use ed25519_dalek::{Keypair, Signature};
use serde_bytes::Bytes;
use sha2::Sha512;

use super::Result;
use crate::cbor;

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
    sig_arr.extend(cbor::encode(Bytes::new(cred_x))?); // payload

    Ok(sig_arr)
}

/// Returns a CBOR encoded `COSE_KDF_Context`.
///
/// This is used as the info input for the HKDF-Expand step.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. "IV-GENERATION" or COSE number
///   e.g. "10" for AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
pub fn build_kdf_context(
    algorithm_id: &str,
    key_data_length: usize,
    other: &[u8],
) -> Result<Vec<u8>> {
    // (keyDataLength, protected, placeholder (other))
    let supp_pub_info = (key_data_length, Bytes::new(&[]), 0);
    // It's the same code, but we need different branches  for the type system
    // depending on whether we have a string or number as algorithm_id
    let mut kdf_arr = match algorithm_id.parse::<usize>() {
        // It's a number
        Ok(algorithm_id) => {
            // (AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo)
            let cose_kdf_context =
                (algorithm_id, [(); 3], [(); 3], supp_pub_info);
            cbor::encode(cose_kdf_context)?
        }
        // It's a string
        Err(_) => {
            // (AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo)
            let cose_kdf_context =
                (algorithm_id, [(); 3], [(); 3], supp_pub_info);
            cbor::encode(cose_kdf_context)?
        }
    };
    // Remove the placeholder item
    kdf_arr.pop();
    // Insert the transcript hash, which is already in its CBOR encoding
    kdf_arr.extend(other);

    Ok(kdf_arr)
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
    // Create array with placeholder
    let mut ad_arr = cbor::encode(("Encrypt0", Bytes::new(&[]), 0))?;
    // Remove the placeholder
    ad_arr.pop();
    // Append the transcript hash, which is already CBOR encoded
    ad_arr.extend(th_i);

    Ok(ad_arr)
}

#[cfg(test)]
mod tests {
    use super::super::test_vectors::*;
    use super::*;

    #[test]
    fn to_be_signed() {
        let to_be_signed =
            build_to_be_signed(&ID_CRED_V, &TH_2, &CRED_V).unwrap();
        assert_eq!(&M_V[..], &to_be_signed[..]);

        let to_be_signed =
            build_to_be_signed(&ID_CRED_U, &TH_3, &CRED_U).unwrap();
        assert_eq!(&M_U[..], &to_be_signed[..]);
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

        let signature = sign(
            &ID_CRED_U,
            &TH_3,
            &CRED_U,
            &build_keypair(&AUTH_U_PRIVATE, &AUTH_U_PUBLIC),
        )
        .unwrap();
        assert_eq!(&U_SIG[..], &signature[..]);
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

    #[test]
    fn context_generation() {
        let context_bytes = build_kdf_context("10", 128, &TH_2).unwrap();
        assert_eq!(&INFO_K_2[..], &context_bytes[..]);
        let context_bytes =
            build_kdf_context("IV-GENERATION", 104, &TH_2).unwrap();
        assert_eq!(&INFO_IV_2[..], &context_bytes[..]);

        let context_bytes = build_kdf_context("10", 128, &TH_3).unwrap();
        assert_eq!(&INFO_K_3[..], &context_bytes[..]);
        let context_bytes =
            build_kdf_context("IV-GENERATION", 104, &TH_3).unwrap();
        assert_eq!(&INFO_IV_3[..], &context_bytes[..]);

        let context_bytes =
            build_kdf_context("OSCORE Master Secret", 128, &TH_4).unwrap();
        assert_eq!(&INFO_MASTER_SECRET[..], &context_bytes[..]);
        let context_bytes =
            build_kdf_context("OSCORE Master Salt", 64, &TH_4).unwrap();
        assert_eq!(&INFO_MASTER_SALT[..], &context_bytes[..]);
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

    #[test]
    fn encrypt_0() {
        assert_eq!(&A_2[..], &build_ad(&TH_2).unwrap()[..]);

        assert_eq!(&A_3[..], &build_ad(&TH_3).unwrap()[..]);
    }

    fn build_keypair(private: &[u8], public: &[u8]) -> Vec<u8> {
        let mut keypair = private.to_vec();
        keypair.extend(public);

        keypair
    }
}
