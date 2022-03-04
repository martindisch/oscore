

use alloc::vec::Vec;
use serde_bytes::Bytes;

use super::Result;
use crate::cbor;






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
            // (AlgorithmID, PartyIInfo, PartyRInfo, SuppPubInfo)
            let cose_kdf_context =
                (algorithm_id, [(); 3], [(); 3], supp_pub_info);
            cbor::encode(cose_kdf_context)?
        }
        // It's a string
        Err(_) => {
            // (AlgorithmID, PartyIInfo, PartyRInfo, SuppPubInfo)
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
pub fn serialize_cred_x(x: &[u8], kid : &Vec<u8>) -> Result<Vec<u8>> { //
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the COSE_Key.
    // ( kid key, kid value, COSE_key key, COSE_key value)
    let raw_key = (1, kid, 2, Bytes::new(x));
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
/*
should test cred_x serialisation instead
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
*/
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
