
use alloc::{collections::LinkedList, string::String, vec::Vec};
use coap_lite::{CoapOption, Packet};
use core::convert::TryFrom;
use hkdf::Hkdf;
use serde_bytes::Bytes;
use sha2::Sha256;

use crate::cbor;

use super::{error::Error, Result};

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 13;

/// Returns the CBOR encoded `info` structure.
///
/// # Arguments
/// * `id` - The sender ID or recipient ID (or empty for IV).
/// * `type` - Either "Key" or "IV".
/// * `l` - The size of the key/nonce for the AEAD, in bytes.
pub fn build_info(id: &[u8], r#type: &str, l: usize) -> Result<Vec<u8>> {
    // (id, id_context, alg_aead, type, L)
    let info = (Bytes::new(id), (), 10, r#type, l);
    // Return the CBOR encoded version of that
    Ok(cbor::encode(info)?)
}

/// Returns the derived key/IV for this `info` structure.
///
/// # Arguments
/// * `master_secret` - The master secret.
/// * `master_salt` - The master salt.
/// * `info` - The `info` structure, different for key and IV derivation.
/// * `l` - The size of the key/nonce for the AEAD used, in bytes.
pub fn hkdf(
    master_secret: &[u8],
    master_salt: &[u8],
    info: &[u8],
    l: usize,
) -> Result<Vec<u8>> {
    // This is the extract step, resulting in the pseudorandom key (PRK)
    let h = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; l];
    h.expand(info, &mut okm)?;

    Ok(okm)
}

/// Returns the CBOR encoded AAD array.
///
/// There's no argument for class I options, because the standard doesn't
/// define any at this point.
pub fn build_aad_array(
    request_kid: &[u8],
    request_piv: &[u8],
) -> Result<Vec<u8>> {
    // (oscore_version, algorithms, request_kid, request_piv, options)
    let arr = (
        1,
        [10],
        Bytes::new(request_kid),
        Bytes::new(request_piv),
        Bytes::new(&[]),
    );
    // Return the CBOR encoded version of that
    Ok(cbor::encode(arr)?)
}

/// Returns the AAD.
pub fn build_aad(request_kid: &[u8], request_piv: &[u8]) -> Result<Vec<u8>> {
    // First we need to construct the AAD array containing our parameters
    let aad_arr = build_aad_array(request_kid, request_piv)?;
    // Then we pack it into an Encrypt0 structure
    let aad = ("Encrypt0", Bytes::new(&[]), Bytes::new(&aad_arr));
    // And return the encoding of that
    Ok(cbor::encode(aad)?)
}

/// Returns the value of the OSCORE option.
pub fn build_oscore_option(kid: Option<&[u8]>, piv: Option<&[u8]>) -> Vec<u8> {
    // Allocate memory for the flag byte and piv and kid
    let mut option =
        vec![0; 1 + piv.map_or(0, |p| p.len()) + kid.map_or(0, |k| k.len())];
    // If we have neither kid nor piv, our option has no value
    if option.len() == 1 {
        option.pop();
        return option;
    }

    if let Some(piv) = piv {
        // Set the partial IV length (3 least significant bits of flag byte)
        option[0] |= piv.len() as u8 & 0b0000_0111;
        // Copy in the partial IV
        option[1..=piv.len()].copy_from_slice(piv);
    }

    if let Some(kid) = kid {
        // Set the kid flag
        option[0] |= 0b0000_1000;
        // Copy in the kid
        option[1 + piv.map_or(0, |p| p.len())..].copy_from_slice(kid);
    }

    option
}

/// Returns the `kid` and `piv` values from the message, if present.
#[allow(clippy::type_complexity)]
pub fn extract_kid_piv(
    message: &Packet,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let option_value = message
        .get_option(CoapOption::Oscore)
        .ok_or(Error::NoOscoreOption)?
        .front()
        .ok_or(Error::NoOscoreOption)?;

    Ok(extract_oscore_option(option_value))
}

/// Returns the encoded `kid` and `piv` values from the option, if present.
fn extract_oscore_option(value: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    // Handle empty option
    if value.is_empty() {
        return (None, None);
    }

    // Unpack piv if present
    let (piv, piv_len) = match value[0] & 0b0000_0111 {
        0 => (None, 0),
        n => {
            // Check if we really received enough data
            if value.len() > n as usize {
                (Some(Vec::from(&value[1..=n as usize])), n)
            } else {
                // If not, abort
                return (None, None);
            }
        }
    };
    // Unpack kid if present
    let kid = match value[0] & 0b0000_1000 {
        0 => None,
        _ => Some(Vec::from(&value[1 + piv_len as usize..])),
    };

    (kid, piv)
}

/// Returns the nonce for the AEAD.
pub fn compute_nonce(
    mut piv: &[u8],
    mut id_piv: &[u8],
    common_iv: &[u8; NONCE_LEN],
) -> [u8; NONCE_LEN] {
    // Since id_piv could be longer than it should, trim it if necessary
    if id_piv.len() > NONCE_LEN - 6 {
        id_piv = &id_piv[id_piv.len() - (NONCE_LEN - 6)..]
    }
    // Same for the piv itself
    if piv.len() > 5 {
        piv = &piv[piv.len() - 5..];
    }

    let mut nonce = [0; NONCE_LEN];
    // Left-pad the Partial IV (PIV) with zeros to exactly 5 bytes
    nonce[NONCE_LEN - piv.len()..].copy_from_slice(piv);
    // Left-pad ID_PIV with zeros to exactly nonce length minus 6 bytes
    nonce[1 + NONCE_LEN - 6 - id_piv.len()..NONCE_LEN - 5]
        .copy_from_slice(id_piv);
    // Add the size of the ID_PIV (a single byte S)
    nonce[0] = id_piv.len() as u8;
    // XOR with common IV
    for (b1, b2) in nonce.iter_mut().zip(common_iv.iter()) {
        *b1 ^= b2;
    }

    nonce
}

/// Returns the `piv` as a u64.
pub fn piv_to_u64(mut piv: &[u8]) -> u64 {
    // Trim piv if it's too long
    if piv.len() > 8 {
        piv = &piv[piv.len() - 8..];
    }
    // Copy piv into an appropriately sized array
    let mut piv_arr = [0; 8];
    piv_arr[8 - piv.len()..].copy_from_slice(piv);

    u64::from_be_bytes(piv_arr)
}

/// Returns the `piv` in its correct format (no leading zero bytes).
pub fn format_piv(piv: u64) -> Vec<u8> {
    // Convert the sender sequence number to its byte representation
    let bytes = piv.to_be_bytes();
    // Find the index of the first byte that is not zero
    let first_nonzero = bytes.iter().position(|&x| x != 0);
    match first_nonzero {
        // If there is one, skip leading zero bytes and return the others
        Some(n) => bytes[n..].to_vec(),
        // If there isn't, we simply return 0
        None => vec![0x00],
    }
}

/// Represents a split-up Proxy-Uri.
#[derive(Debug, PartialEq)]
pub struct ProxyUri {
    pub proxy_scheme: String,
    pub uri_host: String,
    pub uri_port: Option<String>,
    pub uri_path: Option<String>,
    pub uri_query: Option<String>,
}

impl TryFrom<&[u8]> for ProxyUri {
    type Error = Error;
    /// Splits a Proxy-Uri into the Proxy-Scheme, Uri-Host, Uri-Port, Uri-Path
    /// and Uri-Query options.
    ///
    /// I don't implement this myself because I think I can do a better job
    /// than the 105 people wo have contributed to `rust-url`. On the contrary.
    /// I'd love to use it, but it requires `std`. And since I don't know of a
    /// better option, I have to write this abomination.
    fn try_from(bytes: &[u8]) -> Result<ProxyUri> {
        // Convert to a String we can work with
        let mut proxy_uri = String::from_utf8(bytes.to_vec())?;

        // Take the Uri-Scheme out
        let scheme_end = proxy_uri.find(':').ok_or(Error::InvalidProxyUri)?;
        let proxy_scheme: String = proxy_uri.drain(..scheme_end).collect();
        // Drain the next three characters which should be '://'
        proxy_uri.drain(..3);

        // Take the Uri-Host out
        let host_end = if let Some(port_separator) = proxy_uri.find(':') {
            port_separator
        } else if let Some(path_separator) = proxy_uri.find('/') {
            path_separator
        } else if let Some(query_separator) = proxy_uri.find('?') {
            query_separator
        } else {
            proxy_uri.len()
        };
        let uri_host: String = proxy_uri.drain(..host_end).collect();

        // Take the Uri-Port out
        let port_end = if let Some(port_separator) = proxy_uri.find(':') {
            proxy_uri.remove(port_separator);
            if let Some(path_separator) = proxy_uri.find('/') {
                path_separator
            } else if let Some(query_separator) = proxy_uri.find('?') {
                query_separator
            } else {
                proxy_uri.len()
            }
        } else {
            0
        };
        let uri_port: String = proxy_uri.drain(..port_end).collect();
        // Now we can remove the leading path separator, if any
        if let Some(path_separator) = proxy_uri.find('/') {
            proxy_uri.remove(path_separator);
        }

        // Take the path out
        let path_end = if let Some(query_separator) = proxy_uri.find('?') {
            proxy_uri.remove(query_separator);
            query_separator
        } else {
            proxy_uri.len()
        };
        let uri_path: String = proxy_uri.drain(..path_end).collect();

        // Whatever remains is the query
        let uri_query = proxy_uri;

        Ok(ProxyUri {
            proxy_scheme,
            uri_host,
            uri_port: if uri_port.is_empty() {
                None
            } else {
                Some(uri_port)
            },
            uri_path: if uri_path.is_empty() {
                None
            } else {
                Some(uri_path)
            },
            uri_query: if uri_query.is_empty() {
                None
            } else {
                Some(uri_query)
            },
        })
    }
}

impl ProxyUri {
    /// Returns a `LinkedList` of the path components to be added as option
    /// values.
    pub fn get_path_list(&self) -> Option<LinkedList<Vec<u8>>> {
        self.uri_path.as_ref().map(|uri_path| {
            uri_path
                .split('/')
                .filter(|e| !e.is_empty())
                .map(|s| s.as_bytes().to_vec())
                .collect()
        })
    }

    /// Returns a `LinkedList` of the query components to be added as option
    /// values.
    pub fn get_query_list(&self) -> Option<LinkedList<Vec<u8>>> {
        self.uri_query.as_ref().map(|uri_query| {
            uri_query
                .split('&')
                .filter(|e| !e.is_empty())
                .map(|s| s.as_bytes().to_vec())
                .collect()
        })
    }

    /// Returns the class U option value for Proxy-Uri.
    pub fn compose_proxy_uri(&self) -> Vec<u8> {
        let mut proxy_uri_str = self.proxy_scheme.clone();
        proxy_uri_str += "://";
        proxy_uri_str += &self.uri_host;
        if let Some(ref port) = self.uri_port {
            proxy_uri_str += ":";
            proxy_uri_str += port;
        };

        proxy_uri_str.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_vectors::*;
    use super::*;

    #[test]
    fn info() {
        let i_sender = build_info(&CLIENT_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_CLIENT_KEY, &i_sender[..]);

        let i_recipient = build_info(&SERVER_ID, "Key", 16).unwrap();
        assert_eq!(&INFO_SERVER_KEY, &i_recipient[..]);

        let i_iv = build_info(&[], "IV", 13).unwrap();
        assert_eq!(&INFO_COMMON_IV, &i_iv[..]);
    }

    #[test]
    fn aad_array() {
        let example_aad_arr =
            build_aad_array(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD_ARR, &example_aad_arr[..]);

        let v4_aad_arr = build_aad_array(&CLIENT_ID, &REQ_PIV).unwrap();
        assert_eq!(&REQ_AAD_ARR, &v4_aad_arr[..]);
    }

    #[test]
    fn aad() {
        let example_aad = build_aad(&EXAMPLE_KID, &EXAMPLE_PIV).unwrap();
        assert_eq!(&EXAMPLE_AAD, &example_aad[..]);

        let v4_aad = build_aad(&CLIENT_ID, &REQ_PIV).unwrap();
        assert_eq!(&REQ_AAD, &v4_aad[..]);
    }

    #[test]
    fn option_encoding() {
        assert_eq!(&EX1_OPTION, &build_oscore_option(EX1_KID, EX1_PIV)[..]);
        assert_eq!(&EX2_OPTION, &build_oscore_option(EX2_KID, EX2_PIV)[..]);
        assert_eq!(&EX4_OPTION, &build_oscore_option(EX4_KID, EX4_PIV)[..]);
        assert_eq!(&EX5_OPTION, &build_oscore_option(EX5_KID, EX5_PIV)[..]);
    }

    #[test]
    fn option_decoding() {
        let (kid, piv) = extract_oscore_option(&EX1_OPTION);
        assert_eq!(EX1_KID, kid.as_deref());
        assert_eq!(EX1_PIV, piv.as_deref());

        let (kid, piv) = extract_oscore_option(&EX2_OPTION);
        assert_eq!(EX2_KID, kid.as_deref());
        assert_eq!(EX2_PIV, piv.as_deref());

        let (kid, piv) = extract_oscore_option(&EX4_OPTION);
        assert_eq!(EX4_KID, kid.as_deref());
        assert_eq!(EX4_PIV, piv.as_deref());

        let (kid, piv) = extract_oscore_option(&EX5_OPTION);
        assert_eq!(EX5_KID, kid.as_deref());
        assert_eq!(EX5_PIV, piv.as_deref());

        let (kid, piv) = extract_oscore_option(&CRASH_OPTION);
        assert_eq!(None, kid);
        assert_eq!(None, piv);
    }

    #[test]
    fn nonce() {
        assert_eq!(
            CLIENT_NONCE,
            compute_nonce(&REQ_PIV, &CLIENT_ID, &COMMON_IV)
        );
        assert_eq!(
            SERVER_NONCE,
            compute_nonce(&RES_PIV, &SERVER_ID, &COMMON_IV)
        );
        assert_eq!(
            SERVER_NONCE_LONG_PIV,
            compute_nonce(&RES_PIV, &SERVER_ID_LONG, &COMMON_IV)
        );
    }

    #[test]
    fn piv_transform() {
        let piv = [0x00];
        assert_eq!(0, piv_to_u64(&piv));

        let piv = [0x01, 0x02];
        assert_eq!(258, piv_to_u64(&piv));

        let piv = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(1, piv_to_u64(&piv));
    }

    #[test]
    fn piv_format() {
        assert_eq!([0], format_piv(0)[..]);
        assert_eq!([0xFF], format_piv(0xFF)[..]);
        assert_eq!([0x01, 0x00], format_piv(0xFF + 1)[..]);
    }

    #[test]
    fn proxy_uri() {
        let ex1 = "example.com/resource?q=1";
        assert_eq!(
            Error::InvalidProxyUri,
            ProxyUri::try_from(ex1.as_bytes()).unwrap_err()
        );

        let ex2 = "coap://example.com:9999/resource?q=1";
        let ex2_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: Some(String::from("9999")),
            uri_path: Some(String::from("resource")),
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(ex2_split, ProxyUri::try_from(ex2.as_bytes()).unwrap());

        let ex3 = "coap://example.com/resource?q=1";
        let ex3_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: Some(String::from("resource")),
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(ex3_split, ProxyUri::try_from(ex3.as_bytes()).unwrap());

        let ex4 = "coap://example.com:9999";
        let ex4_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: Some(String::from("9999")),
            uri_path: None,
            uri_query: None,
        };
        assert_eq!(ex4_split, ProxyUri::try_from(ex4.as_bytes()).unwrap());

        let ex5 = "coap://example.com";
        let ex5_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: None,
            uri_query: None,
        };
        assert_eq!(ex5_split, ProxyUri::try_from(ex5.as_bytes()).unwrap());

        let ex6 = "coap://example.com/";
        let ex6_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: None,
            uri_query: None,
        };
        assert_eq!(ex6_split, ProxyUri::try_from(ex6.as_bytes()).unwrap());

        let ex7 = "coap://example.com/resource?q=1&b=2&c=3";
        let ex7_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: Some(String::from("resource")),
            uri_query: Some(String::from("q=1&b=2&c=3")),
        };
        assert_eq!(ex7_split, ProxyUri::try_from(ex7.as_bytes()).unwrap());

        let ex8 = "coap://example.com:9999?q=1";
        let ex8_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: Some(String::from("9999")),
            uri_path: None,
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(ex8_split, ProxyUri::try_from(ex8.as_bytes()).unwrap());

        let ex9 = "coap://example.com?q=1";
        let ex9_split = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: None,
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(ex9_split, ProxyUri::try_from(ex9.as_bytes()).unwrap());
    }

    #[test]
    fn compose_uri() {
        let ex_no_port = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: None,
            uri_path: Some(String::from("resource")),
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(
            b"coap://example.com"[..],
            ex_no_port.compose_proxy_uri()[..]
        );

        let ex_port = ProxyUri {
            proxy_scheme: String::from("coap"),
            uri_host: String::from("example.com"),
            uri_port: Some(String::from("9999")),
            uri_path: Some(String::from("resource")),
            uri_query: Some(String::from("q=1")),
        };
        assert_eq!(
            b"coap://example.com:9999"[..],
            ex_port.compose_proxy_uri()[..]
        );
    }

    #[test]
    fn lists() {
        let ex1 = "coap://example.com:1234/path/to/resource?q=1&b=2&c=3";
        let ex1_split = ProxyUri::try_from(ex1.as_bytes()).unwrap();
        let mut path_list = LinkedList::new();
        path_list.push_back("path".as_bytes().to_vec());
        path_list.push_back("to".as_bytes().to_vec());
        path_list.push_back("resource".as_bytes().to_vec());
        assert_eq!(path_list, ex1_split.get_path_list().unwrap());
        let mut query_list = LinkedList::new();
        query_list.push_back("q=1".as_bytes().to_vec());
        query_list.push_back("b=2".as_bytes().to_vec());
        query_list.push_back("c=3".as_bytes().to_vec());
        assert_eq!(query_list, ex1_split.get_query_list().unwrap());

        let ex2 = "coap://example.com:1234/path/to/resource/";
        let ex2_split = ProxyUri::try_from(ex2.as_bytes()).unwrap();
        let mut path_list = LinkedList::new();
        path_list.push_back("path".as_bytes().to_vec());
        path_list.push_back("to".as_bytes().to_vec());
        path_list.push_back("resource".as_bytes().to_vec());
        assert_eq!(path_list, ex2_split.get_path_list().unwrap());
        assert_eq!(None, ex2_split.get_query_list());

        let ex3 = "coap://example.com:1234?q=1&b=2&c=3&";
        let ex3_split = ProxyUri::try_from(ex3.as_bytes()).unwrap();
        assert_eq!(None, ex3_split.get_path_list());
        let mut query_list = LinkedList::new();
        query_list.push_back("q=1".as_bytes().to_vec());
        query_list.push_back("b=2".as_bytes().to_vec());
        query_list.push_back("c=3".as_bytes().to_vec());
        assert_eq!(query_list, ex3_split.get_query_list().unwrap());
    }
}