//! The errors of the crate.

use alloc::string::String;
use coap_lite::error as coap;
use core::fmt;

/// The catch-all error type for this crate, mostly just wrapping errors from
/// various libraries.
// TODO: Derive PartialEq as soon as serde_cbor does for its error type
#[derive(Debug)]
pub enum Error {
    /// Wraps errors from `serde_cbor`.
    Cbor(serde_cbor::Error),
    /// Tried to encode/decode CBOR sequence of more than 23 items.
    TooManyItems,
    /// Wraps errors from `ed25519_dalek`.
    Ed25519(ed25519_dalek::SignatureError),
    /// Wraps errors from `hkdf`.
    Hkdf(hkdf::InvalidLength),
    /// Wraps errors from `aes_ccm`.
    Aead(aes_ccm::Error),
    /// Using an unsupported cipher suite.
    UnsupportedSuite,
    /// Wraps errors from `coap_lite`.
    Coap(coap::MessageError),
    /// CoAP request doesn't contain OSCORE option.
    NoOscoreOption,
    /// CoAP request doesn't have kid or piv.
    NoKidPiv,
    /// Wraps a received EDHOC error message.
    Edhoc(String),
}

impl From<serde_cbor::Error> for Error {
    fn from(e: serde_cbor::Error) -> Error {
        Error::Cbor(e)
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(e: ed25519_dalek::SignatureError) -> Error {
        Error::Ed25519(e)
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(e: hkdf::InvalidLength) -> Error {
        Error::Hkdf(e)
    }
}

impl From<aes_ccm::Error> for Error {
    fn from(e: aes_ccm::Error) -> Error {
        Error::Aead(e)
    }
}

impl From<coap::MessageError> for Error {
    fn from(e: coap::MessageError) -> Error {
        Error::Coap(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR error: {}", e),
            Error::TooManyItems => {
                write!(f, "Can't decode CBOR sequence of more than 23 items")
            }
            Error::Ed25519(e) => write!(f, "Signature error: {}", e),
            Error::Hkdf(e) => write!(f, "HKDF error: {}", e),
            Error::Aead(e) => write!(f, "AEAD error: {}", e),
            Error::UnsupportedSuite => write!(f, "Cipher suite unsupported"),
            Error::Coap(e) => write!(f, "CoAP error: {}", e),
            Error::NoOscoreOption => {
                write!(f, "CoAP request doesn't contain OSCORE option")
            }
            Error::NoKidPiv => {
                write!(f, "CoAP request doesn't have kid or piv")
            }
            Error::Edhoc(e) => write!(f, "EDHOC error message: {}", e),
        }
    }
}
