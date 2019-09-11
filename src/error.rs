//! The errors of the crate.

use alloc::string::String;
use coap_lite::error as coap;
use core::fmt;
#[cfg(feature = "std")]
use std::error;

use crate::cbor;

/// The catch-all error type for this crate, mostly just wrapping errors from
/// various libraries.
// TODO: Derive PartialEq as soon as cbor does for its error type
#[derive(Debug)]
pub enum Error {
    /// Wraps errors from the `cbor` module.
    Cbor(cbor::CborError),
    /// Wraps errors from `ed25519_dalek`.
    Ed25519(ed25519_dalek::SignatureError),
    /// Wraps errors from `hkdf`.
    Hkdf(hkdf::InvalidLength),
    /// Wraps errors from `aes_ccm`.
    Aead(aes_ccm::Error),
    /// Using an unsupported cipher suite.
    UnsupportedSuite,
    /// Wraps a received EDHOC error message.
    Edhoc(String),
    /// Wraps errors from `coap_lite`.
    Coap(coap::MessageError),
    /// CoAP request doesn't contain OSCORE option.
    NoOscoreOption,
    /// CoAP request doesn't have kid or piv.
    NoKidPiv,
    /// This message has been received already.
    ReplayDetected,
}

impl From<cbor::CborError> for Error {
    fn from(e: cbor::CborError) -> Error {
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
            Error::Ed25519(e) => write!(f, "Signature error: {}", e),
            Error::Hkdf(e) => write!(f, "HKDF error: {}", e),
            Error::Aead(e) => write!(f, "AEAD error: {}", e),
            Error::UnsupportedSuite => write!(f, "Cipher suite unsupported"),
            Error::Edhoc(e) => write!(f, "EDHOC error message: {}", e),
            Error::Coap(e) => write!(f, "CoAP error: {}", e),
            Error::NoOscoreOption => {
                write!(f, "CoAP request doesn't contain OSCORE option")
            }
            Error::NoKidPiv => {
                write!(f, "CoAP request doesn't have kid or piv")
            }
            Error::ReplayDetected => {
                write!(f, "This message has been received already")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Cbor(e) => Some(e),
            Error::Hkdf(e) => Some(e),
            Error::Aead(e) => Some(e),
            Error::Coap(e) => Some(e),
            // Other errors that don't implement the Error trait
            _ => None,
        }
    }
}
