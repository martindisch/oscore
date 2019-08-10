use alloc::string::String;
use core::fmt;

/// The error type for this crate, wrapping errors from various libraries.
#[derive(Debug)]
pub enum Error {
    Cbor(serde_cbor::Error),
    TooManyItems,
    Ed25519(ed25519_dalek::SignatureError),
    Hkdf(hkdf::InvalidLength),
    Aead(orion::errors::UnknownCryptoError),
    UnsupportedSuite,
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

impl From<orion::errors::UnknownCryptoError> for Error {
    fn from(e: orion::errors::UnknownCryptoError) -> Error {
        Error::Aead(e)
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
            Error::Edhoc(e) => write!(f, "EDHOC error message: {}", e),
        }
    }
}
