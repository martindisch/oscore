use coap_lite::{error as coap, CoapOption};
use core::fmt;

use crate::cbor;

/// The catch-all error type for this module, mostly just wrapping errors from
/// various libraries.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// CoAP request doesn't contain OSCORE option.
    NoOscoreOption,
    /// CoAP request doesn't have kid or piv.
    NoKidPiv,
    /// This message has been received already.
    ReplayDetected,
    /// Error while parsing Proxy-Uri.
    InvalidProxyUri,
    /// Message contains an unsupported option.
    UnsupportedOption(CoapOption),
    /// Wraps errors from the `cbor` module.
    Cbor(cbor::CborError),
    /// Wraps errors from `hkdf`.
    Hkdf(hkdf::InvalidLength),
    /// Error in `aes_ccm`.
    Aead,
    /// Wraps errors from `coap_lite`.
    Coap(coap::MessageError),
}

impl From<cbor::CborError> for Error {
    fn from(e: cbor::CborError) -> Error {
        Error::Cbor(e)
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(e: hkdf::InvalidLength) -> Error {
        Error::Hkdf(e)
    }
}

impl From<ccm::aead::Error> for Error {
    fn from(_: ccm::aead::Error) -> Error {
        Error::Aead
    }
}

impl From<coap::MessageError> for Error {
    fn from(e: coap::MessageError) -> Error {
        Error::Coap(e)
    }
}

impl From<alloc::string::FromUtf8Error> for Error {
    fn from(_: alloc::string::FromUtf8Error) -> Error {
        Error::InvalidProxyUri
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::NoOscoreOption => {
                write!(f, "CoAP request doesn't contain OSCORE option")
            }
            Error::NoKidPiv => {
                write!(f, "CoAP request doesn't have kid or piv")
            }
            Error::ReplayDetected => {
                write!(f, "This message has been received already")
            }
            Error::InvalidProxyUri => {
                write!(f, "Error while parsing Proxy-Uri")
            }
            Error::UnsupportedOption(o) => {
                write!(f, "Message contains an unsupported option: {:?}", o)
            }
            Error::Cbor(e) => e.fmt(f),
            Error::Hkdf(e) => e.fmt(f),
            Error::Aead => write!(f, "Error using AEAD"),
            Error::Coap(e) => e.fmt(f),
        }
    }
}


