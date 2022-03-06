//! The errors of the `edhoc` module.

use alloc::string::String;
use core::fmt;


use super::util;
use crate::cbor;

static ERR_CBOR: &str = "Error processing CBOR";
static ERR_HKDF: &str = "Error using HKDF";
static ERR_AEAD: &str = "Error using AEAD";
static ERR_SUITE: &str = "Cipher suite unsupported";
static ERR_BADMAC: &str = "Error processing MAC field";

/// The error type for operations that process a message from the other party
/// and may fail if the message is an error message (in which case the protocol
/// needs to be aborted), or if a failure happened while processing, in which
/// case an EDHOC error message is generated that needs to be transmitted to
/// the other party, prior to aborting the protocol.
#[derive(Debug, PartialEq)]
pub enum OwnOrPeerError {
    /// This variant wraps an error message that was received from the other
    /// party. On receiving this error, abort the protocol.
    PeerError(String),
    /// This variant wraps an EDHOC error message that was generated because
    /// something went wrong on our end. These bytes need to be sent to the
    /// other party before aborting the protocol.
    OwnError(alloc::vec::Vec<u8>),
}

impl From<Error> for OwnOrPeerError {
    fn from(e: Error) -> OwnOrPeerError {
        match e {
            Error::UnsupportedSuite => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_SUITE))
            }
            Error::Cbor(_) => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_CBOR))
            }

            Error::Hkdf(_) => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_HKDF))
            }
            Error::Aead => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_AEAD))
            }
            Error::Edhoc(msg) => OwnOrPeerError::PeerError(msg),
            Error::BadMac => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_BADMAC))
            }
        }
    }
}

impl fmt::Display for OwnOrPeerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OwnOrPeerError::PeerError(s) => {
                write!(f, "Peer sent error message: {}", s)
            }
            OwnOrPeerError::OwnError(b) => {
                write!(f, "Generated EDHOC error message: {:?}", &b)
            }
        }
    }
}



/// The error type for operations that may fail and produce an EDHOC error
/// message, which needs to be sent to the other party prior to aborting the
/// protocol.
#[derive(Debug, PartialEq)]
pub struct OwnError(pub alloc::vec::Vec<u8>);

impl From<Error> for OwnError {
    fn from(e: Error) -> OwnError {
        match e {
            Error::UnsupportedSuite => {
                OwnError(util::build_error_message(ERR_SUITE))
            }
            Error::Cbor(_) => OwnError(util::build_error_message(ERR_CBOR)),

            Error::BadMac => OwnError(util::build_error_message(ERR_BADMAC)),
            Error::Hkdf(_) => OwnError(util::build_error_message(ERR_HKDF)),
            Error::Aead => OwnError(util::build_error_message(ERR_AEAD)),
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for OwnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Generated EDHOC error møssage: {:?}", &self.0)
    }
}


/// The error type for operations that may fail before any messages have been
/// sent, which means the protocol can be aborted without any further action.
#[derive(Debug, PartialEq)]
pub struct EarlyError(pub Error);

impl From<Error> for EarlyError {
    fn from(e: Error) -> EarlyError {
        EarlyError(e)
    }
}

impl fmt::Display for EarlyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Encountered early error: {}", &self.0)
    }
}


/// The catch-all error type for this module, mostly just wrapping errors from
/// various libraries.
#[derive(Debug, PartialEq)]
pub enum Error {

    BadMac,
    /// Using an unsupported cipher suite.
    UnsupportedSuite,
    /// Wraps errors from the `cbor` module.
    Cbor(cbor::CborError),
    /// Wraps errors from `ed25519_dalek`.
    /// Wraps errors from `hkdf`.
    Hkdf(hkdf::InvalidLength),
    /// Error in `aes_ccm`.
    Aead,
    /// Wraps a received EDHOC error message.
    Edhoc(String),
    // wraps the error that the mac does not have the correct value
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnsupportedSuite => write!(f, "Cipher suite unsupported"),
            Error::BadMac => write!(f, "Mac tag was wrong"),
            Error::Cbor(e) => e.fmt(f),
            Error::Hkdf(e) => e.fmt(f),
            Error::Aead => write!(f, "{}", ERR_AEAD),
            Error::Edhoc(e) => e.fmt(f),
        }
    }
}

