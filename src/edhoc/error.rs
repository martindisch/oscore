//! The errors of the `edhoc` module.

use core::fmt;

use super::util;
use crate::error::Error;

static ERR_CBOR: &str = "Error processing CBOR";
static ERR_ED25519: &str = "Error processing signature";
static ERR_HKDF: &str = "Error using HKDF";
static ERR_AEAD: &str = "Error using AEAD";
static ERR_SUITE: &str = "Cipher suite unsupported";

/// The error type for operations that process a message from the other party
/// and may fail if the message is an error message (in which case the protocol
/// needs to be aborted), or if a failure happened while processing, in which
/// case an EDHOC error message is generated that needs to be transmitted to
/// the other party, prior to aborting the protocol.
#[derive(Debug)]
pub enum OwnOrPeerError {
    /// This variant wraps an error message that was received from the other
    /// party. On receiving this error, abort the protocol.
    PeerError(alloc::string::String),
    /// This variant wraps an EDHOC error message that was generated because
    /// something went wrong on our end. These bytes need to be sent to the
    /// other party before aborting the protocol.
    OwnError(alloc::vec::Vec<u8>),
}

impl From<Error> for OwnOrPeerError {
    fn from(e: Error) -> OwnOrPeerError {
        match e {
            Error::Cbor(_) => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_CBOR))
            }
            Error::TooManyItems => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_CBOR))
            }
            Error::Ed25519(_) => OwnOrPeerError::OwnError(
                util::build_error_message(ERR_ED25519),
            ),
            Error::Hkdf(_) => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_HKDF))
            }
            Error::Aead(_) => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_AEAD))
            }
            Error::UnsupportedSuite => {
                OwnOrPeerError::OwnError(util::build_error_message(ERR_SUITE))
            }
            Error::Edhoc(msg) => OwnOrPeerError::PeerError(msg),
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
#[derive(Debug)]
pub struct OwnError(pub alloc::vec::Vec<u8>);

impl From<Error> for OwnError {
    fn from(e: Error) -> OwnError {
        match e {
            Error::Cbor(_) => OwnError(util::build_error_message(ERR_CBOR)),
            Error::TooManyItems => {
                OwnError(util::build_error_message(ERR_CBOR))
            }
            Error::Ed25519(_) => {
                OwnError(util::build_error_message(ERR_ED25519))
            }
            Error::Hkdf(_) => OwnError(util::build_error_message(ERR_HKDF)),
            Error::Aead(_) => OwnError(util::build_error_message(ERR_AEAD)),
            Error::UnsupportedSuite => {
                OwnError(util::build_error_message(ERR_SUITE))
            }
            _ => OwnError(util::build_error_message("This should not happen")),
        }
    }
}

impl fmt::Display for OwnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Generated EDHOC error message: {:?}", &self.0)
    }
}

/// The error type for operations that may fail before any messages have been
/// sent, which means the protocol can be aborted without any further action.
#[derive(Debug)]
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
