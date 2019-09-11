use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// The error type for the `cbor` module.
// TODO: Derive PartialEq as soon as serde_cbor does for its error type
#[derive(Debug)]
pub enum CborError {
    /// Wraps errors from `serde_cbor`.
    SerdeCbor(serde_cbor::Error),
    /// Tried to encode/decode CBOR sequence of more than 23 items.
    TooManyItems,
}

impl From<serde_cbor::Error> for CborError {
    fn from(e: serde_cbor::Error) -> CborError {
        CborError::SerdeCbor(e)
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CborError::SerdeCbor(e) => write!(f, "CBOR error: {}", e),
            CborError::TooManyItems => write!(
                f,
                "CBOR error: can't decode CBOR sequence of more than 23 items"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for CborError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            CborError::SerdeCbor(e) => Some(e),
            CborError::TooManyItems => None,
        }
    }
}
