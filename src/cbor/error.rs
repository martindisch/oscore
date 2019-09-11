use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// The error type for the `cbor` module.
// TODO: Derive PartialEq as soon as serde_cbor does for its error type
#[derive(Debug)]
pub enum CborError {
    /// Tried to encode/decode CBOR sequence of more than 23 items.
    TooManyItems,
    /// Wraps errors from `serde_cbor`.
    SerdeCbor(serde_cbor::Error),
}

impl From<serde_cbor::Error> for CborError {
    fn from(e: serde_cbor::Error) -> CborError {
        CborError::SerdeCbor(e)
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CborError::TooManyItems => {
                write!(f, "Can't decode CBOR sequence of more than 23 items")
            }
            CborError::SerdeCbor(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for CborError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            CborError::TooManyItems => None,
            CborError::SerdeCbor(e) => Some(e),
        }
    }
}
