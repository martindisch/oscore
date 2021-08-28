use alloc::string::ToString;
use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// The error type for the `cbor` module.
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

impl PartialEq for CborError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CborError::TooManyItems, CborError::TooManyItems) => true,
            (CborError::SerdeCbor(e1), CborError::SerdeCbor(e2)) => {
                e1.to_string() == e2.to_string()
            }
            _ => false,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::Error;

    #[test]
    fn partial_eq() {
        let own_error = CborError::TooManyItems;
        let serde_error_1 =
            CborError::SerdeCbor(serde_cbor::Error::custom("nope!"));
        let serde_error_2 =
            CborError::SerdeCbor(serde_cbor::Error::custom("what?"));
        assert!(own_error != serde_error_1);
        #[cfg(feature = "std")]
        assert!(serde_error_1 != serde_error_2);
        assert_eq!(own_error, own_error);
        assert_eq!(serde_error_1, serde_error_1);
        assert_eq!(serde_error_2, serde_error_2);
    }
}
