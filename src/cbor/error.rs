use core::fmt;
#[cfg(feature = "std")]

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
                (e1.classify(), e1.offset()) == (e2.classify(), e2.offset())
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



