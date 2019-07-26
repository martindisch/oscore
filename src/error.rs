use core::fmt;

#[derive(Debug)]
pub enum Error {
    Cbor(serde_cbor::Error),
    TooManyItems,
    Ed25519(ed25519_dalek::SignatureError),
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR error: {}", e),
            Error::TooManyItems => {
                write!(f, "Can't decode CBOR sequence of more than 23 items")
            }
            Error::Ed25519(e) => write!(f, "Signature error: {}", e),
        }
    }
}
