use core::fmt;

/// The error type for operations that generate messages which are sent to the
/// other party by the user.
#[derive(Debug)]
pub enum EdhocError {
    // This variant wraps an error message that was received from the other
    // party. On receiving this error, abort the protocol.
    ReceivedError(alloc::string::String),
    // This variant wraps an EDHOC error message that was generated because
    // something went wrong. These bytes need to be sent to the other party,
    // before aborting the protocol.
    CausedError(alloc::vec::Vec<u8>),
}

impl fmt::Display for EdhocError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EdhocError::ReceivedError(s) => {
                write!(f, "Peer sent error message: {}", s)
            }
            EdhocError::CausedError(b) => {
                write!(f, "Generated EDHOC error message: {:?}", &b)
            }
        }
    }
}
