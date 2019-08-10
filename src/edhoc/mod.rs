mod api;
mod error;
mod util;

pub use api::{
    Msg1Receiver, Msg1Sender, Msg2Receiver, Msg2Sender, Msg3Receiver,
    Msg3Sender,
};
pub use error::EdhocError;

/// The result type for situations where failures either happen because an
/// EDHOC error message was received (in which case no action needs to be taken
/// besides aborting the protocol), or because an error happened and an EDHOC
/// error message is generated that needs to be sent to the other party.
pub type EdhocResult<T> = core::result::Result<T, error::EdhocError>;
