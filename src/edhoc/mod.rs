//! Ephemeral Diffie-Hellman Over COSE (EDHOC) to establish an OSCORE context.
//!
//! This is I/O-free, so all it does is provide facilities to parse incoming
//! messages and receive output that can then be sent to the other party.
//! Since doing all of this often depends on previous state, it uses a kind of
//! session types pattern with structs as different protocol states, which
//! are consumed by an action and return the next state struct together with
//! optional data.
//!
//! Party U starts by initializing a `PartyI` and using it to generate the
//! first message and its next state. Party V does the opposite,
//! initializing a `PartyR` and using this to handle the message and get
//! its next state, etc.
//!
//! # Errors
//! EDHOC defines an error message that needs to be sent to the peer to abort
//! the protocol, if any verification of messages goes wrong. This means that
//! when receiving a message, it's possible that this is an error message
//! instead of the expected regular message. If that's the case, we just need
//! to abort the protocol.
//! It's also possible that while processing a message, we ourselves run into
//! trouble, which means that we need to send an error message.
//! And finally there's also the single case where we're Party U preparing the
//! first message and fail, which means we don't need to send an error message,
//! since the protocol hasn't started yet.
//!
//! To make dealing with this reality as easy as possible, this module defines
//! three error types, which are thrown accordingly.
//! * `EarlyError` - When Party U fails before having sent the first message.
//!   When encountering this, just stop executing the protocol.
//! * `OwnError` - Encountered an error while doing something. This error wraps
//!   the bytes (EDHOC error message) that need to be sent to the peer before
//!   aborting the protocol run.
//! * `OwnOrPeerError` - This is for cases where we're dealing with a received
//!   message, so it could be an error message itself, or we could fail while
//!   dealing with the message. This is an enum with two variants:
//!   * `OwnError` - We failed. This wraps the EDHOC error message that needs
//!     to be sent to the peer before aborting the protocol.
//!   * `PeerError` - We received an error message, which is wrapped inside.
//!     Just abort the protocol.
//!
//! The easiest way to work with this, is to just match the results of method
//! calls and deal with all error variants.
//!
//! # Usage
//! A full usage example is in the `examples` directory. This is only intended
//! to demonstrate the general pattern and the error handling.
//! ```rust
//! // This is a case where we get additional data from the message handling,
//! // as well as the next state we can use afterwards.
//! let (v_kid, msg2_verifier) =
//!    // This is a case where we could receive an error message (just abort
//!    // then), or cause an error (send it to the peer)
//!    match msg2_receiver.extract_peer_kid(msg2_bytes) {
//!        Err(OwnOrPeerError::PeerError(s)) => {
//!            panic!("Received error msg: {}", s)
//!        }
//!        Err(OwnOrPeerError::OwnError(b)) => {
//!            panic!("Send these bytes: {:?}", &b)
//!        }
//!        Ok(val) => val,
//!    };
//! // Here we use the struct we received to do something and receive the next
//! let msg3_sender = match msg2_verifier.verify_message_2(&v_public) {
//!     Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
//!     Ok(val) => val,
//! };
//! ```

mod cose;
#[cfg(test)]
mod test_vectors;
pub mod util;

pub mod api;
#[cfg_attr(tarpaulin, skip)]
pub mod error;

/// The result type for internal operations of the `edhoc` module.
type Result<T> = core::result::Result<T, error::Error>;

pub use api::{PartyI,PartyR};
