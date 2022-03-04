
//! OSCORE implementation deriving keys from a master secret and master salt.
//!
//! It's pretty simple to use. Both parties need to establish some information,
//! such as the master secret, salt and their IDs out of band (e.g. with
//! EDHOC). Then both can use these to derive opposite security contexts, with
//! which they can protect and unprotect CoAP requests and responses.
//!
//! # Usage
//! ```rust
//! use oscore::oscore::SecurityContext;
//!
//! // This information has been established between the client and server, for
//! // example with EDHOC.
//! let master_secret = [
//!     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
//!     0x0C, 0x0D, 0x0E, 0x0F, 0x10,
//! ];
//! let master_salt = [0x9E, 0x7C, 0xA9, 0x22, 0x23, 0x78, 0x63, 0x40];
//! let client_id = [];
//! let server_id = [0x01];
//!
//! // Client -----------------------------------------------------------------
//!
//! // Establish security context using master secret & salt from EDHOC
//! let mut client_context = SecurityContext::new(
//!     master_secret.to_vec(),
//!     master_salt.to_vec(),
//!     client_id.to_vec(),
//!     server_id.to_vec(),
//! )
//! .unwrap();
//! // This is the CoAP request we want to send
//! let req_unprotected = [
//!     0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
//!     0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
//! ];
//! // Protect the request
//! let req_protected =
//!     client_context.protect_request(&req_unprotected).unwrap();
//!
//! // Server -----------------------------------------------------------------
//!
//! // Establish security context using master secret & salt from EDHOC (note
//! // that server and client IDs are reversed on this side)
//! let mut server_context = SecurityContext::new(
//!     master_secret.to_vec(),
//!     master_salt.to_vec(),
//!     server_id.to_vec(),
//!     client_id.to_vec(),
//! )
//! .unwrap();
//! // Unprotect the request
//! let req_unprotected_local =
//!     server_context.unprotect_request(&req_protected).unwrap();
//! assert_eq!(&req_unprotected[..], &req_unprotected_local[..]);
//!
//! // This is the CoAP response we want to send
//! let res_unprotected = [
//!     0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65,
//!     0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
//! ];
//! // Protect the response
//! let res_protected = server_context
//!     .protect_response(&res_unprotected, &req_protected, true)
//!     .unwrap();
//!
//! // Client -----------------------------------------------------------------
//!
//! // Unprotect the response
//! let res_unprotected_local =
//!     client_context.unprotect_response(&res_protected).unwrap();
//! assert_eq!(&res_unprotected[..], &res_unprotected_local[..]);
//! ```
//! 
//! #![no_st
mod context;
#[cfg_attr(tarpaulin, skip)]
mod error;
#[cfg(test)]
mod test_vectors;
mod util;

pub use context::SecurityContext;
pub use error::Error;

/// The result type for the `oscore` module.
pub type Result<T> = core::result::Result<T, Error>;
