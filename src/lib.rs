#![no_std]

#[macro_use]
extern crate alloc;

mod cbor;
#[cfg_attr(tarpaulin, skip)]
mod error;

pub mod coap_message;
pub mod edhoc;

/// The result type for internal operations of this crate.
type Result<T> = core::result::Result<T, error::Error>;
