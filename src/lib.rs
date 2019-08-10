#![no_std]

#[macro_use]
extern crate alloc;

mod cbor;
mod cose;

pub mod edhoc;
pub mod error;

/// The result type for normal operations of this crate.
pub type Result<T> = core::result::Result<T, error::Error>;
