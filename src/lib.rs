#![no_std]

#[macro_use]
extern crate alloc;

pub mod cbor;
pub mod cose;
pub mod edhoc;
pub mod error;

/// The result type for this crate.
pub type Result<T> = core::result::Result<T, error::Error>;
