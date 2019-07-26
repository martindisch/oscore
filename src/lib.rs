#![no_std]

#[macro_use]
extern crate alloc;

pub mod cbor;
pub mod cose;
pub mod edhoc;
pub mod error;

pub type Result<T> = core::result::Result<T, error::Error>;
