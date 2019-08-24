#![no_std]

#[macro_use]
extern crate alloc;

mod cbor;
mod cose;
#[cfg_attr(tarpaulin, skip)]
mod error;
#[cfg(test)]
mod test_data;

pub mod edhoc;

/// The result type for internal operations of this crate.
type Result<T> = core::result::Result<T, error::Error>;
