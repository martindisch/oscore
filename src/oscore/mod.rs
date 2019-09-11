//! OSCORE implementation.

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
