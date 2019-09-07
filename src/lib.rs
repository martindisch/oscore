#![no_std]

#[macro_use]
extern crate alloc;

mod cbor;
#[cfg_attr(tarpaulin, skip)]
mod error;

pub mod edhoc;
pub mod oscore;

/// The result type for internal operations of this crate.
type Result<T> = core::result::Result<T, error::Error>;

/// Converts from `&Option<T>` to `Option<&T::Target>`.
///
/// Leaves the original Option in-place, creating a new one with a reference
/// to the original one, additionally coercing the contents via `Deref`.
///
/// This is extracted from the `inner_deref` feature of unstable Rust
/// (https://github.com/rust-lang/rust/issues/50264) and can be removed, as
/// soon as the feature becomes stable.
fn as_deref<T: core::ops::Deref>(option: &Option<T>) -> Option<&T::Target> {
    option.as_ref().map(|t| t.deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REF_BYTES: [u8; 3] = [0x01, 0x02, 0x03];

    #[test]
    fn deref() {
        let orig = Some(REF_BYTES.to_vec());
        let derefed = as_deref(&orig).unwrap();
        assert_eq!(&REF_BYTES, derefed);
    }
}
