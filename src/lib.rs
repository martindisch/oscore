#![no_std]

#[macro_use]
extern crate alloc;

pub mod edhoc;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
