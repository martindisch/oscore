# [WIP] oscore
An experimental
[OSCORE](https://tools.ietf.org/html/rfc8613)
implementation with
[EDHOC](https://tools.ietf.org/html/draft-selander-ace-cose-ecdhe-13)
key exchange.

## Security
This should **not currently be used in production code**, use at your own risk.
Because of the severe lack of Rust crypto libraries that work in `#![no_std]`,
a [library that isn't ready yet](https://github.com/brycx/orion#security)
is employed for AEAD.

## License
Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
