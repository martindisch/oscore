//! Trait and types that allow for interoperability with CoAP implementations.

use alloc::vec::Vec;

/// CoAP method/response codes used by OSCORE.
///
/// Only the ones we need to know because we set them for requests (`POST`) and
/// responses (`CHANGED`) are listed here. The others are wrapped in `Other` and
/// protected (E).
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CoapCode {
    Post,
    Changed,
    Other(usize),
}

/// CoAP option codes used by OSCORE.
///
/// Only the ones we need to know because they're either unprotected (U) or
/// optional and unsupported by our implementation are listed here.
/// All the others are wrapped in `Other` and protected (E) by default.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CoapOption {
    UriHost,
    Observe,
    UriPort,
    Block2,
    Block1,
    Size2,
    ProxyUri,
    ProxyScheme,
    Size1,
    NoResponse,
    Other(usize),
}

/// This needs to be implemented for the CoAP message type of the CoAP
/// implementation for which messages are to be protected with OSCORE.
pub trait CoapMessage {
    /// Returns the method/response code from the header.
    fn get_code(&self) -> CoapCode;

    /// Sets the method/response code of the header.
    fn set_code(&mut self, code: CoapCode);

    /// Returns a vector of all options present in the message.
    ///
    /// It doesn't matter if repeatable options occur once or multiple times,
    /// choose what's more convenient based on the underlying implementation.
    fn options(&self) -> Vec<CoapOption>;

    /// Adds an option to the message.
    ///
    /// Can be called multiple times for repeatable options.
    fn add_option(&mut self, option: CoapOption, value: Vec<u8>);

    /// Deletes an option from the message.
    ///
    /// For repeatable options, this deletes *all* occurrences.
    fn delete_option(&mut self, option: CoapOption);
}
