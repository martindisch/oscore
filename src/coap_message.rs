use alloc::vec::Vec;

#[derive(Debug)]
pub enum MethodCode {
    Get,
    Post,
    Put,
    Delete,
    UnKnown,
}

#[derive(Debug)]
pub enum OptionCode {
    IfMatch,
    UriHost,
    ETag,
    IfNoneMatch,
    Observe,
    UriPort,
    LocationPath,
    UriPath,
    ContentFormat,
    MaxAge,
    UriQuery,
    Accept,
    LocationQuery,
    Block2,
    Block1,
    ProxyUri,
    ProxyScheme,
    Size1,
    Size2,
    NoResponse,
}

pub trait CoapOption {
    fn delete(&mut self);
}

pub trait CoapMessage {
    type Options: Iterator<Item = OptionCode>;

    fn options(&self) -> Self::Options;

    fn set_method(&mut self, method: MethodCode);

    fn add_option(&mut self, option: OptionCode, value: Vec<u8>);
    fn delete_option(&mut self, option: OptionCode);
}
