use commonware_codec::{EncodeSize, Error, RangeCfg, Read, Write};
use std::string::FromUtf8Error;

pub(crate) fn write_string(value: &str, buf: &mut impl bytes::BufMut) {
    value.as_bytes().write(buf);
}

pub(crate) fn string_encode_size(value: &str) -> usize {
    value.as_bytes().encode_size()
}

pub(crate) fn read_string(
    buf: &mut impl bytes::Buf,
    max_bytes: usize,
    context: &'static str,
) -> Result<String, Error> {
    let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=max_bytes), ()))?;
    String::from_utf8(bytes).map_err(|error| string_error(context, error))
}

fn string_error(context: &'static str, error: FromUtf8Error) -> Error {
    Error::Wrapped(context, error.into())
}
