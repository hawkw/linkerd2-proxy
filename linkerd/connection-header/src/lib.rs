use bytes::{
    buf::{Buf, BufExt},
    BytesMut,
};
use linkerd2_error::Error;
use linkerd2_io::{self as io, AsyncReadExt as _};
use std::pin::Pin;

#[derive(Clone, Debug)]
pub struct Header {}

impl Header {
    const PREFIX: &'static [u8] = b"l5d.io/proxy\r\n\r\n";

    pub async fn detect<I: io::AsyncRead + io::AsyncWrite + Unpin>(
        io: &mut io::PrefixedIo<I>,
    ) -> Result<Option<Header>, Error> {
        if io.prefix().len() < Self::PREFIX.len()
            || &io.prefix().as_ref()[..Self::PREFIX.len()] != Self::PREFIX
        {
            return Ok(None);
        }
        let _ = io.prefix_mut().advance(Self::PREFIX.len());

        let sz = prost::decode_length_delimiter(io.prefix_mut())?;
        io.prefix_mut().advance(prost::length_delimiter_len(sz));
        if sz == 0 {
            return Ok(None);
        }

        let buf = {
            let len = sz.min(io.prefix().len());
            io.prefix_mut().split_to(len)
        };
        let needed = sz - buf.len();
        let header = if needed == 0 {
            let _ = buf;
            Header {}
        } else {
            let mut rest = BytesMut::with_capacity(needed);
            Pin::new(io).read_exact(rest.as_mut()).await?;
            let buf = buf.chain(rest.freeze());
            let _ = buf;
            Header {}
        };
        Ok(Some(header))
    }
}
