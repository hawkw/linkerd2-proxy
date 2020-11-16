use bytes::{
    buf::{Buf, BufExt},
    Bytes, BytesMut,
};
use linkerd2_dns::Name;
use linkerd2_error::Error;
use linkerd2_io::{self as io, AsyncReadExt, AsyncWriteExt};
use linkerd2_proxy_transport::Detect;
use prost::Message;
use std::{convert::TryFrom, pin::Pin};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/header.proxy.l5d.io.rs"));
}

#[derive(Clone, Debug)]
pub struct ConnectionHeader {
    pub name: Option<Name>,
    port: u16,
}

#[derive(Clone, Debug)]
pub struct DetectConnectionHeader {
    capacity: usize,
}

const PREFACE: &'static [u8] = b"proxy.l5d.io/connect\r\n\r\n";
const BUFFER_CAPACITY: usize = 65_536;

#[async_trait::async_trait]
impl<I: io::AsyncRead + Unpin + 'static> Detect<I> for DetectConnectionHeader {
    type Kind = Option<ConnectionHeader>;

    async fn detect(&self, mut io: I) -> Result<(Option<ConnectionHeader>, io::PrefixedIo<I>), Error> {
        let mut buf = BytesMut::with_capacity(self.capacity);

        loop {
            match io.read_buf(&mut buf).await? {
                0 => {},
                sz if sz < PREFACE.len() => continue,
                sz => {
                    if &buf[..PREFACE.len()] == PREFACE {
                        break;
                    }
                }
            }
            return Ok((None, io::PrefixedIo::new(buf.freeze(), io)));
        }


        let needed = sz - buf.len();
        let h = if needed == 0 {
            proto::Header::decode(buf)?
        } else {
            let mut rest = BytesMut::with_capacity(needed);
            while Pin::new(&mut io).read_buf(&mut rest).await? != 0 {}
            let rest = rest.freeze();
            let buf = buf.chain(rest);
            proto::Header::decode(buf)?
        };

        let name = if h.name.len() == 0 {
            None
        } else {
            Some(Name::try_from(h.name.as_bytes())?)
        };

        Ok(Some(Self {
            name,
            port: h.port as u16,
        }))
    }
}

impl ConnectionHeader {
    pub async fn encode<I: io::AsyncWrite + Unpin>(&self, io: &mut I) -> Result<(), Error> {
        let header = proto::Header {
            port: self.port as i32,
            name: self
                .name
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_default(),
        };

        let mut buf = {
            let mut buf = BytesMut::new();
            header.encode_length_delimited(&mut buf)?;
            Bytes::from_static(PREFACE).chain(buf.freeze())
        };

        while buf.remaining() != 0 {
            io.write_buf(&mut buf).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkerd2_io::Peekable;

    #[tokio::test]
    async fn roundtrip() {
        let mut buf = Vec::<u8>::with_capacity(1024);

        let a = ConnectionHeader {
            port: 4040,
            name: Some(Name::try_from("foo.bar.example.com".as_bytes()).unwrap()),
        };

        a.encode(&mut std::io::Cursor::new(&mut buf))
            .await
            .expect("encodes");

        let b = {
            let mut rx = std::io::Cursor::new(&mut buf)
                .peek(ConnectionHeader::PREFIX_LEN)
                .await
                .expect("decodes");
            ConnectionHeader::detect(&mut rx)
                .await
                .expect("decodes")
                .expect("decodes")
        };
        assert_eq!(a.port, b.port);
        assert_eq!(a.name, b.name);
    }
}
