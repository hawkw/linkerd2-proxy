#![allow(warnings)]

use bytes::{
    buf::{Buf, BufExt, BufMut},
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
const PREFACE_LEN: usize = PREFACE.len() + 4;
const BUFFER_CAPACITY: usize = 65_536;

#[async_trait::async_trait]
impl<I: io::AsyncRead + Send + Unpin + 'static> Detect<I> for DetectConnectionHeader {
    type Kind = Option<ConnectionHeader>;

    async fn detect(
        &self,
        mut io: I,
    ) -> Result<(Option<ConnectionHeader>, io::PrefixedIo<I>), Error> {
        let Decode { header, buf } = ConnectionHeader::decode(&mut io).await?;
        return Ok((header, io::PrefixedIo::new(buf, io)));
    }
}

struct Decode {
    header: Option<ConnectionHeader>,
    buf: Bytes,
}

impl ConnectionHeader {
    /// Encodes the connection header to a byte buffer.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);

        debug_assert!(buf.capacity() > PREFACE.len());
        buf.put(PREFACE);

        debug_assert!(buf.capacity() > 4);
        // Safety: These bytes must be initialized below once the message has
        // been encoded.
        unsafe {
            buf.advance_mut(4);
        }

        let header = proto::Header {
            port: self.port as i32,
            name: self
                .name
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_default(),
        };
        header.encode(&mut buf);

        // Once the message length is known, we back-fill the length at the
        // start of the buffer.
        let len = buf.len() - PREFACE_LEN;
        assert!(len <= std::u32::MAX as usize);
        {
            let mut buf = &mut buf[PREFACE.len()..PREFACE_LEN];
            buf.put_u32(len as u32);
        }

        buf.freeze()
    }

    /// Attempts to decode a connection header from an I/O stream.
    ///
    /// If the header is not present, the non-header bytes that were read are
    /// returned.
    ///
    /// An I/O error is returned if the connection header is invalid.
    async fn decode<I: io::AsyncRead + Unpin + 'static>(io: &mut I) -> io::Result<Decode> {
        let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);
        debug_assert!(PREFACE_LEN < BUFFER_CAPACITY);

        // Read at least enough data to determine whether a connection header is
        // present and, if so, how long it is.
        while buf.len() < PREFACE_LEN {
            if io.read_buf(&mut buf).await? == 0 {
                return Ok(Decode {
                    header: None,
                    buf: buf.freeze(),
                });
            }
        }

        // Advance the buffer past the preface if it matches.
        if &buf.bytes()[..PREFACE.len()] != PREFACE {
            return Ok(Decode {
                header: None,
                buf: buf.freeze(),
            });
        }
        buf.advance(PREFACE.len());

        // Read the message length. If it is larger than our allowed buffer
        // capacity, fail the connection.
        let msg_len = buf.get_u32() as usize;
        if msg_len > BUFFER_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message length exceeds capacity",
            ));
        }

        buf.reserve(msg_len);
        while buf.len() < msg_len {
            if io.read_buf(&mut buf).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Full header message not provided",
                ));
            }
        }

        let rest = buf.split_off(msg_len);
        // Decode the protobuf message from the buffer.
        let h = proto::Header::decode(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid header message"))?;
        let name = if h.name.len() == 0 {
            None
        } else {
            let n = Name::try_from(h.name.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid name"))?;
            Some(n)
        };
        return Ok(Decode {
            buf: rest.freeze(),
            header: Some(Self {
                name,
                port: h.port as u16,
            }),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let header = ConnectionHeader {
            port: 4040,
            name: Some(Name::try_from("foo.bar.example.com".as_bytes()).unwrap()),
        };
        let buf = header.encode();
        let mut rx = std::io::Cursor::new(buf);
        let d = ConnectionHeader::decode(&mut rx).await.expect("decodes");
        let h = d.header.expect("Must decode");
        assert_eq!(header.port, h.port);
        assert_eq!(header.name, h.name);
    }
}
