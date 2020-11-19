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
        match ConnectionHeader::decode(&mut io).await? {
            Decode::Other(buf) => {
                return Ok((None, io::PrefixedIo::new(buf, io)));
            }
            Decode::Header(h) => {
                return Ok((Some(h), io::PrefixedIo::new(Bytes::new(), io)));
            }
        }
    }
}

enum Decode {
    Header(ConnectionHeader),
    Other(Bytes),
}

impl ConnectionHeader {
    /// Encodes the connection header to a byte buffer.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);

        debug_assert(buf.capacity() > PREFACE.len());
        buf.put(PREFACE);

        debug_assert(buf.capacity() > 4);
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

        // Initialize the buffer to be able to hold the PREFACE and message
        // length.
        debug_assert!(PREFACE_LEN < BUFFER_CAPACITY);
        buf.resize(PREFACE_LEN, 0x0);

        // Fill the initialized buffer from the stream.
        let sz = io.read_exact(buf.as_mut()).await?;
        if sz < PREFACE_LEN || &buf.bytes()[..PREFACE.len()] != PREFACE {
            // Either the stream ended or it did not match the
            buf.truncate(sz);
            return Ok(Decode::Other(buf.freeze()));
        }
        // Advance the cursor past the preface message;
        buf.advance(PREFACE.len());

        // Read the message length from the stream and advance the cursor.
        let msg_len = buf.get_u32() as usize;

        // Prevent malfeasent clients form forcing us to allocate a huge buffer.
        if msg_len > BUFFER_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message length exceeds capacity",
            ));
        }

        // Drop the preface data from the buffer and initialize enough memory to
        // hold the header message.
        let _ = buf.split();
        buf.reserve(msg_len);
        buf.resize(msg_len, 0x0);
        // Fill the initilalized buffer from the stream.
        if io.read_exact(buf.as_mut()).await? < msg_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Full header message not provided",
            ));
        }

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
        return Ok(Decode::Header(Self {
            name,
            port: h.port as u16,
        }));
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
        let h = match ConnectionHeader::decode(&mut rx).await.expect("decodes") {
            Decode::Other(_) => panic!("Must decode"),
            Decode::Header(h) => h,
        };
        assert_eq!(header.port, h.port);
        assert_eq!(header.name, h.name);
    }
}
