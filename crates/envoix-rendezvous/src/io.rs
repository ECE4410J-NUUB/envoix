//! Length-prefixed JSON framing for the control messages, shared by the broker
//! and its clients. Each frame is a 4-byte big-endian body length followed by
//! the JSON body. The opaque pairing traffic uses the same shape, which is why
//! the broker can read one `Join`, write one `Paired`, and then raw-byte-relay
//! the remainder transparently.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::RendezvousError;

/// Upper bound on a single control frame (the messages are tiny).
pub(crate) const MAX_FRAME_BODY: usize = 64 * 1024;

/// Read one length-prefixed JSON frame and decode it into `T`.
pub async fn read_framed<R, T>(reader: &mut R) -> Result<T, RendezvousError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BODY {
        return Err(RendezvousError::FrameTooLarge);
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| RendezvousError::BadMessage(e.to_string()))
}

/// Encode `value` as a length-prefixed JSON frame and write it.
pub async fn write_framed<W, T>(writer: &mut W, value: &T) -> Result<(), RendezvousError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value).map_err(|e| RendezvousError::BadMessage(e.to_string()))?;
    if body.len() > MAX_FRAME_BODY {
        return Err(RendezvousError::FrameTooLarge);
    }
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}
