//! Shared domain types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Wire protocol version used by the resumable transfer flow.
pub const PROTOCOL_VERSION: u32 = 1;

/// Minimum byte length for a SPAKE2 shared pairing token.
pub const MIN_SHARED_TOKEN_LEN: usize = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub struct TransferId(pub String);

impl TransferId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub struct FileId(pub String);

impl FileId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct ChunkId(pub u64);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct ChunkSize(pub u64);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct ByteCount(pub u64);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub enum ConnectionMode {
    QuicDirect,
    Relay,
    ServerFallback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub enum PeerRole {
    Sender,
    Receiver,
}
