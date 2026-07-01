//! The small control protocol between a peer and the broker: a peer sends
//! [`Join`], the broker replies with [`Paired`]. Everything after that is the
//! opaque end-to-end pairing traffic the broker relays without parsing.

use serde::{Deserialize, Serialize};

/// SPAKE2 role assigned by the broker, decided by join order (first = initiator).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Initiator,
    Responder,
}

/// A peer's opening message: which room it wants to pair in.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Join {
    pub room_id: String,
}

/// The broker's reply once a partner is present: the peer's assigned role.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Paired {
    pub role: Role,
}
