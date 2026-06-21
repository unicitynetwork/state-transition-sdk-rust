//! Network identifier (α) scoping token ids and other network-bound values.

use crate::error::Error;

/// A Unicity network identifier. Wraps a 16-bit unsigned value; the well-known
/// networks are provided as constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(u16);

impl NetworkId {
    /// Production network (id 1).
    pub const MAINNET: NetworkId = NetworkId(1);
    /// Test network (id 2).
    pub const TESTNET: NetworkId = NetworkId(2);
    /// Local/dev network (id 3).
    pub const LOCAL: NetworkId = NetworkId(3);

    /// Construct from a numeric id. The id must be in `1..=0xffff`.
    pub fn new(id: u16) -> Result<Self, Error> {
        if id == 0 {
            return Err(Error::OutOfRange("network id must be >= 1"));
        }
        Ok(NetworkId(id))
    }

    /// The numeric id.
    pub fn id(self) -> u16 {
        self.0
    }
}
