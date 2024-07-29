//! Group struct and its implementation.

use serde::{Deserialize, Serialize};

/// Defines a group for categorizing messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group id uniquely identified
    pub id: String,
    /// Unix timestamp
    pub timestamp: u64,
}

impl Group {
    /// Create a new Group instance. The timestamp is set to the current time.
    pub(crate) fn new(id: String) -> Self {
        Self {
            id,
            timestamp: web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Group {}
