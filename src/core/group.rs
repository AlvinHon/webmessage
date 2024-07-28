use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub timestamp: u64, // Unix timestamp
}

impl Group {
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
