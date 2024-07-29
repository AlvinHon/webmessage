//! Provides a struct `GroupStore` for storing group related data.

use crate::core::group::Group;

use super::SerdeLocalStore;

const KEY_GROUPS: &str = "groups";

/// GroupStore is a store for group related data. It implements the trait [SerdeLocalStore](crate::store::SerdeLocalStore).
#[derive(Default)]
pub(crate) struct GroupStore {}

impl GroupStore {
    /// Returns the list of groups.
    pub(crate) fn groups(&self) -> Vec<Group> {
        self.get(KEY_GROUPS).unwrap_or_default()
    }

    /// Adds a group to the list of groups.
    pub(crate) fn add_group(&mut self, group: Group) {
        let mut groups = self.groups();
        if !groups.contains(&group) {
            groups.push(group);
            self.set(KEY_GROUPS, groups);
        }
    }
}

impl SerdeLocalStore for GroupStore {}
