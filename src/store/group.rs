use crate::core::group::Group;

use super::SerdeLocalStore;

const KEY_GROUPS: &str = "groups";

#[derive(Default)]
pub(crate) struct GroupStore {}

impl GroupStore {
    pub(crate) fn groups(&self) -> Vec<Group> {
        self.get(KEY_GROUPS).unwrap_or_default()
    }

    pub(crate) fn add_group(&mut self, group: Group) {
        let mut groups = self.groups();
        if !groups.contains(&group) {
            groups.push(group);
            self.set(KEY_GROUPS, groups);
        }
    }
}

impl SerdeLocalStore for GroupStore {}
