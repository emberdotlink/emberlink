use core_types::{IdentityRoot, LinkageAssertion};

pub fn create_root(id: impl Into<String>, display_name: impl Into<String>) -> IdentityRoot {
    IdentityRoot {
        id: id.into(),
        display_name: display_name.into(),
    }
}

pub fn local_linkage(source_root_id: impl Into<String>, target_root_id: impl Into<String>) -> LinkageAssertion {
    LinkageAssertion {
        source_root_id: source_root_id.into(),
        target_root_id: target_root_id.into(),
        disclosed: false,
    }
}

