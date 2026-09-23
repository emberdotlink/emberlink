use std::path::Path;

use crate::{audit::DurableStore, model::Refusal};

pub struct DurableRestoreAdapter;

impl DurableRestoreAdapter {
    pub fn restore(root: &Path) -> Result<DurableStore, Refusal> {
        DurableStore::restore(root)
    }
}
