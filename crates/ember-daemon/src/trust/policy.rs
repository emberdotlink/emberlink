//! Re-export shim — the policy logic lifted to core-approval per
//! implementation-note-254. Existing daemon-internal callers
//! import via this shim during transition; once `crate::trust::policy::*` usages
//! are dropped from the daemon, this file can be deleted.

pub use core_approval::policy::*;
