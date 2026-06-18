//! Re-export shim — the policy logic lifted to core-approval per
//! ARCH-POLICY-LIFT-TO-CORE-APPROVAL. Existing daemon-internal callers
//! import via this shim during transition; once `crate::trust::policy::*` usages
//! are dropped from the daemon, this file can be deleted.

pub use core_approval::policy::*;
