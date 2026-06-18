//! Session lifecycle module — heartbeat watcher + dirty-exit termination path.
//!
//! H1 invariant (cohort-A test plan): every grant terminates in a signed
//! Receipt across all four termination paths — clean exit / dirty
//! exit / TTL expiry / explicit revoke. This module implements the dirty-exit
//! path: the daemon detects when a launcher PID has died without sending a
//! `session.close`, transitions the session to `terminated_dirty`, emits a
//! Receipt with `termination_reason: heartbeat_lost`, and revokes any
//! outstanding broker grants.
//!
//! Layout:
//!   - [`heartbeat`] — watcher loop (90s timeout + PID liveness check).
//!   - [`lifecycle`] — `terminated_dirty` transition (Receipt emission + grant
//!     revocation, sharing the clean-exit code path so signing logic isn't
//!     duplicated).

pub mod heartbeat;
pub mod lifecycle;
