//! SCION-side daemon primitives.
//!
//! "SCION" here means the host-level composition layer described by ADR 164:
//! workflow grants that thread `workflow_id_root` across host → container
//! boundaries, with revocation propagating across descendant agents inside
//! SCION-sandboxed containers.
//!
//! This module hosts the SCION-facing seams that compose with the daemon's
//! authority plane. Specifically:
//!
//! - [`lifecycle`] documents the orchestrator-owned process-lifecycle
//!   contract for descendant agents after their workflow root is revoked.
//!   The daemon's authority cascade lives in [`crate::grants::cascade`];
//!   driving SIGTERM/SIGKILL on descendant agent processes is the
//!   orchestrator's job — this module describes the seam, it does not own
//!   the kill.

pub mod lifecycle;
