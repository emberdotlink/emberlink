//! ember-broker — approval-delivery channels and grant routing.
//!
//! Locks the SHAPE of the approval-channel surface so policy can route
//! `persona → channels[]` and the kernel knows which adapter to call.
//! Real wire (Slack webhook, AppleScript iMessage, SMTP) lands in
//! per-channel follow-up tasks (`implementation-note-7`,
//! `implementation-note-6`, `implementation-note-5`).
pub mod channels;
