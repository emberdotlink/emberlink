//! Dev IdentityRoot rotation — grace-window tracker + handlers.
//!
//! Per ADR 162 §Component 3 (META-TRUST-ROTATE-DEV-IR). The CLI side
//! (`crates/emberlink-cli/src/trust/rotate.rs`) drives the operator-facing
//! flow: Touch ID gate, new keypair mint, Keychain stash at the `.v2`
//! label, re-sign of the dev manifest, plist rewrite + `launchctl kickstart`.
//! Once the CLI has stashed both keys, it issues `trust.rotate_dev_ir` to
//! this module so the daemon can:
//!
//! 1. Record the rotation in a process-global registry keyed by the new
//!    fingerprint, including the grace-window end (default 7d, configurable
//!    via the request body's `grace_window_secs` field).
//! 2. Emit a `trust.rotation` Receipt at registration time with both
//!    fingerprints + the requested grace window (presence_proof is folded
//!    in by the higher-level receipt builder).
//! 3. Schedule a daemon-internal timer that fires at grace expiry to
//!    remove the old root from the trust-root snapshot + emit
//!    `trust.rotation_complete`.
//!
//! ## Scope
//!
//! This module owns the tracker + RPC handlers. The Receipt body
//! emission is delegated to the higher-level receipt builder once the
//! handler reports a successful registration; the daemon's broker
//! handler dispatch wires `trust.rotate_dev_ir` to
//! [`handle_trust_rotate_dev_ir`] and `trust.rotation_status` to
//! [`handle_trust_rotation_status`].
//!
//! ## Grace-window semantics
//!
//! During the grace window:
//! - The new root is the canonical signer for future manifest re-signs.
//! - The old root remains in the trust set so already-signed artifacts
//!   continue to verify cleanly.
//! - Every accept of the old root SHOULD emit a `trust.deprecation_warning`
//!   trace entry (deferred to a follow-up — wire it in
//!   `verify_manifest_signature_with_trust_roots` once the rotation
//!   substrate is in place).
//!
//! After grace expiry:
//! - The old root is removed from the trust set snapshot.
//! - A `trust.rotation_complete` Receipt is emitted.
//! - Artifacts signed under the old key fail verification.
//!
//! Failure recovery (daemon refuses to start with detailed error if the
//! rotation registry is corrupted) is surfaced via
//! [`RotationError::CorruptRegistry`] and routed by the
//! `ember recover authority --scope identity-root` scaffold.
//!
//! Anchor: `trust_rotate_dev_ir_landed`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::binary_manifest::{TrustRootRecord, TrustRootSource, trust_roots_snapshot};

// trust_rotate_dev_ir_landed — checkpoint anchoring this PR (META-TRUST-ROTATE-DEV-IR).

/// Default grace window for dev IdentityRoot rotation. ADR 162 §Component 3
/// specifies 7 days as the canonical default. Operator can shorten via
/// the request body's `grace_window_secs` field, but the daemon refuses
/// values below [`MIN_GRACE_WINDOW_SECS`] (defense against fat-finger
/// "rotate-and-immediately-yank" mistakes that strand in-flight callers
/// holding old-rooted manifests).
pub const DEFAULT_GRACE_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// Minimum grace window. One hour — short enough for test environments
/// and operator drills, long enough to catch the inevitable "I forgot
/// to update the CI cache" failure mode.
pub const MIN_GRACE_WINDOW_SECS: u64 = 60 * 60;

/// One in-flight dev IR rotation record. Captures the old + new
/// fingerprints (so the rotation-complete handler knows what to evict
/// from the trust set), the grace window deadline (Unix seconds), and
/// an optional operator-supplied reason that lands in the audit
/// Receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    /// Hex-lowercase fingerprint of the old (pre-rotation) dev IR.
    pub old_fingerprint_hex: String,
    /// Hex-lowercase fingerprint of the new dev IR.
    pub new_fingerprint_hex: String,
    /// Unix seconds at which the grace window ends. The daemon-internal
    /// scheduler fires at this point to evict the old root + emit
    /// `trust.rotation_complete`.
    pub grace_window_end_secs: u64,
    /// Optional operator-supplied rationale (`--reason STRING`). Lands
    /// in the audit Receipt verbatim; bounded at 1024 chars by the
    /// CLI side so the registry doesn't grow unbounded.
    pub reason: Option<String>,
    /// Unix seconds at which the rotation was registered. Surfaced by
    /// `trust.rotation_status` so operators can compute "time
    /// remaining" without re-deriving from the deadline + clock skew.
    pub registered_at_secs: u64,
}

/// Errors raised by the rotation handlers. Each variant maps to a
/// stable JSON-RPC error code so the CLI side can branch on the
/// machine-readable error string without parsing free text.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RotationError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid field {field}: {detail}")]
    InvalidField {
        field: &'static str,
        detail: String,
    },
    #[error("grace_window_secs {got} below minimum {min}")]
    GraceWindowTooShort { got: u64, min: u64 },
    #[error("rotation already in flight for new fingerprint {fingerprint}")]
    Duplicate { fingerprint: String },
    #[error("no rotation in flight for fingerprint {fingerprint}")]
    NotFound { fingerprint: String },
    #[error("rotation registry corrupted: {0}")]
    CorruptRegistry(String),
}

impl RotationError {
    /// Stable JSON-RPC error code for this variant. -32602 for
    /// invalid-params class errors; -32004 for not-found / duplicate;
    /// -32000 for internal corruption.
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::MissingField(_)
            | Self::InvalidField { .. }
            | Self::GraceWindowTooShort { .. } => -32602,
            Self::Duplicate { .. } | Self::NotFound { .. } => -32004,
            Self::CorruptRegistry(_) => -32000,
        }
    }
}

/// Process-global rotation registry. Keyed by new-fingerprint so
/// duplicate `trust.rotate_dev_ir` calls for the same target key fail
/// fast rather than overwriting an in-flight record.
///
/// `OnceLock<Mutex<HashMap>>` mirrors the snapshot pattern in
/// `binary_manifest::TRUST_ROOTS_SNAPSHOT`: process-globally
/// initialized once, mutated under a short-held lock, never held
/// across an `.await`.
static ROTATION_REGISTRY: OnceLock<Mutex<HashMap<String, RotationRecord>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, RotationRecord>> {
    ROTATION_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Wall-clock seconds since the Unix epoch. Pulled into a helper so
/// tests can override it via [`set_clock_for_test`] without paying for
/// a full mockable-clock abstraction.
fn now_secs() -> u64 {
    if let Some(t) = test_clock() {
        return t;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static TEST_CLOCK: OnceLock<Mutex<Option<u64>>> = OnceLock::new();

fn test_clock() -> Option<u64> {
    TEST_CLOCK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|g| *g)
}

/// Override the rotation tracker's wall clock. Public so integration
/// tests in `crates/ember-daemon/tests/` can drive deterministic
/// timelines without a tokio runtime. The override applies process-
/// globally until cleared; production callsites do not set it, so the
/// live `SystemTime::now()` reading is the steady-state behavior.
/// Hidden from rustdoc because no production caller should reach for
/// this.
#[doc(hidden)]
pub fn set_clock_for_test(t: Option<u64>) {
    let cell = TEST_CLOCK.get_or_init(|| Mutex::new(None));
    if let Ok(mut g) = cell.lock() {
        *g = t;
    }
}

/// Drain the rotation registry. Public so integration tests in
/// `crates/ember-daemon/tests/` can isolate their setup; production
/// callers MUST NOT use this (it would silently abandon a real
/// in-flight rotation). Hidden from rustdoc.
#[doc(hidden)]
pub fn clear_registry_for_test() {
    if let Ok(mut g) = registry().lock() {
        g.clear();
    }
}

/// Register a new rotation in the daemon-side tracker. Returns the
/// canonical [`RotationRecord`] (which the caller folds into the
/// `trust.rotation` Receipt body via the higher-level receipt builder).
///
/// Side-effects:
/// - Adds the record to the process-global registry.
/// - Does NOT mutate the trust-root snapshot itself — the additive
///   plist update + `launchctl kickstart` cycle is the operator-side
///   responsibility (CLI side), so the next daemon startup re-reads
///   `EMBER_TRUST_ROOTS` with both roots present and rebuilds the
///   snapshot from scratch.
/// - Does NOT schedule the grace-window timer — the runtime layer
///   ([`spawn_grace_window_scheduler`]) walks the registry on its own
///   cadence and fires [`expire_rotation`] when the deadline passes.
///   Kept separate so unit tests for the tracker don't need a tokio
///   runtime.
pub fn register_rotation(
    old_fingerprint_hex: &str,
    new_fingerprint_hex: &str,
    grace_window_secs: u64,
    reason: Option<String>,
) -> Result<RotationRecord, RotationError> {
    validate_fingerprint("old_fingerprint_hex", old_fingerprint_hex)?;
    validate_fingerprint("new_fingerprint_hex", new_fingerprint_hex)?;
    if old_fingerprint_hex == new_fingerprint_hex {
        return Err(RotationError::InvalidField {
            field: "new_fingerprint_hex",
            detail: "new fingerprint must differ from old".to_string(),
        });
    }
    if grace_window_secs < MIN_GRACE_WINDOW_SECS {
        return Err(RotationError::GraceWindowTooShort {
            got: grace_window_secs,
            min: MIN_GRACE_WINDOW_SECS,
        });
    }

    let now = now_secs();
    let record = RotationRecord {
        old_fingerprint_hex: old_fingerprint_hex.to_string(),
        new_fingerprint_hex: new_fingerprint_hex.to_string(),
        grace_window_end_secs: now.saturating_add(grace_window_secs),
        reason: reason.map(|r| r.chars().take(1024).collect()),
        registered_at_secs: now,
    };

    let mut guard = registry()
        .lock()
        .map_err(|e| RotationError::CorruptRegistry(format!("registry mutex poisoned: {e}")))?;
    if guard.contains_key(new_fingerprint_hex) {
        return Err(RotationError::Duplicate {
            fingerprint: new_fingerprint_hex.to_string(),
        });
    }
    guard.insert(new_fingerprint_hex.to_string(), record.clone());
    Ok(record)
}

/// Look up an in-flight rotation by the NEW fingerprint. Returns
/// `Ok(None)` when no rotation is in flight for that key.
pub fn get_rotation(new_fingerprint_hex: &str) -> Result<Option<RotationRecord>, RotationError> {
    let guard = registry()
        .lock()
        .map_err(|e| RotationError::CorruptRegistry(format!("registry mutex poisoned: {e}")))?;
    Ok(guard.get(new_fingerprint_hex).cloned())
}

/// Walk the registry and return every record whose grace window has
/// passed at or before `now`. Pure read — callers ([`expire_rotation`])
/// re-acquire the lock to perform the removal.
pub fn list_expired(now: u64) -> Result<Vec<RotationRecord>, RotationError> {
    let guard = registry()
        .lock()
        .map_err(|e| RotationError::CorruptRegistry(format!("registry mutex poisoned: {e}")))?;
    Ok(guard
        .values()
        .filter(|r| r.grace_window_end_secs <= now)
        .cloned()
        .collect())
}

/// Snapshot of all currently in-flight rotations. Used by
/// `trust.rotation_status` to surface "is anything in flight?" to
/// operators without a per-fingerprint query.
pub fn list_in_flight() -> Result<Vec<RotationRecord>, RotationError> {
    let guard = registry()
        .lock()
        .map_err(|e| RotationError::CorruptRegistry(format!("registry mutex poisoned: {e}")))?;
    Ok(guard.values().cloned().collect())
}

/// Mark a rotation as complete: remove the record from the registry +
/// signal to the trust-root snapshot evictor that the old fingerprint
/// can be dropped. Caller is responsible for actually rebuilding the
/// snapshot (via [`evict_from_trust_root_snapshot`]) and emitting the
/// `trust.rotation_complete` Receipt; this function only owns the
/// registry-side bookkeeping so the tracker stays unit-testable.
pub fn expire_rotation(
    new_fingerprint_hex: &str,
) -> Result<RotationRecord, RotationError> {
    let mut guard = registry()
        .lock()
        .map_err(|e| RotationError::CorruptRegistry(format!("registry mutex poisoned: {e}")))?;
    guard
        .remove(new_fingerprint_hex)
        .ok_or_else(|| RotationError::NotFound {
            fingerprint: new_fingerprint_hex.to_string(),
        })
}

/// Remove the named fingerprint from the process-global trust-root
/// snapshot. Returns `Ok(true)` when an entry was evicted, `Ok(false)`
/// when the snapshot did not contain the fingerprint (already gone —
/// rotation-complete is idempotent against a daemon restart that
/// already dropped the old plist entry from `EMBER_TRUST_ROOTS`).
pub fn evict_from_trust_root_snapshot(fingerprint_hex: &str) -> bool {
    let current = trust_roots_snapshot();
    let kept: Vec<TrustRootRecord> = current
        .iter()
        .filter(|r| r.fingerprint_hex != fingerprint_hex)
        .cloned()
        .collect();
    let evicted = kept.len() < current.len();
    if evicted {
        crate::binary_manifest::set_trust_roots_snapshot(kept);
    }
    evicted
}

fn validate_fingerprint(field: &'static str, hex: &str) -> Result<(), RotationError> {
    if hex.is_empty() {
        return Err(RotationError::MissingField(field));
    }
    if hex.len() != 64 {
        return Err(RotationError::InvalidField {
            field,
            detail: format!("expected 64 hex chars, got {}", hex.len()),
        });
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RotationError::InvalidField {
            field,
            detail: "non-hex characters".to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON-RPC handlers
// ---------------------------------------------------------------------------

/// Handle `trust.rotate_dev_ir` JSON-RPC. Request body:
///
/// ```json
/// {
///   "old_fingerprint_hex": "<64-hex>",
///   "new_fingerprint_hex": "<64-hex>",
///   "grace_window_secs": <u64>,     // optional; default 7d
///   "reason": "<string>"              // optional
/// }
/// ```
///
/// Response body:
///
/// ```json
/// {
///   "old_fingerprint_hex": "<64-hex>",
///   "new_fingerprint_hex": "<64-hex>",
///   "grace_window_end_secs": <u64>,
///   "registered_at_secs": <u64>,
///   "reason": "<string>" | null
/// }
/// ```
///
/// The CLI side calls this AFTER it has stashed the new keypair at
/// `sh.emberlink.dev-identity-root.v2`. The trust-root snapshot
/// mutation itself happens at the NEXT daemon startup when the
/// operator-rewritten plist's `EMBER_TRUST_ROOTS` carries both keys
/// (additive rotation per ADR 162 §Component 3 step 3).
pub fn handle_trust_rotate_dev_ir(params: &Value) -> Result<Value, (i32, String)> {
    let obj = params
        .as_object()
        .ok_or((-32602, "params must be a JSON object".to_string()))?;

    let old = obj
        .get("old_fingerprint_hex")
        .and_then(|v| v.as_str())
        .ok_or((
            -32602,
            "missing or non-string field: old_fingerprint_hex".to_string(),
        ))?;
    let new = obj
        .get("new_fingerprint_hex")
        .and_then(|v| v.as_str())
        .ok_or((
            -32602,
            "missing or non-string field: new_fingerprint_hex".to_string(),
        ))?;
    let grace = obj
        .get("grace_window_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_GRACE_WINDOW_SECS);
    let reason = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let record = register_rotation(old, new, grace, reason).map_err(|e| (e.rpc_code(), e.to_string()))?;

    Ok(json!({
        "old_fingerprint_hex": record.old_fingerprint_hex,
        "new_fingerprint_hex": record.new_fingerprint_hex,
        "grace_window_end_secs": record.grace_window_end_secs,
        "registered_at_secs": record.registered_at_secs,
        "reason": record.reason,
    }))
}

/// Handle `trust.rotation_status` JSON-RPC. Returns the in-flight
/// rotations + the daemon's current trust-root snapshot. Read-only;
/// safe to expose to any ConnectOnly caller (same posture as
/// `trust.list`).
///
/// Response body:
///
/// ```json
/// {
///   "in_flight": [<RotationRecord>...],
///   "trust_roots": [{"fingerprint_hex": "...", "source": "release"|"operator"}, ...]
/// }
/// ```
pub fn handle_trust_rotation_status(_params: &Value) -> Result<Value, (i32, String)> {
    let in_flight = list_in_flight().map_err(|e| (e.rpc_code(), e.to_string()))?;
    let in_flight_json: Vec<Value> = in_flight
        .iter()
        .map(|r| {
            json!({
                "old_fingerprint_hex": r.old_fingerprint_hex,
                "new_fingerprint_hex": r.new_fingerprint_hex,
                "grace_window_end_secs": r.grace_window_end_secs,
                "registered_at_secs": r.registered_at_secs,
                "reason": r.reason,
            })
        })
        .collect();
    let roots = trust_roots_snapshot();
    let roots_json: Vec<Value> = roots
        .iter()
        .map(|r| {
            json!({
                "fingerprint_hex": r.fingerprint_hex,
                "source": match r.source {
                    TrustRootSource::Release => "release",
                    TrustRootSource::Operator => "operator",
                },
            })
        })
        .collect();
    Ok(json!({
        "in_flight": in_flight_json,
        "trust_roots": roots_json,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    fn fresh() {
        clear_registry_for_test();
        set_clock_for_test(Some(1_000_000));
    }

    #[test]
    fn register_rotation_records_fingerprints_and_deadline() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let rec = register_rotation(
            &fp(0x11),
            &fp(0x22),
            DEFAULT_GRACE_WINDOW_SECS,
            Some("scheduled monthly rotation".to_string()),
        )
        .expect("register must succeed");
        assert_eq!(rec.old_fingerprint_hex, fp(0x11));
        assert_eq!(rec.new_fingerprint_hex, fp(0x22));
        assert_eq!(
            rec.grace_window_end_secs,
            1_000_000 + DEFAULT_GRACE_WINDOW_SECS
        );
        assert_eq!(rec.registered_at_secs, 1_000_000);
        assert_eq!(rec.reason.as_deref(), Some("scheduled monthly rotation"));
    }

    #[test]
    fn register_rotation_rejects_short_fingerprint() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let err = register_rotation("aa", &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect_err("short fp must fail");
        match err {
            RotationError::InvalidField { field, .. } => {
                assert_eq!(field, "old_fingerprint_hex");
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn register_rotation_rejects_non_hex_fingerprint() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let mut bad = String::new();
        for _ in 0..64 {
            bad.push('z');
        }
        let err = register_rotation(&bad, &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect_err("non-hex must fail");
        assert!(matches!(err, RotationError::InvalidField { .. }));
    }

    #[test]
    fn register_rotation_rejects_grace_window_below_floor() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let err = register_rotation(&fp(0x11), &fp(0x22), 60, None)
            .expect_err("short grace window must fail");
        match err {
            RotationError::GraceWindowTooShort { got, min } => {
                assert_eq!(got, 60);
                assert_eq!(min, MIN_GRACE_WINDOW_SECS);
            }
            other => panic!("expected GraceWindowTooShort, got {other:?}"),
        }
    }

    #[test]
    fn register_rotation_rejects_identical_old_and_new() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let err = register_rotation(&fp(0x11), &fp(0x11), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect_err("identical must fail");
        match err {
            RotationError::InvalidField { field, .. } => {
                assert_eq!(field, "new_fingerprint_hex");
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn register_rotation_rejects_duplicate() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        register_rotation(&fp(0x11), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect("first must succeed");
        let err = register_rotation(&fp(0x33), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect_err("dup new must fail");
        assert!(matches!(err, RotationError::Duplicate { .. }));
    }

    #[test]
    fn register_rotation_truncates_reason_at_1024_chars() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let long = "a".repeat(2048);
        let rec = register_rotation(&fp(0x11), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, Some(long))
            .expect("register must succeed");
        assert_eq!(rec.reason.as_ref().unwrap().chars().count(), 1024);
    }

    #[test]
    fn get_rotation_returns_none_for_unknown() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let out = get_rotation(&fp(0xFF)).expect("get must succeed");
        assert!(out.is_none());
    }

    #[test]
    fn list_expired_returns_only_past_deadline() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        // Two rotations: one expires at t = 1_000_000 + 3600, the
        // other at t = 1_000_000 + 86400.
        register_rotation(&fp(0x11), &fp(0x22), 3600, None).expect("r1");
        register_rotation(&fp(0x33), &fp(0x44), 86400, None).expect("r2");
        // At t = 1_000_000 + 7200, only the first is past deadline.
        let expired = list_expired(1_000_000 + 7200).expect("list");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].new_fingerprint_hex, fp(0x22));
        // At t = 1_000_000 + 100_000, both are past deadline.
        let expired = list_expired(1_000_000 + 100_000).expect("list");
        assert_eq!(expired.len(), 2);
    }

    #[test]
    fn expire_rotation_removes_record() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        register_rotation(&fp(0x11), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect("register");
        let rec = expire_rotation(&fp(0x22)).expect("expire");
        assert_eq!(rec.new_fingerprint_hex, fp(0x22));
        // Second expire fails — record is gone.
        let err = expire_rotation(&fp(0x22)).expect_err("second expire fails");
        assert!(matches!(err, RotationError::NotFound { .. }));
    }

    #[test]
    fn list_in_flight_returns_all_registered() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        register_rotation(&fp(0x11), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None).expect("r1");
        register_rotation(&fp(0x33), &fp(0x44), DEFAULT_GRACE_WINDOW_SECS, None).expect("r2");
        let all = list_in_flight().expect("list");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn evict_from_trust_root_snapshot_idempotent_on_missing() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Reset snapshot to a known state.
        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: fp(0x11),
            source: TrustRootSource::Release,
        }]);
        // Evict a fingerprint that is NOT present — returns false.
        let did_evict = evict_from_trust_root_snapshot(&fp(0x99));
        assert!(!did_evict);
        // Snapshot is unchanged.
        let snap = trust_roots_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].fingerprint_hex, fp(0x11));
    }

    #[test]
    fn evict_from_trust_root_snapshot_drops_named_root() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::binary_manifest::set_trust_roots_snapshot(vec![
            TrustRootRecord {
                fingerprint_hex: fp(0x11),
                source: TrustRootSource::Release,
            },
            TrustRootRecord {
                fingerprint_hex: fp(0x22),
                source: TrustRootSource::Operator,
            },
        ]);
        let did_evict = evict_from_trust_root_snapshot(&fp(0x22));
        assert!(did_evict);
        let snap = trust_roots_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].fingerprint_hex, fp(0x11));
    }

    #[test]
    fn handle_trust_rotate_dev_ir_happy_path_returns_record_body() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let params = json!({
            "old_fingerprint_hex": fp(0x11),
            "new_fingerprint_hex": fp(0x22),
            "grace_window_secs": DEFAULT_GRACE_WINDOW_SECS,
            "reason": "test rotation",
        });
        let out = handle_trust_rotate_dev_ir(&params).expect("handle must succeed");
        assert_eq!(out["old_fingerprint_hex"], fp(0x11));
        assert_eq!(out["new_fingerprint_hex"], fp(0x22));
        assert_eq!(
            out["grace_window_end_secs"].as_u64().unwrap(),
            1_000_000 + DEFAULT_GRACE_WINDOW_SECS
        );
        assert_eq!(out["reason"], "test rotation");
    }

    #[test]
    fn handle_trust_rotate_dev_ir_defaults_grace_window() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let params = json!({
            "old_fingerprint_hex": fp(0x11),
            "new_fingerprint_hex": fp(0x22),
        });
        let out = handle_trust_rotate_dev_ir(&params).expect("handle must succeed");
        assert_eq!(
            out["grace_window_end_secs"].as_u64().unwrap(),
            1_000_000 + DEFAULT_GRACE_WINDOW_SECS
        );
    }

    #[test]
    fn handle_trust_rotate_dev_ir_rejects_missing_old() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        let params = json!({
            "new_fingerprint_hex": fp(0x22),
        });
        let err = handle_trust_rotate_dev_ir(&params).expect_err("missing old must fail");
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("old_fingerprint_hex"));
    }

    #[test]
    fn handle_trust_rotation_status_returns_in_flight_and_snapshot() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fresh();
        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: fp(0xAA),
            source: TrustRootSource::Release,
        }]);
        register_rotation(&fp(0x11), &fp(0x22), DEFAULT_GRACE_WINDOW_SECS, None)
            .expect("register");
        let out = handle_trust_rotation_status(&Value::Null).expect("status");
        assert_eq!(out["in_flight"].as_array().unwrap().len(), 1);
        assert_eq!(out["trust_roots"].as_array().unwrap().len(), 1);
        assert_eq!(out["trust_roots"][0]["fingerprint_hex"], fp(0xAA));
        assert_eq!(out["trust_roots"][0]["source"], "release");
    }
}
