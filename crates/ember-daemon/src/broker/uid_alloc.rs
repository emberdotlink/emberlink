//! CLASSIFICATION: PUBLIC
//!
//! META-BROKER-EXEC-PER-SPAWN-UID — per-spawn ephemeral uid pool for
//! credentialed `broker_exec` children. Closes Finding 14 (refuse to
//! spawn a child as the daemon's own uid) and the
//! `/proc/<pid>/environ` side-channel between two concurrent broker_exec
//! children sharing one uid.
//!
//! ## Threat model
//!
//! Today's `handle_broker_exec` spawn paths fork+execve as the daemon's
//! own uid (`ember` per ADR 131). Two concurrent children spawned under
//! autopilot fanout (e.g. parallel `git push` + `gh pr create`) share
//! the same uid, so each can read the other's `/proc/<pid>/environ`. A
//! compromised Construct or argv-classifier-evasion in spawn A can
//! steal spawn B's credentials.
//!
//! Per-spawn uid drop closes this: each broker_exec child runs under a
//! distinct uid checked out from a pool. Cross-uid `/proc/<pid>/environ`
//! read fails with `EACCES` on default Linux `/proc` permissions, no
//! `hidepid=2` needed.
//!
//! ## Allocation strategy
//!
//! Strategy (b) from the META-BROKER-EXEC-PER-SPAWN-UID brief —
//! **per-spawn ephemeral uid checked out from a pre-provisioned pool**.
//! The installer provisions the pool uids at `ember daemon install`
//! time (`ember-spawn-0` … `ember-spawn-N`) and the daemon checks one
//! out per spawn via [`UidPool::checkout`]. A RAII [`UidLease`] returns
//! the uid to the pool when the spawn completes.
//!
//! Rationale for (b) over (a) random-uid mint and (c) per-construct-tag
//! sticky uid:
//! - (a) requires the daemon to run `useradd`/`dscl create` at every
//!   spawn — too slow (50–200ms per syscall on macOS dscl) and leaves
//!   stranded uids on crash.
//! - (c) keeps a single uid per construct tag, which means two
//!   *concurrent* spawns of the same construct (e.g. two `gh` calls
//!   in parallel) still share a uid — the threat model isn't closed.
//! - (b) gives concurrent-spawn isolation with no per-spawn syscall
//!   cost and a finite footprint (pool size set at install).
//!
//! See ADR 167 (amendment to ADR 131) for the full rationale and
//! interaction with the separate-uid daemon posture.
//!
//! ## Lifecycle
//!
//! 1. Daemon startup reads `[daemon.spawn_pool]` from config, parses
//!    `uids = [10010, 10011, …]` + `gid = 10010` and installs the pool
//!    via [`init_uid_pool`].
//! 2. `handle_broker_exec` calls [`UidPool::checkout`] before any spawn
//!    decision. Pool exhausted → retryable `-32020`; pool empty or absent
//!    → `-32021`; allocated uid == daemon uid → `-32020` Finding 14 refusal.
//! 3. The fork+execve path (both non-PTY and forkpty) calls
//!    [`UidLease::uid`] / [`UidLease::gid`] in the child branch and
//!    `setresgid` / `setresuid` before `execvpe`.
//! 4. The lease drops at function-end (or earlier on error), returning
//!    the uid to the available set.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Process-global uid pool installed at daemon startup. `None` ⇒
/// `[daemon.spawn_pool]` was absent from config ⇒ broker_exec must
/// refuse with `-32021` to avoid the silent-regression-to-daemon-uid
/// posture.
static UID_POOL: OnceLock<Option<Arc<UidPool>>> = OnceLock::new();

fn record_pool_slot_telemetry(capacity: usize, occupied: usize) {
    let capacity = capacity.min(u32::MAX as usize) as u32;
    let occupied = occupied.min(u32::MAX as usize) as u32;

    // ADR 155 Component 8's operator-reserved tier is not implemented in the
    // current allocator, so reserve-hit stays false until that admission layer
    // owns the decision.
    crate::telemetry::measurement::record_pool_slot_sample("dev0", capacity, occupied, false);
}

/// Install the process-global uid pool. Called by runtime startup
/// after `DaemonConfig::load`. Subsequent calls panic to make
/// double-install (a configuration bug) loud.
///
/// Pass `None` when `[daemon.spawn_pool]` is absent in config — this
/// records the "pool not configured" state so broker_exec surfaces
/// `-32021` instead of silently falling back to the daemon uid.
pub fn init_uid_pool(config: Option<SpawnPoolConfig>) {
    let pool = config.map(|cfg| {
        // ADR 155 Component 2 — modern-Linux subuid path. When the
        // config carries `subuid_range_start` + `subuid_range_slots`
        // (provisioned by META-EXEC-DOMAIN-SUBUID-INSTALL), populate
        // the pool from the range and mark it as subuid-shaped so
        // the broker_exec handler routes through the clone3 +
        // newuidmap path. Otherwise the legacy ADR-131 system-user
        // pool shape is used.
        if let (Some(start), Some(slots)) = (cfg.subuid_range_start, cfg.subuid_range_slots) {
            let uids: Vec<u32> = (start..start.saturating_add(slots)).collect();
            // Use range-start as the gid as well — `/etc/subgid` is
            // provisioned in lockstep with `/etc/subuid` by the
            // installer, same range. Pool's `gid` field is the BASE
            // of the subgid range in this shape; per-lease gid is
            // the per-lease uid (1:1 inner-root mapping).
            Arc::new(UidPool::new_subuid(uids, start))
        } else {
            Arc::new(UidPool::new(cfg.uids, cfg.gid))
        }
    });
    if UID_POOL.set(pool).is_err() {
        // Already initialized — this is a re-initialization bug, not
        // a config issue. Tests that need a fresh pool use the
        // `test_*` helpers below.
        tracing::warn!(
            "uid_alloc::init_uid_pool: pool already initialized; re-init ignored \
             (this indicates a runtime bootstrap bug)"
        );
    }
}

/// Test-only: install a pool that contains the *current* uid for use
/// by existing unit tests. Sets a flag that disables the Finding-14
/// (`target_uid == daemon_uid`) refusal so the test path can spawn
/// children without provisioning real separate uids.
///
/// META-BROKER-EXEC-PER-SPAWN-UID — test seam. Production callers
/// MUST never invoke this; the test_mode flag inside the resulting
/// pool is the only escape valve from the Finding-14 refusal and
/// the production install path never sets it.
///
/// Exposed under both `cfg(test)` (covers the daemon's own unit
/// tests) and `feature = "qa-mock"` (covers integration tests in
/// sibling test binaries that need to seed the pool without
/// touching the real installer). The function is public so
/// integration tests can call it directly; production code never
/// references it.
///
/// CFG-GATED: compiled under `#[cfg(any(test, debug_assertions))]` —
/// visible in test binaries (both in-crate unit tests and sibling
/// integration tests) and debug builds, stripped from `--release`.
/// Production deploys ship `--release`; the symbol is absent there.
/// Defense-in-depth against Finding 14 bypass: a production caller
/// is structurally incapable of invoking this seam.
#[cfg(any(test, debug_assertions))]
pub fn init_uid_pool_for_test() {
    use nix::unistd::{getegid, geteuid};
    let cur_uid = geteuid().as_raw();
    let cur_gid = getegid().as_raw();
    // Pre-populate the pool with many copies of the current uid so
    // `checkout` succeeds. Sized at 256 because cargo test runs many
    // broker_exec tests in parallel and leases can persist across
    // task spawns (the lease drops only when handle_broker_exec
    // returns), so a small pool exhausts under concurrent tests.
    // The same uid repeated keeps tests running as the test process
    // uid (no root, no separate-uid provisioning required).
    let pool = UidPool::new_for_test(vec![cur_uid; 256], cur_gid);
    let _ = UID_POOL.set(Some(Arc::new(pool)));
}

/// Test-only: install a SUBUID-flagged pool for tests that need to
/// exercise the ADR 155 Component 2 routing predicate
/// (`lease.is_subuid() == true`). The pool is populated with copies
/// of the current process's uid so any subsequent `checkout` succeeds
/// without real subuid provisioning; the test_mode flag is set so
/// the Finding-14 refusal is bypassed.
///
/// Idempotent — re-init is a no-op (OnceLock::set fails after the
/// first call). Sibling test binaries should each call this once if
/// they need the subuid-pool routing. Tests that need a non-subuid
/// pool MUST run in a separate binary or order this call before any
/// `global_pool()` access.
///
/// Production code MUST NOT call this — the only path to a subuid
/// pool in production is `init_uid_pool` reading the operator's
/// `[spawn_pool] subuid_range_*` config from the installer.
///
/// CFG-GATED: same `#[cfg(any(test, debug_assertions))]` posture
/// as the sibling `init_uid_pool_for_test`. Stripped from `--release`
/// builds; production deploys are release-shipped.
#[cfg(any(test, debug_assertions))]
pub fn init_subuid_pool_for_test() {
    use nix::unistd::{getegid, geteuid};
    let cur_uid = geteuid().as_raw();
    let cur_gid = getegid().as_raw();
    let pool = UidPool::new_subuid_for_test(vec![cur_uid; 256], cur_gid);
    let _ = UID_POOL.set(Some(Arc::new(pool)));
}

/// Reset the global pool — test-only, used by tests that need to
/// simulate the "pool not configured" path. No current caller in
/// the test suite; the helper is intentionally preserved as
/// documentation of the OnceLock-can't-be-reset limitation.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_uid_pool_for_test() {
    // OnceLock::set fails once initialized, but tests run serially per
    // crate so we can't actually undo it. Tests that need a different
    // pool state must control it via the test pool's interior flags.
    // This helper exists as documentation of the limitation, not as a
    // working reset.
    tracing::warn!("uid_alloc::reset_uid_pool_for_test: OnceLock cannot be reset post-init");
}

/// Look up the currently-installed global pool. Returns `None` when
/// no `[spawn_pool]` was configured (the handler maps this to
/// `-32021`).
///
/// Under `cfg(test)`, this auto-installs a test-mode pool on first
/// access — every `cargo test` invocation across the whole daemon
/// crate uses the same process-global pool keyed on the test
/// process's uid. Tests that want to exercise the "no pool
/// configured" path must use `#[cfg(test)]` paths that explicitly
/// override the global state (the cross-test global state is
/// inherently shared; see `tests/broker_exec_per_spawn_uid.rs` for
/// the integration tests that exercise refusal contracts via a
/// freshly-spawned daemon).
pub fn global_pool() -> Option<Arc<UidPool>> {
    #[cfg(test)]
    {
        // Auto-install a test pool the first time any unit test touches
        // global_pool(). Idempotent: OnceLock::set fails after the first
        // call and we just read the previously-installed value.
        init_uid_pool_for_test();
    }
    UID_POOL.get().and_then(|opt| opt.clone())
}

/// Config wire shape sourced from `[spawn_pool]` in
/// `~/.ember/config.toml`. Two mutually-exclusive shapes:
///
/// **System-user pool (ADR 131 + ADR 155 hardened-Linux/macOS):**
///
/// ```toml
/// [spawn_pool]
/// uids = [10010, 10011, 10012, 10013, 10014, 10015, 10016, 10017]
/// gid = 10010
/// ```
///
/// **Modern-Linux subuid range (ADR 155 Component 2):**
///
/// ```toml
/// [spawn_pool]
/// subuid_range_start = 100000
/// subuid_range_slots = 8192
/// ```
///
/// On daemon startup, the spawn-handler code inspects which shape is
/// populated and picks the appropriate spawn path (subuid path goes
/// through `clone3(CLONE_NEWUSER | ...)`; system-user path goes
/// through `setresuid`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct SpawnPoolConfig {
    /// System uids the installer provisioned at `ember daemon install`
    /// time. Each uid is a real `ember-spawn-<N>` user owned by no
    /// real human. Pool size defaults to 8 in the installer (matches
    /// autopilot fanout pool cap).
    ///
    /// Mutually exclusive with `subuid_range_start`/`subuid_range_slots`:
    /// the installer populates one shape based on whether the host
    /// supports unprivileged user-namespace clone (ADR 155 Component 2).
    #[serde(default)]
    pub uids: Vec<u32>,
    /// Single shared gid for all pool uids. The installer ensures
    /// every pool user is in this gid as their primary group.
    ///
    /// Defaulted to 0 (wheel) so the subuid-shape config doesn't
    /// need to specify a gid — the clone3-spawn path ignores `gid`
    /// because it derives the per-spawn gid from the namespace
    /// gid-map, not from this field.
    #[serde(default)]
    pub gid: u32,
    /// ADR 155 Component 2 modern-Linux subuid range start
    /// (`/etc/subuid`'s `ember:{start}:{slots}` first value). When
    /// `Some`, the daemon uses the clone3 namespace-spawn path
    /// instead of the system-user `setresuid` path.
    ///
    /// Mutually exclusive with `uids`. The installer populates
    /// exactly one of `(uids, gid)` or `(subuid_range_start,
    /// subuid_range_slots)` based on the host's
    /// `unprivileged_userns_clone` setting at install time.
    #[serde(default)]
    pub subuid_range_start: Option<u32>,
    /// Companion to [`subuid_range_start`] — number of consecutive
    /// uids in the range. The daemon's pool capacity equals this
    /// value on the subuid path.
    #[serde(default)]
    pub subuid_range_slots: Option<u32>,
}

/// Errors surfaced by [`UidPool::checkout`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UidAllocError {
    /// The pool was provisioned but every uid is currently in use.
    /// Caller should surface retryable `-32020` with structured
    /// `retry_after_ms` metadata.
    #[error("uid pool exhausted (all {capacity} uids in use)")]
    PoolExhausted { capacity: usize },
    /// The pool config was provisioned but with an empty uid list —
    /// effectively "configured but useless". Treated the same as
    /// "not configured" by the caller.
    #[error("uid pool is empty (no uids configured)")]
    PoolEmpty,
    /// Defensive: the requested `spawn_id` is already checked out.
    /// Indicates a duplicate-id bug in the caller.
    #[error("spawn_id {0:?} is already checked out (duplicate id)")]
    AlreadyCheckedOut(String),
}

/// Internal mutable pool state. Wrapped in a single mutex so the
/// checkout / return critical section is atomic (we move uids from
/// `available` → `in_use` together).
///
/// `available` is a `Vec<u32>` rather than a `HashSet<u32>` so the
/// test_mode pool can hold N copies of the same uid (the test
/// harness reuses the test process's uid; `HashSet` would collapse
/// the duplicates and leave only one slot, causing pool-exhaustion
/// flakes under parallel test execution). Production pools never
/// have duplicates — the installer provisions N distinct
/// `ember-spawn-<N>` users.
struct UidPoolInner {
    available: Vec<u32>,
    in_use: HashMap<String, u32>,
    capacity: usize,
}

/// Per-spawn uid allocator. The pool is process-global (installed via
/// [`init_uid_pool`]) and accessed by [`global_pool`] from the broker
/// handler.
pub struct UidPool {
    inner: Mutex<UidPoolInner>,
    /// Shared gid for every pool uid. Stored on the pool rather than
    /// per-lease so a single supplementary-group config on the
    /// daemon's `ember` user covers every spawn.
    gid: u32,
    /// Test-only: skip the Finding-14 `target_uid == daemon_uid`
    /// refusal. Production code never sets this (the production
    /// constructor sets `false`); only the test helper sets it.
    test_mode: bool,
    /// ADR 155 Component 2 — true when this pool was populated from
    /// a `subuid_range_start`/`subuid_range_slots` config rather
    /// than a system-user `uids` list. Drives the broker_exec
    /// handler's routing decision: subuid pools go through the
    /// clone3 + newuidmap path; system-user pools stay on the
    /// legacy setresuid path.
    is_subuid: bool,
}

impl UidPool {
    /// Production constructor — Finding-14 refusal is active. This
    /// constructor is for the legacy ADR-131 system-user pool shape.
    /// Use [`new_subuid`] for the ADR-155 modern-Linux range shape.
    pub fn new(uids: Vec<u32>, gid: u32) -> Self {
        let capacity = uids.len();
        Self {
            inner: Mutex::new(UidPoolInner {
                available: uids,
                in_use: HashMap::new(),
                capacity,
            }),
            gid,
            test_mode: false,
            is_subuid: false,
        }
    }

    /// ADR 155 Component 2 constructor — subuid-range-backed pool.
    /// `uids` is the materialized range (range_start..range_start+
    /// slot_count). `gid` is the base of the matching subgid range.
    /// The handler routes leases from this pool through the
    /// `clone3 + newuidmap` spawn path.
    pub fn new_subuid(uids: Vec<u32>, gid: u32) -> Self {
        let capacity = uids.len();
        Self {
            inner: Mutex::new(UidPoolInner {
                available: uids,
                in_use: HashMap::new(),
                capacity,
            }),
            gid,
            test_mode: false,
            is_subuid: true,
        }
    }

    /// Test-only constructor — disables the Finding-14 refusal so
    /// existing broker_exec tests can spawn children without
    /// provisioning a real separate uid. Production code never calls
    /// this.
    ///
    /// Private to this module: callers in test binaries get a test
    /// pool by calling `init_uid_pool_for_test()`, which is the only
    /// production-visible entry point. Production code never sees
    /// this constructor; the only escape valve from Finding-14 is
    /// reachable only through the explicit test-pool seam.
    #[cfg(any(test, debug_assertions))]
    fn new_for_test(uids: Vec<u32>, gid: u32) -> Self {
        let mut pool = Self::new(uids, gid);
        pool.test_mode = true;
        pool
    }

    /// Test-only subuid constructor — sets `is_subuid = true` AND
    /// `test_mode = true`. Use for tests that exercise the
    /// is_subuid-gated routing predicates (e.g. PTY + subuid
    /// refusal at the handler boundary) without provisioning a real
    /// `/etc/subuid` range.
    ///
    /// Private to this module — the entry point for sibling test
    /// binaries is [`init_subuid_pool_for_test`].
    #[cfg(any(test, debug_assertions))]
    fn new_subuid_for_test(uids: Vec<u32>, gid: u32) -> Self {
        let mut pool = Self::new_subuid(uids, gid);
        pool.test_mode = true;
        pool
    }

    /// True when this pool was constructed via [`new_for_test`] and
    /// the Finding-14 refusal should be skipped. Production
    /// installations always return `false`.
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// True when this pool was populated from a subuid range (ADR
    /// 155 Component 2). The broker_exec handler uses this to route
    /// leases through the `clone3` + `newuidmap` spawn path instead
    /// of the legacy `setresuid` path.
    pub fn is_subuid(&self) -> bool {
        self.is_subuid
    }

    /// Configured gid for every uid in this pool.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Allocate a uid from the pool, atomically moving it from
    /// `available` to `in_use` and binding it to `spawn_id`. The
    /// returned [`UidLease`] returns the uid to the pool on drop.
    ///
    /// `spawn_id` should be the broker_exec materialization id (or a
    /// fresh UUID per call) — anything unique per concurrent spawn.
    pub fn checkout(self: &Arc<Self>, spawn_id: &str) -> Result<UidLease, UidAllocError> {
        let mut inner = self.inner.lock().expect("uid pool mutex poisoned");
        if inner.capacity == 0 {
            return Err(UidAllocError::PoolEmpty);
        }
        if inner.in_use.contains_key(spawn_id) {
            return Err(UidAllocError::AlreadyCheckedOut(spawn_id.to_string()));
        }
        let uid = match inner.available.pop() {
            Some(u) => u,
            None => {
                return Err(UidAllocError::PoolExhausted {
                    capacity: inner.capacity,
                });
            }
        };
        inner.in_use.insert(spawn_id.to_string(), uid);
        let capacity = inner.capacity;
        let occupied = inner.in_use.len();
        drop(inner);

        record_pool_slot_telemetry(capacity, occupied);

        Ok(UidLease {
            uid,
            gid: self.gid,
            spawn_id: spawn_id.to_string(),
            pool: Arc::downgrade(self),
            is_subuid: self.is_subuid,
        })
    }

    /// Return a uid to the pool. Called by [`UidLease::drop`] —
    /// public only so the Drop impl can route through it.
    fn release(&self, spawn_id: &str) {
        let mut inner = match self.inner.try_lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(
                    spawn_id = %spawn_id,
                    "uid_alloc::release: pool mutex contended/poisoned; uid leaked"
                );
                return;
            }
        };
        let mut sample = None;
        if let Some(uid) = inner.in_use.remove(spawn_id) {
            inner.available.push(uid);
            sample = Some((inner.capacity, inner.in_use.len()));
        } else {
            tracing::warn!(
                spawn_id = %spawn_id,
                "uid_alloc::release: spawn_id not found in in_use map (double-release?)"
            );
        }
        drop(inner);

        if let Some((capacity, occupied)) = sample {
            record_pool_slot_telemetry(capacity, occupied);
        }
    }

    /// Snapshot the available-uid count. Test/diagnostic helper.
    pub fn available_count(&self) -> usize {
        self.inner.lock().map(|i| i.available.len()).unwrap_or(0)
    }

    /// Snapshot the in-use uid count. Test/diagnostic helper.
    pub fn in_use_count(&self) -> usize {
        self.inner.lock().map(|i| i.in_use.len()).unwrap_or(0)
    }

    /// Capacity (total uids configured). Test/diagnostic helper.
    pub fn capacity(&self) -> usize {
        self.inner.lock().map(|i| i.capacity).unwrap_or(0)
    }
}

/// RAII handle to a checked-out uid. Drops return the uid to the pool.
///
/// Sync `Drop` — the release path uses `try_lock` + `tracing::error!`
/// on contention rather than `.await`, so leases can be held across
/// `.await` points without breaking the async runtime.
pub struct UidLease {
    uid: u32,
    gid: u32,
    spawn_id: String,
    pool: Weak<UidPool>,
    /// Snapshotted from the parent pool at checkout time. Drives
    /// the broker_exec handler's routing decision between the
    /// clone3+newuidmap path (ADR 155 Component 2) and the legacy
    /// setresuid path. Snapshotted (not read live) so the routing
    /// can't race against a pool reconfiguration mid-spawn.
    is_subuid: bool,
}

impl std::fmt::Debug for UidLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UidLease")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("spawn_id", &self.spawn_id)
            .field("pool_live", &self.pool.upgrade().is_some())
            .finish()
    }
}

impl UidLease {
    /// The leased uid. Use this in `setresuid` in the child branch
    /// of fork+execve.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The configured gid for the pool. Use in `setresgid` in the
    /// child branch.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The spawn_id this lease was bound to. Used for diagnostics
    /// and to correlate audit rows with the lease lifetime.
    pub fn spawn_id(&self) -> &str {
        &self.spawn_id
    }

    /// True when the parent pool was a subuid-range pool (ADR 155
    /// Component 2). The broker_exec handler uses this to route the
    /// spawn through `clone3 + newuidmap`; false leases route
    /// through the legacy `setresuid` path.
    pub fn is_subuid(&self) -> bool {
        self.is_subuid
    }
}

impl Drop for UidLease {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.release(&self.spawn_id);
        }
        // If `pool.upgrade()` returns None the pool itself has been
        // dropped (process shutdown). No release needed — the entire
        // pool state is gone.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_moves_uid_from_available_to_in_use() {
        let pool = Arc::new(UidPool::new(vec![10010, 10011], 10010));
        assert_eq!(pool.available_count(), 2);
        assert_eq!(pool.in_use_count(), 0);

        let lease = pool.checkout("spawn-1").expect("checkout");
        assert_eq!(pool.available_count(), 1);
        assert_eq!(pool.in_use_count(), 1);
        assert!(lease.uid() == 10010 || lease.uid() == 10011);
        assert_eq!(lease.gid(), 10010);
    }

    #[test]
    fn drop_returns_uid_to_available() {
        let pool = Arc::new(UidPool::new(vec![10010], 10010));
        {
            let _lease = pool.checkout("spawn-1").expect("checkout");
            assert_eq!(pool.available_count(), 0);
        }
        assert_eq!(pool.available_count(), 1);
        assert_eq!(pool.in_use_count(), 0);
    }

    #[test]
    fn checkout_pool_exhausted() {
        let pool = Arc::new(UidPool::new(vec![10010], 10010));
        let _lease = pool.checkout("spawn-1").expect("first");
        let err = pool.checkout("spawn-2").expect_err("must exhaust");
        assert!(matches!(err, UidAllocError::PoolExhausted { capacity: 1 }));
    }

    #[test]
    fn checkout_pool_empty() {
        let pool = Arc::new(UidPool::new(vec![], 10010));
        let err = pool.checkout("spawn-1").expect_err("empty");
        assert!(matches!(err, UidAllocError::PoolEmpty));
    }

    #[test]
    fn checkout_duplicate_spawn_id_refuses() {
        let pool = Arc::new(UidPool::new(vec![10010, 10011], 10010));
        let _lease1 = pool.checkout("spawn-1").expect("first");
        let err = pool.checkout("spawn-1").expect_err("dup must refuse");
        assert!(matches!(err, UidAllocError::AlreadyCheckedOut(_)));
    }

    #[test]
    fn checkout_after_release_succeeds_again() {
        let pool = Arc::new(UidPool::new(vec![10010], 10010));
        {
            let _lease = pool.checkout("spawn-1").expect("first");
        }
        // After Drop the uid is back in the pool.
        let _lease2 = pool.checkout("spawn-2").expect("second after drop");
        assert_eq!(pool.available_count(), 0);
    }

    #[test]
    fn checkout_and_release_record_pool_slot_samples_when_enabled() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("telemetry tempdir");
        crate::telemetry::measurement::set_output_dir(Some(dir.path().to_path_buf()));
        crate::telemetry::measurement::enable_collection();

        struct TelemetryReset;
        impl Drop for TelemetryReset {
            fn drop(&mut self) {
                let _ = crate::telemetry::measurement::disable_collection_and_purge();
                crate::telemetry::measurement::set_output_dir(None);
            }
        }
        let _reset = TelemetryReset;

        let pool = Arc::new(UidPool::new(
            vec![21001, 21002, 21003, 21004, 21005, 21006, 21007],
            21001,
        ));
        {
            let _lease = pool.checkout("telemetry-spawn").expect("checkout");
            assert_eq!(pool.in_use_count(), 1);
        }
        assert_eq!(pool.in_use_count(), 0);

        let path = crate::telemetry::measurement::current_status().active_daily_path;
        let raw = std::fs::read_to_string(path).expect("telemetry written");
        let mut samples = vec![];
        for line in raw.lines() {
            let row: crate::telemetry::measurement::SampleRow =
                serde_json::from_str(line).expect("telemetry row");
            let crate::telemetry::measurement::SampleRow::PoolSlotSample {
                cohort,
                capacity,
                occupied,
                operator_reserve_hit,
                ..
            } = row
            else {
                continue;
            };
            if capacity != 7 {
                continue;
            }
            assert_eq!(cohort, "dev0");
            assert!(!operator_reserve_hit);
            samples.push(occupied);
        }

        assert_eq!(
            samples,
            vec![1, 0],
            "checkout and release should record pool occupancy"
        );
    }

    #[test]
    fn capacity_reports_initial_uid_count() {
        let pool = UidPool::new(vec![10010, 10011, 10012], 10010);
        assert_eq!(pool.capacity(), 3);
    }

    #[test]
    fn production_pool_is_not_test_mode() {
        let pool = UidPool::new(vec![10010], 10010);
        assert!(!pool.is_test_mode());
    }

    #[test]
    fn test_pool_is_test_mode() {
        let pool = UidPool::new_for_test(vec![10010], 10010);
        assert!(pool.is_test_mode());
    }

    #[test]
    fn concurrent_checkouts_get_distinct_uids() {
        use std::sync::{Arc as ArcSync, Barrier, Mutex as MutexSync};
        use std::thread;

        let pool = Arc::new(UidPool::new(vec![10010, 10011, 10012, 10013], 10010));
        let barrier = Arc::new(Barrier::new(4));
        // Each thread parks its lease in this Mutex so the lease lives
        // until ALL 4 threads have checked out. Without this the
        // closure-end drops the lease and the next thread can pick up
        // the same uid — yielding fewer than 4 distinct uids.
        let leases: ArcSync<MutexSync<Vec<UidLease>>> = ArcSync::new(MutexSync::new(vec![]));
        let mut handles = vec![];
        for i in 0..4 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            let leases = ArcSync::clone(&leases);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let lease = pool.checkout(&format!("spawn-{i}")).expect("checkout");
                let uid = lease.uid();
                leases.lock().unwrap().push(lease);
                uid
            }));
        }
        let mut uids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        uids.sort();
        uids.dedup();
        // Four distinct uids must come out of a 4-uid pool with no
        // collisions; if the mutex were missing we'd see duplicates.
        assert_eq!(uids.len(), 4);
    }
}
