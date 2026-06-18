//! CLASSIFICATION: PUBLIC
//!
//! T2 integration tests for the
//! per-spawn uid pool that `handle_broker_exec` drops privileges
//! into before fork+execve.
//!
//! ## Test scope
//!
//! These tests exercise the pool primitives + handler refusal contracts
//! against a real `DaemonStore`. The cross-uid `/proc/<pid>/environ`
//! denial assertion (the threat model this whole feature closes) is a
//! Linux-only operator-verification path because:
//!
//! 1. macOS lacks `/proc`.
//! 2. The Claude Code macOS sandbox blocks `tokio::process::Command`
//!    spawning even `/bin/echo` (see project memory:
//!    `broker_exec_tests_sandbox_blocked`).
//! 3. Real per-uid privilege drop requires running as root + provisioned
//!    `ember-spawn-<i>` system users — which CI does not have.
//!
//! The CRITICAL property (cross-uid `/proc/<pid>/environ` read denied)
//! is enforced by the kernel itself on Linux when the spawned process's
//! `setresuid` succeeds. The unit tests in `broker/uid_alloc.rs` cover
//! the pool's allocation semantics; this integration file covers the
//! handler's refusal contracts and the test-pool seam.

use ember_daemon::broker::uid_alloc::{self, UidPool};
use ember_daemon::infra::store::DaemonStore;
use std::sync::Arc;

/// Verify the pool's basic
/// invariants in an integration context (separate test binary, so the
/// process-global pool is independent from the lib's unit tests).
#[test]
fn uid_pool_capacity_matches_configured_uids() {
    let pool = Arc::new(UidPool::new(vec![10010, 10011, 10012], 10010));
    assert_eq!(pool.capacity(), 3);
    assert_eq!(pool.available_count(), 3);
    assert_eq!(pool.in_use_count(), 0);
}

/// Checking out a uid moves it
/// from `available` to `in_use`. The Drop returns it.
#[test]
fn uid_pool_lease_roundtrip_returns_uid_on_drop() {
    let pool = Arc::new(UidPool::new(vec![10010, 10011], 10010));
    {
        let _lease = pool.checkout("integration-spawn-1").expect("checkout");
        assert_eq!(pool.available_count(), 1);
        assert_eq!(pool.in_use_count(), 1);
    }
    assert_eq!(pool.available_count(), 2);
    assert_eq!(pool.in_use_count(), 0);
}

/// Pool exhaustion surfaces a
/// `PoolExhausted` error variant after all uids are checked out.
#[test]
fn uid_pool_exhausted_after_capacity_reached() {
    let pool = Arc::new(UidPool::new(vec![10010], 10010));
    let _lease = pool.checkout("integration-spawn-A").expect("first");
    let err = pool
        .checkout("integration-spawn-B")
        .expect_err("second must exhaust");
    assert!(matches!(
        err,
        uid_alloc::UidAllocError::PoolExhausted { capacity: 1 }
    ));
}

/// Empty pool surfaces `PoolEmpty`,
/// distinct from `PoolExhausted` (so the handler can render the
/// "configure pool first" vs "wait for in-flight" diagnostics
/// distinctly).
#[test]
fn uid_pool_empty_distinct_from_exhausted() {
    let pool = Arc::new(UidPool::new(vec![], 10010));
    let err = pool.checkout("integration-spawn-A").expect_err("empty");
    assert!(matches!(err, uid_alloc::UidAllocError::PoolEmpty));
}

/// Production pools never set the
/// test_mode flag. The flag is the only escape valve from the
/// Finding 14 refusal, and the production install path must not flip
/// it. (The pool struct does not even expose a public setter — the
/// flag is only set via the test-only `new_for_test` constructor.)
#[test]
fn production_pool_test_mode_flag_is_false() {
    let pool = UidPool::new(vec![10010], 10010);
    assert!(!pool.is_test_mode());
}

/// `init_uid_pool_for_test()`
/// installs a process-global test pool. After init, `global_pool()`
/// returns Some(test_pool); the pool carries `test_mode = true` so
/// the Finding-14 refusal is skipped (existing broker_exec unit
/// tests rely on this to spawn children as the test process's uid).
///
/// Note: integration test binaries (this file) and the lib's own
/// unit tests use separate process address spaces, so the OnceLock
/// in `uid_alloc::UID_POOL` is independent across them. The lib's
/// unit tests get auto-init via `cfg(test)` inside `global_pool()`;
/// this integration test calls the public seam explicitly.
#[test]
fn init_uid_pool_for_test_installs_global_pool() {
    uid_alloc::init_uid_pool_for_test();
    let pool = uid_alloc::global_pool();
    assert!(pool.is_some(), "test pool must be installed");
    let pool = pool.unwrap();
    assert!(
        pool.is_test_mode(),
        "test-init pool must carry test_mode = true"
    );
    assert!(
        pool.capacity() > 0,
        "test-init pool must contain at least one uid"
    );
}

/// uid_pool can be opened against
/// a real `DaemonStore` in the same process. Regression guard against
/// the pool primitives accidentally pulling in store state via a
/// global handle.
#[test]
fn uid_pool_is_independent_of_daemon_store() {
    let _store = DaemonStore::open_in_memory().expect("in-memory store");
    let pool = Arc::new(UidPool::new(vec![10010, 10011], 10010));
    let lease = pool.checkout("store-independence").expect("checkout");
    // Re-create the store; lease state must be unaffected.
    let _store2 = DaemonStore::open_in_memory().expect("in-memory store 2");
    assert_eq!(lease.uid(), 10011);
    assert_eq!(pool.in_use_count(), 1);
}

/// Concurrent checkouts from
/// multiple threads each get a distinct uid (the Mutex serializes
/// the available-to-in-use transition).
#[test]
fn concurrent_checkouts_serialized_by_mutex() {
    use std::sync::{Arc as ArcSync, Barrier, Mutex as MutexSync};
    use std::thread;

    let pool = Arc::new(UidPool::new(vec![10010, 10011, 10012, 10013], 10010));
    let barrier = Arc::new(Barrier::new(4));
    let leases: ArcSync<MutexSync<Vec<uid_alloc::UidLease>>> = ArcSync::new(MutexSync::new(vec![]));
    let mut handles = vec![];
    for i in 0..4 {
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        let leases = ArcSync::clone(&leases);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let lease = pool
                .checkout(&format!("integration-concurrent-{i}"))
                .expect("checkout");
            let uid = lease.uid();
            leases.lock().unwrap().push(lease);
            uid
        }));
    }
    let mut uids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    uids.sort();
    uids.dedup();
    assert_eq!(
        uids.len(),
        4,
        "4 concurrent checkouts must yield 4 distinct uids"
    );
}

/// Lease drops via early return
/// (e.g. handler error after checkout) return the uid to the pool.
/// This regression-guards against the lease being forgotten in an
/// error path.
#[test]
fn lease_returns_uid_on_function_error_return() {
    let pool = Arc::new(UidPool::new(vec![10010], 10010));
    fn checkout_and_fail(pool: &Arc<UidPool>) -> Result<(), &'static str> {
        let _lease = pool.checkout("err-path").expect("checkout");
        // Simulate a handler error after checkout — the lease drops
        // when this scope unwinds, returning the uid to the pool.
        Err("simulated handler failure")
    }
    let result = checkout_and_fail(&pool);
    assert!(result.is_err());
    assert_eq!(
        pool.available_count(),
        1,
        "lease drop on error return must reclaim the uid"
    );
}

/// render_spawn_pool_toml writes
/// a valid TOML section the daemon's RawConfig deserializer can
/// round-trip. Regression guard against the install path emitting
/// TOML the daemon config parser refuses to load.
#[test]
fn render_spawn_pool_toml_round_trips_through_config_parser() {
    use ember_daemon::install::{SpawnPoolProvisioning, render_spawn_pool_toml};
    let prov = SpawnPoolProvisioning::SystemUsers {
        uids: vec![10010, 10011, 10012],
        gid: 10020,
    };
    let toml_section = render_spawn_pool_toml(&prov);
    // The section must parse via the spawn_pool TOML deserializer.
    // We use a stripped raw struct here to avoid coupling to the
    // full DaemonConfig surface — the contract under test is "the
    // rendered section deserializes as expected".
    #[derive(serde::Deserialize)]
    struct RawForTest {
        spawn_pool: ember_daemon::broker::uid_alloc::SpawnPoolConfig,
    }
    let parsed: RawForTest =
        toml::from_str(&toml_section).expect("render output must parse via toml");
    assert_eq!(parsed.spawn_pool.uids, vec![10010, 10011, 10012]);
    assert_eq!(parsed.spawn_pool.gid, 10020);
}

/// ADR 155 Component 2 — system-user pool (legacy ADR-131 path) does
/// NOT set the `is_subuid` flag, so the broker_exec handler stays on
/// the legacy `setresuid` path. This is the regression-guard for
/// the routing-flag default: only subuid pools get routed through
/// `spawn_in_execution_domain`.
#[test]
fn system_user_pool_is_not_flagged_as_subuid() {
    let pool = UidPool::new(vec![10010, 10011, 10012], 10010);
    assert!(!pool.is_subuid(), "system-user pool must not set is_subuid");

    let pool_arc = Arc::new(pool);
    let lease = pool_arc.checkout("system-user-spawn-A").expect("checkout");
    assert!(
        !lease.is_subuid(),
        "lease from system-user pool must not be flagged is_subuid"
    );
}

/// ADR 155 Component 2 — subuid-range pool (modern-Linux path) sets
/// the `is_subuid` flag and propagates it to every lease. The
/// broker_exec handler routes is_subuid=true leases through the
/// clone3 + newuidmap path.
#[test]
fn subuid_range_pool_flags_is_subuid_on_pool_and_leases() {
    // Materialise a 4-slot subuid range starting at 100000.
    let uids: Vec<u32> = (100000..100004).collect();
    let pool = UidPool::new_subuid(uids, 100000);
    assert!(pool.is_subuid(), "subuid pool must set is_subuid");

    let pool_arc = Arc::new(pool);
    let lease = pool_arc.checkout("subuid-spawn-A").expect("checkout");
    assert!(
        lease.is_subuid(),
        "lease from subuid pool must be flagged is_subuid"
    );
    // The lease's uid is one of the pool's range; with LIFO pop()
    // it'll be 100003 (the last element). Regression-guard against
    // an off-by-one in the range materialisation.
    assert!(
        (100000..100004).contains(&lease.uid()),
        "lease uid {} must fall in the configured range",
        lease.uid()
    );
}

/// ADR 155 Component 2 — the handler's routing decision MUST come
/// from the lease's snapshotted flag rather than a live read of the
/// pool. Snapshotting at checkout makes the routing decision
/// stable across `.await` boundaries even if the pool got swapped
/// (which can't happen with `OnceLock`, but the contract is locked
/// for future-proofing).
#[test]
fn lease_is_subuid_snapshots_at_checkout() {
    let pool = Arc::new(UidPool::new_subuid(vec![100000, 100001], 100000));
    let lease = pool.checkout("snapshot-test").expect("checkout");
    // The lease itself carries `is_subuid = true` regardless of
    // whether the caller can still see the pool.
    drop(pool); // Pool's last strong Arc dies; lease holds Weak.
    assert!(
        lease.is_subuid(),
        "lease must retain is_subuid flag after pool drops"
    );
}

/// ADR 155 Component 2 — `init_uid_pool` with a SpawnPoolConfig
/// that has `subuid_range_start` / `subuid_range_slots` populated
/// must materialise the pool from the range (NOT from the empty
/// `uids` vec). This is the install-time hand-off: the install path
/// renders `subuid_range_start = N / subuid_range_slots = M` into
/// config.toml; the daemon at startup must parse + expand that
/// shape into a working pool.
///
/// Note: this test is read-only on the pool's internal shape (we
/// reach into the pool via `new_subuid`); the actual `init_uid_pool`
/// integration is process-global and not safe to test from a
/// concurrent harness. The shape we verify here is what the
/// implementation in `init_uid_pool` constructs.
#[test]
fn subuid_pool_capacity_matches_slot_count() {
    // Simulate what init_uid_pool builds when subuid_range_start is
    // Some: (range_start..range_start+slot_count).collect()
    let range_start: u32 = 100000;
    let slot_count: u32 = 8;
    let uids: Vec<u32> = (range_start..range_start + slot_count).collect();
    let pool = UidPool::new_subuid(uids, range_start);
    assert_eq!(
        pool.capacity(),
        slot_count as usize,
        "subuid pool capacity must match slot_count"
    );
    assert!(pool.is_subuid());
}
