//! UX2-BUDGET-FLAGS-DROPPED regression coverage.
//!
//! Pre-fix the simple-grant CLI path called `store.create_grant(...)` (which
//! built the canonical block-zero statement with `budget = None`) and then
//! UPDATE'd the flat `budget_json` column. But `row_to_grant` projects
//! `GrantInfo.budget` from the signed chain's first-statement budget when
//! present, so the chain shadowed the UPDATE and `--budget-tokens`,
//! `--budget-usd`, `--budget-requests`, `--budget-seconds` were all silently
//! dropped on read — including in `/api/grants`, which the landing page's
//! "live budget meter" promise depends on.
//!
//! Post-fix the CLI now routes through `create_grant_with_budget`, which
//! threads the supplied `Budget` into block-zero's statement at mint time.
//! The dashboard `/api/grants` handler additionally surfaces the projected
//! `budget` + `usage` so the dashboard BUDGET column has data to render.
//!
//! These tests pin both halves of the contract:
//!
//!   1. `create_grant_with_budget` round-trip: all 4 budget axes survive
//!      `get_grant` and `list_active_grants` reads.
//!   2. `GET /api/grants` JSON: a grant minted with all 4 axes shows up
//!      with `budget: { tokens, cents, requests, wall_clock_secs }` and a
//!      zeroed `usage`. A grant minted WITHOUT any budget axes must NOT
//!      carry a `budget` key — backwards-compat for existing consumers
//!      and clean serialization on the wire.

use std::rc::Rc;
use std::time::Duration;

use core_grant_types::Budget;
use ember_daemon::infra::dashboard::run_dashboard;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

/// Deterministic vault key for these tests. Stable across the binary so the
/// persona-secret encrypt/decrypt round-trips.
const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

fn store_with_vault(db_path: &std::path::Path) -> DaemonStore {
    let store = DaemonStore::open(db_path).expect("open daemon store");
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    store
}

#[test]
fn budget_persists_on_simple_grant_round_trip() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");
    let store = store_with_vault(&db_path);

    let persona = store
        .create_persona("agent-budget-roundtrip")
        .expect("create_persona");

    let budget = Budget {
        tokens: Some(50_000),
        cents: Some(50),
        requests: Some(100),
        wall_clock_secs: Some(3_600),
        ..Budget::default()
    };

    let info = store
        .create_grant_with_budget(
            &persona.id,
            "anthropic-key",
            "llm:generate",
            Some(3_600),
            Some(budget.clone()),
        )
        .expect("create_grant_with_budget");

    // GrantInfo shape: budget projection is non-empty.
    let projected = info.budget.as_ref().expect("budget projected from chain");
    assert_eq!(projected.tokens, Some(50_000));
    assert_eq!(projected.cents, Some(50));
    assert_eq!(projected.requests, Some(100));
    assert_eq!(projected.wall_clock_secs, Some(3_600));

    // Round-trip via `get_grant` — the read path that the dashboard,
    // `ember grant show`, and the proxy all share.
    let fetched = store.get_grant(&info.id).expect("get_grant");
    let projected = fetched.budget.as_ref().expect("budget round-trips");
    assert_eq!(projected.tokens, Some(50_000));
    assert_eq!(projected.cents, Some(50));
    assert_eq!(projected.requests, Some(100));
    assert_eq!(projected.wall_clock_secs, Some(3_600));

    // Round-trip via `list_active_grants` — the read path used by
    // `/api/grants`.
    let active = store
        .list_active_grants()
        .expect("list_active_grants")
        .into_iter()
        .find(|g| g.id == info.id)
        .expect("created grant must appear in active list");
    let projected = active.budget.as_ref().expect("budget on list_active read");
    assert_eq!(projected.tokens, Some(50_000));
    assert_eq!(projected.cents, Some(50));
    assert_eq!(projected.requests, Some(100));
    assert_eq!(projected.wall_clock_secs, Some(3_600));

    // Usage starts zero on a freshly minted grant; the projection must
    // reflect that (no None defaulted into bogus values).
    assert_eq!(active.usage.tokens, 0);
    assert_eq!(active.usage.cents, 0);
    assert_eq!(active.usage.requests, 0);
    assert_eq!(active.usage.wall_clock_secs, 0);
}

/// A grant minted with no budget axes must round-trip with `budget = None`,
/// so existing CLI/SDK/test consumers that key on `Option::is_none()` keep
/// working. This pins the back-compat half of the fix.
#[test]
fn no_budget_grant_round_trips_as_none() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");
    let store = store_with_vault(&db_path);

    let persona = store
        .create_persona("agent-budget-none")
        .expect("create_persona");

    let info = store
        .create_grant(&persona.id, "github-token", "repo:read", Some(3_600))
        .expect("create_grant (no budget)");

    assert!(info.budget.is_none(), "no-budget grant projects None");

    let fetched = store.get_grant(&info.id).expect("get_grant");
    assert!(
        fetched.budget.is_none(),
        "no-budget grant round-trips as None on get_grant"
    );
}

/// `GET /api/grants` MUST surface `budget` + `usage` on a grant minted with
/// all 4 axes. The landing page's live-budget-meter promise rests on the
/// dashboard JS reading these fields. A grant without budgets must NOT
/// include the `budget` key at all (cleanliness + back-compat).
#[tokio::test]
async fn api_grants_includes_budget_when_set() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");

    // 1. Pre-seed the DB with two grants: one with full budget, one without.
    let with_budget_id;
    let without_budget_id;
    {
        let store = store_with_vault(&db_path);
        let persona = store.create_persona("agent-budget-api").expect("persona");

        let with_budget = store
            .create_grant_with_budget(
                &persona.id,
                "anthropic-key",
                "llm:generate",
                Some(3_600),
                Some(Budget {
                    tokens: Some(50_000),
                    cents: Some(50),
                    requests: Some(100),
                    wall_clock_secs: Some(3_600),
                    ..Budget::default()
                }),
            )
            .expect("with-budget grant");
        with_budget_id = with_budget.id;

        let without_budget = store
            .create_grant(&persona.id, "github-token", "repo:read", Some(3_600))
            .expect("no-budget grant");
        without_budget_id = without_budget.id;
    } // Drop store before run_dashboard re-opens the DB.

    // 2. Let run_dashboard own the ephemeral bind to avoid nextest port races.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (bind_tx, bind_rx) = oneshot::channel();
    let requested_addr = "127.0.0.1:0".parse().expect("loopback addr");
    let db = db_path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &rt,
            run_dashboard(
                requested_addr,
                db,
                "0.0.0-test".to_string(),
                None,
                shutdown_rx,
                Some(bind_tx),
            ),
        );
    });
    let addr = tokio::time::timeout(Duration::from_secs(2), bind_rx)
        .await
        .expect("dashboard bind timed out")
        .expect("dashboard bind channel closed")
        .expect("dashboard bind failed");

    // 3. GET /api/grants and parse the JSON body.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/grants HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = std::str::from_utf8(&response).unwrap();
    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "expected 200 OK, got: {}",
        &response_str[..response_str.len().min(120)]
    );
    // Body is everything after the "\r\n\r\n" separator.
    let body_start = response_str.find("\r\n\r\n").expect("CRLF body separator") + 4;
    let body = &response_str[body_start..];
    let json: serde_json::Value = serde_json::from_str(body).expect("api response is valid JSON");
    let arr = json.as_array().expect("api response is JSON array");

    let with = arr
        .iter()
        .find(|g| g["id"] == serde_json::json!(with_budget_id))
        .expect("with-budget grant present in /api/grants");
    let without = arr
        .iter()
        .find(|g| g["id"] == serde_json::json!(without_budget_id))
        .expect("no-budget grant present in /api/grants");

    // 4. With-budget assertions: every axis surfaced with the supplied value.
    let budget = &with["budget"];
    assert!(
        budget.is_object(),
        "budget must be a JSON object, got: {budget}"
    );
    assert_eq!(budget["tokens"], serde_json::json!(50_000));
    assert_eq!(budget["cents"], serde_json::json!(50));
    assert_eq!(budget["requests"], serde_json::json!(100));
    assert_eq!(budget["wall_clock_secs"], serde_json::json!(3_600));

    // Usage must be present and zeroed for a freshly minted grant.
    let usage = &with["usage"];
    assert!(
        usage.is_object(),
        "usage must be a JSON object, got: {usage}"
    );
    assert_eq!(usage["tokens"], serde_json::json!(0));
    assert_eq!(usage["cents"], serde_json::json!(0));
    assert_eq!(usage["requests"], serde_json::json!(0));
    assert_eq!(usage["wall_clock_secs"], serde_json::json!(0));

    // 5. No-budget assertion: NO `budget` key at all (back-compat).
    assert!(
        without.get("budget").is_none(),
        "no-budget grant must omit the `budget` key, got: {without}"
    );
    assert!(
        without.get("usage").is_none(),
        "no-budget grant must omit the `usage` key, got: {without}"
    );

    shutdown_tx.send(true).unwrap();
}
