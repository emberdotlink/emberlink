use std::cell::RefCell;
use std::time::Duration;

use bytes::Bytes;
use ember_daemon::auth::presence_token::{DaemonSigner, PresenceToken, ScopeKey, mint};
use ember_daemon::infra::handler::{
    DispatchSource, PeerCred, RequestContext, dispatch_method_with_context,
};
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::receipt::{self, DaemonPersona};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::PolicyEngine;
use serde_json::{Value, json};

struct CurrentIdentitySigner(&'static DaemonPersona);

impl DaemonSigner for CurrentIdentitySigner {
    fn sign(&self, msg: &[u8]) -> Bytes {
        Bytes::copy_from_slice(&*self.0.sign(msg))
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::try_from(sig) else {
            return false;
        };
        ed25519_dalek::Verifier::verify(self.0.verifying_key(), msg, &signature).is_ok()
    }
}

fn ensure_identity() -> &'static DaemonPersona {
    if receipt::current_identity().is_none() {
        let dir = tempfile::tempdir().expect("daemon identity tempdir");
        receipt::init_identity(dir.path()).expect("init daemon identity");
        std::mem::forget(dir);
    }
    receipt::current_identity().expect("daemon identity initialized")
}

fn presence_token(uid: u32, scope: ScopeKey, ttl: Duration) -> PresenceToken {
    let signer = CurrentIdentitySigner(ensure_identity());
    mint(uid, scope, ttl, &signer)
}

fn socket_ctx(uid: u32, token: Option<PresenceToken>) -> RequestContext {
    RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid,
            pid: Some(24_601),
        }),
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: token,
        bypass_binary_pin_gate_for_test: false,
    }
}

async fn dispatch(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    ctx: RequestContext,
    method: &str,
    params: Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        None,
        ctx,
        method,
        &params,
    )
    .await
}

// T2 integration coverage for META-AP-DAEMON-PER-METHOD-AUTHORITY-FIXED:
// per-method authority resolution admits ConnectOnly with peer creds, and binds
// OperatorPresence tokens to uid + expiry + method scope before dispatching.
#[tokio::test]
async fn per_method_authority_binds_operator_presence_token_to_uid_expiry_and_method() {
    let _presence_guard = ember_daemon::trust::presence::test_state_guard();
    ember_daemon::trust::presence::reset_for_tests();
    ensure_identity();

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let vault = Vault::new([42u8; 32]);
    let policy = PolicyEngine::default();
    let rate_limiter = RefCell::new(RateLimiter::default());

    let ping = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(501, None),
        "ping",
        Value::Null,
    )
    .await
    .expect("ConnectOnly ping should not require a presence token");
    assert_eq!(ping, json!({"pong": true}));

    ember_daemon::trust::presence::lock();
    let missing = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(501, None),
        "grant_summary",
        json!({}),
    )
    .await
    .expect_err("locked OperatorPresence method without token must fail");
    assert_eq!(missing.0, -32001);
    assert!(missing.1.contains("locked"), "got {missing:?}");

    ember_daemon::trust::presence::mark_unlocked();
    let wrong_uid = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(
            501,
            Some(presence_token(
                777,
                ScopeKey::new("grant_summary"),
                Duration::from_secs(60),
            )),
        ),
        "grant_summary",
        json!({}),
    )
    .await
    .expect_err("presence token minted for another uid must fail");
    assert_eq!(wrong_uid.0, -32001);
    assert!(wrong_uid.1.contains("uid-mismatch"), "got {wrong_uid:?}");

    let expired = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(
            501,
            Some(presence_token(
                501,
                ScopeKey::new("grant_summary"),
                Duration::ZERO,
            )),
        ),
        "grant_summary",
        json!({}),
    )
    .await
    .expect_err("expired presence token must fail");
    assert_eq!(expired.0, -32001);
    assert!(expired.1.contains("expired"), "got {expired:?}");

    let wrong_scope = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(
            501,
            Some(presence_token(
                501,
                ScopeKey::new("vault_unlock"),
                Duration::from_secs(60),
            )),
        ),
        "grant_summary",
        json!({}),
    )
    .await
    .expect_err("presence token for another method must fail");
    assert_eq!(wrong_scope.0, -32001);
    assert!(
        wrong_scope.1.contains("scope-mismatch"),
        "got {wrong_scope:?}"
    );

    let created = dispatch(
        &store,
        &vault,
        &policy,
        &rate_limiter,
        socket_ctx(
            501,
            Some(presence_token(
                501,
                ScopeKey::new("grant_summary"),
                Duration::from_secs(60),
            )),
        ),
        "grant_summary",
        json!({}),
    )
    .await
    .expect("valid uid + unexpired method-bound token should pass OperatorPresence");
    assert_eq!(created["active"], json!(0));
    assert_eq!(created["expired"], json!(0));
    assert_eq!(created["revoked"], json!(0));
}
