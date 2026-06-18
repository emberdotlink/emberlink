use super::*;

/// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE - set the cohort A
/// dev0 bridge env var process-wide for the duration of the test
/// binary's run, exactly once.
///
/// `EMBER_LOOSE_PEER_GID_FOR_EMBER_CLIENTS=1` is the operator-presence
/// proof until Phase D ships WebAuthn presence-tokens; cargo's test
/// runner inherits the env once set, and the value is global so
/// parallel tests cannot race on it. Tests that explicitly want to
/// observe the gate's negative path (`authority_class_not_met`)
/// construct a `RequestContext` directly without going through this
/// shim, or scope the env removal via `remove_var` ahead of their
/// dispatch call.
pub(crate) fn ensure_test_authority_bridge_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY (Rust 2024): `set_var` is `unsafe` because env-var
        // mutation while other threads read the env races on libc's
        // internal env table. We gate the call behind `Once` so the
        // mutation happens at most once per test binary; cargo's
        // test runner serializes module-static initialisation before
        // any test thread reads the var via `std::env::var`. The
        // operator-presence bridge is otherwise a process-wide
        // installer flag, so the runtime semantics match production.
        unsafe {
            std::env::set_var("EMBER_LOOSE_PEER_GID_FOR_EMBER_CLIENTS", "1");
        }
    });
}

pub(crate) fn write_open_session_meta(
    sessions_dir: &std::path::Path,
    session_id: &str,
    persona_id: &str,
) {
    write_open_session_meta_with_launcher_pid(
        sessions_dir,
        session_id,
        persona_id,
        std::process::id(),
    );
}

pub(crate) fn write_open_session_meta_with_launcher_pid(
    sessions_dir: &std::path::Path,
    session_id: &str,
    persona_id: &str,
    launcher_pid: u32,
) {
    let session_store = core_state::SessionStore::new(sessions_dir.to_path_buf());
    session_store
        .create(&core_state::SessionMeta {
            session_id: session_id.to_string(),
            persona: persona_id.to_string(),
            durable_persona: None,
            grant_id: "grant-session-runtime".to_string(),
            caller_binding_id: None,
            started_at: chrono::Utc::now(),
            launcher_pid,
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        })
        .expect("write open session meta");
}

pub(crate) fn seed_socket_enrollment_for_test(
    store: &DaemonStore,
    socket_path: &str,
    persona_id: &str,
    peer_uid: u32,
) {
    store
        .record_agent_socket_enrollment(
            socket_path,
            persona_id,
            "grant-test",
            "hash-test",
            None,
            None,
            None,
        )
        .expect("seed socket enrollment");
    store
        .conn()
        .execute(
            "UPDATE agent_socket_enrollments SET peer_uid = ?1 WHERE socket_path = ?2",
            rusqlite::params![peer_uid as i64, socket_path],
        )
        .expect("seed peer uid");
}

pub(crate) fn session_runtime_socket_ctx(
    sessions_dir: &std::path::Path,
    socket_path: &str,
    uid: u32,
    pid: i32,
) -> RequestContext {
    RequestContext {
        source: DispatchSource::Socket,
        peer: Some(PeerCred {
            uid,
            pid: Some(pid),
        }),
        principal: None,
        sessions_dir: Some(sessions_dir.to_path_buf()),
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: Some(crate::infra::runtime::PeerCredPrincipal::new(
            uid,
            pid,
            std::path::PathBuf::from(socket_path),
        )),
        presence_token: None,
        bypass_binary_pin_gate_for_test: true,
    }
}

pub(crate) fn session_runtime_mtls_ctx(
    sessions_dir: &std::path::Path,
    uid: u32,
    persona_id: &str,
    session_id: &str,
) -> RequestContext {
    RequestContext {
        source: DispatchSource::Bridge(MtlsPrincipal {
            persona_id: persona_id.to_owned(),
            container_id: session_id.to_owned(),
            cert_fingerprint: [7u8; 32],
        }),
        peer: Some(PeerCred {
            uid,
            pid: Some(std::process::id() as i32),
        }),
        principal: None,
        sessions_dir: Some(sessions_dir.to_path_buf()),
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: None,
        bypass_binary_pin_gate_for_test: true,
    }
}

pub(crate) fn session_runtime_bridge_ctx(
    sessions_dir: &std::path::Path,
    uid: u32,
    persona_id: &str,
    session_id: &str,
) -> RequestContext {
    let mut ctx = session_runtime_mtls_ctx(sessions_dir, uid, persona_id, session_id);
    ctx.peer_cred_principal = Some(crate::infra::runtime::PeerCredPrincipal::new(
        uid,
        std::process::id() as i32,
        std::path::PathBuf::from("/Users/example/.ember/run/daemon.sock"),
    ));
    ctx
}

pub(crate) struct TestChildProcess(std::process::Child);

impl TestChildProcess {
    pub(crate) fn spawn() -> Self {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        Self(child)
    }

    pub(crate) fn pid_u32(&self) -> u32 {
        self.0.id()
    }

    pub(crate) fn pid_i32(&self) -> i32 {
        self.0.id() as i32
    }
}

impl Drop for TestChildProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
