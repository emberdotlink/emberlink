//! DEMO-MAY3-BIO-REAL: server-side WebAuthn relying-party.
//!
//! Wraps `webauthn-rs` with a `DaemonStore`-backed credential and
//! ceremony-state persistence so the dashboard's Approve flow can
//! gate on a verified passkey assertion. Replaces the prior
//! "trust-the-client-claim" path where the browser POSTed
//! `{biometric: true}` and the daemon recorded it without verifying
//! anything.
//!
//! ## Trust boundary
//!
//! The trust boundary lives at the daemon. The daemon:
//!
//! 1. Persists each enrolled credential's COSE public key in the
//!    `webauthn_credentials` table (per-persona).
//! 2. Mints a fresh challenge per ceremony, binds it to either
//!    `kind = "register"` (no approval) or `kind = "auth"` + a
//!    specific `approval_id`, and persists the in-flight ceremony
//!    state in `webauthn_challenges`.
//! 3. On finish, looks up the persisted state, calls
//!    `webauthn_rs::Webauthn::finish_passkey_{registration,
//!    authentication}` which performs the full spec-mandated
//!    verification (origin check, challenge match, signature
//!    against stored COSE key, sign-counter monotonicity).
//! 4. Deletes the challenge row on finish so a single ceremony
//!    state is never re-usable for a second assertion.
//!
//! A `curl` POST with `{biometric: true}` no longer flips approval
//! state — the caller must produce a `PublicKeyCredential` whose
//! signature verifies against a passkey that was previously
//! enrolled for the persona.
//!
//! ## Headless test gate
//!
//! `EMBER_DISABLE_BIO=1` environment variable bypasses the gate
//! entirely, returning `Ok(VerifyOutcome::Bypassed)`. This keeps
//! `qember.sh demo headless` green and matches the same env gate
//! used by the CLI's `LocalAuthentication` path
//! (`crates/emberlink-cli/src/biometric.rs`). Production daemons
//! should not set this.

#![cfg(feature = "webauthn")]

use std::sync::Arc;

use rusqlite::params;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    Webauthn, WebauthnBuilder,
};

use crate::infra::store::{DaemonStore, StoreError};

/// Default ceremony lifetime: 5 minutes. Browser timeouts are usually
/// 60s but a slow user picking a passkey from the OS sheet on macOS
/// can stretch past that. Five minutes cleans up stale state without
/// being aggressive.
const CHALLENGE_TTL_SECS: i64 = 300;

/// One-line identity hint shown in the OS passkey-creation sheet.
const RP_NAME: &str = "ember";

/// Display name for the operator user record at registration time.
/// Single-tenant local daemon — every passkey is attached to the
/// persona record but the WebAuthn `user.name` is just a label the
/// OS surfaces to disambiguate.
const OPERATOR_DISPLAY_NAME: &str = "ember operator";

/// Errors surfaced to the dashboard handler. Each variant maps to an
/// HTTP status — `NotEnrolled` is 401 (no credential to verify
/// against), `VerifyFailed` is 401 (assertion didn't pass), `Bug` is
/// 500. The error messages avoid leaking ceremony internals.
#[derive(Debug)]
pub enum WebauthnError {
    /// No passkey has ever been enrolled for the persona that owns
    /// the approval. Operator must visit `/settings/passkeys` first.
    NotEnrolled,
    /// The challenge_id submitted on `finish_*` does not exist or
    /// has expired. Caller must call `begin` again.
    UnknownChallenge,
    /// The challenge was for a different ceremony kind, persona, or
    /// approval. Replay attempt or programmer error.
    ChallengeMismatch,
    /// `webauthn_rs::Webauthn::finish_passkey_*` returned an error
    /// (origin mismatch, signature failure, sign-counter regression,
    /// etc.). The browser-supplied credential did not verify.
    VerifyFailed(String),
    /// SQLite or serialization error. Daemon-internal — not the
    /// caller's fault.
    Storage(String),
}

impl std::fmt::Display for WebauthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnrolled => {
                f.write_str("no passkey enrolled for this persona — visit /settings/passkeys")
            }
            Self::UnknownChallenge => f.write_str("challenge expired or not found"),
            Self::ChallengeMismatch => f.write_str("challenge does not match this ceremony"),
            Self::VerifyFailed(why) => write!(f, "assertion did not verify: {why}"),
            Self::Storage(why) => write!(f, "internal storage error: {why}"),
        }
    }
}

impl std::error::Error for WebauthnError {}

impl From<rusqlite::Error> for WebauthnError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<StoreError> for WebauthnError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for WebauthnError {
    fn from(e: serde_json::Error) -> Self {
        Self::Storage(format!("ceremony state serialization: {e}"))
    }
}

/// Outcome of a successful authentication finish. The credential_id
/// here is the one the daemon verified against — it travels into
/// the audit log and (stretch goal) into the Grant Receipt's
/// `human_consent` field as cryptographic evidence of human
/// in-the-loop consent.
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// Persona that owns the verified credential.
    pub persona_id: String,
    /// Credential ID (base64url) of the passkey that signed.
    pub credential_id: String,
    /// Approval that the assertion was bound to, mirrored back so the
    /// caller can sanity-check before flipping state.
    pub approval_id: String,
}

/// `WebauthnGate` is the single entry point dashboard handlers use.
/// Holds a configured `Webauthn` and a clone of the daemon's
/// `DaemonStore` so it can persist credentials and ceremony state.
///
/// `!Send + !Sync` because `DaemonStore` wraps a `!Send` rusqlite
/// connection. Lives inside the daemon's `LocalSet`, same as the
/// dashboard listener.
pub struct WebauthnGate {
    inner: Webauthn,
    store: Arc<DaemonStore>,
}

impl WebauthnGate {
    /// Build a gate configured for the dashboard's bind address.
    ///
    /// ## RP ID and origin policy
    ///
    /// WebAuthn requires the `rp_id` to be a *registrable suffix* of
    /// the page's effective domain. Bare IP addresses (like
    /// `127.0.0.1`) are not valid rp_ids — browsers reject the
    /// ceremony at registration time with `SecurityError`. The only
    /// hostname that works for a localhost-bound daemon is the
    /// special-cased `localhost` (treated as a secure context for
    /// WebAuthn purposes per Permissions Policy + Secure Contexts).
    ///
    /// We therefore:
    ///
    /// 1. Hardcode `rp_id = "localhost"`.
    /// 2. Pass the daemon's actual bound origin (`http://127.0.0.1:<port>`)
    ///    as the *primary* origin so the daemon-builder accepts it.
    ///    But the browser will only successfully complete the ceremony
    ///    when the page is loaded from `http://localhost:<port>` —
    ///    accessing the dashboard via `127.0.0.1` triggers the
    ///    rp-id-vs-origin mismatch.
    /// 3. Append `http://localhost:<port>` as an allowed origin so
    ///    the browser-side ceremony actually succeeds.
    ///
    /// **Recording-day requirement:** the operator MUST access the
    /// dashboard via `http://localhost:<port>` (not `127.0.0.1`) for
    /// TouchID to fire. The runbook calls this out.
    pub fn new(expected_origin: &str, store: Arc<DaemonStore>) -> Result<Self, WebauthnError> {
        let parsed = Url::parse(expected_origin)
            .map_err(|e| WebauthnError::Storage(format!("invalid origin url: {e}")))?;
        // Hardcoded rp_id for the localhost-bound daemon. See doc-comment.
        let rp_id = "localhost";
        // Build the localhost-flavored origin URL the browser will
        // actually use, preserving the daemon's port.
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| WebauthnError::Storage("origin missing port".into()))?;
        let scheme = parsed.scheme();
        let localhost_origin_str = format!("{scheme}://localhost:{port}");
        let localhost_origin = Url::parse(&localhost_origin_str)
            .map_err(|e| WebauthnError::Storage(format!("localhost url: {e}")))?;
        let mut builder = WebauthnBuilder::new(rp_id, &localhost_origin)
            .map_err(|e| WebauthnError::Storage(format!("webauthn init: {e}")))?
            .rp_name(RP_NAME);
        // Allow the actual bound origin too (127.0.0.1) so a daemon
        // that accidentally serves a page from 127.0.0.1 returns a
        // legible "origin mismatch" rather than a builder error;
        // browser-side rp_id check still rejects 127.0.0.1, so this
        // is defense in depth, not a bypass.
        if parsed.host_str() != Some("localhost") {
            builder = builder.append_allowed_origin(&parsed);
        }
        let inner = builder
            .build()
            .map_err(|e| WebauthnError::Storage(format!("webauthn build: {e}")))?;
        Ok(Self { inner, store })
    }

    /// Begin a passkey-registration ceremony for `persona_id`. The
    /// returned `CreationChallengeResponse` is JSON-serialized to
    /// the browser; the browser passes it to `navigator.credentials.create()`.
    ///
    /// Persists the in-flight `PasskeyRegistration` state keyed by a
    /// fresh challenge_id so the matching `finish_register` call can
    /// look it back up. The challenge_id is also returned to the
    /// browser so the finish call can reference it.
    pub fn start_register(
        &self,
        persona_id: &str,
    ) -> Result<(String, CreationChallengeResponse), WebauthnError> {
        // Already-enrolled credentials become `exclude_credentials` so
        // the OS doesn't offer to overwrite an existing passkey.
        let exclude: Vec<webauthn_rs::prelude::CredentialID> = self
            .list_credentials_for_persona(persona_id)?
            .into_iter()
            .map(|p| p.cred_id().clone())
            .collect();

        // webauthn-rs uses a Uuid for the user.id field. We mint one
        // per persona deterministically from the persona_id so a
        // passkey enrolled today survives across daemon restarts and
        // the OS records it as the "same user" in subsequent
        // ceremonies.
        let user_uuid = uuid_from_persona(persona_id);

        let (ccr, reg_state) = self
            .inner
            .start_passkey_registration(user_uuid, persona_id, OPERATOR_DISPLAY_NAME, Some(exclude))
            .map_err(|e| WebauthnError::Storage(format!("start register: {e}")))?;

        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now = unix_now();
        let state_json = serde_json::to_string(&reg_state)?;
        self.store.conn().execute(
            "INSERT INTO webauthn_challenges
                (challenge_id, approval_id, persona_id, kind, state_json,
                 created_at, expires_at)
             VALUES (?1, NULL, ?2, 'register', ?3, ?4, ?5)",
            params![
                challenge_id,
                persona_id,
                state_json,
                now,
                now + CHALLENGE_TTL_SECS,
            ],
        )?;
        self.reap_expired(now)?;
        Ok((challenge_id, ccr))
    }

    /// Complete the ceremony by verifying the
    /// `RegisterPublicKeyCredential` against the persisted state.
    /// On success the credential pubkey is persisted in
    /// `webauthn_credentials` and the challenge row is deleted.
    pub fn finish_register(
        &self,
        challenge_id: &str,
        credential: RegisterPublicKeyCredential,
    ) -> Result<String, WebauthnError> {
        let (persona_id, state_json) = self.consume_challenge(challenge_id, "register", None)?;
        let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)?;
        let passkey = self
            .inner
            .finish_passkey_registration(&credential, &reg_state)
            .map_err(|e| WebauthnError::VerifyFailed(format!("register: {e}")))?;
        let credential_id_b64url = base64url_encode(passkey.cred_id().as_ref());
        let passkey_json = serde_json::to_string(&passkey)?;
        let now = unix_now();
        self.store.conn().execute(
            "INSERT OR REPLACE INTO webauthn_credentials
                (credential_id, persona_id, passkey_json, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![&credential_id_b64url, persona_id, passkey_json, now],
        )?;
        Ok(credential_id_b64url)
    }

    /// Begin an authentication ceremony bound to a specific
    /// approval. The browser uses the returned options with
    /// `navigator.credentials.get()`; the resulting assertion is
    /// fed to `finish_auth(challenge_id, ...)`.
    ///
    /// Errors with `NotEnrolled` if the persona has never registered
    /// a passkey — the dashboard surfaces this as a clear "enroll
    /// first" message.
    pub fn start_auth(
        &self,
        persona_id: &str,
        approval_id: &str,
    ) -> Result<(String, RequestChallengeResponse), WebauthnError> {
        let credentials = self.list_credentials_for_persona(persona_id)?;
        if credentials.is_empty() {
            return Err(WebauthnError::NotEnrolled);
        }
        let (rcr, auth_state) = self
            .inner
            .start_passkey_authentication(&credentials)
            .map_err(|e| WebauthnError::Storage(format!("start auth: {e}")))?;

        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now = unix_now();
        let state_json = serde_json::to_string(&auth_state)?;
        self.store.conn().execute(
            "INSERT INTO webauthn_challenges
                (challenge_id, approval_id, persona_id, kind, state_json,
                 created_at, expires_at)
             VALUES (?1, ?2, ?3, 'auth', ?4, ?5, ?6)",
            params![
                challenge_id,
                approval_id,
                persona_id,
                state_json,
                now,
                now + CHALLENGE_TTL_SECS,
            ],
        )?;
        self.reap_expired(now)?;
        Ok((challenge_id, rcr))
    }

    /// Verify an assertion against a previously-issued challenge.
    /// The challenge row is consumed (deleted) on success OR
    /// failure to prevent replay.
    ///
    /// On success, also bumps the credential's sign counter and
    /// `last_used_at` so future verifications enforce monotonicity.
    pub fn finish_auth(
        &self,
        challenge_id: &str,
        approval_id: &str,
        credential: PublicKeyCredential,
    ) -> Result<VerifiedAssertion, WebauthnError> {
        let (persona_id, state_json) =
            self.consume_challenge(challenge_id, "auth", Some(approval_id))?;
        let auth_state: PasskeyAuthentication = serde_json::from_str(&state_json)?;
        let result = self
            .inner
            .finish_passkey_authentication(&credential, &auth_state)
            .map_err(|e| WebauthnError::VerifyFailed(format!("auth: {e}")))?;

        let credential_id_b64url = base64url_encode(result.cred_id().as_ref());

        // Update sign counter on the stored Passkey so a replayed
        // assertion (older counter) gets rejected by webauthn-rs on
        // the next verify.
        if result.needs_update() {
            if let Some(mut stored) = self.load_credential(&credential_id_b64url)? {
                stored.update_credential(&result);
                let stored_json = serde_json::to_string(&stored)?;
                let now = unix_now();
                self.store.conn().execute(
                    "UPDATE webauthn_credentials
                     SET passkey_json = ?1, last_used_at = ?2
                     WHERE credential_id = ?3",
                    params![stored_json, now, &credential_id_b64url],
                )?;
            }
        } else {
            let now = unix_now();
            self.store.conn().execute(
                "UPDATE webauthn_credentials SET last_used_at = ?1 WHERE credential_id = ?2",
                params![now, &credential_id_b64url],
            )?;
        }

        Ok(VerifiedAssertion {
            persona_id,
            credential_id: credential_id_b64url,
            approval_id: approval_id.to_string(),
        })
    }

    /// List enrolled credentials for a persona — used by the
    /// `/settings/passkeys` page to render the enrolled list and by
    /// `start_auth` to populate `allowCredentials`.
    pub fn list_credential_ids(&self, persona_id: &str) -> Result<Vec<String>, WebauthnError> {
        let mut stmt = self.store.conn().prepare(
            "SELECT credential_id FROM webauthn_credentials
             WHERE persona_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map(params![persona_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Remove an enrolled credential. Used by the settings page's
    /// "Remove" button.
    pub fn delete_credential(
        &self,
        persona_id: &str,
        credential_id: &str,
    ) -> Result<(), WebauthnError> {
        self.store.conn().execute(
            "DELETE FROM webauthn_credentials
             WHERE persona_id = ?1 AND credential_id = ?2",
            params![persona_id, credential_id],
        )?;
        Ok(())
    }

    // -----------------------------------------------------------
    // internals
    // -----------------------------------------------------------

    fn list_credentials_for_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<Passkey>, WebauthnError> {
        let mut stmt = self.store.conn().prepare(
            "SELECT passkey_json FROM webauthn_credentials
             WHERE persona_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map(params![persona_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|json| serde_json::from_str::<Passkey>(&json).map_err(WebauthnError::from))
            .collect()
    }

    fn load_credential(&self, credential_id: &str) -> Result<Option<Passkey>, WebauthnError> {
        let json: Option<String> = self
            .store
            .conn()
            .query_row(
                "SELECT passkey_json FROM webauthn_credentials WHERE credential_id = ?1",
                params![credential_id],
                |row| row.get(0),
            )
            .ok();
        json.map(|j| serde_json::from_str::<Passkey>(&j).map_err(WebauthnError::from))
            .transpose()
    }

    /// Looks up + deletes a challenge row, returning (persona_id,
    /// state_json). Validates kind and (for auth) approval_id binding.
    fn consume_challenge(
        &self,
        challenge_id: &str,
        expected_kind: &str,
        expected_approval_id: Option<&str>,
    ) -> Result<(String, String), WebauthnError> {
        let row: Option<(String, String, String, Option<String>, i64)> = self
            .store
            .conn()
            .query_row(
                "SELECT persona_id, kind, state_json, approval_id, expires_at
                 FROM webauthn_challenges WHERE challenge_id = ?1",
                params![challenge_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .ok();
        let (persona_id, kind, state_json, approval_id, expires_at) =
            row.ok_or(WebauthnError::UnknownChallenge)?;

        // Always delete; a failed verify should not leave a replay-
        // able row behind.
        self.store.conn().execute(
            "DELETE FROM webauthn_challenges WHERE challenge_id = ?1",
            params![challenge_id],
        )?;

        if expires_at < unix_now() {
            return Err(WebauthnError::UnknownChallenge);
        }
        if kind != expected_kind {
            return Err(WebauthnError::ChallengeMismatch);
        }
        if let Some(want) = expected_approval_id {
            match approval_id.as_deref() {
                Some(got) if got == want => {}
                _ => return Err(WebauthnError::ChallengeMismatch),
            }
        }
        Ok((persona_id, state_json))
    }

    fn reap_expired(&self, now: i64) -> Result<(), WebauthnError> {
        self.store.conn().execute(
            "DELETE FROM webauthn_challenges WHERE expires_at < ?1",
            params![now],
        )?;
        Ok(())
    }
}

/// Returns true when the operator (or test harness) has explicitly
/// disabled biometric gating via the same env gate the CLI honors.
/// The dashboard handler treats this as "skip the gate, record
/// `biometric=false` in the audit log, proceed with the approval"
/// — same posture as the pre-DEMO-MAY3-BIO-REAL behavior so qember
/// headless smoke stays green without a real authenticator.
pub fn bio_disabled_via_env() -> bool {
    std::env::var("EMBER_DISABLE_BIO").is_ok()
}

fn uuid_from_persona(persona_id: &str) -> Uuid {
    let digest = blake3::hash(persona_id.as_bytes());
    let bytes: [u8; 16] = digest.as_bytes()[..16]
        .try_into()
        .expect("16 bytes from blake3");
    Uuid::from_bytes(bytes)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        }
    }
    out
}
