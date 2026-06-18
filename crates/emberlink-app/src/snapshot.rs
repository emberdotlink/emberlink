use serde::{Deserialize, Serialize};

use crate::backend::AppBackend;

/// Serializable snapshot of full app state for frontends and read clients.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AppSnapshot {
    pub roots: Vec<RootView>,
    pub personas: Vec<PersonaView>,
    pub devices: Vec<DeviceView>,
    pub trust_attestations: Vec<TrustView>,
    pub grants: Vec<GrantSummaryView>,
    /// Credential metadata per persona (populated on demand via ListCredentials,
    /// not on every snapshot refresh since vault catalog reads require decryption).
    pub credentials: Vec<CredentialView>,
    /// Recovery status derived from materialized state; `None` if no policy exists.
    pub recovery: Option<RecoveryStatusView>,
    pub event_count: usize,
}

/// Lightweight credential metadata view — schema and timing only.
/// The payload (username, password, etc.) is never included in snapshots;
/// retrieve it via GetCredential.
#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialView {
    pub object_id: String,
    pub persona_id: String,
    /// Schema identifier (e.g. `emberlink:claim:password:1.0`).
    pub schema: String,
    /// Human-readable label derived from claim_schema or schema (e.g. "Password", "Employment").
    pub display_label: String,
    /// Claim type string (`self-asserted`, `service-issued`, etc.), if this is a claim.
    pub claim_type: Option<String>,
    /// Semantic claim schema (e.g. `employment`, `membership`), if present.
    pub claim_schema: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Metadata view of a service binding (passkey, OAuth, password-import, etc.).
#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceBindingView {
    pub binding_id: String,
    pub persona_id: String,
    /// Adapter kind string: `"passkey"`, `"oauth2"`, `"password-import"`, etc.
    pub adapter_kind: String,
    /// Human-readable service label.
    pub service_label: String,
    /// Service endpoint / origin.
    pub endpoint: String,
    /// Human-readable account identifier (RP ID for passkeys, account ID for OAuth/password-import).
    pub display_account: String,
    pub created_at: u64,
}

/// Recovery posture derived from materialized state.
#[derive(Serialize, Deserialize, Clone)]
pub struct RecoveryStatusView {
    pub guardian_count: usize,
    /// Number of guardians required to approve recovery (`None` = no policy set).
    pub threshold: Option<u8>,
    pub cooldown_seconds: Option<u32>,
    pub pending_request_count: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RootView {
    pub id: String,
    pub display_name: String,
    pub is_revoked: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PersonaView {
    pub id: String,
    pub label: String,
    pub root_id: String,
    pub profile: String,
    pub color: Option<String>,
    pub is_revoked: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceView {
    pub id: String,
    pub label: String,
    pub root_id: String,
    pub is_revoked: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TrustView {
    pub id: String,
    pub from_persona: String,
    pub to_persona: String,
    pub domain: String,
    pub score: f32,
}

/// View of a badge for display.
#[derive(Serialize, Deserialize, Clone)]
pub struct BadgeView {
    pub badge_id: String,
    pub issuer_persona_id: String,
    pub recipient_persona_id: String,
    pub badge_type: String,
    pub display_name: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub revoked_reason: Option<String>,
}

/// A badge entry in a persona's gallery, with visibility status.
/// `visible=true` means the owner has chosen to show this badge publicly.
#[derive(Serialize, Deserialize, Clone)]
pub struct BadgeGalleryEntry {
    pub badge_id: String,
    pub issuer_persona_id: String,
    pub badge_type: String,
    pub display_name: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    /// Whether the persona has set this badge as publicly visible in their gallery.
    pub visible: bool,
}

/// Summary view of a grant for list displays.
///
/// Composite-grant shape per ADR 073: statements are enumerated across all
/// blocks in the chain; distinct resource_types are surfaced for the persona
/// chip / badge rendering.
#[derive(Serialize, Deserialize, Clone)]
pub struct GrantSummaryView {
    pub id: String,
    pub label: Option<String>,
    pub issuing_persona_id: String,
    pub recipient_kind: String,
    pub recipient_id: String,
    pub recipient_profile: String,
    pub status: String,
    pub mode: String,
    pub block_count: usize,
    pub statement_count: usize,
    /// Distinct resource types across all statements, first-seen order. Used
    /// by the dashboard to render persona chip badges.
    pub resource_types: Vec<String>,
    /// Effective chain expiry — earliest `expires_at` across all blocks.
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

/// Full grant detail including lifecycle history.
///
/// Composite-grant shape per ADR 073: `blocks` is the signed, append-only
/// chain; each block carries typed `Statement`s with per-statement budgets,
/// resource selectors, and conditions. Envelope-level `not_before`/
/// `renewable_until` are gone — that metadata lives on blocks now.
#[derive(Serialize, Deserialize, Clone)]
pub struct GrantDetailView {
    pub id: String,
    pub version: u32,
    pub label: Option<String>,
    pub issuing_persona_id: String,
    pub recipient_kind: String,
    pub recipient_id: String,
    pub recipient_profile: String,
    pub status: String,
    pub mode: String,
    pub blocks: Vec<BlockView>,
    pub created_at: u64,
    pub updated_at: u64,
    /// Effective chain expiry — earliest `expires_at` across all blocks.
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
    pub last_used_at: Option<u64>,
    pub linked_artifact_count: usize,
    pub history: Vec<GrantHistoryView>,
}

/// View of a single signed block in the grant chain. `Statement`,
/// `ApprovalChallenge`, and related leaves already derive `Serialize`,
/// so we re-export them directly instead of building parallel wire types.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockView {
    pub statements: Vec<core_grant_types::Statement>,
    pub nbf: Option<u64>,
    pub expires_at: Option<u64>,
    pub issued_by: String,
    pub issued_at: u64,
    pub approval: Option<core_grant_types::ApprovalChallenge>,
    pub note: Option<String>,
    /// Hex-encoded public key that signs the next appended block.
    pub pubkey_next: String,
    /// Hex-encoded Ed25519 signature over the block's canonical bytes.
    pub signature: String,
}

/// Single entry in a grant's lifecycle history.
#[derive(Serialize, Deserialize, Clone)]
pub struct GrantHistoryView {
    pub action: String,
    pub timestamp: u64,
    pub version: u32,
    pub note: Option<String>,
}

impl AppSnapshot {
    pub fn from_store<S: AppBackend>(store: &S) -> Self {
        let mat = store.materialized();

        let roots = mat
            .roots_current
            .values()
            .map(|r| RootView {
                id: r.root_id.clone(),
                display_name: r.display_name.clone(),
                is_revoked: r.status == core_eventlog::RootStatus::Revoked,
            })
            .collect();

        let personas = mat
            .personas_current
            .values()
            .map(|p| PersonaView {
                id: p.persona_id.clone(),
                label: p.label.clone(),
                root_id: p.root_id.clone(),
                profile: p.disclosure_profile.clone().unwrap_or_default(),
                color: None,
                is_revoked: p.status == core_eventlog::PersonaStatus::Revoked,
            })
            .collect();

        let devices = mat
            .devices_current
            .values()
            .map(|d| DeviceView {
                id: d.device_id.clone(),
                label: d.label.clone(),
                root_id: d.root_id.clone(),
                is_revoked: matches!(d.status, core_eventlog::DeviceStatus::Revoked),
            })
            .collect();

        let trust_attestations = mat
            .trust_edges_current
            .values()
            .map(|t| TrustView {
                id: t.id.clone(),
                from_persona: t.attester.clone(),
                to_persona: t.subject.clone(),
                domain: t.domain.clone(),
                score: t.score,
            })
            .collect();

        let grants = store
            .list_active_grants(None, None)
            .unwrap_or_default()
            .into_iter()
            .map(|g| GrantSummaryView {
                id: g.id,
                label: g.label,
                issuing_persona_id: g.issuing_persona_id,
                recipient_kind: g.recipient_kind.as_str().to_string(),
                recipient_id: g.recipient_id,
                recipient_profile: g.recipient_profile.as_str().to_string(),
                status: g.status.as_str().to_string(),
                mode: g.mode.as_str().to_string(),
                block_count: g.block_count,
                statement_count: g.statement_count,
                resource_types: g
                    .resource_types
                    .into_iter()
                    .map(|rt| rt.as_str().to_string())
                    .collect(),
                expires_at: g.expires_at,
                last_used_at: g.last_used_at,
            })
            .collect();

        // Recovery status — derived purely from materialized state, no decryption needed.
        let recovery = mat.recovery_policies_current.values().next().map(|policy| {
            let pending_request_count = mat
                .recovery_requests_current
                .values()
                .filter(|r| {
                    r.status == core_eventlog::RecoveryRequestStatus::Requested
                        || r.status == core_eventlog::RecoveryRequestStatus::Approved
                })
                .count();
            RecoveryStatusView {
                guardian_count: mat.guardians_current.len(),
                threshold: Some(policy.guardian_threshold),
                cooldown_seconds: Some(policy.cooldown_seconds),
                pending_request_count,
            }
        });

        Self {
            roots,
            personas,
            devices,
            trust_attestations,
            grants,
            credentials: vec![], // populated on demand via ListCredentials
            recovery,
            event_count: store.event_count(),
        }
    }
}

impl GrantDetailView {
    pub fn from_detail(detail: &core_grant_types::AccessGrantDetail) -> Self {
        let g = &detail.grant;
        Self {
            id: g.id.clone(),
            version: g.version,
            label: g.label.clone(),
            issuing_persona_id: g.issuing_persona_id.clone(),
            recipient_kind: g.recipient_kind.as_str().to_string(),
            recipient_id: g.recipient_id.clone(),
            recipient_profile: g.recipient_profile.as_str().to_string(),
            status: g.status.as_str().to_string(),
            mode: g.mode.as_str().to_string(),
            blocks: g
                .blocks
                .iter()
                .map(|sb| BlockView {
                    statements: sb.block.statements.clone(),
                    nbf: sb.block.nbf,
                    expires_at: sb.block.expires_at,
                    issued_by: sb.block.issued_by.clone(),
                    issued_at: sb.block.issued_at,
                    approval: sb.block.approval.clone(),
                    note: sb.block.note.clone(),
                    pubkey_next: sb.pubkey_next.clone(),
                    signature: sb.signature.clone(),
                })
                .collect(),
            created_at: g.created_at,
            updated_at: g.updated_at,
            expires_at: g.effective_expires_at(),
            revoked_at: g.revoked_at,
            revoked_reason: g.revoked_reason.clone(),
            last_used_at: g.last_used_at,
            linked_artifact_count: detail.linked_artifact_count,
            history: detail
                .history
                .iter()
                .map(|h| GrantHistoryView {
                    action: h.action.clone(),
                    timestamp: h.timestamp,
                    version: h.version,
                    note: h.note.clone(),
                })
                .collect(),
        }
    }
}
