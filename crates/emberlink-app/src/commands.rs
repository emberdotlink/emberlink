use serde::{Deserialize, Serialize};

/// Actions that any surface (CLI, GUI, extension, test) can dispatch to
/// [`crate::AppRuntime`]. This is the stable command boundary — shells
/// construct these and hand them to `handle_action`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UiAction {
    // --- Read ---
    /// Return the current state snapshot (no mutation).
    GetState,
    /// Return full detail for a specific grant.
    GetGrantDetail {
        grant_id: String,
    },

    // --- Identity setup ---
    /// First-launch init: create root + device + persona in one shot.
    Init {
        name: String,
        device_label: String,
        persona_label: String,
    },
    /// Create a new identity root.
    CreateRoot {
        name: String,
    },
    /// Create a new persona under an existing root.
    CreatePersona {
        root: String,
        label: String,
        template: String,
    },
    /// Add a device to an existing root.
    AddDevice {
        root: String,
        label: String,
    },

    // --- Revocation ---
    RevokeRoot {
        root_id: String,
        reason: String,
    },
    RevokePersona {
        root_id: String,
        persona_id: String,
        reason: String,
    },
    RevokeDevice {
        root_id: String,
        device_id: String,
        reason: String,
    },

    // --- Access grants ---
    RevokeGrant {
        grant_id: String,
        reason: String,
    },

    /// Create a new access grant.
    /// `recipient_kind`: "peer" | "service"
    /// `recipient_profile`: "human" | "agent" | "service"
    /// `mode`: "one_shot" | "renewable" | "standing"
    /// `statement_specs`: shorthand statement specs parsed by
    /// `runtime::parse_statement_spec` (`read_credential:<id>` etc.).
    /// `not_before` / `expires_at` are carried onto block 0.
    CreateGrant {
        issuing_persona_id: String,
        recipient_kind: String,
        recipient_id: String,
        recipient_profile: String,
        mode: String,
        statement_specs: Vec<String>,
        label: Option<String>,
        not_before: Option<u64>,
        expires_at: Option<u64>,
    },

    /// Edit an existing grant's mutable envelope fields. `statement_specs`,
    /// if present, replaces the statements inside block 0. `expires_at`
    /// rewrites block 0's `expires_at`. `note` lands on the history entry.
    EditGrant {
        grant_id: String,
        label: Option<String>,
        statement_specs: Option<Vec<String>>,
        expires_at: Option<u64>,
        note: Option<String>,
    },

    // --- Credentials & service bindings ---
    /// Create a single persona credential.
    ///
    /// `claim_type`: `"self-asserted"` | `"peer-attested"` | `"service-issued"` | `"derived"`
    /// `payload_json`: JSON object with a top-level `"schema"` string field, e.g.
    ///   `{"schema":"password","username":"alice","password":"s3cr3t"}`
    /// `device_id`: the device creating the record (must have persona access)
    CreateCredential {
        persona_id: String,
        device_id: String,
        claim_type: String,
        payload_json: String,
    },

    /// List credential summaries for a persona (metadata only, no payload).
    ListCredentials {
        persona_id: String,
    },

    /// Get a single credential's metadata. Returns `CredentialView`.
    GetCredential {
        object_id: String,
        persona_id: String,
    },

    /// List service bindings (passkeys, OAuth, password-import, etc.) for a persona.
    ListServiceBindings {
        persona_id: String,
    },

    /// List credential summaries across all personas. Returns `Vec<CredentialView>`.
    ListAllCredentials,

    // --- Grant offers ---
    /// Create a grant offer and return the grant link URL.
    /// `mode`: "one_shot" | "renewable" | "standing"
    /// `statement_specs`: shorthand specs parsed by `parse_statement_spec`
    /// `expires_in_secs`: how long the offer is valid (default: 86400 = 24h)
    CreateGrantOffer {
        issuing_persona_id: String,
        mode: String,
        statement_specs: Vec<String>,
        expires_in_secs: Option<u64>,
        relay_hint: Option<String>,
        conditions: Vec<core_grant_types::grant_conditions::GrantCondition>,
    },

    /// Create a grant offer from typed statements rather than CLI shorthand.
    ///
    /// Recovery-plane callers use this for scopes such as guardian enrollment,
    /// which are not credential shorthand and must not be forced through
    /// `parse_statement_spec`.
    CreateGrantOfferTyped {
        issuing_persona_id: String,
        mode: String,
        statements: Vec<core_grant_types::Statement>,
        expires_in_secs: Option<u64>,
        relay_hint: Option<String>,
        conditions: Vec<core_grant_types::grant_conditions::GrantCondition>,
    },

    /// Claim a grant offer from a link URL or QR string.
    ///
    /// If `claiming_persona_id` is `None` and no identity exists, a new identity
    /// is created automatically (new-user flow). If `claiming_persona_id`
    /// is provided (or an existing persona is found), that persona claims the
    /// offer (existing-user flow).
    ///
    /// `link_url`: the grant link URL (`emberlink://` or `https://ember.link/...`)
    ///   or an EL1:... QR string from `grant offer qr`.
    /// `claiming_persona_id`: optional — if omitted, auto-select the first active
    ///   persona (or create a new identity if none exist).
    /// `new_user_name`: name for the new root identity when auto-creating (default: "me").
    ClaimGrantOffer {
        link_url: String,
        claiming_persona_id: Option<String>,
        new_user_name: Option<String>,
    },

    // --- Badges ---
    /// Issue a badge from one persona to a recipient (self or peer).
    /// `badge_type`: freeform, namespaced by convention (e.g. "subway:king:A")
    /// `display_name`: human-readable label for the badge
    /// `evidence_type` + `evidence_payload_hex`: optional attestation evidence
    /// `expires_in_secs`: optional expiry duration from now
    IssueBadge {
        issuer_persona_id: String,
        recipient_persona_id: String,
        badge_type: String,
        display_name: String,
        evidence_type: Option<String>,
        evidence_payload_hex: Option<String>,
        expires_in_secs: Option<u64>,
    },

    /// Revoke a badge previously issued by this persona.
    RevokeBadge {
        badge_id: String,
        revoker_persona_id: String,
        reason: String,
    },

    /// List badges. Filter by issuer or recipient persona, and/or badge type.
    ListBadges {
        persona_id: Option<String>,
        role: Option<String>,
        badge_type: Option<String>,
    },

    /// Set badge visibility for a persona's gallery (local-only, never leaves device).
    /// `visible=true` means the badge will appear in the persona's badge gallery.
    SetBadgeVisibility {
        badge_id: String,
        persona_id: String,
        visible: bool,
    },

    /// Return the badge gallery for a persona: all active, non-expired recipient
    /// badges with their visibility status. Pass `visible_only=true` to filter
    /// to only the publicly shown badges.
    GetBadgeGallery {
        persona_id: String,
        visible_only: bool,
    },

    /// Compute authority weight for a specific badge's issuer from the viewer's perspective.
    ///
    /// `badge_id`: the badge whose issuer will be evaluated.
    /// `viewer_persona_id`: the persona computing the weight (defaults to first persona if None).
    /// `max_depth`: maximum trust graph traversal depth (defaults to 3).
    BadgeWeight {
        badge_id: String,
        viewer_persona_id: Option<String>,
        max_depth: Option<u32>,
    },

    /// File a dispute against a badge (ADR 030 counter-attestation).
    /// The disputer challenges the badge's validity. Disputes are weighted by
    /// the viewer's trust graph when computing badge authority.
    DisputeBadge {
        target_badge_id: String,
        disputer_persona_id: String,
        reason: String,
        evidence: Option<String>,
    },
}
