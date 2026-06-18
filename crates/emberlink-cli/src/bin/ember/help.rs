use super::*;

pub(super) fn render_top_level_help() -> String {
    let theme = current_cli_render_theme();
    let mut out = String::new();
    let _ = writeln!(out, "{}", theme.title("Ember", Some(CliRenderTone::Brand)));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Local-first authority, launch, and audit tooling for Claude, Codex, Cursor, Gemini, and operator work."
    );
    let _ = writeln!(out);
    push_row_section(
        &mut out,
        "Start",
        &[("init", "Set up Ember for Claude, Codex, Cursor, or Gemini")],
    );
    push_row_section(
        &mut out,
        "Launch",
        &[
            ("claude", "Launch Claude with Ember wiring"),
            ("codex", "Launch Codex with Ember wiring"),
            ("cursor", "Launch Cursor with Ember wiring"),
            ("gemini", "Launch the Gemini CLI with Ember wiring"),
        ],
    );
    push_row_section(
        &mut out,
        "Check",
        &[
            ("status", "Show readiness and the next action"),
            ("doctor", "Diagnose problems and route repairs"),
        ],
    );
    push_row_section(
        &mut out,
        "Inspect",
        &[
            ("approval", "Review pending approvals"),
            ("grant", "Inspect and manage delegated authority"),
            ("trust", "Inspect trust roots and verification chains"),
            ("receipt", "Inspect signed receipts"),
            ("audit", "Inspect local audit evidence"),
        ],
    );
    push_row_section(
        &mut out,
        "Advanced",
        &[
            ("github", "Inspect or repair GitHub posture"),
            ("daemon", "Install, inspect, and repair the managed daemon"),
            ("vault", "Manage stored credentials"),
            ("headless", "Manage unattended delegation"),
            ("recover", "Open class and lifecycle recovery"),
        ],
    );
    push_row_section(
        &mut out,
        "More",
        &[
            (
                "ember explain <command>",
                "Show the deeper manual for a surface",
            ),
            ("ember status --json", "Emit machine-readable status"),
        ],
    );
    out.trim_end().to_string()
}

pub(super) fn render_init_help() -> String {
    render_help_card(
        "ember init",
        "Set up Ember on this machine and wire Claude, Codex, or Cursor into the managed launcher path.",
        &[
            (
                "ember init --for claude",
                "Set up Claude as the first managed lane",
            ),
            ("ember init --for codex", "Set up Codex as a managed lane"),
            (
                "ember init --for cursor",
                "Set up the baseline Cursor host path",
            ),
            (
                "ember init --for claude --non-interactive",
                "Refuse prompts and print the repair command instead",
            ),
        ],
        &[
            ("--for <target>", "Choose `claude`, `codex`, or `cursor`"),
            ("--non-interactive", "Skip prompts and guided input"),
            ("--migrate", "Relocate older shadow PATH shims"),
            (
                "Claude path",
                "Patches `~/.claude/settings.json` for the managed launcher",
            ),
            (
                "Codex path",
                "Patches `~/.codex/hooks.json`; check auth with `codex login status` or `codex login --device-auth`",
            ),
            (
                "Cursor path",
                "Creates the baseline host persona/grant; Cursor account/model auth stays Cursor-owned",
            ),
        ],
        &[
            ("ember status", "Check readiness after setup"),
            ("ember github setup", "Set up the GitHub App lane"),
            ("ember explain init", "Read the deeper setup flow"),
        ],
    )
}

pub(super) fn render_uninstall_help() -> String {
    render_help_card(
        "ember uninstall",
        "Remove Ember's launcher integration for Claude, Codex, or Cursor without destroying your local authority state.",
        &[
            (
                "ember uninstall --for claude",
                "Remove only the Claude settings patch",
            ),
            (
                "ember uninstall --for codex",
                "Remove only the Codex hook wiring",
            ),
            (
                "ember uninstall --for cursor",
                "Leave Cursor persona/grant state in place",
            ),
        ],
        &[
            ("--for <target>", "Choose `claude`, `codex`, or `cursor`"),
            (
                "what stays",
                "Personas, grants, receipts, and stored credentials remain in place",
            ),
        ],
        &[
            ("ember status", "Confirm the machine posture after removal"),
            (
                "ember explain uninstall",
                "Read the deeper integration-removal contract",
            ),
        ],
    )
}

pub(super) fn render_claude_help() -> String {
    render_help_card(
        "ember claude",
        "Launch Claude with Ember-managed env, PATH wiring, and session setup.",
        &[
            ("ember claude", "Launch on the default managed lane"),
            (
                "ember claude --delegated landing-page-edits",
                "Launch with one explicit delegation template attached",
            ),
            (
                "ember claude --strict --delegated landing-page-edits",
                "Launch a bounded lane: delegated authority with no out-of-scope fallback",
            ),
            (
                "ember claude --attach <runtime-persona-id>",
                "Attach to a live runtime after Ember shows its authority summary",
            ),
            (
                "ember claude --fork --delegated landing-page-edits",
                "Fork to a fresh runtime and reattest one delegation template",
            ),
            (
                "ember claude --host -- -p \"Reply with OK only.\"",
                "Run on the host lane",
            ),
            (
                "ember claude --isolated",
                "Force the isolated/container launcher path",
            ),
            (
                "ember claude --sandbox sandvault --worktree <name>",
                "Launch through the Sandvault runtime adapter",
            ),
        ],
        &[
            (
                "trailing args",
                "Forwarded to Claude on both host and isolated paths; also forwarded on sandbox paths",
            ),
            ("--host", "Force the host-resident launcher path"),
            (
                "--isolated",
                "Force Ember's isolated/container launcher path",
            ),
            (
                "--sandbox sandvault",
                "Use Sandvault's macOS user + sandbox-exec runtime adapter",
            ),
            (
                "--delegated <template>",
                "Attach one delegation template at launch; omit to open the selector",
            ),
            (
                "--attach <runtime-persona-id>",
                "Attach to an already-live Runtime Persona",
            ),
            ("--fork", "Open a fresh Runtime Persona explicitly"),
            (
                "--strict",
                "Deny out-of-scope authority instead of falling through to JIT approval",
            ),
            ("--backend <name>", "Requires `--isolated`"),
            ("--preset <name>", "Requires `--isolated`"),
        ],
        &[
            ("ember status", "Check readiness before launch"),
            ("ember doctor", "Diagnose blocked or degraded launches"),
            ("ember explain claude", "Read the deeper launcher contract"),
        ],
    )
}

pub(super) fn render_codex_help() -> String {
    render_help_card(
        "ember codex",
        "Launch Codex with Ember-managed env, PATH wiring, and session setup.",
        &[
            ("ember codex", "Launch on the default managed lane"),
            (
                "ember codex --delegated release-proof",
                "Launch with one explicit delegation template attached",
            ),
            (
                "ember codex --strict --delegated release-proof",
                "Launch a bounded lane: delegated authority with no out-of-scope fallback",
            ),
            (
                "ember codex --attach <runtime-persona-id>",
                "Attach to a live runtime after Ember shows its authority summary",
            ),
            (
                "ember codex --fork --delegated release-proof",
                "Fork to a fresh runtime and reattest one delegation template",
            ),
            ("ember codex --host", "Force the host lane"),
            (
                "ember codex --isolated",
                "Force the isolated/container launcher path",
            ),
            (
                "ember codex --sandbox sandvault --worktree <name>",
                "Launch through the Sandvault runtime adapter",
            ),
        ],
        &[
            (
                "auth",
                "Use `codex login` first; on a headless host use `codex login --device-auth`",
            ),
            (
                "isolated auth",
                "Reuses the host `~/.codex` auth state via bind-mount",
            ),
            (
                "--sandbox sandvault",
                "Use Sandvault's macOS user + sandbox-exec runtime adapter",
            ),
            (
                "--backend <name>",
                "Leave unset to auto-detect; requires `--isolated`",
            ),
            (
                "--delegated <template>",
                "Attach one delegation template at launch",
            ),
            (
                "--attach <runtime-persona-id>",
                "Attach to an already-live Runtime Persona",
            ),
            ("--fork", "Open a fresh Runtime Persona explicitly"),
            (
                "--strict",
                "Deny out-of-scope authority instead of falling through to JIT approval",
            ),
            ("--preset <name>", "Requires `--isolated`"),
            (
                "trailing args",
                "Forwarded to Codex on both host and isolated paths; also forwarded on sandbox paths",
            ),
        ],
        &[
            ("ember status", "Check readiness before launch"),
            ("ember doctor", "Diagnose blocked or degraded launches"),
            ("ember explain codex", "Read the deeper launcher contract"),
        ],
    )
}

pub(super) fn render_cursor_help() -> String {
    render_help_card(
        "ember cursor",
        "Launch Cursor with Ember-managed env, PATH wiring, and session setup.",
        &[
            ("ember cursor", "Launch on the host baseline lane"),
            (
                "ember cursor --delegated release-proof",
                "Launch with one explicit delegation template attached",
            ),
            (
                "ember cursor --strict --delegated release-proof",
                "Launch a bounded lane: delegated authority with no out-of-scope fallback",
            ),
            (
                "ember cursor --attach <runtime-persona-id>",
                "Attach to a live runtime after Ember shows its authority summary",
            ),
            (
                "ember cursor --fork --delegated release-proof",
                "Fork to a fresh runtime and reattest one delegation template",
            ),
            ("ember cursor --host", "Force the host lane"),
            (
                "ember cursor --worktree <name>",
                "Launch from an Ember-managed worktree",
            ),
        ],
        &[
            (
                "auth",
                "Cursor account/model auth remains Cursor-owned on this baseline lane",
            ),
            (
                "governance",
                "Ember registers the session and governs PATH-shadowed tools; it does not broker Cursor model spend",
            ),
            (
                "egress",
                "HTTPS_PROXY is injected only when the daemon returns a Cursor egress URL; ambient proxy env is stripped otherwise",
            ),
            ("--host", "Force the host-resident launcher path"),
            (
                "--isolated",
                "Reserved for a future governed loopback-projector mediation lane; currently returns an explicit error",
            ),
            (
                "--sandbox sandvault",
                "Reserved for future Cursor sandbox support; currently returns an explicit error",
            ),
            (
                "--delegated <template>",
                "Attach one delegation template at launch",
            ),
            (
                "--attach <runtime-persona-id>",
                "Attach to an already-live Runtime Persona",
            ),
            ("--fork", "Open a fresh Runtime Persona explicitly"),
            (
                "--strict",
                "Deny out-of-scope authority instead of falling through to JIT approval",
            ),
            ("trailing args", "Forwarded to Cursor on the host path"),
        ],
        &[
            ("ember status", "Check readiness before launch"),
            ("ember doctor", "Diagnose blocked or degraded launches"),
            ("ember explain cursor", "Read the deeper launcher contract"),
        ],
    )
}

pub(super) fn render_status_help() -> String {
    render_help_card(
        "ember status",
        "Show the current Ember posture and the most important next action.",
        &[
            ("ember status", "Show the compact readiness view"),
            ("ember status --json", "Emit machine-readable status"),
            ("ember doctor", "Open the deeper diagnosis and repair view"),
        ],
        &[
            ("--json", "Emit the structured status contract"),
            ("--troubleshoot", "Show the older bounded repair appendix"),
        ],
        &[
            ("ember doctor", "Deep diagnosis and repair routing"),
            (
                "ember explain status",
                "Read how posture and repair flow work",
            ),
        ],
    )
}

pub(super) fn render_doctor_help() -> String {
    render_help_card(
        "ember doctor",
        "Diagnose the current Ember posture and route you to the right repair path.",
        &[
            ("ember doctor", "Show the deep diagnosis view"),
            ("ember status", "Show the compact readiness view"),
            (
                "ember explain error E-DAEMON-NOT-INSTALLED",
                "Read a specific error manual",
            ),
        ],
        &[(
            "--json",
            "Emit the status-shaped machine contract for automation",
        )],
        &[
            ("ember status", "Compact posture and next-step view"),
            ("ember explain doctor", "Read the deeper diagnosis contract"),
        ],
    )
}

pub(super) fn render_github_help() -> String {
    render_help_card(
        "ember github",
        "Inspect or repair the GitHub App lane used by Ember's brokered GitHub flows.",
        &[
            ("ember github status", "Show the current GitHub posture"),
            ("ember github setup", "Walk the local GitHub App setup flow"),
        ],
        &[],
        &[
            ("ember doctor", "Diagnose broader launch or repair issues"),
            (
                "ember explain github setup",
                "Read the deeper setup contract",
            ),
        ],
    )
}

pub(super) fn render_github_setup_help() -> String {
    render_help_card(
        "ember github setup",
        "Store or repair the local GitHub App credential triple for the HTTPS/App lane.",
        &[
            (
                "ember github setup --from-manifest",
                "Register an operator-owned App through GitHub's manifest flow",
            ),
            (
                "ember github setup",
                "Use the manifest flow in an interactive terminal; prompt for fields otherwise",
            ),
            (
                "ember github setup --pem-file key.pem --app-id 123 --installation-id 456 --slug my-app",
                "Run fully specified without prompt fallback",
            ),
        ],
        &[
            (
                "--from-manifest",
                "Create a new operator-owned GitHub App through GitHub",
            ),
            ("--pem-file <path>", "Path to the App private key PEM"),
            ("--app-id <id>", "Numeric GitHub App ID"),
            ("--installation-id <id>", "Numeric GitHub installation ID"),
            ("--slug <name>", "Human-readable App slug"),
            (
                "--replace",
                "Replace an existing stored triple for the same App",
            ),
        ],
        &[
            ("ember github status", "Confirm the lane is ready afterward"),
            (
                "ember explain github setup",
                "Read the deeper setup contract",
            ),
        ],
    )
}

pub(super) fn render_grant_help() -> String {
    render_help_card(
        "ember grant",
        "Issue, inspect, and repair access grants without wading through the full daemon model.",
        &[
            ("ember grant create", "Issue a new grant"),
            ("ember grant list", "Inspect active grants"),
            (
                "ember grant budget <id>",
                "Check usage and remaining budget",
            ),
            (
                "ember grant evaluate --grant <id> --attempt attempt.toml",
                "Preflight a spend attempt against one grant",
            ),
        ],
        &[
            (
                "create",
                "Mint a new grant with scope, TTL, and optional budgets",
            ),
            ("show", "Inspect one grant in a detail-first renderer"),
            (
                "list --kind spend",
                "Render payment statements as spend grants",
            ),
            (
                "evaluate",
                "Preflight one spend attempt via the daemon evaluator",
            ),
            ("extend", "Add TTL or budget to an existing grant"),
            ("revoke", "Terminate a grant and emit its terminal witness"),
            ("delegate", "Mint a narrowed child grant for a sub-agent"),
            (
                "--json",
                "Emit machine-readable grant output where supported",
            ),
        ],
        &[
            ("ember explain grant", "Read the deeper grant model"),
            ("ember receipt list", "Find signed grant witnesses"),
        ],
    )
}

pub(super) fn render_grant_create_help() -> String {
    render_help_card(
        "ember grant create",
        "Issue a new access grant with explicit scope, TTL, and optional budgets.",
        &[
            (
                "ember grant create --persona p1 --credential github/app --scope repo:read --ttl 30m",
                "Issue a time-bounded grant",
            ),
            (
                "ember grant create --persona p1 --credential anthropic/oauth-token --scope llm:generate --ttl 2h --budget-tokens 20000 --budget-usd 0.50",
                "Issue a budgeted LLM grant",
            ),
            (
                "ember grant create --persona p1 --kind spend --vendor clearbit --max-cents 4900 --window 24h --hard-cap 25000",
                "Issue a spend grant rendered from Statement<Payment>",
            ),
        ],
        &[
            ("--persona <id>", "Grant owner persona"),
            (
                "--credential <name>",
                "Credential or secret lane being delegated",
            ),
            ("--scope <value>", "Authority scope being granted"),
            (
                "--kind spend",
                "Render the grant as a payment-backed spend lane",
            ),
            (
                "--vendor / --max-cents / --window / --hard-cap",
                "Spend lane vendor, per-attempt threshold, lifetime window, and total cap",
            ),
            (
                "--ttl <duration>",
                "Lifetime such as `30m`, `2h`, or bare seconds",
            ),
            (
                "--standing",
                "Create a standing parent grant for later delegation",
            ),
            (
                "budget flags",
                "Cap tokens, USD, requests, or wall-clock seconds",
            ),
        ],
        &[
            ("ember grant list", "Confirm the grant is active"),
            ("ember explain grant", "Read the grant and delegation model"),
        ],
    )
}

pub(super) fn render_approval_help() -> String {
    render_help_card(
        "ember approval",
        "Inspect and resolve approval requests without reading the full policy machinery.",
        &[
            ("ember approval list", "Show pending approval requests"),
            ("ember approval approve <id>", "Approve one request"),
            ("ember approval narrow <id>", "Approve with reduced scope"),
        ],
        &[
            ("approve", "Approve the exact pending request"),
            ("deny", "Reject the request outright"),
            ("narrow", "Approve with a smaller authority envelope"),
            (
                "--json",
                "Emit machine-readable approval output where supported",
            ),
        ],
        &[
            (
                "ember explain approval",
                "Read the approval and standing-grant model",
            ),
            ("ember grant list", "Inspect grants created by approvals"),
        ],
    )
}

pub(super) fn render_approval_approve_help() -> String {
    render_help_card(
        "ember approval approve",
        "Approve one pending request, optionally turning it into a standing grant.",
        &[
            (
                "ember approval approve apr_123",
                "Approve the pending request exactly once",
            ),
            (
                "ember approval approve apr_123 --always --ttl 30d",
                "Create a standing grant for future matching requests",
            ),
        ],
        &[
            ("<id>", "Approval request ID from `ember approval list`"),
            ("--always", "Create a standing grant for future matches"),
            ("--ttl <duration>", "Standing-grant TTL, default `30d`"),
        ],
        &[
            ("ember approval list", "Return to the pending queue"),
            (
                "ember explain approval",
                "Read when `--always` is the right move",
            ),
        ],
    )
}

pub(super) fn render_audit_help() -> String {
    render_help_card(
        "ember audit",
        "Inspect the audit chain, quarantine posture, and exported evidence without parsing internal ADR copy.",
        &[
            ("ember audit show", "Show recent audit events"),
            ("ember audit summary", "Aggregate receipt-backed audit rows"),
            ("ember audit verify", "Verify the audit chain"),
            ("ember audit explain <id>", "Explain one decision chain"),
        ],
        &[
            (
                "verify",
                "Check audit-chain integrity and quarantine relevance",
            ),
            ("summary", "Aggregate by receipt kind and persona/session"),
            ("query", "Query receipt-backed audit rows"),
            ("usage", "Inspect audit storage footprint"),
            (
                "--json",
                "Emit machine-readable audit output where supported",
            ),
        ],
        &[
            ("ember doctor", "Diagnose quarantine or repair posture"),
            (
                "ember explain audit",
                "Read how audit verification fits the operator flow",
            ),
        ],
    )
}

pub(super) fn render_audit_verify_help() -> String {
    render_help_card(
        "ember audit verify",
        "Verify the audit chain and surface whether repair or quarantine follow-up is needed.",
        &[
            ("ember audit verify", "Walk the full audit chain"),
            (
                "ember audit verify --tail 500",
                "Verify only the most recent rows",
            ),
            (
                "ember audit verify --since 7d",
                "Run the seven-day verifier using the full-chain walker",
            ),
            (
                "ember audit verify --json",
                "Emit a machine-readable verdict",
            ),
        ],
        &[
            ("--tail <n>", "Limit the walk to the most recent `n` rows"),
            (
                "--since <WINDOW>",
                "Compatibility window (`1d`, `7d`, `24h`, or ISO-8601); currently walks the full chain",
            ),
            ("--json", "Emit the verification verdict for automation"),
        ],
        &[
            ("ember doctor", "Open the repair lane if verification fails"),
            ("ember explain audit", "Read the audit and quarantine model"),
        ],
    )
}

pub(super) fn render_receipt_help() -> String {
    render_help_card(
        "ember receipt",
        "Inspect and verify signed grant witnesses and exported receipt artifacts.",
        &[
            ("ember receipt list", "Show recent receipts"),
            ("ember receipt show <id>", "Inspect one receipt in full"),
            (
                "ember receipt verify",
                "Verify a receipt by ID or exported JSON",
            ),
        ],
        &[
            ("export", "Write a signed receipt artifact for sharing"),
            (
                "verify",
                "Check a receipt signature or exported tree offline",
            ),
            ("tree", "Render or export a delegated authority graph"),
            ("rollup", "Aggregate construct-invocation sub-receipts"),
        ],
        &[
            (
                "ember explain receipt",
                "Read why receipts are the durable witness",
            ),
            ("ember audit query", "Cross-check receipt-backed audit rows"),
        ],
    )
}

pub(super) fn render_receipt_verify_help() -> String {
    render_help_card(
        "ember receipt verify",
        "Verify a receipt by local ID, exported JSON file, or offline tree export.",
        &[
            (
                "ember receipt verify rct_123",
                "Verify a receipt from the local daemon store",
            ),
            (
                "ember receipt verify --file receipt.json --pubkey <hex>",
                "Verify an exported receipt offline",
            ),
            (
                "ember receipt verify --tree receipt-tree.json --offline",
                "Verify a tree export without daemon RPC",
            ),
        ],
        &[
            ("[id]", "Local receipt ID from `ember receipt list`"),
            ("--file <path>", "Verify one exported receipt JSON file"),
            (
                "--pubkey <hex>",
                "Override the expected signer key for offline files",
            ),
            (
                "--tree <path>",
                "Verify a tree export from `ember receipt tree --export`",
            ),
            (
                "--offline",
                "Document daemon-free verification intent for tree exports",
            ),
            (
                "--materialization <id>",
                "Verify a construct rollup by materialization ID",
            ),
        ],
        &[
            (
                "ember receipt show <id>",
                "Inspect the full receipt payload",
            ),
            ("ember explain receipt", "Read the durable witness model"),
        ],
    )
}

pub(super) fn render_trust_help() -> String {
    render_help_card(
        "ember trust",
        "Inspect trust roots, explain verification chains, and manage exportable key backups.",
        &[
            ("ember trust list", "Show current trust roots"),
            ("ember trust show <fingerprint>", "Inspect one trust root"),
            (
                "ember trust explain <artifact>",
                "Explain how an artifact verifies",
            ),
        ],
        &[
            ("list", "Show the active trust roots"),
            ("show", "Inspect one root by fingerprint or prefix"),
            ("backup", "Export encrypted keychain-held Persona backups"),
            (
                "restore",
                "Restore keychain-held operator/workstation Personas",
            ),
        ],
        &[
            (
                "ember explain trust",
                "Read the deeper trust and verification model",
            ),
            (
                "ember receipt verify",
                "Verify a signed witness against a trust anchor",
            ),
        ],
    )
}

pub(super) fn render_daemon_help() -> String {
    render_help_card(
        "ember daemon",
        "Install, inspect, and repair the managed daemon without scanning internal lifecycle jargon.",
        &[
            ("ember daemon status", "Inspect the managed daemon"),
            (
                "sudo ember daemon install",
                "Install or repair the managed daemon",
            ),
            ("ember daemon reload", "Gracefully restart the daemon"),
        ],
        &[
            (
                "status",
                "Inspect the current daemon process and socket posture",
            ),
            (
                "install",
                "Install or repair the managed separate-uid daemon",
            ),
            ("stop", "Stop a running daemon"),
            (
                "migrate",
                "Move a single-uid install onto the separate-uid posture",
            ),
            ("diagnose", "Inspect deeper daemon-specific failure modes"),
        ],
        &[
            (
                "ember doctor",
                "Use the higher-level machine diagnosis lane",
            ),
            ("ember explain daemon", "Read the managed daemon model"),
        ],
    )
}

pub(super) fn render_recover_help() -> String {
    render_help_card(
        "ember recover",
        "Open Ember's recovery surface by failure class or lifecycle when `doctor` is not enough.",
        &[
            (
                "ember recover diagnose",
                "Inspect daemon, vault, persona, grant, and audit posture",
            ),
            (
                "ember recover daemon --help",
                "Inspect daemon failure-class recovery verbs",
            ),
            (
                "ember recover audit-chain --dry-run",
                "Preview guided audit-chain lifecycle recovery",
            ),
            (
                "ember recover grant abandon <grant-id> --reason <text>",
                "Plan explicit grant abandonment with provenance",
            ),
            (
                "ember recover explain F-DAEMON-2",
                "Print one runbook section by failure code",
            ),
        ],
        &[
            (
                "daemon",
                "Recover process, socket, or daemon-state failures",
            ),
            (
                "authority",
                "Recover delegated-authority, identity, or keychain state",
            ),
            ("broker", "Recover provider credential and cache posture"),
            ("audit", "Recover audit-chain verification or repair state"),
            ("install", "Recover install, shadow-path, or binary posture"),
            (
                "lifecycle",
                "diagnose, audit-chain, persona, grant, vault, trust",
            ),
        ],
        &[
            ("ember doctor", "Start with the adaptive diagnosis surface"),
            (
                "ember explain recover",
                "Read when to use class recovery versus doctor",
            ),
        ],
    )
}

pub(super) fn render_recover_diagnose_help() -> String {
    render_help_card(
        "ember recover diagnose",
        "Walk the recovery lifecycle probes and print one bounded next step.",
        &[
            (
                "ember recover diagnose",
                "Emit a recovery.action receipt and inspect local posture",
            ),
            (
                "ember recover audit-chain --dry-run",
                "Follow up when audit verification or quarantine is not green",
            ),
            (
                "ember recover vault --dry-run",
                "Follow up when the vault lane is locked or unavailable",
            ),
        ],
        &[
            ("daemon", "Composes the daemon status RPC"),
            ("vault", "Composes the vault status RPC"),
            ("persona/grant", "Composes daemon journal summaries"),
            ("audit", "Composes audit verify"),
            (
                "receipt",
                "Refuses without a daemon-signed recovery.action receipt",
            ),
        ],
        &[
            ("ember recover --help", "Return to the recovery map"),
            ("ember explain recover", "Read the recovery model"),
        ],
    )
}

pub(super) fn render_recover_audit_chain_help() -> String {
    render_help_card(
        "ember recover audit-chain",
        "Plan and execute guided audit-chain lifecycle recovery.",
        &[
            (
                "ember recover audit-chain --dry-run",
                "Inspect daemon verifier state and print a confirmation token",
            ),
            (
                "ember recover audit-chain --confirm <token> --from-row-id <id> --operator-pubkey ed25519:<hex> --operator-signature-hex <hex> --current-chain-tip-hash <hash> --daemon-identity-root-fingerprint <hash>",
                "Execute truncate-after-row through the daemon repair RPC",
            ),
        ],
        &[
            ("clean", "No mutation; receipt records the no-op plan"),
            (
                "quarantined break",
                "Routes to ADR 174 operator-co-signed truncate-after-row",
            ),
            (
                "cordoned legacy rows",
                "Routes to the ADR 176 migration acknowledgement path",
            ),
            (
                "receipt",
                "Refuses without a daemon-signed recovery.action plan receipt",
            ),
        ],
        &[
            ("ember audit verify", "Inspect the raw verifier outcome"),
            (
                "ember recover diagnose",
                "Return to the broader recovery lifecycle walk",
            ),
        ],
    )
}

pub(super) fn render_recover_explain_help() -> String {
    render_help_card(
        "ember recover explain",
        "Print the recovery runbook section for one failure code.",
        &[
            (
                "ember recover explain F-DAEMON-2",
                "Show the daemon runbook entry for that failure",
            ),
            (
                "ember recover explain f-audit-1",
                "F-codes are case-insensitive",
            ),
        ],
        &[
            ("<f-code>", "For example `F-DAEMON-2` or `F-AUDIT-1`"),
            (
                "source",
                "Reads the matching section from `docs/runbook/recovery.md`",
            ),
        ],
        &[
            ("ember recover --help", "Return to the recovery class map"),
            ("ember doctor", "Use the adaptive diagnosis surface first"),
        ],
    )
}

pub(super) fn render_recover_grant_help() -> String {
    render_help_card(
        "ember recover grant",
        "Guided grant lifecycle recovery: abandon a broken grant chain with provenance.",
        &[
            (
                "ember recover grant abandon <grant-id> --reason <text>",
                "Print the abandonment plan and confirmation token",
            ),
            (
                "ember recover grant abandon <grant-id> --reason <text> --execute --confirm <token>",
                "Mark the grant abandoned through the daemon recovery lane",
            ),
        ],
        &[
            (
                "abandon",
                "Does not rebuild or widen the chain; records why the grant is dead",
            ),
            (
                "confirmation",
                "Execution requires retyping the dry-run token",
            ),
            (
                "receipt",
                "Both planning and execution emit daemon-signed recovery.action receipts",
            ),
        ],
        &[
            (
                "ember grant show <grant-id>",
                "Inspect the grant before planning recovery",
            ),
            (
                "ember recover audit-chain --dry-run",
                "Use when journal evidence is missing or inconsistent",
            ),
        ],
    )
}

pub(super) fn render_recover_vault_help() -> String {
    render_help_card(
        "ember recover vault",
        "Guided vault lifecycle recovery: retry unlock, review key-rotation guidance, verify backup.",
        &[
            (
                "ember recover vault unlock-retry",
                "Retry vault unlock up to 3 times with clear backoff messaging",
            ),
            (
                "ember recover vault unlock-retry --max-attempts 5",
                "Override the default attempt budget",
            ),
            (
                "ember recover vault rotate-key",
                "Print key-rotation plan and contingency (dry-run guidance only)",
            ),
            (
                "ember recover vault verify-backup <path>",
                "Validate a vault backup file (format, signature, key coverage)",
            ),
        ],
        &[
            (
                "unlock-retry",
                "Composes the vault_unlock daemon RPC in a bounded retry loop",
            ),
            (
                "rotate-key",
                "Guidance only — execution deferred to S5b (ADR 198 primitive needed)",
            ),
            (
                "verify-backup",
                "Read-only; emits a recovery.action receipt on pass or fail",
            ),
        ],
        &[
            (
                "ember recover diagnose",
                "Return to the umbrella recovery walk",
            ),
            ("ember vault status", "Check current vault posture"),
        ],
    )
}

pub(super) fn render_recover_trust_help() -> String {
    render_help_card(
        "ember recover trust",
        "Audit the local trust-root list for provenance gaps against the audit log.",
        &[
            (
                "ember recover trust list-audit",
                "Walk each trust root and flag any without a matching audit-log event",
            ),
            (
                "ember recover trust list-audit --since 2026-05-01T00:00:00Z",
                "Limit the audit-log scan to events since a timestamp",
            ),
        ],
        &[
            (
                "list-audit",
                "Composes trust_list + audit_log_query; read-only; emits recovery.action receipt",
            ),
            (
                "re-attest",
                "Retired for v0.3.0 — use ADR 206 device enrollment/replacement",
            ),
        ],
        &[
            ("ember trust list", "Inspect the raw trust-root set"),
            (
                "ember audit query --action-prefix trust",
                "Inspect trust-related audit events directly",
            ),
        ],
    )
}

pub(super) fn render_persona_help() -> String {
    render_help_card(
        "ember persona",
        "Create, inspect, and revoke agent personas used by grants and delegated authority.",
        &[
            ("ember persona create --name researcher", "Create a persona"),
            ("ember persona list", "Show existing personas"),
            ("ember persona revoke per_123", "Revoke one persona"),
        ],
        &[
            ("create", "Mint a new persona identity"),
            ("list", "Inspect the local persona set"),
            (
                "revoke",
                "Deactivate a persona that should stop issuing work",
            ),
        ],
        &[
            ("ember grant create", "Issue authority to a persona"),
            (
                "ember explain persona",
                "Read how personas fit grants and delegated authority",
            ),
        ],
    )
}

pub(super) fn render_vault_help() -> String {
    render_help_card(
        "ember vault",
        "Store, retrieve, export, and re-lock credentials without leaking secrets through argv.",
        &[
            (
                "echo \"$TOKEN\" | ember vault add --name github/app --stdin",
                "Store a secret safely from stdin",
            ),
            ("ember vault list", "Inspect stored credential names"),
            ("ember vault lock", "Re-lock the current vault session"),
        ],
        &[
            (
                "add / put",
                "Safe-input credential writes; `--value` is intentionally refused",
            ),
            ("get", "Retrieve a stored value"),
            (
                "export / import",
                "Move encrypted credential sets between hosts",
            ),
            (
                "lock / unlock",
                "Control the current vault session explicitly",
            ),
        ],
        &[
            (
                "ember explain vault",
                "Read the safe-input and vault-session model",
            ),
            ("ember doctor", "Diagnose blocked vault or daemon posture"),
        ],
    )
}

pub(super) fn render_vault_add_help() -> String {
    render_help_card(
        "ember vault add",
        "Add a credential with safe input modes instead of leaking the secret in shell history.",
        &[
            (
                "echo \"$TOKEN\" | ember vault add --name github/app --stdin",
                "Read the secret from stdin",
            ),
            (
                "ember vault add --name anthropic-key --file ./token.txt --delete-source",
                "Read from a file and securely remove the source afterward",
            ),
        ],
        &[
            ("--name <value>", "Credential key to store"),
            ("--stdin", "Read from stdin; best fit for pipes and scripts"),
            (
                "--file <path>",
                "Read from a file without putting the value on argv",
            ),
            (
                "--require-biometric",
                "Require fresh presence on every future read",
            ),
            (
                "argv secrets",
                "The legacy `--value` form is refused on purpose",
            ),
        ],
        &[
            ("ember vault list", "Confirm the credential name is present"),
            (
                "ember explain vault",
                "Read the safe-input credential model",
            ),
        ],
    )
}

pub(super) fn render_sandbox_help() -> String {
    render_help_card(
        "ember sandbox",
        "Create and inspect sandboxes for agent work without starting from raw container flags.",
        &[
            ("ember sandbox list", "Show existing sandboxes"),
            (
                "ember sandbox create --name demo",
                "Create a new sandbox with the default image",
            ),
            (
                "ember sandbox run-scion --task DEPLOY-PREVIEW --dry-run",
                "Preview the SCION orchestration flow",
            ),
        ],
        &[
            ("create / delete / stop", "Manage sandbox lifecycle"),
            ("exec", "Run a command inside one sandbox"),
            ("run", "Launch a one-off agent task with grant wiring"),
            ("run-scion", "Drive the SCION orchestration loop"),
        ],
        &[
            (
                "ember explain sandbox",
                "Read how sandbox work fits the operator model",
            ),
            ("ember grant create", "Inspect adjacent authority controls"),
        ],
    )
}

pub(super) fn render_config_help() -> String {
    render_help_card(
        "ember config",
        "Inspect the current config file and where Ember is reading it from.",
        &[
            ("ember config show", "Print the current effective config"),
            ("ember config path", "Print the config file path"),
        ],
        &[],
        &[
            ("ember status", "Return to posture and next-step view"),
            (
                "ember explain config",
                "Read how config fits the operator flow",
            ),
        ],
    )
}

pub(super) fn render_headless_help() -> String {
    render_help_card(
        "ember headless",
        "Run unattended work as a bounded strict + delegated lane on an attested device.",
        &[
            (
                "ember headless preflight --input tasks.json",
                "Check queued actions and declared materials before enrollment",
            ),
            (
                "ember headless enroll --input tasks.json --duration 4h",
                "Create the bounded unattended lane",
            ),
            ("ember headless status", "Show the active enrollment"),
        ],
        &[
            ("enroll", "Attach short-lived delegated authority"),
            ("revoke", "Terminate an active enrollment"),
            ("status", "Inspect the current enrollment or `none`"),
            (
                "preflight",
                "Compare queued scope against the enrollment template",
            ),
        ],
        &[
            (
                "ember explain headless",
                "Read the unattended delegation model",
            ),
            ("ember doctor", "Diagnose blocked or degraded posture"),
        ],
    )
}

pub(super) fn render_headless_enroll_help() -> String {
    render_help_card(
        "ember headless enroll",
        "Create a strict + delegated unattended lane from a declared task queue.",
        &[
            (
                "ember headless preflight --input tasks.json",
                "Check coverage before opening the unattended window",
            ),
            (
                "ember headless enroll --input tasks.json --duration 4h",
                "Enroll with the default short-lived window",
            ),
            (
                "ember headless enroll --input tasks.json --persona ops-bot --duration 3d -y",
                "Enroll a bot persona without the prompt",
            ),
        ],
        &[
            (
                "--input <tasks.json>",
                "Required queued task declaration used to derive authority and material",
            ),
            (
                "--duration <value>",
                "Examples: `4h`, `3d`, `1w`; current ceiling is `7d`",
            ),
            ("--persona <id>", "Target a persona other than `main`"),
            ("-y, --yes", "Skip the interactive confirmation prompt"),
        ],
        &[
            ("ember headless status", "Confirm the active enrollment"),
            (
                "ember explain headless",
                "Read when headless delegation is the right fit",
            ),
        ],
    )
}

pub(super) fn render_explain_help() -> String {
    render_help_card(
        "ember explain",
        "Show the deeper manual for a command, delegated-authority surface, or error code.",
        &[
            ("ember explain init", "Read the full setup flow"),
            ("ember explain status", "Read the posture and repair model"),
            ("ember explain grant", "Read the grant and delegation model"),
            (
                "ember explain error E-DAEMON-NOT-INSTALLED",
                "Explain a specific error and recovery path",
            ),
        ],
        &[],
        &[
            ("ember --help", "Show the compact command map"),
            ("ember doctor", "Open the deep diagnosis surface"),
        ],
    )
}

pub(super) fn render_explain_topic(topic: &[String]) -> Result<String, String> {
    let normalized = topic
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Ok(render_explain_help());
    }

    let key = normalized.join(" ").to_ascii_lowercase();
    let text = match key.as_str() {
        "init" => {
            "ember explain init\n\nWhat it does\n  Sets up the local daemon, persona wiring, and launcher integration for Claude, Codex, or Cursor.\n\nWhat it may change\n  - local Ember config\n  - daemon install state\n  - ~/.claude/settings.json or ~/.codex/hooks.json\n  - stored provider credentials when you choose to save them\n  - Cursor baseline persona/grant state; Cursor account/model auth remains Cursor-owned\n\nHappy path\n  1. Install or repair the daemon\n  2. Patch the selected launcher integration\n  3. Check GitHub readiness\n  4. End on the launcher command you should run next\n\nCommon commands\n  ember init --for claude\n  ember init --for codex\n  ember init --for cursor\n\nRecovery\n  ember status\n  ember doctor\n  ember github setup"
        }
        "status" => {
            "ember explain status\n\nWhat it does\n  Shows the current Ember posture and the most important next action.\n\nHow to read it\n  - Ready: launch work can proceed\n  - Needs attention: one concrete setup or repair step is blocking the happy path\n  - Running (quarantined): write-class work is blocked until audit repair completes\n\nRelated surfaces\n  ember doctor\n  ember status --json\n  ember explain doctor"
        }
        "doctor" => {
            "ember explain doctor\n\nWhat it does\n  Opens Ember's deep diagnosis lane for the current machine.\n\nWhen to use it\n  - status says the machine needs attention\n  - a launcher or broker command fails and points you here\n  - you want the next repair steps, not just the posture headline\n\nRelated surfaces\n  ember status\n  ember explain error E-DAEMON-NOT-INSTALLED"
        }
        "uninstall" => {
            "ember explain uninstall\n\nWhat it does\n  Removes Ember's launcher integration for Claude, Codex, or Cursor without deleting persona, grant, receipt, or vault state.\n\nWhat changes\n  - Claude path: removes the managed patch Ember added to `~/.claude/settings.json`\n  - Codex path: removes the managed hook block Ember added to `~/.codex/hooks.json`\n  - Cursor path: no Cursor config is mutated; persona/grant state stays in place\n\nRelated surfaces\n  ember uninstall --for claude\n  ember uninstall --for codex\n  ember uninstall --for cursor\n  ember status"
        }
        "grant" => {
            "ember explain grant\n\nWhat it does\n  Grants delegate authority from a persona to a credential and scope for a bounded period of time.\n\nHow to think about it\n  - create: mint a fresh authority envelope\n  - extend: add more time or budget to an active grant\n  - revoke / expire: move a grant to terminal state and emit its witness\n  - delegate: mint a narrower child grant from a standing or active parent\n\nRelated surfaces\n  ember grant create\n  ember grant list\n  ember receipt list"
        }
        "delegation" => {
            "ember explain delegation\n\nWhat it does\n  Delegated authority is a narrower child grant minted from a standing or active parent grant. As of the unified authority model (ADR 205 §6) it is created, inspected, and revoked through `ember grant` — there is no separate `ember delegation` command.\n\nHow to think about it\n  - delegate: `ember grant` mints a narrower child grant from a parent\n  - inspect: `ember grant list` shows active grants and the authority they delegate\n  - revoke: `ember grant revoke` cuts off a grant and the authority it delegated\n\nRelated surfaces\n  ember grant list\n  ember grant revoke\n  ember explain grant"
        }
        "approval" => {
            "ember explain approval\n\nWhat it does\n  Approval requests are the human checkpoint between a proposed authority use and the grant that would authorize it.\n\nDecision model\n  - approve: allow exactly what was requested\n  - narrow: allow a reduced authority envelope\n  - deny: refuse the request outright\n  - approve --always: convert repeated friction into a standing grant intentionally\n\nRelated surfaces\n  ember approval list\n  ember grant list\n  ember receipt list"
        }
        "audit" => {
            "ember explain audit\n\nWhat it does\n  Audit surfaces the durable evidence chain behind Ember decisions, grants, and repairs.\n\nWhy verify matters\n  `ember audit verify` checks whether the local audit chain is intact. When verification fails, write-class operations may be quarantined until repair completes.\n\nRelated surfaces\n  ember audit verify\n  ember doctor\n  ember receipt verify"
        }
        "recover" => {
            "ember explain recover\n\nWhat it does\n  `ember recover` is the operator recovery surface. Failure-class verbs keep the ADR 161 runbook bridge live; lifecycle verbs add ADR 195 guided recovery for daemon, audit, persona, grant, vault, and trust posture.\n\nHow to use it\n  - start with `ember doctor` for adaptive diagnosis\n  - use `ember recover diagnose` when the failure class is not obvious\n  - move to `ember recover <class>` when you need class-specific actions\n  - use `ember recover explain F-CODE` to print the exact runbook section\n\nRelated surfaces\n  ember doctor\n  ember recover diagnose\n  ember recover explain F-DAEMON-2\n  docs/runbook/recovery.md"
        }
        "receipt" => {
            "ember explain receipt\n\nWhat it does\n  Receipts are the signed witness artifacts emitted when grants or delegated authority reach meaningful terminal or exportable states.\n\nWhy they matter\n  The receipt is the durable artifact you can export, verify offline, and hand to a third party as evidence of what happened.\n\nRelated surfaces\n  ember receipt list\n  ember receipt show <id>\n  ember receipt verify"
        }
        "persona" => {
            "ember explain persona\n\nWhat it does\n  Personas are the local identities Ember uses as the subject for grants, delegated authority, and related authority-bearing actions.\n\nOperator jobs\n  - create a persona for a new agent or lane\n  - inspect the current persona set\n  - revoke a persona that should stop receiving authority\n\nRelated surfaces\n  ember persona create\n  ember persona list\n  ember grant create"
        }
        "vault" => {
            "ember explain vault\n\nWhat it does\n  The vault stores local credential material behind Ember's managed authority and unlock posture.\n\nInput model\n  Safe write paths use stdin or files. Passing secrets on argv is intentionally refused because it leaks into shell history and process listings.\n\nRelated surfaces\n  ember vault add\n  ember vault list\n  ember vault lock"
        }
        "sandbox" => {
            "ember explain sandbox\n\nWhat it does\n  Sandboxes provide bounded execution environments for agent work, with Ember authority and grant surfaces sitting alongside the container lifecycle.\n\nOperator jobs\n  - create or inspect sandboxes\n  - exec into one sandbox deliberately\n  - run a grant-backed or SCION-backed task flow\n\nRelated surfaces\n  ember sandbox list\n  ember sandbox create\n  ember sandbox run-scion"
        }
        "config" => {
            "ember explain config\n\nWhat it does\n  Config surfaces the effective local configuration Ember is reading and where that file lives.\n\nWhy it stays small\n  This is an inspection surface, not the primary teaching lane. Use it when posture or path questions require the literal config source.\n\nRelated surfaces\n  ember config show\n  ember config path\n  ember status"
        }
        "trust" => {
            "ember explain trust\n\nWhat it does\n  Trust surfaces the roots, Principals, and verification chains Ember relies on when it proves artifacts back to an operator-controlled anchor.\n\nOperator jobs\n  - inspect active trust posture\n  - explain how an artifact verifies\n  - backup or restore exportable keychain-held material deliberately\n\nRelated surfaces\n  ember trust list\n  ember trust explain\n  ember receipt verify"
        }
        "daemon" => {
            "ember explain daemon\n\nWhat it does\n  The managed daemon owns durable state, policy enforcement, receipt emission, and session registration for the main Ember operator path.\n\nOperator jobs\n  - install or repair the managed daemon\n  - inspect daemon posture\n  - reload after configuration or lane changes\n\nRelated surfaces\n  ember daemon status\n  ember doctor\n  ember status"
        }
        "headless" => {
            "ember explain headless\n\nWhat it does\n  Headless is an unattended operating context, not another authority posture. A bounded headless lane runs as strict + delegated: it gets one short-lived delegated subset and denies out-of-scope work instead of prompting while you are away.\n\nHow to use it\n  - declare queued tasks and their materials in a tasks JSON file\n  - preflight the file to see missing action or material coverage\n  - enroll with the same file and an explicit TTL\n  - inspect receipts, then revoke or let the enrollment expire\n\nRelated surfaces\n  ember headless preflight --input tasks.json\n  ember headless enroll --input tasks.json --duration 4h\n  ember headless status\n  ember receipt list"
        }
        "github" => {
            "ember explain github\n\nWhat it does\n  GitHub surfaces the local transport posture Ember uses for brokered GitHub actions.\n\nOperator jobs\n  - inspect whether the App lane is ready\n  - set up or repair the local App credential triple\n  - return to doctor when GitHub issues are only part of a broader problem\n\nRelated surfaces\n  ember github status\n  ember github setup\n  ember doctor"
        }
        "claude" => {
            "ember explain claude\n\nWhat it does\n  Launches Claude with Ember-managed PATH wiring and session setup.\n\nLauncher model\n  - default lane: managed prod daemon\n  - host lane: explicit `--host`\n  - isolated lane: explicit `--isolated`\n\nNotes\n  Trailing Claude args are forwarded on both host and isolated paths.\n  `--backend` and `--preset` only apply with `--isolated`.\n\nRelated surfaces\n  ember status\n  ember doctor"
        }
        "codex" => {
            "ember explain codex\n\nWhat it does\n  Launches Codex with Ember-managed PATH wiring and session setup.\n\nAuth model\n  Codex keeps its native login lane. Use `codex login` first, or `codex login --device-auth` on a headless host.\n\nLauncher model\n  - default lane: managed prod daemon\n  - host lane: explicit `--host`\n  - isolated lane: explicit `--isolated`\n\nRelated surfaces\n  ember status\n  ember doctor"
        }
        "cursor" => {
            "ember explain cursor\n\nWhat it does\n  Launches Cursor with Ember-managed PATH wiring and session setup.\n\nAuth model\n  Cursor account/model auth remains Cursor-owned on the baseline lane. Ember does not broker Cursor model spend unless a future loopback-projector mediation mode is explicitly designed.\n\nLauncher model\n  - default lane: host baseline through the managed prod daemon\n  - host lane: explicit `--host`\n  - isolated and Sandvault lanes: reserved; currently return explicit errors\n\nGovernance boundary\n  Ember governs session registration, delegated authority posture, and PATH-shadowed tools. Cursor's upstream model credential stays client-side.\n\nEgress boundary\n  `ember cursor` strips ambient proxy env and injects `HTTPS_PROXY` only from a daemon-returned `cursor_egress_proxy_url`. Current daemon releases do not return that field yet, so this is a typed seam for the future egress endpoint, not a governed model-spend claim.\n\nRelated surfaces\n  ember status\n  ember doctor"
        }
        "github setup" => {
            "ember explain github setup\n\nWhat it does\n  Registers or stores the GitHub App credentials Ember needs for the HTTPS/App lane.\n\nManifest flow\n  `ember github setup --from-manifest` starts GitHub's App-manifest flow on a 127.0.0.1 callback, exchanges the returned code for the App credential bundle, and keeps private key material out of terminal output.\n\nDirect recovery inputs\n  - App private key PEM\n  - numeric App ID\n  - numeric installation ID\n  - App slug\n\nAfter success\n  Re-run `ember github status` to confirm the lane is ready.\n\nRelated surfaces\n  ember github status\n  ember doctor"
        }
        "error e-daemon-not-installed" => {
            "ember explain error E-DAEMON-NOT-INSTALLED\n\nMeaning\n  The managed daemon is not installed or not reachable from the current launcher path.\n\nWhy it matters\n  Session launch and broker-backed flows depend on the managed daemon.\n\nPrimary recovery\n  Run `sudo ember daemon install`, then re-check with `ember status` or `ember doctor`."
        }
        "error e-github-not-configured" => {
            "ember explain error E-GITHUB-NOT-CONFIGURED\n\nMeaning\n  The GitHub App lane is not configured on this machine.\n\nWhy it matters\n  Claude or Codex can still launch, but GitHub-brokered actions will fail or stay degraded.\n\nPrimary recovery\n  Run `ember github setup`, then confirm with `ember github status`."
        }
        "error e-status-json-troubleshoot-conflict" => {
            "ember explain error E-STATUS-JSON-TROUBLESHOOT-CONFLICT\n\nMeaning\n  `ember status --json --troubleshoot` mixes the machine contract with the human troubleshoot appendix.\n\nPrimary recovery\n  Use `ember status --json` for automation or `ember doctor` for the human diagnosis flow."
        }
        _ => {
            return Err(render_actionable_error(
                "E-EXPLAIN-TOPIC-NOT-FOUND",
                "Unknown explain topic",
                "Ember does not have a manual page for that topic yet.",
                &[format!("Try `ember explain {}`", normalized[0])],
                &[
                    "ember explain init".to_string(),
                    "ember explain status".to_string(),
                    "ember explain grant".to_string(),
                    "ember explain error E-DAEMON-NOT-INSTALLED".to_string(),
                ],
            ));
        }
    };
    Ok(style_explain_text(text))
}

pub(super) fn render_help_for_path(help_path: &[String]) -> Option<String> {
    match help_path {
        [] => Some(render_top_level_help()),
        [command] if command == "init" => Some(render_init_help()),
        [command] if command == "uninstall" => Some(render_uninstall_help()),
        [command] if command == "claude" => Some(render_claude_help()),
        [command] if command == "codex" => Some(render_codex_help()),
        [command] if command == "cursor" => Some(render_cursor_help()),
        [command] if command == "status" => Some(render_status_help()),
        [command] if command == "doctor" => Some(render_doctor_help()),
        [command] if command == "github" => Some(render_github_help()),
        [command, subcommand] if command == "github" && subcommand == "setup" => {
            Some(render_github_setup_help())
        }
        [command] if command == "grant" => Some(render_grant_help()),
        [command, subcommand] if command == "grant" && subcommand == "create" => {
            Some(render_grant_create_help())
        }
        [command] if command == "approval" => Some(render_approval_help()),
        [command, subcommand] if command == "approval" && subcommand == "approve" => {
            Some(render_approval_approve_help())
        }
        [command] if command == "audit" => Some(render_audit_help()),
        [command, subcommand] if command == "audit" && subcommand == "verify" => {
            Some(render_audit_verify_help())
        }
        [command] if command == "receipt" => Some(render_receipt_help()),
        [command, subcommand] if command == "receipt" && subcommand == "verify" => {
            Some(render_receipt_verify_help())
        }
        [command] if command == "trust" => Some(render_trust_help()),
        [command] if command == "daemon" => Some(render_daemon_help()),
        [command] if command == "recover" => Some(render_recover_help()),
        [command, subcommand] if command == "recover" && subcommand == "diagnose" => {
            Some(render_recover_diagnose_help())
        }
        [command, subcommand] if command == "recover" && subcommand == "audit-chain" => {
            Some(render_recover_audit_chain_help())
        }
        [command, subcommand] if command == "recover" && subcommand == "explain" => {
            Some(render_recover_explain_help())
        }
        [command, subcommand] if command == "recover" && subcommand == "grant" => {
            Some(render_recover_grant_help())
        }
        [command, subcommand] if command == "recover" && subcommand == "vault" => {
            Some(render_recover_vault_help())
        }
        [command, subcommand] if command == "recover" && subcommand == "trust" => {
            Some(render_recover_trust_help())
        }
        [command] if command == "persona" => Some(render_persona_help()),
        [command] if command == "vault" => Some(render_vault_help()),
        [command, subcommand] if command == "vault" && subcommand == "add" => {
            Some(render_vault_add_help())
        }
        [command] if command == "sandbox" => Some(render_sandbox_help()),
        [command] if command == "config" => Some(render_config_help()),
        [command] if command == "headless" => Some(render_headless_help()),
        [command, subcommand] if command == "headless" && subcommand == "enroll" => {
            Some(render_headless_enroll_help())
        }
        [command] if command == "explain" => Some(render_explain_help()),
        _ => render_generated_help_card(help_path),
    }
}

pub(super) fn render_custom_help(raw_args: &[String]) -> Option<String> {
    let help_path = resolve_help_path(raw_args)?;
    render_help_for_path(&help_path)
}

pub(super) fn render_entry_help(raw_args: &[String]) -> Option<String> {
    let help_path = resolve_entry_help_path(raw_args)?;
    if matches!(help_path.as_slice(), [command] if command == "delegation") {
        return None;
    }
    render_help_for_path(&help_path)
}
