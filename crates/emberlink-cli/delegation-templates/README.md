# Workflow Templates

Pre-baked delegation templates that `ember claude-code` offers the user at launcher prompt time. Each template represents a scoped pre-grant: a named set of action scopes, a TTL ceiling, and optional explicit excludes.

## Schema

Templates are TOML files parsed by `ember_construct::DelegationTemplate`. Required fields:

| Field | Type | Description |
|---|---|---|
| `name` | string | Template name, must match the filename stem (e.g. `emberd-development` for `emberd-development.toml`). Only `[a-z0-9-]` characters allowed. |
| `description` | string | One-line human description rendered in the launcher selector UX. |
| `ttl` | string | TTL ceiling for any grant issued from this template (e.g. `4h`, `90m`, `1h30m`). The daemon refuses TTLs above this ceiling. |
| `scopes` | array of strings | Action keys this template permits. Each entry is either an exact action key (`gh.pr_create`) or a namespace glob (`git.*`). |

Optional fields:

| Field | Type | Description |
|---|---|---|
| `excludes` | array of strings | Action keys explicitly excluded even when a broader `scopes` glob would otherwise match. |
| `capability.<name>` | table | Optional capability blocks (e.g. `[capability.spawn_subagent]` with `max_depth`). |

## Action-key naming

Action keys follow the `<namespace>.<snake_case_action>` convention (e.g. `gh.pr_create`, `git.push`, `kubectl.apply`). Namespace glob `<namespace>.*` matches any action in that namespace.

## Bundled templates

| File | TTL | Purpose |
|---|---|---|
| `emberd-development.toml` | 4h | Daily emberd development — git, gh, cargo, kubectl, npm |
| `landing-page-edits.toml` | 2h | Landing-page content edits — git, gh PR ops, npm, wrangler |
| `infra-iteration.toml` | 1h | Cluster infra iteration — kubectl, pulumi, helm (no destroy) |
| `read-only.toml` | 8h | Read-only investigation — git fetch/log/status/diff, gh pr_list, kubectl get/describe |

## Install locations

The install pipeline copies these templates to:

- Production: `/usr/local/lib/ember/delegation-templates/`
- Development: `/usr/local/lib/ember-dev/delegation-templates/`

Operator overlays at `~/.config/emberlink/delegation-templates/<name>.toml` take precedence over bundled templates.

## Authoritative source

The canonical bundled set lives at `lib/ember/delegation-templates/` in the source tree. This directory (`crates/emberlink-cli/delegation-templates/`) is the CLI-crate-local copy for `ember claude-code` launcher integration.
