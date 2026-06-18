//! CLASSIFICATION: PUBLIC
//!
//! Pure URL / scope / glob matching primitives extracted from
//! `ember-daemon/src/infra/proxy.rs` (ARCH-PROXY-MATCH-EXTRACT).
//!
//! These functions have no daemon-state coupling — no `&self`, no DB, no
//! Vault, no runtime config. They take plain strings (or byte slices) and
//! return deterministic results. Splitting them out of proxy.rs keeps the
//! matching contracts unit-testable in isolation and lets sibling crates
//! (e.g. standing-grant lookups) share the same matchers.
//!
//! Naming uses the Rust raw identifier `r#match` because `match` is a
//! reserved keyword; callers spell it `core_proxy_forward::r#match::...`.

/// Parse `X-Ember-Target` into an `http::Uri` and build the effective URI
/// that scope enforcement should check against.
///
/// The proxy accepts an `X-Ember-Target` header that names the complete
/// outbound URL. Scope enforcement was historically driven by `req.uri()`,
/// which is a DIFFERENT string — this split let an attacker present a
/// scope-satisfying `req.uri` while forwarding the credential to an
/// attacker-controlled `X-Ember-Target` (C-1 in the 2026-04-23 adversarial
/// review). We collapse the two to a single authoritative URI so the
/// scope check can never disagree with the forwarding destination.
///
/// Effective URI construction:
/// - **Scheme + authority**: always from `target_url`. The `req.uri`
///   authority is advisory (the proxy listens on localhost; production
///   clients sometimes send an absolute-URI request line to a random
///   authority). Only the target's authority decides provider
///   classification.
/// - **Path + query**: from `target_url` when it carries a non-trivial
///   path (anything other than empty or `"/"`); otherwise from
///   `req.uri`. This preserves the existing convention where
///   `X-Ember-Target: https://api.github.com` + `GET /repos/owner/repo`
///   arrives at the proxy as a two-part descriptor.
///
/// Returns `Err` with a `bad_request` response message when the
/// target URL can't be parsed as an absolute URI with an authority.
pub fn effective_scope_uri(target_url: &str, req_uri: &http::Uri) -> Result<http::Uri, String> {
    let target_uri: http::Uri = target_url
        .parse()
        .map_err(|e: http::uri::InvalidUri| format!("invalid X-Ember-Target: {e}"))?;

    // Require absolute URI with authority — we must know which host the
    // credential is about to be sent to before we can answer "does the
    // scope permit this call?". A bare path-only target (e.g. `/foo`) is
    // a misuse that would otherwise default-match any provider.
    let target_authority = target_uri
        .authority()
        .ok_or_else(|| "X-Ember-Target must include scheme + authority".to_string())?
        .clone();
    let scheme = target_uri
        .scheme()
        .cloned()
        .ok_or_else(|| "X-Ember-Target must include a scheme".to_string())?;

    // Pick the path+query source. Target wins when it has a non-trivial
    // path; otherwise fall back to the request URI's path+query so the
    // (bare-host target, path-bearing request) convention keeps working.
    let target_pq = target_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let target_path_is_trivial = target_pq.is_empty() || target_pq == "/";
    let path_and_query: String = if target_path_is_trivial {
        req_uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    } else {
        target_pq.to_string()
    };

    let rebuilt = http::Uri::builder()
        .scheme(scheme)
        .authority(target_authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| format!("failed to assemble effective URI: {e}"))?;

    Ok(rebuilt)
}

/// Method tier classification — the abstraction the composite-grant action
/// grammar (`github:read`, `github:push`, `generic:read`, `generic:write`)
/// is built on top of. HTTP methods that don't map to either tier (e.g.
/// `CONNECT`) return `None` from [`method_tier`], which forces callers to
/// deny rather than guess at the verb a request authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodTier {
    Read,
    Write,
}

/// Map an HTTP method to a tier (`Read` or `Write`) used by the composite-
/// grant action grammar. Returns `None` for methods (`CONNECT`, `TRACE`,
/// custom verbs) that have no defined tier — the caller MUST treat that as
/// "deny".
pub fn method_tier(method: &http::Method) -> Option<MethodTier> {
    match *method {
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS => Some(MethodTier::Read),
        http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE => {
            Some(MethodTier::Write)
        }
        _ => None,
    }
}

/// Map an HTTP (method, URI) pair to the composite-grant (action, resource)
/// tuple used by `Statement.applicable_to`.
///
/// Actions are colon-delimited IAM verbs (`github:read`, `github:push`,
/// `llm:generate`, `generic:read`, `generic:write`). Resources are the
/// request URI's path, host-prefixed for provider-scoped namespaces so a
/// single statement glob (e.g. `anthropic/*`) can scope inference traffic
/// to a specific upstream without leaking matches from other providers.
///
/// This is the authoritative bridge between the legacy method-tier scope
/// grammar and the composite-grant selector model. New callers (dashboard
/// streaming, approval flow, standing-grant matcher) share this mapping so
/// the selector a request is checked against is identical across paths.
pub fn request_to_action_resource(
    method: &http::Method,
    uri: &http::Uri,
) -> Option<(String, String)> {
    let tier = method_tier(method)?;
    let host = uri.host().unwrap_or("");
    let path = uri.path();

    // C-2 fix (2026-04-23 adversarial review): use strict domain-suffix
    // matching so look-alike hosts like `notgithub.com` or `fakegithub.com`
    // do NOT classify as the `github` provider. `host_matches_domain`
    // requires `host == "github.com"` or a trailing `.github.com` label.
    //
    // The third arm (`anthropic`) classifies LLM inference traffic with the
    // provider-agnostic `llm:generate` verb. Resource is host-slug-prefixed
    // (e.g. `anthropic/v1/messages`) so future provider branches (OpenAI,
    // Cohere) plug in by adding another host match — same verb, different
    // slug — and statements scope via glob (`anthropic/*`, `openai/*`).
    let (provider, action, host_slug): (&str, &str, Option<&str>) =
        if host_matches_domain(host, "github.com") {
            (
                "github",
                match tier {
                    MethodTier::Read => "read",
                    MethodTier::Write => "push",
                },
                None,
            )
        } else if host_matches_domain(host, "api.anthropic.com") {
            ("llm", "generate", Some("anthropic"))
        } else if host_matches_domain(host, "chatgpt.com") {
            // Codex GPT-plan lane (P22-S2): ChatGPT *subscription* inference via
            // `chatgpt.com/backend-api/codex/responses`. Same `llm:generate`
            // verb as Anthropic, `openai` slug → statements scope via the
            // `openai/*` glob (symmetric with `anthropic/*`). This is the OpenAI
            // branch the comment above anticipated.
            ("llm", "generate", Some("openai"))
        } else if host_matches_domain(host, "generativelanguage.googleapis.com") {
            // gemini GATEWAY lane (ADR 215 slice 2): Google Generative Language
            // API inference via `generativelanguage.googleapis.com/v1beta/models/
            // {model}:{generate|streamGenerate|countTokens|embed}Content`. Same
            // `llm:generate` verb as Anthropic/OpenAI, `google` slug → statements
            // scope via the `google/*` glob (symmetric with `anthropic/*` /
            // `openai/*`). The proxy injects `x-goog-api-key` server-side and the
            // grant carries a `google/gemini-api-key` credential; classifying the
            // host here is what lets a `google/*` statement clamp the lane (rather
            // than it falling through to the host-agnostic `generic:write`).
            ("llm", "generate", Some("google"))
        } else if host_matches_domain(host, "cloudcode-pa.googleapis.com") {
            // gemini Code Assist lane (ADR 215 slice 2): the "Sign in with
            // Google" free tier is served by the Cloud Code / Code Assist API at
            // `cloudcode-pa.googleapis.com/v1internal:<method>` (a DIFFERENT host
            // than the API-key GATEWAY lane above). Same `llm:generate` verb,
            // same `google` slug → a `google/*` statement glob clamps both
            // gemini lanes. The proxy injects a daemon-refreshed OAuth Bearer
            // server-side and the grant carries a `google/`-prefixed OAuth
            // credential.
            ("llm", "generate", Some("google"))
        } else {
            (
                "generic",
                match tier {
                    MethodTier::Read => "read",
                    MethodTier::Write => "write",
                },
                None,
            )
        };

    // Resource string: github strips leading "/repos/" so paths match
    // selectors like `emberdotlink/ember-daemon`. LLM providers prefix the
    // path with their host slug so `anthropic/*` globs hit only Anthropic
    // traffic. Generic falls through to the raw path.
    let resource = match (provider, host_slug) {
        ("github", _) => {
            let trimmed = path.strip_prefix('/').unwrap_or(path);
            trimmed
                .strip_prefix("repos/")
                .unwrap_or(trimmed)
                .to_string()
        }
        ("llm", Some(slug)) => {
            let trimmed = path.strip_prefix('/').unwrap_or(path);
            format!("{slug}/{trimmed}")
        }
        _ => path.to_string(),
    };

    Some((format!("{provider}:{action}"), resource))
}

/// Strict domain-suffix comparison that avoids the classic `ends_with` bypass.
///
/// Returns `true` iff `host` is exactly `domain` or a sub-domain of `domain`
/// (`host == domain || host.ends_with(&format!(".{domain}"))`). This rejects
/// attacker-registered look-alike domains that share a trailing byte-string
/// with the target — `notgithub.com`, `fakegithub.com`, `evilgithub.com` all
/// fall out of the match surface, while `api.github.com` and `github.com`
/// still resolve.
///
/// Host matching is ASCII-case-insensitive (DNS names are case-insensitive per
/// RFC 4343). Normalized HERE rather than trusting a caller invariant:
/// `request_to_action_resource` feeds `hyper::Uri::host()` verbatim and
/// `Uri::host()` does NOT lowercase, so `Host: API.GitHub.com` would otherwise
/// miss `github.com` and misclassify a real GitHub call as the `generic`
/// provider — breaking `github:*` grant-scope matching. (Sweep 3 finding
/// S-HOST.) `domain` must NOT start with `.`; the helper adds it.
pub fn host_matches_domain(host: &str, domain: &str) -> bool {
    let host_lower = host.to_ascii_lowercase();
    // Trim the absolute-FQDN trailing dot (`host.com.`) so the classifier
    // canonicalizes a host the same way the meter does (`provider_for_host` in
    // `pricing.rs` already `trim_end_matches('.')`). Without this an
    // absolute-form host (`generativelanguage.googleapis.com.`, which some
    // resolver / gRPC stacks emit) under-classifies to the host-agnostic
    // `generic` lane instead of its provider, diverging from how the same
    // request meters (adversarial M-1). Strict-suffix matching still rejects
    // look-alikes (`github.com.evil.com.` → trims to `github.com.evil.com`,
    // which does not end in `.github.com`).
    let host = host_lower.trim_end_matches('.');
    let domain = domain.to_ascii_lowercase();
    if host == domain {
        return true;
    }
    // `format!` allocates, but proxy classification only runs once per
    // request and keeps the helper simple. Avoids an off-by-one between
    // `host.ends_with(".{domain}")` and a caller that forgets the dot.
    let suffix = format!(".{domain}");
    host.ends_with(&suffix)
}

/// Extract the lowercased host component from a `scheme://host[...]` URL.
///
/// Stops at the first `/`, `?`, `#`, or `:` after the authority. Returns
/// `None` when the input is missing the `://` separator.
pub fn extract_host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());
    Some(after_scheme[..end].to_ascii_lowercase())
}

/// Recognise the two git smart-HTTP path shapes we care about.
///
/// Returns `true` for both push and fetch transport endpoints:
///   - `.../info/refs?service=git-receive-pack`
///   - `.../info/refs?service=git-upload-pack`
///   - `.../git-receive-pack`
///   - `.../git-upload-pack`
///
/// Fails closed: any unexpected shape returns `false`, which means the echo
/// will forward the request without credential injection. Upstream will 401
/// and the mistake is visible at the client.
pub fn is_git_smart_http_path(path_and_query: &str) -> bool {
    // Split path from query once, avoiding allocations on the hot path.
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    if path.ends_with("/git-receive-pack") || path.ends_with("/git-upload-pack") {
        return true;
    }

    if path.ends_with("/info/refs")
        && let Some(q) = query
    {
        // Parse query params minimally; we only care about `service=`.
        for pair in q.split('&') {
            if let Some(value) = pair.strip_prefix("service=")
                && (value == "git-receive-pack" || value == "git-upload-pack")
            {
                return true;
            }
        }
    }

    false
}

/// Extract `"owner/repo"` from an upstream git smart-HTTP path.
///
/// Input is the path-and-query component AFTER stripping the upstream-host
/// prefix, e.g. `/emberdotlink/emberlink.git/git-receive-pack`.  Returns
/// `Some("emberdotlink/emberlink")` for that example, or `None` if the path
/// doesn't match the expected two-segment leading shape.
///
/// The `.git` suffix is stripped from the repo segment when present so the
/// returned string is the canonical `owner/repo` form used in the
/// `action = "github.push.<owner/repo>"` audit field.
pub fn git_echo_owner_repo(upstream_path_and_query: &str) -> Option<String> {
    // Strip leading `/` so `components` doesn't start with an empty segment.
    let path = upstream_path_and_query.split('?').next()?;
    let mut segments = path.trim_start_matches('/').splitn(3, '/');
    let owner = segments.next().filter(|s| !s.is_empty())?;
    let repo_raw = segments.next().filter(|s| !s.is_empty())?;
    let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
    Some(format!("{owner}/{repo}"))
}

/// Tiny glob matcher supporting `*` as "any run of characters". No `?`, no
/// character classes, no escaping. Used for owner/repo/path matching where
/// `*` wildcards are the only thing we claim to support. Falls back to a
/// prefix-match for the final `*` so that `"emberdotlink/*"` matches any
/// repo.
pub fn wildcard_match(pattern: &str, s: &str) -> bool {
    // Fast path: no wildcard at all means literal equality.
    if !pattern.contains('*') {
        return pattern == s;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;

    // Anchor the first literal fragment to the start.
    let first = parts[0];
    if !s[cursor..].starts_with(first) {
        return false;
    }
    cursor += first.len();

    // Middle fragments: find each in turn.
    for frag in &parts[1..parts.len() - 1] {
        if frag.is_empty() {
            continue;
        }
        match s[cursor..].find(frag) {
            Some(idx) => cursor += idx + frag.len(),
            None => return false,
        }
    }

    // Anchor the final literal to the end of the input.
    let last = parts[parts.len() - 1];
    s[cursor..].ends_with(last)
}

/// Match a github target (`owner/repo`, possibly with `*` wildcards) against
/// the URI path of a GitHub API request. We recognise the common
/// `/repos/{owner}/{repo}/...` and `/{owner}/{repo}` shapes; anything else
/// fails closed.
pub fn github_target_matches(target: &str, path: &str) -> bool {
    // Split target into owner/repo; targets without a slash are invalid.
    let (t_owner, t_repo) = match target.split_once('/') {
        Some((o, r)) if !o.is_empty() && !r.is_empty() => (o, r),
        _ => return false,
    };

    // Strip a leading "/repos" if present, then leading "/".
    let rest = path.strip_prefix('/').unwrap_or(path);
    let rest = rest.strip_prefix("repos/").unwrap_or(rest);

    let mut segments = rest.split('/');
    let owner = segments.next().unwrap_or("");
    let repo = segments.next().unwrap_or("");
    if owner.is_empty() || repo.is_empty() {
        return false;
    }

    wildcard_match(t_owner, owner) && wildcard_match(t_repo, repo)
}

/// Parse an application/x-www-form-urlencoded query string and return the
/// percent-decoded value of the first `ref` parameter, if any. Returns `None`
/// for empty values.
pub fn extract_ref_query_param(query: &str) -> Option<String> {
    use percent_encoding::percent_decode_str;

    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");
        if key == "ref" {
            let decoded = percent_decode_str(value).decode_utf8_lossy().into_owned();
            if decoded.is_empty() {
                return None;
            }
            return Some(decoded);
        }
    }
    None
}

/// Known single-word sub-resource suffixes that appear after a branch name in
/// the GitHub REST API path.  These are stripped when extracting the branch
/// from a `/branches/{branch}/{sub-resource}` path.
pub const GITHUB_BRANCH_SUBRESOURCES: &[&str] = &["protection", "rename"];

/// Extract the branch name from a GitHub API URI that explicitly encodes
/// the branch, given the URI's `path` and (optional) raw `query` string.
///
/// Caller is responsible for splitting a `hyper::Uri` into its `path()` /
/// `query()` parts before invoking this helper — that's the only `hyper`
/// dependency we used to carry through. By taking `&str` arguments this
/// function stays pure and keeps `core-proxy-forward` free of `hyper`.
///
/// Recognised shapes:
///   - `.../branches/{branch}[/sub-resource]`
///     The tail after `branches/` is the branch name.  If the last segment of
///     that tail is a known single-word sub-resource (`protection`, `rename`)
///     it is stripped, leaving just the branch.  This handles both simple
///     branches (`main`) and slash-containing branches (`feat/foo`).
///   - `.../git/refs/heads/{branch}` — the entire tail after `/heads/` is the
///     branch name, which may contain `/` (e.g. `feat/foo`).
///   - `.../contents/{path}?ref={branch}` — the branch is in the `ref` query
///     parameter (GitHub's Contents API). The path itself names a file, not a
///     branch, so we look to the query.
///
/// The raw path is percent-decoded before matching so that a branch
/// delivered as `feat%2Ffoo` (a valid GitHub API percent-encoding) compares
/// equal to the glob `feat/*` rather than failing to match `%2F` against `/`.
///
/// Returns `None` if the URI doesn't match any shape.
pub fn extract_github_branch(raw_path: &str, query: Option<&str>) -> Option<String> {
    use percent_encoding::percent_decode_str;

    // Decode the whole path once up front.  percent_decode on a plain path
    // (no `%XX` sequences) is a no-op and returns a borrowed Cow, so this is
    // cheap in the common case.
    let decoded = percent_decode_str(raw_path)
        .decode_utf8_lossy()
        .into_owned();
    let path = decoded.as_str();

    // Shape 1: .../branches/{branch}[/sub-resource]
    // Find the byte offset of "/branches/" and take everything after it.
    const BRANCHES: &str = "/branches/";
    if let Some(idx) = path.find(BRANCHES) {
        let tail = path[idx + BRANCHES.len()..].trim_end_matches('/');
        if tail.is_empty() {
            return None;
        }
        // Strip a known single-word sub-resource from the end if present.
        let branch = if let Some(last_slash) = tail.rfind('/') {
            let last_seg = &tail[last_slash + 1..];
            if GITHUB_BRANCH_SUBRESOURCES.contains(&last_seg) {
                &tail[..last_slash]
            } else {
                tail
            }
        } else {
            tail
        };
        return if branch.is_empty() {
            None
        } else {
            Some(branch.to_owned())
        };
    }

    // Shape 2: .../git/refs/heads/{branch}
    // The entire tail after "/heads/" is the branch name (may contain '/').
    const HEADS: &str = "/git/refs/heads/";
    if let Some(idx) = path.find(HEADS) {
        let tail = path[idx + HEADS.len()..].trim_end_matches('/');
        return if tail.is_empty() {
            None
        } else {
            Some(tail.to_owned())
        };
    }

    // Shape 3: .../contents/{file-path}?ref={branch}
    // The branch comes from the `ref` query parameter, not the URI path.
    const CONTENTS: &str = "/contents/";
    if path.contains(CONTENTS)
        && let Some(q) = query
    {
        return extract_ref_query_param(q);
    }

    None
}

#[derive(Debug)]
enum GlobTok<'a> {
    Literal(&'a str),
    Star,       // single *: matches run not containing '/'
    DoubleStar, // **: matches any run
}

/// Branch-aware glob matcher for scope subtargets.
///
/// Semantics (distinct from `wildcard_match`, which treats `*` as "any run
/// of characters" including `/`):
///
/// * `*`  — matches zero or more characters *excluding* `/`. So `feat/*`
///   matches `feat/foo` but not `feat/foo/bar` and not `main`.
/// * `**` — matches zero or more characters *including* `/`. So `release/**`
///   matches `release/v2`, `release/v2/hotfix`, and `release/`.
/// * Everything else matches literally; comparisons are case-sensitive.
///
/// Implementation: tokenise the pattern, then run an iterative
/// reachability-based matcher (DP over `(token_idx, byte_pos)` states).
/// The previous recursive backtracking implementation could blow up
/// exponentially on adversarial patterns like `**/a/**/b/**/c/**/d/**/e`
/// (multiple non-adjacent `**` segments) — a single attacker-supplied URI
/// could pin the daemon's single-threaded `LocalSet` for seconds. The DP
/// version is O(|toks| * |s|) worst-case and bounded.
pub fn glob_match_branch(pattern: &str, s: &str) -> bool {
    // Tokenise.
    let bytes = pattern.as_bytes();
    let mut toks: Vec<GlobTok<'_>> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                toks.push(GlobTok::DoubleStar);
                i += 2;
            } else {
                toks.push(GlobTok::Star);
                i += 1;
            }
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b'*' {
                i += 1;
            }
            toks.push(GlobTok::Literal(&pattern[start..i]));
        }
    }

    // Collapse adjacent stars so that `***` or `* *` reductions don't cause
    // redundant work in the matcher. `**` absorbs any adjacent `*`; two
    // adjacent `*`s collapse to one (neither can cross `/`).
    let mut collapsed: Vec<GlobTok<'_>> = Vec::with_capacity(toks.len());
    for t in toks {
        match (collapsed.last(), &t) {
            (Some(GlobTok::DoubleStar), GlobTok::Star)
            | (Some(GlobTok::DoubleStar), GlobTok::DoubleStar) => {
                // Already DoubleStar; drop redundant star.
            }
            (Some(GlobTok::Star), GlobTok::DoubleStar) => {
                collapsed.pop();
                collapsed.push(GlobTok::DoubleStar);
            }
            (Some(GlobTok::Star), GlobTok::Star) => {
                // Two singles in a row — same as one (neither crosses /).
            }
            _ => collapsed.push(t),
        }
    }

    glob_match_iter(&collapsed, s)
}

/// Iterative reachability-based glob matcher. Replaces the prior recursive
/// backtracking impl which had exponential worst-case behaviour on
/// non-adjacent `**` patterns (CPU DoS).
///
/// State = `(tok_idx, byte_pos)`. We compute reachable states as a 2D grid
/// `reach[tok_idx][byte_pos]`. Transitions:
///
/// * `Literal(lit)`: `(i, p) → (i+1, p+lit.len())` iff `s[p..]` starts with
///   `lit`.
/// * `Star`: stay at the same token while consuming a non-`/` char
///   (`(i, p) → (i, p+ch_len)` if `s[p]` ∉ `/`), and skip the token without
///   consuming (`(i, p) → (i+1, p)`).
/// * `DoubleStar`: stay at the same token while consuming any char
///   (`(i, p) → (i, p+ch_len)`), and skip without consuming
///   (`(i, p) → (i+1, p)`).
///
/// Match iff `(toks.len(), s.len())` is reachable. Each state visited at
/// most once → O(|toks| * |s|) time.
fn glob_match_iter(toks: &[GlobTok<'_>], s: &str) -> bool {
    let n_tok = toks.len();
    let n_str = s.len();

    // reach[i][p] = state (i, p) reachable.
    let mut reach = vec![vec![false; n_str + 1]; n_tok + 1];
    reach[0][0] = true;

    // Precompute char boundaries: for each byte p where p..p+ch_len is a
    // valid UTF-8 char, store the next boundary. Otherwise None.
    let bytes = s.as_bytes();

    for i in 0..=n_tok {
        for p in 0..=n_str {
            if !reach[i][p] {
                continue;
            }
            if i == n_tok {
                // No more tokens; nothing to expand.
                continue;
            }
            match &toks[i] {
                GlobTok::Literal(lit) => {
                    let lit_b = lit.as_bytes();
                    if p + lit_b.len() <= n_str && &bytes[p..p + lit_b.len()] == lit_b {
                        reach[i + 1][p + lit_b.len()] = true;
                    }
                }
                GlobTok::Star => {
                    // Skip without consuming.
                    reach[i + 1][p] = true;
                    // Consume one char if it's not '/' and we're at a char
                    // boundary. (s.is_char_boundary(p) is true for any p
                    // where reach[i][p] is set, by induction.)
                    if p < n_str && bytes[p] != b'/' {
                        // Find next char boundary.
                        let next = next_char_boundary(s, p);
                        reach[i][next] = true;
                    }
                }
                GlobTok::DoubleStar => {
                    // Skip without consuming.
                    reach[i + 1][p] = true;
                    // Consume one char (any).
                    if p < n_str {
                        let next = next_char_boundary(s, p);
                        reach[i][next] = true;
                    }
                }
            }
        }
    }

    reach[n_tok][n_str]
}

/// Given a byte index `p` that is a char boundary in `s` and `p < s.len()`,
/// return the next char boundary. UTF-8 chars are 1-4 bytes.
fn next_char_boundary(s: &str, p: usize) -> usize {
    let bytes = s.as_bytes();
    let b0 = bytes[p];
    let len = if b0 < 0x80 {
        1
    } else if b0 < 0xC0 {
        // Invalid lead byte (continuation); treat as 1 to make progress.
        // Should not occur for valid UTF-8 strings.
        1
    } else if b0 < 0xE0 {
        2
    } else if b0 < 0xF0 {
        3
    } else {
        4
    };
    (p + len).min(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---- request_to_action_resource provider classification ----

    #[test]
    fn request_to_action_resource_classifies_llm_providers() {
        let post = http::Method::POST;

        // Anthropic → llm:generate, anthropic-slugged resource.
        let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "anthropic/v1/messages".to_string()
            ))
        );

        // ChatGPT plan backend (codex GPT-plan lane) → llm:generate,
        // openai-slugged resource → covered by an `openai/*` statement glob.
        let uri: http::Uri = "https://chatgpt.com/backend-api/codex/responses"
            .parse()
            .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "openai/backend-api/codex/responses".to_string()
            ))
        );

        // Gemini GATEWAY backend (ADR 215 slice 2) → llm:generate,
        // google-slugged resource → covered by a `google/*` statement glob.
        let uri: http::Uri =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash:generateContent"
                .parse()
                .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "google/v1beta/models/gemini-3-flash:generateContent".to_string()
            ))
        );

        // The streaming method carries a `?alt=sse` query; the resource is
        // path-only (query excluded), so the same `google/*` glob still clamps it.
        let uri: http::Uri =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse"
                .parse()
                .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "google/v1beta/models/gemini-3-flash:streamGenerateContent".to_string()
            ))
        );

        // Strict domain-suffix matching: a look-alike host must NOT classify as
        // the google provider (it falls through to `generic:write`).
        let uri: http::Uri =
            "https://notgenerativelanguage.googleapis.com.evil.example/v1beta/models/x:generateContent"
                .parse()
                .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "generic:write".to_string(),
                "/v1beta/models/x:generateContent".to_string()
            )),
            "a look-alike host must not be classified as the google llm provider"
        );

        // Gemini Code Assist ("Sign in with Google") backend → llm:generate,
        // google-slugged resource → the SAME `google/*` glob covers both gemini
        // lanes (API-key GATEWAY + OAuth Code Assist), on a different host. Both
        // GET (operation polls) and POST classify identically (the LLM lane uses
        // `llm:generate` regardless of method tier).
        let uri: http::Uri =
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
                .parse()
                .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "google/v1internal:streamGenerateContent".to_string()
            ))
        );
        let uri: http::Uri = "https://cloudcode-pa.googleapis.com/v1internal/operations/abc123"
            .parse()
            .unwrap();
        assert_eq!(
            request_to_action_resource(&http::Method::GET, &uri),
            Some((
                "llm:generate".to_string(),
                "google/v1internal/operations/abc123".to_string()
            ))
        );

        // Absolute-FQDN trailing dot still classifies as google (adversarial
        // M-1): the classifier canonicalizes the host like the meter does, so a
        // `google/*` grant clamps it rather than it slipping to `generic:write`.
        let uri: http::Uri =
            "https://generativelanguage.googleapis.com./v1beta/models/gemini-3-flash:generateContent"
                .parse()
                .unwrap();
        assert_eq!(
            request_to_action_resource(&post, &uri),
            Some((
                "llm:generate".to_string(),
                "google/v1beta/models/gemini-3-flash:generateContent".to_string()
            )),
            "absolute-FQDN trailing dot must still classify as the google provider"
        );
    }

    // ---- is_git_smart_http_path examples ----

    #[test]
    fn is_git_smart_http_path_examples() {
        assert!(is_git_smart_http_path(
            "/emberdotlink/emberlink.git/git-receive-pack"
        ));
        assert!(is_git_smart_http_path(
            "/emberdotlink/emberlink.git/git-upload-pack"
        ));
        assert!(is_git_smart_http_path(
            "/emberdotlink/emberlink.git/info/refs?service=git-receive-pack"
        ));
        assert!(is_git_smart_http_path(
            "/emberdotlink/emberlink.git/info/refs?service=git-upload-pack"
        ));
        // Non-git shapes fail closed.
        assert!(!is_git_smart_http_path("/repos/emberdotlink/emberlink"));
        assert!(!is_git_smart_http_path(
            "/emberdotlink/emberlink.git/info/refs"
        ));
        assert!(!is_git_smart_http_path(
            "/emberdotlink/emberlink.git/info/refs?service=git-nope"
        ));
        assert!(!is_git_smart_http_path("/"));
        assert!(!is_git_smart_http_path("/git-receive-pack-but-not"));
    }

    // ---- host_matches_domain examples ----

    #[test]
    fn host_matches_domain_examples() {
        assert!(host_matches_domain("github.com", "github.com"));
        assert!(host_matches_domain("api.github.com", "github.com"));
        assert!(host_matches_domain("uploads.api.github.com", "github.com"));

        // Look-alike domains — classic `ends_with("github.com")` bypass.
        assert!(!host_matches_domain("notgithub.com", "github.com"));
        assert!(!host_matches_domain("fakegithub.com", "github.com"));
        assert!(!host_matches_domain("evilgithub.com", "github.com"));
        assert!(!host_matches_domain("my-github.com", "github.com"));

        // Unrelated TLD / empty.
        assert!(!host_matches_domain("github.io", "github.com"));
        assert!(!host_matches_domain("", "github.com"));

        // Absolute-FQDN trailing dot is trimmed (canonicalized), matching how
        // `provider_for_host` (pricing.rs) normalizes — adversarial M-1.
        assert!(host_matches_domain("github.com.", "github.com"));
        assert!(host_matches_domain("api.github.com.", "github.com"));
        // ...but trimming the dot must NOT open a look-alike bypass.
        assert!(!host_matches_domain("github.com.evil.com.", "github.com"));
        assert!(!host_matches_domain("notgithub.com.", "github.com"));

        // ASCII-case-insensitive (DNS is case-insensitive; `Uri::host()` does
        // not lowercase) — regression for Sweep 3 finding S-HOST.
        assert!(host_matches_domain("API.GitHub.com", "github.com"));
        assert!(host_matches_domain("GITHUB.COM", "github.com"));
        assert!(host_matches_domain("api.github.com", "GitHub.com"));
        assert!(!host_matches_domain("EVILGITHUB.COM", "github.com"));
    }

    // ---- extract_host_from_url examples ----

    #[test]
    fn extract_host_from_url_examples() {
        assert_eq!(
            extract_host_from_url("https://api.github.com/repos/owner/repo"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("HTTPS://API.GITHUB.COM/x"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://localhost:8080/path"),
            Some("localhost".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("not-a-url"),
            None,
            "missing :// returns None"
        );
    }

    // ---- wildcard_match examples ----

    #[test]
    fn wildcard_match_examples() {
        // No wildcard → literal equality.
        assert!(wildcard_match("main", "main"));
        assert!(!wildcard_match("main", "mainline"));

        // Trailing star.
        assert!(wildcard_match("emberdotlink/*", "emberdotlink/emberlink"));
        assert!(wildcard_match("emberdotlink/*", "emberdotlink/"));
        assert!(!wildcard_match("emberdotlink/*", "other/repo"));

        // Star treats `/` as just another char (distinct from glob_match_branch).
        assert!(wildcard_match("*/repo", "owner/repo"));
        assert!(wildcard_match("a*b*c", "axbyc"));
        assert!(!wildcard_match("a*b*c", "axyzd"));
    }

    // Property-based test (T1 tier) exercising the GLOB-style matcher
    // (`wildcard_match`) over generated patterns + inputs. The
    // invariants are:
    //
    // 1. A pattern with NO `*` matches a string iff they are byte-equal.
    // 2. The all-wildcard pattern `*` matches every string.
    // 3. Concatenating a literal `prefix` and an arbitrary suffix matches
    //    `prefix*` (and `*` matches the empty string).
    // 4. The matcher never panics on arbitrary str inputs.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn wildcard_match_proptest(
            // Restrict to printable ASCII so we don't blow up state space
            // with random UTF-8 + asterisk-soup. The matcher is
            // byte-oriented; ASCII coverage exercises every branch.
            pattern in "[a-zA-Z0-9/\\-_]{0,16}",
            input in "[a-zA-Z0-9/\\-_]{0,32}",
            prefix in "[a-zA-Z0-9/\\-_]{0,8}",
            suffix in "[a-zA-Z0-9/\\-_]{0,8}",
        ) {
            // Invariant 1: no-wildcard pattern → literal equality.
            prop_assert_eq!(wildcard_match(&pattern, &input), pattern == input);

            // Invariant 2: bare "*" matches anything.
            prop_assert!(wildcard_match("*", &input));

            // Invariant 3: "prefix*" matches anything that starts with prefix.
            let pat = format!("{prefix}*");
            let candidate = format!("{prefix}{suffix}");
            prop_assert!(wildcard_match(&pat, &candidate));

            // Invariant 4: matcher never panics. The fact that we got here
            // without a panic is sufficient, but assert something concrete:
            // the empty pattern matches only the empty string.
            prop_assert_eq!(wildcard_match("", &input), input.is_empty());
        }
    }

    // ---- github_target_matches examples ----

    #[test]
    fn github_target_matches_examples() {
        assert!(github_target_matches("owner/repo", "/repos/owner/repo"));
        assert!(github_target_matches("owner/repo", "/owner/repo"));
        assert!(github_target_matches(
            "owner/repo",
            "/repos/owner/repo/branches/main"
        ));

        // Wildcards on both halves.
        assert!(github_target_matches("*/repo", "/repos/anyone/repo"));
        assert!(github_target_matches(
            "emberdotlink/*",
            "/repos/emberdotlink/emberlink"
        ));

        // Mismatch.
        assert!(!github_target_matches("owner/repo", "/repos/owner/other"));
        assert!(!github_target_matches("owner/repo", "/owner"));

        // Invalid target — fails closed.
        assert!(!github_target_matches("owner", "/repos/owner/repo"));
        assert!(!github_target_matches("", "/repos/owner/repo"));
    }

    // ---- glob_match_branch examples ----

    #[test]
    fn glob_match_branch_examples() {
        // Single * does not cross slash.
        assert!(glob_match_branch("feat/*", "feat/foo"));
        assert!(!glob_match_branch("feat/*", "feat/foo/bar"));
        assert!(!glob_match_branch("feat/*", "main"));
        assert!(glob_match_branch("feat/*", "feat/"));

        // ** crosses slashes.
        assert!(glob_match_branch("feat/**", "feat/foo"));
        assert!(glob_match_branch("feat/**", "feat/foo/bar"));
        assert!(glob_match_branch("feat/**", "feat/"));
        assert!(glob_match_branch("feat/**", "feat/a/b/c"));
        assert!(!glob_match_branch("feat/**", "main"));
        assert!(!glob_match_branch("feat/**", "feat"));

        // Literal only.
        assert!(glob_match_branch("main", "main"));
        assert!(!glob_match_branch("main", "Main"));
        assert!(!glob_match_branch("main", "mainline"));

        // Trailing wildcard within segment.
        assert!(glob_match_branch("release-*", "release-1"));
        assert!(!glob_match_branch("release-*", "release-1/rc1"));
    }

    /// Regression for catastrophic-backtracking glob patterns. The DP-based
    /// matcher must complete in well under 100ms even on adversarial
    /// non-adjacent `**` patterns that previously made the recursive
    /// implementation exponential.
    #[test]
    fn glob_match_branch_no_catastrophic_backtracking() {
        let pattern = "**/a/**/b/**/c/**/d/**/e";
        let input = "x".repeat(50);

        let start = std::time::Instant::now();
        let matched = glob_match_branch(pattern, &input);
        let elapsed = start.elapsed();

        assert!(!matched, "pattern {pattern} must not match {input}");
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "glob_match_branch took {elapsed:?} on adversarial input \
             (must be <100ms — backtracking regression)"
        );

        // Positive matches on the same family still work.
        assert!(glob_match_branch("**/a/**/b/**/c", "x/a/y/b/z/c"));
        assert!(glob_match_branch("a/**/b/**/c", "a/x/b/y/c"));
        assert!(!glob_match_branch("**/a/**/b/**/c", "a/b/c/extra"));
    }

    // ---- extract_ref_query_param examples ----

    #[test]
    fn extract_ref_query_param_examples() {
        assert_eq!(
            extract_ref_query_param("ref=main"),
            Some("main".to_string())
        );
        assert_eq!(
            extract_ref_query_param("foo=bar&ref=feat%2Ffoo"),
            Some("feat/foo".to_string()),
            "percent-decoded"
        );
        assert_eq!(extract_ref_query_param("foo=bar"), None);
        assert_eq!(extract_ref_query_param("ref="), None, "empty value → None");
        assert_eq!(extract_ref_query_param(""), None);
    }

    // ---- extract_github_branch examples ----

    #[test]
    fn extract_github_branch_examples() {
        // /branches/{branch}
        assert_eq!(
            extract_github_branch("/repos/owner/repo/branches/main", None),
            Some("main".to_string())
        );
        // /branches/{branch}/protection — strip sub-resource.
        assert_eq!(
            extract_github_branch("/repos/owner/repo/branches/main/protection", None),
            Some("main".to_string())
        );
        // /git/refs/heads/{branch} — branch may contain slashes.
        assert_eq!(
            extract_github_branch("/repos/owner/repo/git/refs/heads/feat/foo", None),
            Some("feat/foo".to_string())
        );
        // /contents/{path}?ref={branch}
        assert_eq!(
            extract_github_branch("/repos/owner/repo/contents/README.md", Some("ref=main")),
            Some("main".to_string())
        );
        // Percent-decoded branch name.
        assert_eq!(
            extract_github_branch("/repos/owner/repo/branches/feat%2Ffoo", None),
            Some("feat/foo".to_string())
        );
        // No shape matches.
        assert_eq!(extract_github_branch("/repos/owner/repo", None), None);
        assert_eq!(
            extract_github_branch("/repos/owner/repo/branches/", None),
            None
        );
    }

    // ---- git_echo_owner_repo examples ----

    #[test]
    fn git_echo_owner_repo_examples() {
        assert_eq!(
            git_echo_owner_repo("/emberdotlink/emberlink.git/git-receive-pack"),
            Some("emberdotlink/emberlink".to_string())
        );
        assert_eq!(
            git_echo_owner_repo("/owner/repo/git-upload-pack"),
            Some("owner/repo".to_string())
        );
        assert_eq!(
            git_echo_owner_repo("/owner/repo.git/info/refs?service=git-upload-pack"),
            Some("owner/repo".to_string())
        );
        // Too few segments → None.
        assert_eq!(git_echo_owner_repo("/owner"), None);
        assert_eq!(git_echo_owner_repo("/"), None);
    }
}
