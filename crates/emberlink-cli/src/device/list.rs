// CLASSIFICATION: PUBLIC
//! `ember device list` — call the daemon's `identity.device.list` JSON-RPC
//! and render the operator-visible enrolled-device inventory.
//!
//! ConnectOnly query (no vault tap, no presence gate). Returns every
//! `DeviceRecord` the daemon materializes from the identity event log,
//! including all custody classes and statuses.
//!
use std::io::{BufRead, BufReader, IsTerminal as _, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// One device record in the `identity.device.list` response. Mirrors
/// `DeviceRecord` from `core-eventlog` on the wire; the CLI side
/// redefines the type instead of cross-depending on the daemon crate
/// (CLI should not link against the daemon's internals).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceView {
    pub device_id: String,
    pub device_label: String,
    /// `"presence"` | `"recovery"` | `"co-authority"` | `"container"` |
    /// `"daemon"`. Per the ADR 200 amendment 2026-06-12 this mirrors
    /// `custody_class` (the founding `"primary"`/`"backup"` role split was
    /// retired — capability flows from custody class). Kept on the wire for
    /// backward compat with #5897 callers.
    #[serde(default)]
    pub device_role: String,
    /// `"presence"` | `"recovery"` | `"co-authority"` | `"container"` |
    /// `"daemon"`. The v2 wire field (post ADR 200 amendment 2026-06-12).
    /// Mirrors `custody_class`; capability flows from this class.
    #[serde(default)]
    pub device_class: String,
    /// Full signing public key in `p256:<sec1-hex>` wire form.
    pub device_pubkey: String,
    /// Full ECIES recipient public key in `p256:<sec1-hex>` wire form.
    pub device_encryption_pubkey: String,
    /// RFC 3339 timestamp of enrollment, or `None` when the event store
    /// predates this field.
    #[serde(default)]
    pub enrolled_at: Option<String>,
    /// `"active"` | `"revoked"` | `"frozen"` | `"replaced"`.
    pub status: String,
    /// `"presence"` | `"co-authority"` | `"container"` | `"daemon"` | `"recovery"`.
    pub custody_class: String,
    /// `"secure_enclave"` | `"yubikey_piv"` | `"genuine_app"` | `"none"`.
    /// Maps to `AttestationTier` on the daemon side.
    pub attestation_kind: String,
    /// `true` when this Device is the sole Active `presence`-class Device
    /// under the operator root — revoking it would fail the daemon's
    /// structural last-presence-device guard and brick the authority set. The
    /// daemon computes the flag from the same
    /// `active_presence_device_keys_under_operator_root` filter the revoke
    /// path uses. Defaults to `false` so pre-amendment daemons (no field on
    /// the wire) render unchanged.
    #[serde(default)]
    pub is_last_authority: bool,
}

impl DeviceView {
    /// Return the canonical class label for display, preferring the v2
    /// `device_class` field over the legacy `device_role`. Pre-amendment
    /// daemons may only emit `device_role`; the CLI continues to render
    /// correctly against those by treating that as the class.
    pub fn class(&self) -> &str {
        if !self.device_class.is_empty() {
            &self.device_class
        } else if !self.custody_class.is_empty() {
            &self.custody_class
        } else {
            &self.device_role
        }
    }
}

/// Decoded body of the `identity.device.list` RPC response.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceView>,
}

/// Errors surfaced by [`fetch_device_list`].
#[derive(Debug, thiserror::Error)]
pub enum DeviceListError {
    #[error("daemon socket at {socket} unreachable: {source}")]
    DaemonUnavailable {
        socket: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("daemon RPC error {code}: {message}")]
    DaemonRpc { code: i32, message: String },
    #[error("invalid daemon response: {0}")]
    Protocol(String),
    #[error("I/O error: {0}")]
    Io(String),
}

// ── Rendering ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Theme {
    color: bool,
}

impl Theme {
    fn current() -> Self {
        Self {
            color: std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal(),
        }
    }

    fn bold(self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn heading(self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m\x1b[38;2;217;106;29m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn badge(self, text: &str) -> String {
        let code = match text.trim().to_ascii_lowercase().as_str() {
            "active" => Some("\x1b[32m"),
            "revoked" => Some("\x1b[31m"),
            "frozen" | "replaced" => Some("\x1b[33m"),
            _ => None,
        };
        match (self.color, code) {
            (true, Some(code)) => format!("\x1b[1m{code}{text}\x1b[0m"),
            _ => self.bold(text),
        }
    }

    /// Truncate a long hex key for human display: show 16 prefix + 8 suffix.
    fn truncate_key(key: &str) -> String {
        // Strip `p256:` prefix for display
        let raw = key.strip_prefix("p256:").unwrap_or(key);
        if raw.len() <= 32 {
            return raw.to_string();
        }
        format!("{}…{}", &raw[..16], &raw[raw.len() - 8..])
    }
}

/// Render a human-readable block of enrolled devices.
pub fn render_human(resp: &DeviceListResponse) -> String {
    let theme = Theme::current();
    let mut out = String::new();

    out.push_str(&theme.bold("Enrolled devices"));
    out.push('\n');

    if resp.devices.is_empty() {
        out.push_str("No devices enrolled yet.\n\n");
        out.push_str(&theme.heading("Next"));
        out.push('\n');
        out.push_str("  ember device enroll --secure-enclave\n");
        out.push_str("    Enroll the operator presence device (dev0 floor: SE + Touch ID)\n");
        return out.trim_end().to_string();
    }

    out.push_str(&format!(
        "{} enrolled.\n",
        if resp.devices.len() == 1 {
            "1 device".to_string()
        } else {
            format!("{} devices", resp.devices.len())
        }
    ));
    out.push('\n');

    for d in &resp.devices {
        // Annotate the only-Authority Device inline with its label so an
        // operator triaging which device to revoke sees the structural warning
        // before any other field.
        if d.is_last_authority {
            out.push_str(&theme.heading(&format!(
                "{} (only authority — revoke would brick)",
                d.device_label,
            )));
        } else {
            out.push_str(&theme.heading(&d.device_label));
        }
        out.push('\n');
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("device_id"),
            d.device_id
        ));
        // ADR 200 amendment 2026-06-12: capability flows from class. The
        // primary/backup role label is retired; `class` is the load-bearing
        // column. Older daemons emit `device_role`; we read whichever the
        // daemon supplied via `DeviceView::class()`.
        out.push_str(&format!("  {:22} {}\n", theme.bold("class"), d.class()));
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("custody"),
            d.custody_class
        ));
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("attestation"),
            d.attestation_kind
        ));
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("status"),
            theme.badge(&d.status)
        ));
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("signing_key"),
            Theme::truncate_key(&d.device_pubkey)
        ));
        out.push_str(&format!(
            "  {:22} {}\n",
            theme.bold("encryption_key"),
            Theme::truncate_key(&d.device_encryption_pubkey)
        ));
        if let Some(ts) = &d.enrolled_at
            && !ts.is_empty()
        {
            out.push_str(&format!("  {:22} {}\n", theme.bold("enrolled_at"), ts));
        }
        out.push('\n');
    }

    out.trim_end().to_string()
}

// ── I/O layer ─────────────────────────────────────────────────────────────────

/// Call `identity.device.list` against the daemon socket and parse the
/// response. Pure I/O — no rendering. Tests exercise the parse helpers.
pub fn fetch_device_list(socket_path: &Path) -> Result<DeviceListResponse, DeviceListError> {
    let response = call_daemon(
        socket_path,
        "identity.device.list",
        &Value::Object(Default::default()),
    )?;
    parse_device_list_response(&response)
}

/// Parse the daemon's `identity.device.list` response body into a typed
/// struct. Separated from the socket I/O so tests can exercise the
/// parsing path without a live daemon.
pub fn parse_device_list_response(body: &Value) -> Result<DeviceListResponse, DeviceListError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        DeviceListError::Protocol(format!("decode identity.device.list response: {e}"))
    })
}

/// Entry point for `ember device list`. Calls the daemon, prints to
/// stdout. Returns a non-zero exit code on error.
pub fn run(socket_path: &Path, json_output: bool) -> i32 {
    match fetch_device_list(socket_path) {
        Ok(resp) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!(resp.devices)).unwrap()
                );
            } else {
                println!("{}", render_human(&resp));
            }
            0
        }
        Err(DeviceListError::DaemonUnavailable { socket, source }) => {
            eprintln!(
                "ember device list: {}",
                crate::format_daemon_unavailable(&socket, &source)
            );
            2
        }
        Err(err) => {
            eprintln!("ember device list: {err}");
            2
        }
    }
}

fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, DeviceListError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        DeviceListError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| DeviceListError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| DeviceListError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| DeviceListError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| DeviceListError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(DeviceListError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device_json(
        id: &str,
        label: &str,
        class: &str,
        status: &str,
        custody: &str,
        attestation: &str,
    ) -> serde_json::Value {
        json!({
            "device_id": id,
            "device_label": label,
            "device_role": class,
            "device_class": class,
            "device_pubkey": format!("p256:{}", "ab".repeat(33)),
            "device_encryption_pubkey": format!("p256:{}", "cd".repeat(33)),
            "enrolled_at": "2026-06-12T00:00:00Z",
            "status": status,
            "custody_class": custody,
            "attestation_kind": attestation,
        })
    }

    fn make_device_view(
        id: &str,
        label: &str,
        class: &str,
        status: &str,
        custody: &str,
        attestation: &str,
    ) -> DeviceView {
        DeviceView {
            device_id: id.to_string(),
            device_label: label.to_string(),
            device_role: class.to_string(),
            device_class: class.to_string(),
            device_pubkey: format!("p256:{}", "ab".repeat(33)),
            device_encryption_pubkey: format!("p256:{}", "cd".repeat(33)),
            enrolled_at: Some("2026-06-12T00:00:00Z".to_string()),
            status: status.to_string(),
            custody_class: custody.to_string(),
            attestation_kind: attestation.to_string(),
            is_last_authority: false,
        }
    }

    // T1: parsing ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_list() {
        let body = json!({ "devices": [] });
        let resp = parse_device_list_response(&body).unwrap();
        assert!(resp.devices.is_empty());
    }

    #[test]
    fn parse_single_presence_device() {
        let body = json!({
            "devices": [
                make_device_json(
                    "device-operator-abc123",
                    "Operator Presence Device",
                    "presence",
                    "active",
                    "presence",
                    "secure_enclave",
                )
            ]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert_eq!(resp.devices.len(), 1);
        let d = &resp.devices[0];
        assert_eq!(d.device_id, "device-operator-abc123");
        assert_eq!(d.device_label, "Operator Presence Device");
        assert_eq!(d.device_class, "presence");
        assert_eq!(d.class(), "presence");
        assert_eq!(d.status, "active");
        assert_eq!(d.custody_class, "presence");
        assert_eq!(d.attestation_kind, "secure_enclave");
        assert_eq!(d.enrolled_at.as_deref(), Some("2026-06-12T00:00:00Z"));
    }

    #[test]
    fn parse_two_presence_devices() {
        let body = json!({
            "devices": [
                make_device_json("dev-1", "First Presence Device",  "presence", "active", "presence", "secure_enclave"),
                make_device_json("dev-2", "Second Presence Device", "presence", "active", "presence", "none"),
            ]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert_eq!(resp.devices.len(), 2);
        assert_eq!(resp.devices[0].class(), "presence");
        assert_eq!(resp.devices[1].class(), "presence");
    }

    #[test]
    fn parse_presence_plus_recovery() {
        let body = json!({
            "devices": [
                make_device_json("dev-presence", "Presence Device", "presence", "active", "presence", "secure_enclave"),
                make_device_json("dev-recovery", "Printed Recovery Code", "recovery", "active", "recovery", "none"),
            ]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert_eq!(resp.devices.len(), 2);
        assert_eq!(resp.devices[0].class(), "presence");
        assert_eq!(resp.devices[1].class(), "recovery");
    }

    /// Forward-compat: a pre-amendment daemon (v0.3.0 ship as of #5897)
    /// that emits ONLY `device_role` and no `device_class` must still
    /// render under the v2 CLI.
    #[test]
    fn parse_pre_amendment_daemon_falls_back_to_device_role() {
        let body = json!({
            "devices": [{
                "device_id": "dev-1",
                "device_label": "Old Daemon Device",
                "device_role": "primary",
                "device_pubkey": "p256:aa",
                "device_encryption_pubkey": "p256:bb",
                "status": "active",
                "custody_class": "presence",
                "attestation_kind": "secure_enclave",
            }]
        });
        let resp = parse_device_list_response(&body).unwrap();
        let d = &resp.devices[0];
        assert!(
            d.device_class.is_empty(),
            "pre-amendment daemons omit device_class"
        );
        // class() preference: device_class > custody_class > device_role.
        assert_eq!(d.class(), "presence", "falls back to custody_class");
    }

    #[test]
    fn parse_rejects_missing_status() {
        let body = json!({
            "devices": [{
                "device_id": "x",
                "device_label": "X",
                "device_role": "presence",
                "device_class": "presence",
                "device_pubkey": "p256:aa",
                "device_encryption_pubkey": "p256:bb",
                "custody_class": "presence",
                "attestation_kind": "none",
                // status omitted
            }]
        });
        let err = parse_device_list_response(&body).unwrap_err();
        assert!(matches!(err, DeviceListError::Protocol(_)));
    }

    #[test]
    fn parse_enrolled_at_optional() {
        let body = json!({
            "devices": [{
                "device_id": "d",
                "device_label": "D",
                "device_role": "presence",
                "device_class": "presence",
                "device_pubkey": "p256:aa",
                "device_encryption_pubkey": "p256:bb",
                "status": "active",
                "custody_class": "presence",
                "attestation_kind": "none",
                // no enrolled_at
            }]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert_eq!(resp.devices[0].enrolled_at, None);
    }

    // T2: rendering ───────────────────────────────────────────────────────────

    #[test]
    fn render_empty_shows_next_steps() {
        let resp = DeviceListResponse { devices: vec![] };
        let out = render_human(&resp);
        assert!(out.contains("No devices enrolled yet."));
        assert!(out.contains("ember device enroll"));
    }

    #[test]
    fn render_one_active_device_shows_all_fields() {
        let resp = DeviceListResponse {
            devices: vec![make_device_view(
                "device-operator-deadbeef",
                "Operator Presence Device",
                "presence",
                "active",
                "presence",
                "secure_enclave",
            )],
        };
        let out = render_human(&resp);
        assert!(out.contains("1 device enrolled"));
        assert!(out.contains("Operator Presence Device"));
        assert!(out.contains("device-operator-deadbeef"));
        assert!(out.contains("class"));
        assert!(out.contains("presence"));
        assert!(out.contains("secure_enclave"));
        assert!(out.contains("active"));
        assert!(out.contains("2026-06-12T00:00:00Z"));
    }

    #[test]
    fn render_two_devices_shows_count() {
        let resp = DeviceListResponse {
            devices: vec![
                make_device_view(
                    "dev-1",
                    "First Presence Device",
                    "presence",
                    "active",
                    "presence",
                    "none",
                ),
                make_device_view(
                    "dev-2",
                    "Second Presence Device",
                    "presence",
                    "active",
                    "presence",
                    "none",
                ),
            ],
        };
        let out = render_human(&resp);
        assert!(out.contains("2 devices enrolled"));
        assert!(out.contains("First Presence Device"));
        assert!(out.contains("Second Presence Device"));
    }

    #[test]
    fn render_presence_plus_recovery_distinguishes_class() {
        let resp = DeviceListResponse {
            devices: vec![
                make_device_view(
                    "dev-pres",
                    "Presence Device",
                    "presence",
                    "active",
                    "presence",
                    "secure_enclave",
                ),
                make_device_view(
                    "dev-rec",
                    "Printed Recovery Code",
                    "recovery",
                    "active",
                    "recovery",
                    "none",
                ),
            ],
        };
        let out = render_human(&resp);
        assert!(out.contains("Presence Device"));
        assert!(out.contains("Printed Recovery Code"));
        // The class column distinguishes presence from recovery.
        assert!(out.contains("presence"));
        assert!(out.contains("recovery"));
    }

    #[test]
    fn render_omits_enrolled_at_when_none() {
        let mut d = make_device_view("dev-1", "Device", "presence", "active", "presence", "none");
        d.enrolled_at = None;
        let resp = DeviceListResponse { devices: vec![d] };
        let out = render_human(&resp);
        assert!(!out.contains("enrolled_at"));
    }

    // T1 — is_last_authority flag parsing + render ─────────────────────────────

    /// The daemon emits `is_last_authority: true` on the single Active
    /// presence Device when no other presence Device exists; the CLI parses it
    /// verbatim.
    #[test]
    fn parse_is_last_authority_flag_round_trip() {
        let body = json!({
            "devices": [{
                "device_id": "dev-only",
                "device_label": "Only Presence Device",
                "device_role": "presence",
                "device_class": "presence",
                "device_pubkey": "p256:aa",
                "device_encryption_pubkey": "p256:bb",
                "status": "active",
                "custody_class": "presence",
                "attestation_kind": "secure_enclave",
                "is_last_authority": true,
            }]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert!(resp.devices[0].is_last_authority);
    }

    /// Pre-amendment daemons omit the field; the CLI MUST default it to
    /// `false` instead of failing to decode (no `Option<bool>` — the wire
    /// shape is "either explicit true or implicit false").
    #[test]
    fn parse_pre_amendment_daemon_defaults_is_last_authority_false() {
        let body = json!({
            "devices": [{
                "device_id": "dev-1",
                "device_label": "Old Daemon Device",
                "device_role": "presence",
                "device_class": "presence",
                "device_pubkey": "p256:aa",
                "device_encryption_pubkey": "p256:bb",
                "status": "active",
                "custody_class": "presence",
                "attestation_kind": "secure_enclave",
                // is_last_authority omitted
            }]
        });
        let resp = parse_device_list_response(&body).unwrap();
        assert!(!resp.devices[0].is_last_authority);
    }

    /// The human render annotates the only-authority device inline with its
    /// label so an operator triaging which device to revoke sees the
    /// structural warning before any other field.
    #[test]
    fn render_annotates_last_authority_device() {
        let mut d = make_device_view(
            "dev-only",
            "Only Presence Device",
            "presence",
            "active",
            "presence",
            "secure_enclave",
        );
        d.is_last_authority = true;
        let resp = DeviceListResponse { devices: vec![d] };
        let out = render_human(&resp);
        assert!(
            out.contains("(only authority — revoke would brick)"),
            "last-authority annotation missing from human render:\n{out}"
        );
    }

    /// Devices that are NOT last-authority don't get the annotation — render
    /// stays clean on the steady-state case (≥2 presence devices, or only
    /// recovery/co-authority survivors).
    #[test]
    fn render_does_not_annotate_non_last_authority_device() {
        let d = make_device_view(
            "dev-1",
            "First Presence Device",
            "presence",
            "active",
            "presence",
            "secure_enclave",
        );
        let resp = DeviceListResponse { devices: vec![d] };
        let out = render_human(&resp);
        assert!(
            !out.contains("only authority"),
            "non-last-authority device must not carry the annotation:\n{out}"
        );
    }

    /// JSON pass-through: `--json` output carries the field verbatim
    /// (serialization round-trips through serde_json::to_value).
    #[test]
    fn json_output_carries_is_last_authority() {
        let mut d = make_device_view(
            "dev-only",
            "Only Presence Device",
            "presence",
            "active",
            "presence",
            "secure_enclave",
        );
        d.is_last_authority = true;
        let resp = DeviceListResponse { devices: vec![d] };
        // The CLI's `--json` path serializes `resp.devices` (Vec<DeviceView>)
        // directly; assert the new field is included with the right value.
        let serialized = serde_json::to_value(&resp.devices).unwrap();
        let arr = serialized.as_array().unwrap();
        assert_eq!(arr[0].get("is_last_authority").and_then(|v| v.as_bool()), Some(true));
    }
}
