//! Binary-pin RPC helpers for the launcher-facing `binary_pin_generate`
//! method.
//! CLASSIFICATION: PUBLIC

use serde_json::{Value, json};

use crate::infra::{
    handler::{DispatchSource, check_user_presence_gate, current_vault},
    handlers::support::local_state_vault_name,
    receipt::current_identity,
    store::DaemonStore,
};
use crate::trust::presence::HighRiskOp;

pub(crate) fn handle_generate(
    store: &DaemonStore,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    if source.is_internal() {
        return Err((
            -32401,
            "binary_pin_generate is wire-only; refuse Internal dispatch".to_string(),
        ));
    }
    check_user_presence_gate(HighRiskOp::BinaryPinGenerate, false)?;

    let pins_value = params["pins"].as_array().ok_or((
        -32602,
        "missing 'pins' (expected array of {caller, path})".to_string(),
    ))?;
    let force = params["force"].as_bool().unwrap_or(false);

    let identity = current_identity().ok_or((
        -32000,
        "daemon identity not initialised — cannot sign binary-pin manifest".to_string(),
    ))?;
    let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());

    let vault = current_vault(store, "binary_pin_generate")?;
    let existing = crate::infra::binary_pin::load_manifest(&vault, store, &pubkey_str)
        .map_err(|e| (-32000, format!("load existing manifest: {e}")))?;
    if existing.is_some() && !force {
        return Err((
            -32401,
            "binary-pin manifest already exists — re-run with `force: true` to overwrite (requires user-presence proof)".to_string(),
        ));
    }

    let mut targets: Vec<(String, std::path::PathBuf)> = Vec::new();
    for entry in pins_value {
        let caller = entry["caller"]
            .as_str()
            .ok_or((-32602, "pin entry missing 'caller'".to_string()))?;
        let _ = local_state_vault_name(caller)?;
        let path = entry["path"]
            .as_str()
            .ok_or((-32602, "pin entry missing 'path'".to_string()))?;
        targets.push((caller.to_string(), std::path::PathBuf::from(path)));
    }

    let outcome = crate::infra::binary_pin::build_manifest_from_paths(&targets, &pubkey_str)
        .map_err(|e| (-32000, format!("build manifest: {e}")))?;
    let mut manifest = outcome.manifest;
    manifest
        .sign(&crate::session::lifecycle::DaemonPersonaSigner::new(
            identity,
        ))
        .map_err(|e| (-32000, format!("sign manifest: {e}")))?;
    crate::infra::binary_pin::store_manifest(&vault, store, &manifest)
        .map_err(|e| (-32000, format!("store manifest: {e}")))?;

    tracing::info!(
        pins = manifest.pins.len(),
        missing = outcome.missing.len(),
        "binary_pin_generate: manifest signed and stored"
    );

    Ok(json!({
        "pins_signed": manifest.pins.iter().map(|p| serde_json::json!({
            "caller": p.caller,
            "blake3_hex": p.blake3_hex,
            "binary_path": p.binary_path,
            "basename": p.basename,
        })).collect::<Vec<_>>(),
        "missing": outcome.missing.iter().map(|(c, p)| serde_json::json!({
            "caller": c,
            "path": p,
        })).collect::<Vec<_>>(),
        "signer_pubkey": manifest.signer_pubkey,
        "signed_at": manifest.signed_at,
    }))
}
