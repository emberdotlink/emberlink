use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use core_crypto::EncryptedContent;

use crate::local_state::{self, LocalState};

const ENCRYPTED_MAGIC: &[u8] = b"EMBER_ENC\x01";
const STATE_AAD: &[u8] = b"emberlink-local-state";

// ---------------------------------------------------------------------------
// Encrypt / decrypt — same wire format as the CLI's local-state.enc
// ---------------------------------------------------------------------------

pub fn encrypt_state(plaintext: &[u8], content_key: &str) -> Result<Vec<u8>, String> {
    let encrypted = core_crypto::encrypt_content(content_key, plaintext, STATE_AAD)
        .map_err(|e| e.to_string())?;
    let nonce_bytes = core_types::hex_to_bytes(&encrypted.nonce_hex).map_err(|e| e.to_string())?;
    let mut out =
        Vec::with_capacity(ENCRYPTED_MAGIC.len() + nonce_bytes.len() + encrypted.ciphertext.len());
    out.extend_from_slice(ENCRYPTED_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&encrypted.ciphertext);
    Ok(out)
}

pub fn decrypt_state(data: &[u8], content_key: &str) -> Result<Vec<u8>, String> {
    if data.len() < ENCRYPTED_MAGIC.len() + 24 {
        return Err("encrypted state file too short".into());
    }
    if &data[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
        return Err("invalid magic header in state file".into());
    }
    let nonce_hex =
        core_types::bytes_to_hex(&data[ENCRYPTED_MAGIC.len()..ENCRYPTED_MAGIC.len() + 24]);
    let ciphertext = data[ENCRYPTED_MAGIC.len() + 24..].to_vec();
    let encrypted = EncryptedContent {
        nonce_hex,
        ciphertext,
    };
    core_crypto::decrypt_content(content_key, &encrypted, STATE_AAD).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Load / persist helpers — callers supply the content_key
// ---------------------------------------------------------------------------

/// Load and decrypt `LocalState` from `path`. Returns an empty state if the
/// file does not exist.
pub fn load_state(path: &Path, content_key: &str) -> Result<LocalState, String> {
    match fs::read(path) {
        Ok(raw) => {
            let plaintext = decrypt_state(&raw, content_key)?;
            let text = String::from_utf8(plaintext)
                .map_err(|e| format!("decrypted state not valid utf-8: {e}"))?;
            local_state::deserialize(&text)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(LocalState::empty()),
        Err(e) => Err(format!("failed to read local state: {e}")),
    }
}

/// Encrypt and atomically write `LocalState` to `path`.
pub fn persist_state(path: &Path, state: &LocalState, content_key: &str) -> Result<(), String> {
    let plaintext = local_state::serialize(state);
    let encrypted = encrypt_state(plaintext.as_bytes(), content_key)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create data dir: {e}"))?;
    }
    atomic_write_bytes(path, &encrypted).map_err(|e| format!("write state file: {e}"))
}

/// Write `bytes` to `path` atomically: write to a temp file, fsync, rename.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("local-state");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".{file_name}.{unique}.tmp"));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::generate_content_key;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key = generate_content_key("local-state");
        let plaintext = b"hello world";
        let ciphertext = encrypt_state(plaintext, &key).unwrap();
        let recovered = decrypt_state(&ciphertext, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("emberlink-app-atomic-{unique}.enc"));
        let name = path.file_name().unwrap().to_str().unwrap().to_string();

        atomic_write_bytes(&path, b"first").unwrap();
        atomic_write_bytes(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        let prefix = format!(".{name}.");
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| {
                let p = e.ok()?.path();
                let n = p.file_name()?.to_str()?;
                (n.starts_with(&prefix) && n.ends_with(".tmp")).then_some(p)
            })
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
        let _ = fs::remove_file(path);
    }
}
