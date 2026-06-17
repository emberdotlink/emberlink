use std::fmt;

use zeroize::Zeroize;

#[derive(Debug)]
pub enum SecretError {
    Revoked,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Revoked => write!(f, "secret has been revoked"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Holds sensitive credential bytes in memory.
///
/// - Memory is mlock'd to prevent swapping to disk (best-effort)
/// - Bytes are zeroized on drop, revocation, or expiry
/// - Cannot be cloned
/// - Debug prints `[REDACTED]`
pub struct SecretHandle {
    inner: Vec<u8>,
    revoked: bool,
}

impl SecretHandle {
    /// Take ownership of secret bytes and attempt to mlock the buffer.
    pub fn new(data: Vec<u8>) -> Self {
        let handle = Self {
            inner: data,
            revoked: false,
        };
        mlock_buffer(handle.inner.as_ptr(), handle.inner.len());
        handle
    }

    /// Access the secret bytes. Fails if revoked.
    pub fn expose(&self) -> Result<&[u8], SecretError> {
        if self.revoked {
            return Err(SecretError::Revoked);
        }
        Ok(&self.inner)
    }

    /// Immediately zeroize and mark as revoked.
    pub fn revoke(&mut self) {
        self.inner.zeroize();
        munlock_buffer(self.inner.as_ptr(), self.inner.len());
        self.revoked = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.inner.zeroize();
        munlock_buffer(self.inner.as_ptr(), self.inner.len());
    }
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretHandle([REDACTED], len={})", self.inner.len())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn mlock_buffer(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn munlock_buffer(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(target_arch = "wasm32")]
fn mlock_buffer(_ptr: *const u8, _len: usize) {}

#[cfg(target_arch = "wasm32")]
fn munlock_buffer(_ptr: *const u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_original_bytes() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let handle = SecretHandle::new(data.clone());
        assert_eq!(handle.expose().unwrap(), &data);
    }

    #[test]
    fn revoke_prevents_access() {
        let mut handle = SecretHandle::new(vec![1, 2, 3]);
        assert!(!handle.is_revoked());
        handle.revoke();
        assert!(handle.is_revoked());
        assert!(handle.expose().is_err());
    }

    #[test]
    fn debug_prints_redacted() {
        let handle = SecretHandle::new(vec![0xFF; 32]);
        let debug_str = format!("{handle:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("len=32"));
        assert!(!debug_str.contains("255")); // actual byte value
        assert!(!debug_str.contains("0xff"));
    }

    #[test]
    fn len_and_is_empty() {
        let handle = SecretHandle::new(vec![1, 2, 3]);
        assert_eq!(handle.len(), 3);
        assert!(!handle.is_empty());

        let empty = SecretHandle::new(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn revoked_then_dropped() {
        let mut handle = SecretHandle::new(vec![0xCD; 16]);
        handle.revoke();
        drop(handle); // double-zeroize is fine
    }

    #[test]
    fn revoke_zero_fills_underlying_buffer() {
        // Construct a handle, capture the raw buffer pointer before revoke,
        // then after revoke verify the bytes at that pointer are all zero.
        // This guards against a future refactor that marks `revoked=true`
        // without actually zeroizing the allocation.
        let data: Vec<u8> = (1..=32u8).collect();
        let len = data.len();
        let mut handle = SecretHandle::new(data);
        let ptr: *const u8 = handle.inner.as_ptr();

        // Sanity: bytes are non-zero before revoke.
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            assert!(slice.iter().any(|b| *b != 0), "buffer should be non-zero");
        }

        handle.revoke();

        // After revoke, `zeroize` must have rewritten all bytes to 0.
        // The Vec's capacity is unchanged, so the pointer is still valid.
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            assert!(
                slice.iter().all(|b| *b == 0),
                "buffer must be zero-filled after revoke, got: {slice:?}"
            );
        }

        // Post-condition: expose fails with Revoked.
        assert!(matches!(handle.expose(), Err(SecretError::Revoked)));
    }
}
