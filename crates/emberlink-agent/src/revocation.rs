use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type RevocationCallback = Box<dyn Fn(&GrantRevokedEvent) + Send>;

/// Tracks active grants and handles revocation events.
pub struct GrantTracker {
    grants: Arc<Mutex<HashMap<String, GrantState>>>,
    callbacks: Arc<Mutex<Vec<RevocationCallback>>>,
}

#[derive(Debug, Clone)]
pub struct GrantState {
    pub grant_id: String,
    pub credential_name: String,
    pub scope: String,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct GrantRevokedEvent {
    pub grant_id: String,
    pub reason: Option<String>,
}

impl GrantTracker {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(Mutex::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register(&self, grant_id: &str, credential_name: &str, scope: &str) {
        let mut grants = self.grants.lock().unwrap();
        grants.insert(
            grant_id.to_string(),
            GrantState {
                grant_id: grant_id.to_string(),
                credential_name: credential_name.to_string(),
                scope: scope.to_string(),
                active: true,
            },
        );
    }

    pub fn handle_revocation(&self, event: &GrantRevokedEvent) {
        {
            let mut grants = self.grants.lock().unwrap();
            if let Some(state) = grants.get_mut(&event.grant_id) {
                state.active = false;
            } else {
                return;
            }
        }
        let callbacks = self.callbacks.lock().unwrap();
        for cb in callbacks.iter() {
            cb(event);
        }
    }

    pub fn is_active(&self, grant_id: &str) -> bool {
        let grants = self.grants.lock().unwrap();
        grants.get(grant_id).map(|s| s.active).unwrap_or(false)
    }

    pub fn active_grants(&self) -> Vec<GrantState> {
        let grants = self.grants.lock().unwrap();
        grants.values().filter(|s| s.active).cloned().collect()
    }

    pub fn on_revocation(&self, callback: Box<dyn Fn(&GrantRevokedEvent) + Send + 'static>) {
        let mut callbacks = self.callbacks.lock().unwrap();
        callbacks.push(callback);
    }
}

impl Default for GrantTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn register_grant_is_active() {
        let tracker = GrantTracker::new();
        tracker.register("grant-1", "my-cred", "ReadCredential");
        assert!(tracker.is_active("grant-1"));
    }

    #[test]
    fn handle_revocation_marks_inactive() {
        let tracker = GrantTracker::new();
        tracker.register("grant-1", "my-cred", "ReadCredential");
        tracker.handle_revocation(&GrantRevokedEvent {
            grant_id: "grant-1".to_string(),
            reason: Some("user revoked".to_string()),
        });
        assert!(!tracker.is_active("grant-1"));
    }

    #[test]
    fn active_grants_excludes_revoked() {
        let tracker = GrantTracker::new();
        tracker.register("grant-1", "cred-a", "ReadCredential");
        tracker.register("grant-2", "cred-b", "UsePasskey");
        tracker.handle_revocation(&GrantRevokedEvent {
            grant_id: "grant-1".to_string(),
            reason: None,
        });
        let active = tracker.active_grants();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].grant_id, "grant-2");
    }

    #[test]
    fn callback_fires_on_revocation() {
        let tracker = GrantTracker::new();
        tracker.register("grant-1", "cred-a", "ReadCredential");
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        tracker.on_revocation(Box::new(move |_event| {
            fired_clone.store(true, Ordering::SeqCst);
        }));
        tracker.handle_revocation(&GrantRevokedEvent {
            grant_id: "grant-1".to_string(),
            reason: None,
        });
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn revoking_unknown_grant_is_noop() {
        let tracker = GrantTracker::new();
        // Should not panic
        tracker.handle_revocation(&GrantRevokedEvent {
            grant_id: "nonexistent".to_string(),
            reason: None,
        });
    }

    #[test]
    fn multiple_grants_revoke_one_others_remain_active() {
        let tracker = GrantTracker::new();
        tracker.register("grant-1", "cred-a", "ReadCredential");
        tracker.register("grant-2", "cred-b", "UsePasskey");
        tracker.register("grant-3", "cred-c", "WriteCredential");
        tracker.handle_revocation(&GrantRevokedEvent {
            grant_id: "grant-2".to_string(),
            reason: Some("expired".to_string()),
        });
        assert!(tracker.is_active("grant-1"));
        assert!(!tracker.is_active("grant-2"));
        assert!(tracker.is_active("grant-3"));
        let active = tracker.active_grants();
        assert_eq!(active.len(), 2);
    }
}
