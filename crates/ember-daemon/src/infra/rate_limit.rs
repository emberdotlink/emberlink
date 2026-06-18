use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-persona pre-evaluation rate limiter.
/// Tracks request counts in a sliding window.
pub struct RateLimiter {
    window: Duration,
    max_requests: usize,
    state: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            max_requests,
            state: HashMap::new(),
        }
    }

    /// Check if a request from this persona is allowed.
    /// Returns true if allowed, false if rate-limited.
    pub fn check(&mut self, persona_id: &str) -> bool {
        self.check_key_at(persona_id, self.max_requests, self.window, Instant::now())
    }

    fn check_key_at(
        &mut self,
        key: &str,
        max_requests: usize,
        window: Duration,
        now: Instant,
    ) -> bool {
        let entries = self.state.entry(key.to_string()).or_default();

        // Remove expired entries
        entries.retain(|t| now.saturating_duration_since(*t) < window);

        if entries.len() >= max_requests {
            return false;
        }

        entries.push(now);
        true
    }

    /// Pre-evaluation check keyed by persona_id + action.
    ///
    /// Called BEFORE policy evaluation and grant creation. If the persona has
    /// exceeded the rate limit for this action, returns `false` and the caller
    /// should short-circuit with a `rate_spike` denial. No state is mutated on
    /// rejection, so repeated rejected calls do not extend the window.
    pub fn check_action(&mut self, persona_id: &str, action: &str) -> bool {
        let key = format!("{persona_id}\u{1f}{action}");
        self.check(&key)
    }

    /// Per-action minimum-interval gate.
    ///
    /// This uses the same keyed sliding-window state as [`Self::check_action`],
    /// but pins the action to one request per `window_secs`. `refresh_cert`
    /// uses this to enforce ADR 173's 60-second floor per cert chain without
    /// changing the broader default pre-evaluation limit.
    pub fn check_action_min_interval(
        &mut self,
        persona_id: &str,
        action: &str,
        window_secs: u64,
    ) -> bool {
        let key = format!("{persona_id}\u{1f}{action}");
        self.check_key_at(&key, 1, Duration::from_secs(window_secs), Instant::now())
    }

    /// Clean up expired entries for all personas.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.state.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < self.window);
            !entries.is_empty()
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(100, 60) // 100 requests per minute per persona
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_limit() {
        let mut rl = RateLimiter::new(10, 60);
        for _ in 0..5 {
            assert!(rl.check("persona-1"));
        }
    }

    #[test]
    fn blocks_over_limit() {
        let mut rl = RateLimiter::new(10, 60);
        for _ in 0..10 {
            assert!(rl.check("persona-1"));
        }
        assert!(!rl.check("persona-1"));
    }

    #[test]
    fn check_action_isolates_by_action() {
        let mut rl = RateLimiter::new(2, 60);
        assert!(rl.check_action("persona-1", "git.push"));
        assert!(rl.check_action("persona-1", "git.push"));
        // Same persona + action: limit reached.
        assert!(!rl.check_action("persona-1", "git.push"));
        // Same persona, different action: independent window.
        assert!(rl.check_action("persona-1", "deploy.staging"));
    }

    #[test]
    fn check_action_min_interval_blocks_until_window_expires() {
        let mut rl = RateLimiter::new(100, 60);
        assert!(rl.check_action_min_interval("persona-1", "refresh_cert:ctr-a", 60));
        assert!(!rl.check_action_min_interval("persona-1", "refresh_cert:ctr-a", 60));
        assert!(rl.check_action_min_interval("persona-1", "refresh_cert:ctr-b", 60));

        let mut expired = RateLimiter::new(100, 60);
        assert!(expired.check_action_min_interval("persona-1", "refresh_cert:ctr-a", 0));
        assert!(expired.check_action_min_interval("persona-1", "refresh_cert:ctr-a", 0));
    }

    #[test]
    fn resets_after_window() {
        let mut rl = RateLimiter::new(10, 60);
        for _ in 0..10 {
            rl.check("persona-1");
        }
        // cleanup with empty window should remove all entries
        let mut rl2 = RateLimiter::new(10, 60);
        rl2.check("persona-2");
        rl2.cleanup();
        // persona-2 still has a recent entry, so state should still have it
        assert!(!rl2.state.is_empty());

        // A limiter with zero window effectively expires everything immediately
        let mut rl3 = RateLimiter::new(10, 0);
        for _ in 0..10 {
            rl3.check("persona-3");
        }
        rl3.cleanup();
        assert!(rl3.state.is_empty());
    }
}
