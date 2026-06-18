//! Dev-channel typed-phrase opt-in gate.
//!
//! # Checkpoint
//!
//! `dev_channel_opt_in_phrase` — the constant [`DEV_CHANNEL_OPT_IN_PHRASE`]
//! that the operator must type verbatim to enable the `dev` channel.
//!
//! # Policy summary
//!
//! - `Release` and `Canary` channels are selected without any prompt.
//! - `Dev` channel requires the operator to type a specific phrase
//!   (see [`DEV_CHANNEL_OPT_IN_PHRASE`]) confirming they understand that
//!   dev-channel images carry operator-only signing trust (ADR 169 D6).
//! - `Ent0` cohort operators are refused dev channel selection outright —
//!   no prompt is shown; [`ChannelSelectError::DevForbiddenInEnt0`] is
//!   returned immediately.

/// The exact phrase the operator must type to enable the `Dev` channel.
///
/// The phrase is intentional plain English that carries load-bearing meaning:
/// it surfaces the key policy implication (operator-only signing trust for
/// dev-channel images, per ADR 169 D6) so the operator cannot claim they
/// were unaware.
pub const DEV_CHANNEL_OPT_IN_PHRASE: &str =
    "I understand dev-channel images carry operator-only signing trust";

/// Operator cohort — controls which channel policies apply.
///
/// - `Dev0`: internal development cohort; all channels available with opt-in.
/// - `Team0`: early-access team cohort; all channels available with opt-in.
/// - `Ent0`: enterprise cohort; `Dev` channel is refused outright (no prompt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cohort {
    Dev0,
    Team0,
    Ent0,
}

/// Update channel selection.
///
/// If an `ember-update::channel::Channel` type is introduced in the dep tree,
/// this local enum should be replaced by that import and this module updated
/// to re-export it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Release,
    Dev,
    Canary,
}

/// Errors returned by [`select_channel_interactive`].
#[derive(Debug, thiserror::Error)]
pub enum ChannelSelectError {
    /// The operator is in the `Ent0` cohort, which prohibits the `Dev` channel.
    /// No opt-in prompt is shown — the refusal is unconditional.
    #[error(
        "dev channel is not available for Ent0 cohort operators; \
         contact your Ember Systems account team to discuss channel policy"
    )]
    DevForbiddenInEnt0,

    /// The operator typed a phrase that does not match [`DEV_CHANNEL_OPT_IN_PHRASE`].
    #[error(
        "typed phrase did not match the required opt-in phrase; \
         dev channel not enabled"
    )]
    OptInPhraseMismatch,
}

/// Select an update channel, enforcing the typed-phrase opt-in gate for `Dev`.
///
/// # Arguments
///
/// - `requested`: the channel the operator wants to use.
/// - `cohort`: the operator's deployment cohort — controls whether `Dev` is
///   allowed at all and whether a prompt is required.
/// - `prompt_input`: a closure that, when invoked, returns the operator's
///   typed phrase. Only called when `requested == Dev` and `cohort != Ent0`.
///   For `Release`/`Canary` requests the closure is **never called**.
///
/// # Returns
///
/// - `Ok(channel)` when the selection is permitted.
/// - `Err(ChannelSelectError::DevForbiddenInEnt0)` when `cohort == Ent0` and
///   `requested == Dev` — no prompt is shown.
/// - `Err(ChannelSelectError::OptInPhraseMismatch)` when the operator's typed
///   phrase does not exactly match [`DEV_CHANNEL_OPT_IN_PHRASE`].
pub fn select_channel_interactive(
    requested: Channel,
    cohort: Cohort,
    prompt_input: impl FnOnce() -> String,
) -> Result<Channel, ChannelSelectError> {
    match requested {
        Channel::Release | Channel::Canary => Ok(requested),
        Channel::Dev => {
            if cohort == Cohort::Ent0 {
                return Err(ChannelSelectError::DevForbiddenInEnt0);
            }
            let typed = prompt_input();
            if typed == DEV_CHANNEL_OPT_IN_PHRASE {
                Ok(Channel::Dev)
            } else {
                Err(ChannelSelectError::OptInPhraseMismatch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ent0_dev_request_is_refused_without_prompt() {
        let result = select_channel_interactive(Channel::Dev, Cohort::Ent0, || {
            panic!("prompt must not be invoked for Ent0")
        });
        assert!(
            matches!(result, Err(ChannelSelectError::DevForbiddenInEnt0)),
            "expected DevForbiddenInEnt0, got {result:?}"
        );
    }

    #[test]
    fn dev0_dev_correct_phrase_returns_ok() {
        let result = select_channel_interactive(Channel::Dev, Cohort::Dev0, || {
            DEV_CHANNEL_OPT_IN_PHRASE.to_string()
        });
        assert!(
            matches!(result, Ok(Channel::Dev)),
            "expected Ok(Dev), got {result:?}"
        );
    }

    #[test]
    fn dev0_dev_wrong_phrase_returns_mismatch() {
        let result =
            select_channel_interactive(Channel::Dev, Cohort::Dev0, || "wrong phrase".to_string());
        assert!(
            matches!(result, Err(ChannelSelectError::OptInPhraseMismatch)),
            "expected OptInPhraseMismatch, got {result:?}"
        );
    }

    #[test]
    fn dev0_release_request_skips_prompt() {
        let result = select_channel_interactive(Channel::Release, Cohort::Dev0, || {
            panic!("prompt must not be invoked for Release channel")
        });
        assert!(
            matches!(result, Ok(Channel::Release)),
            "expected Ok(Release), got {result:?}"
        );
    }
}
