//! `ember binary update <tool>`
//!
//! For v1: not yet implemented. Real publisher-repo download is deferred.

use clap::Parser;

#[derive(Debug, Parser)]
pub struct BinaryUpdateArgs {
    /// Tool name to update (e.g. `ember-gh`).
    pub tool_name: String,
}

pub fn binary_update(args: &BinaryUpdateArgs) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!(
        "not yet implemented; install a new version explicitly via \
         'ember binary install {}@<new-version> --from-path <path>'",
        args.tool_name
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_returns_not_implemented_error() {
        let args = BinaryUpdateArgs {
            tool_name: "ember-gh".to_string(),
        };
        let result = binary_update(&args);
        assert!(result.is_err(), "update must return an error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not yet implemented"),
            "error must mention 'not yet implemented', got: {msg}"
        );
    }
}
