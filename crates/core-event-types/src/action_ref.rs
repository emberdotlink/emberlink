use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Canonical authority-side action identity per ADR 184 / ADR 186.
///
/// `plugin_address` identifies the publishing package, `action_key`
/// identifies the action within that package, and `action_version`
/// versions the action contract itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionRef {
    pub plugin_address: String,
    pub action_key: String,
    pub action_version: String,
}

impl ActionRef {
    pub fn new(
        plugin_address: impl Into<String>,
        action_key: impl Into<String>,
        action_version: impl Into<String>,
    ) -> Self {
        Self {
            plugin_address: plugin_address.into(),
            action_key: action_key.into(),
            action_version: action_version.into(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.plugin_address.trim().is_empty() {
            return Err("plugin_address must not be empty");
        }
        if self.action_key.trim().is_empty() {
            return Err("action_key must not be empty");
        }
        if self.action_version.trim().is_empty() {
            return Err("action_version must not be empty");
        }
        Ok(())
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let (lhs, action_version) = input
            .rsplit_once('@')
            .ok_or_else(|| "expected plugin_address/action_key@action_version".to_string())?;
        let (plugin_address, action_key) = lhs
            .rsplit_once('/')
            .ok_or_else(|| "expected plugin_address/action_key@action_version".to_string())?;
        let action_ref = Self::new(plugin_address, action_key, action_version);
        action_ref.validate().map_err(str::to_string)?;
        Ok(action_ref)
    }
}

impl std::fmt::Display for ActionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}@{}",
            self.plugin_address, self.action_key, self.action_version
        )
    }
}

/// Structured action-ref matcher used by delegation grants and other
/// construct-facing policy surfaces. `*` matches any value within a field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ActionRefPattern {
    pub plugin_address: String,
    pub action_key: String,
    pub action_version: String,
}

impl ActionRefPattern {
    pub fn new(
        plugin_address: impl Into<String>,
        action_key: impl Into<String>,
        action_version: impl Into<String>,
    ) -> Self {
        Self {
            plugin_address: plugin_address.into(),
            action_key: action_key.into(),
            action_version: action_version.into(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.plugin_address.trim().is_empty() {
            return Err("plugin_address must not be empty");
        }
        if self.action_key.trim().is_empty() {
            return Err("action_key must not be empty");
        }
        if self.action_version.trim().is_empty() {
            return Err("action_version must not be empty");
        }
        Ok(())
    }

    pub fn matches(&self, action_ref: &ActionRef) -> bool {
        matches_component(&self.plugin_address, &action_ref.plugin_address)
            && matches_component(&self.action_key, &action_ref.action_key)
            && matches_component(&self.action_version, &action_ref.action_version)
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let (lhs, action_version) = input
            .rsplit_once('@')
            .ok_or_else(|| "expected plugin_address/action_key@action_version".to_string())?;
        let (plugin_address, action_key) = lhs
            .rsplit_once('/')
            .ok_or_else(|| "expected plugin_address/action_key@action_version".to_string())?;
        let pattern = Self::new(plugin_address, action_key, action_version);
        pattern.validate().map_err(str::to_string)?;
        Ok(pattern)
    }
}

impl From<ActionRef> for ActionRefPattern {
    fn from(value: ActionRef) -> Self {
        Self::new(value.plugin_address, value.action_key, value.action_version)
    }
}

impl From<&ActionRef> for ActionRefPattern {
    fn from(value: &ActionRef) -> Self {
        Self::new(
            value.plugin_address.clone(),
            value.action_key.clone(),
            value.action_version.clone(),
        )
    }
}

impl std::fmt::Display for ActionRefPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}@{}",
            self.plugin_address, self.action_key, self.action_version
        )
    }
}

impl<'de> Deserialize<'de> for ActionRefPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            String(String),
            Struct {
                plugin_address: String,
                action_key: String,
                action_version: String,
            },
        }

        let pattern = match Repr::deserialize(deserializer)? {
            Repr::String(value) => Self::parse(&value).map_err(serde::de::Error::custom)?,
            Repr::Struct {
                plugin_address,
                action_key,
                action_version,
            } => Self::new(plugin_address, action_key, action_version),
        };
        pattern.validate().map_err(serde::de::Error::custom)?;
        Ok(pattern)
    }
}

fn matches_component(pattern: &str, actual: &str) -> bool {
    pattern == "*" || pattern == actual
}

/// Mixed selector used on generic grant/policy seams that still need to
/// represent both structured construct refs and non-construct named verbs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActionSelector {
    Named { pattern: String },
    ActionRef(ActionRefPattern),
}

impl ActionSelector {
    pub fn named(pattern: impl Into<String>) -> Self {
        Self::Named {
            pattern: pattern.into(),
        }
    }

    pub fn action_ref(pattern: ActionRefPattern) -> Self {
        Self::ActionRef(pattern)
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("action selector must not be empty".to_string());
        }
        match ActionRefPattern::parse(trimmed) {
            Ok(pattern) => Ok(Self::ActionRef(pattern)),
            Err(_) => Ok(Self::named(trimmed)),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Named { pattern } => {
                if pattern.trim().is_empty() {
                    return Err("named action pattern must not be empty");
                }
                Ok(())
            }
            Self::ActionRef(pattern) => pattern.validate(),
        }
    }

    pub fn matches_action(&self, action: &str) -> bool {
        match self {
            Self::Named { pattern } => glob_matches(pattern, action),
            Self::ActionRef(pattern) => ActionRef::parse(action)
                .map(|action_ref| pattern.matches(&action_ref))
                .unwrap_or(false),
        }
    }

    pub fn matches_action_ref(&self, action_ref: &ActionRef) -> bool {
        match self {
            Self::Named { pattern } => glob_matches(pattern, &action_ref.to_string()),
            Self::ActionRef(pattern) => pattern.matches(action_ref),
        }
    }
}

impl std::fmt::Display for ActionSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named { pattern } => write!(f, "{pattern}"),
            Self::ActionRef(pattern) => write!(f, "{pattern}"),
        }
    }
}

impl Serialize for ActionSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Named { pattern } => {
                map.serialize_entry("kind", "named")?;
                map.serialize_entry("pattern", pattern)?;
            }
            Self::ActionRef(pattern) => {
                map.serialize_entry("kind", "action_ref")?;
                map.serialize_entry("plugin_address", &pattern.plugin_address)?;
                map.serialize_entry("action_key", &pattern.action_key)?;
                map.serialize_entry("action_version", &pattern.action_version)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ActionSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            String(String),
            Tagged(TaggedSelector),
            ActionRefFields {
                plugin_address: String,
                action_key: String,
                action_version: String,
            },
        }

        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum TaggedSelector {
            Named {
                pattern: String,
            },
            ActionRef {
                plugin_address: String,
                action_key: String,
                action_version: String,
            },
        }

        let selector = match Repr::deserialize(deserializer)? {
            Repr::String(value) => Self::parse(&value).map_err(serde::de::Error::custom)?,
            Repr::Tagged(TaggedSelector::Named { pattern }) => Self::named(pattern),
            Repr::Tagged(TaggedSelector::ActionRef {
                plugin_address,
                action_key,
                action_version,
            })
            | Repr::ActionRefFields {
                plugin_address,
                action_key,
                action_version,
            } => Self::action_ref(ActionRefPattern::new(
                plugin_address,
                action_key,
                action_version,
            )),
        };
        selector.validate().map_err(serde::de::Error::custom)?;
        Ok(selector)
    }
}

fn glob_matches(pattern: &str, s: &str) -> bool {
    fn inner(p: &[u8], s: &[u8]) -> bool {
        let (mut pi, mut si) = (0usize, 0usize);
        let (mut star_pi, mut star_si) = (usize::MAX, 0usize);
        while si < s.len() {
            if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
                pi += 1;
                si += 1;
            } else if pi < p.len() && p[pi] == b'*' {
                star_pi = pi;
                star_si = si;
                pi += 1;
            } else if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_si += 1;
                si = star_si;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }
    inner(pattern.as_bytes(), s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{ActionRef, ActionRefPattern, ActionSelector};

    #[test]
    fn parses_pattern_string() {
        let pattern =
            ActionRefPattern::parse("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1")
                .unwrap();
        assert_eq!(
            pattern,
            ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_merge",
                "v1"
            )
        );
    }

    #[test]
    fn wildcard_action_key_matches() {
        let pattern =
            ActionRefPattern::new("registry.ember.systems/ember-systems/ember-gh", "*", "v1");
        assert!(pattern.matches(&ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1"
        )));
        assert!(!pattern.matches(&ActionRef::new(
            "registry.ember.systems/ember-systems/ember-git",
            "push",
            "v1"
        )));
    }

    #[test]
    fn wildcard_version_matches() {
        let pattern = ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "*",
        );
        assert!(pattern.matches(&ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v2"
        )));
    }

    #[test]
    fn parses_action_ref_string() {
        let action_ref =
            ActionRef::parse("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1").unwrap();
        assert_eq!(
            action_ref,
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_merge",
                "v1"
            )
        );
    }

    #[test]
    fn action_selector_parses_named_pattern() {
        let selector = ActionSelector::parse("credential.access.*").unwrap();
        assert_eq!(
            selector,
            ActionSelector::Named {
                pattern: "credential.access.*".to_string()
            }
        );
    }

    #[test]
    fn action_selector_parses_action_ref_pattern_string() {
        let selector =
            ActionSelector::parse("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1")
                .unwrap();
        assert_eq!(
            selector,
            ActionSelector::action_ref(ActionRefPattern::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_merge",
                "v1"
            ))
        );
    }

    #[test]
    fn action_selector_named_matches_glob() {
        let selector = ActionSelector::named("credential.access.*");
        assert!(selector.matches_action("credential.access.github-token"));
        assert!(!selector.matches_action("tool.call"));
    }

    #[test]
    fn action_selector_action_ref_matches_structured_ref() {
        let selector = ActionSelector::action_ref(ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1",
        ));
        assert!(selector.matches_action_ref(&ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1"
        )));
        assert!(
            selector.matches_action("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1")
        );
    }
}
