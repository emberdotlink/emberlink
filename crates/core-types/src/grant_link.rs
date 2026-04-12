use crate::ValidationError;

/// A parsed grant link containing all fields needed to claim a grant offer.
///
/// Grant links are the atomic viral unit: they encode everything a recipient
/// needs to claim a grant without any out-of-band coordination.
///
/// Two URL formats are supported:
/// - Native: `emberlink://claim/<offer-id>?ek=...&exp=...&sig=...`
/// - Web:    `https://ember.link/#/claim/<offer-id>?ek=...&exp=...&sig=...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLink {
    /// Unique offer identifier. Format: `offer-{random}`.
    pub offer_id: String,
    /// Hex-encoded ephemeral public key. The sealed offer payload is
    /// encrypted to this key.
    pub ephemeral_public_key_hex: String,
    /// Expiry timestamp (epoch seconds).
    pub expires_at: u64,
    /// Issuer's signature over `offer_id|ek|exp`, proving link authenticity.
    pub issuer_signature: String,
    /// Optional relay endpoint hint for async pickup.
    pub relay_hint: Option<String>,
}

impl GrantLink {
    /// Render as a native deep link.
    ///
    /// Format: `emberlink://claim/<offer-id>?ek=<hex>&exp=<epoch>&sig=<hex>[&relay=<url>]`
    pub fn to_url(&self) -> String {
        let mut url = format!(
            "emberlink://claim/{}?ek={}&exp={}&sig={}",
            self.offer_id, self.ephemeral_public_key_hex, self.expires_at, self.issuer_signature,
        );
        if let Some(relay) = &self.relay_hint {
            url.push_str(&format!("&relay={relay}"));
        }
        url
    }

    /// Render as a minimal deep link for OS URI handler dispatch.
    ///
    /// **Security:** Only `offer_id` and optional `relay` are included.
    /// Ephemeral key material (`ek`, `sig`, `exp`) is excluded because OS URI
    /// handlers log the full URL in browser history, system logs, and crash
    /// reporters. The native app fetches the sealed offer from the relay.
    pub fn to_deep_link_url(&self) -> String {
        match &self.relay_hint {
            Some(relay) => format!("emberlink://claim/{}?relay={relay}", self.offer_id),
            None => format!("emberlink://claim/{}", self.offer_id),
        }
    }

    /// Render as a web redirect URL.
    ///
    /// Crypto material travels in the fragment so it is never sent to the
    /// web server. The relay hint (if present) is a query parameter since
    /// the client needs it to fetch the sealed payload.
    pub fn to_web_url(&self) -> String {
        let relay_query = match &self.relay_hint {
            Some(relay) => format!("?relay={relay}"),
            None => String::new(),
        };
        format!(
            "https://ember.link/{relay_query}#/claim/{}?ek={}&exp={}&sig={}",
            self.offer_id, self.ephemeral_public_key_hex, self.expires_at, self.issuer_signature,
        )
    }

    /// Parse a grant link from either native or web URL format.
    pub fn parse(url: &str) -> Result<Self, ValidationError> {
        // Determine scheme and extract the path+query portion, plus any
        // pre-fragment query params (web URLs put relay hint there).
        let mut pre_fragment_relay: Option<String> = None;

        let claim_part = if let Some(rest) = url.strip_prefix("emberlink://claim/") {
            rest.to_string()
        } else if url.starts_with("https://ember.link/") {
            // Web URLs may have ?relay=... before the fragment
            let (before_fragment, fragment_raw) = url
                .split_once('#')
                .ok_or_else(|| ValidationError::invalid_format("web URL missing fragment"))?;

            // Parse pre-fragment query for relay hint
            if let Some((_, query_part)) = before_fragment.split_once('?') {
                for pair in query_part.split('&') {
                    if let Some((key, value)) = pair.split_once('=')
                        && key == "relay"
                    {
                        pre_fragment_relay = Some(value.to_string());
                    }
                }
            }

            fragment_raw
                .strip_prefix("/claim/")
                .ok_or_else(|| {
                    ValidationError::invalid_format("web URL fragment must start with /claim/")
                })?
                .to_string()
        } else {
            return Err(ValidationError::invalid_format(
                "grant link must start with emberlink://claim/ or https://ember.link/",
            ));
        };

        // Split offer-id from query string
        let (offer_id, query) = claim_part.split_once('?').ok_or_else(|| {
            ValidationError::invalid_format("grant link missing query parameters")
        })?;

        if offer_id.is_empty() {
            return Err(ValidationError::empty_field("offer_id"));
        }

        let mut ek = None;
        let mut exp = None;
        let mut sig = None;
        let mut relay = pre_fragment_relay;

        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                match key {
                    "ek" => ek = Some(value.to_string()),
                    "exp" => exp = Some(value.to_string()),
                    "sig" => sig = Some(value.to_string()),
                    "relay" => relay = Some(value.to_string()),
                    _ => {} // ignore unknown params for forward compat
                }
            }
        }

        let ephemeral_public_key_hex = ek.ok_or_else(|| {
            ValidationError::invalid_format("grant link missing ek parameter")
        })?;
        let expires_str = exp.ok_or_else(|| {
            ValidationError::invalid_format("grant link missing exp parameter")
        })?;
        let expires_at = expires_str.parse::<u64>().map_err(|_| {
            ValidationError::invalid_format("exp must be a valid u64 epoch timestamp")
        })?;
        let issuer_signature = sig.ok_or_else(|| {
            ValidationError::invalid_format("grant link missing sig parameter")
        })?;

        Ok(GrantLink {
            offer_id: offer_id.to_string(),
            ephemeral_public_key_hex,
            expires_at,
            issuer_signature,
            relay_hint: relay,
        })
    }

    /// The canonical payload that the issuer signs to prove link authenticity.
    ///
    /// Format: `<offer_id>|<ephemeral_public_key_hex>|<expires_at>`
    pub fn signing_payload(offer_id: &str, ek_hex: &str, expires_at: u64) -> Vec<u8> {
        format!("{offer_id}|{ek_hex}|{expires_at}").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_link() -> GrantLink {
        GrantLink {
            offer_id: "offer-abc123".to_string(),
            ephemeral_public_key_hex: "deadbeef".to_string(),
            expires_at: 1700000000,
            issuer_signature: "sig0011".to_string(),
            relay_hint: None,
        }
    }

    #[test]
    fn native_url_round_trips() {
        let link = sample_link();
        let url = link.to_url();
        assert!(url.starts_with("emberlink://claim/offer-abc123?"));
        let parsed = GrantLink::parse(&url).unwrap();
        assert_eq!(parsed, link);
    }

    #[test]
    fn web_url_round_trips() {
        let link = sample_link();
        let url = link.to_web_url();
        assert!(url.starts_with("https://ember.link/"));
        assert!(url.contains("#/claim/offer-abc123?"));
        let parsed = GrantLink::parse(&url).unwrap();
        assert_eq!(parsed, link);
    }

    #[test]
    fn relay_hint_included() {
        let mut link = sample_link();
        link.relay_hint = Some("wss://relay.example.com".to_string());

        let native = link.to_url();
        assert!(native.contains("&relay=wss://relay.example.com"));
        let parsed = GrantLink::parse(&native).unwrap();
        assert_eq!(parsed.relay_hint, Some("wss://relay.example.com".to_string()));

        let web = link.to_web_url();
        assert!(web.contains("?relay=wss://relay.example.com"));
        let parsed_web = GrantLink::parse(&web).unwrap();
        assert_eq!(parsed_web.relay_hint, Some("wss://relay.example.com".to_string()));
    }

    #[test]
    fn missing_ek_rejected() {
        let url = "emberlink://claim/offer-1?exp=100&sig=abc";
        assert!(GrantLink::parse(url).is_err());
    }

    #[test]
    fn missing_exp_rejected() {
        let url = "emberlink://claim/offer-1?ek=abc&sig=abc";
        assert!(GrantLink::parse(url).is_err());
    }

    #[test]
    fn missing_sig_rejected() {
        let url = "emberlink://claim/offer-1?ek=abc&exp=100";
        assert!(GrantLink::parse(url).is_err());
    }

    #[test]
    fn invalid_scheme_rejected() {
        let url = "http://example.com/claim/offer-1?ek=abc&exp=100&sig=xyz";
        assert!(GrantLink::parse(url).is_err());
    }

    #[test]
    fn empty_offer_id_rejected() {
        let url = "emberlink://claim/?ek=abc&exp=100&sig=xyz";
        assert!(GrantLink::parse(url).is_err());
    }

    #[test]
    fn deep_link_url_excludes_key_material() {
        let link = sample_link();
        let url = link.to_deep_link_url();
        assert_eq!(url, "emberlink://claim/offer-abc123");
        assert!(!url.contains("ek="));
        assert!(!url.contains("sig="));
        assert!(!url.contains("exp="));
    }

    #[test]
    fn deep_link_url_includes_relay_hint() {
        let mut link = sample_link();
        link.relay_hint = Some("wss://relay.example.com".to_string());
        let url = link.to_deep_link_url();
        assert_eq!(url, "emberlink://claim/offer-abc123?relay=wss://relay.example.com");
        assert!(!url.contains("ek="));
    }

    #[test]
    fn signing_payload_deterministic() {
        let p1 = GrantLink::signing_payload("offer-1", "aabb", 12345);
        let p2 = GrantLink::signing_payload("offer-1", "aabb", 12345);
        assert_eq!(p1, p2);
        assert_eq!(p1, b"offer-1|aabb|12345");
    }
}
