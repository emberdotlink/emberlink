use core_types::ValidationError;

/// A parsed grant link containing all fields needed to claim a grant offer.
///
/// Grant links are the atomic viral unit: they encode everything a recipient
/// needs to claim a grant without any out-of-band coordination.
///
/// Two URL formats are supported:
/// - Native: `emberlink://claim/<offer-id>?ek=...&exp=...&sig=...&issuer=...&ipk=...&rpk=...`
/// - Web:    `https://ember.link/#/claim/<offer-id>?ek=...&exp=...&sig=...&issuer=...&ipk=...&rpk=...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLink {
    /// Unique offer identifier. Format: `offer-{random}`.
    pub offer_id: String,
    /// Hex-encoded ephemeral public key. The sealed offer payload is
    /// encrypted to this key.
    pub ephemeral_public_key_hex: String,
    /// Expiry timestamp (epoch seconds).
    pub expires_at: u64,
    /// Issuer's signature over the canonical signing payload — proves link
    /// authenticity and binds both issuer identity and recipient public key
    /// into the signed bytes.
    pub issuer_signature: String,
    /// Optional relay endpoint hint for async pickup.
    ///
    /// Bound into [`Self::signing_payload`] so an on-path attacker cannot
    /// swap the relay endpoint without invalidating the signature
    /// (security review `docs/security-reviews/grant-link-rs-2026-04-23.md`,
    /// finding H-1).
    pub relay_hint: Option<String>,
    /// Compatibility field name for the issuer Principal ID bound into the
    /// signed payload.
    ///
    /// Prevents an attacker from reusing a valid link while substituting a
    /// different issuer identity — the verifier rejects any mismatch between
    /// the Principal recorded in the offer event and this signed field. Both
    /// self-parented root Principals and child Durable/Runtime Personas use
    /// this same value path.
    pub issuer_persona_id: String,
    /// Hex-encoded issuer public key that verifies [`Self::issuer_signature`].
    ///
    /// The browser-extension claim path is self-contained: a recipient may not
    /// have the issuer's event log yet, so the link must carry the key that
    /// authenticates the signed payload. This is still not a trust anchor by
    /// itself; callers display the fingerprint and later reconcile it with the
    /// issuer's identity material.
    pub issuer_public_key_hex: String,
    /// Hex-encoded recipient public key bound into the signed payload.
    ///
    /// Empty string for open (undirected) offers. When set, the verifier
    /// rejects any rewrite of this field that was not signed by the issuer,
    /// preventing an attacker from redirecting a directed offer to a key
    /// they control.
    pub recipient_pubkey_hex: String,
}

impl GrantLink {
    /// Unified Principal issuer for this grant link.
    pub fn issuer_principal_id(&self) -> &str {
        &self.issuer_persona_id
    }

    /// Render as a native deep link.
    ///
    /// Format: `emberlink://claim/<offer-id>?ek=<hex>&exp=<epoch>&sig=<hex>&issuer=<id>&ipk=<hex>&rpk=<hex>[&relay=<url>]`
    pub fn to_url(&self) -> String {
        let mut url = format!(
            "emberlink://claim/{}?ek={}&exp={}&sig={}&issuer={}&ipk={}&rpk={}",
            self.offer_id,
            self.ephemeral_public_key_hex,
            self.expires_at,
            self.issuer_signature,
            self.issuer_persona_id,
            self.issuer_public_key_hex,
            self.recipient_pubkey_hex,
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
            "https://ember.link/{relay_query}#/claim/{}?ek={}&exp={}&sig={}&issuer={}&ipk={}&rpk={}",
            self.offer_id,
            self.ephemeral_public_key_hex,
            self.expires_at,
            self.issuer_signature,
            self.issuer_persona_id,
            self.issuer_public_key_hex,
            self.recipient_pubkey_hex,
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
        let mut issuer = None;
        let mut ipk = None;
        let mut rpk = None;

        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                match key {
                    "ek" => ek = Some(value.to_string()),
                    "exp" => exp = Some(value.to_string()),
                    "sig" => sig = Some(value.to_string()),
                    "relay" => relay = Some(value.to_string()),
                    "issuer" => issuer = Some(value.to_string()),
                    "ipk" => ipk = Some(value.to_string()),
                    "rpk" => rpk = Some(value.to_string()),
                    _ => {} // ignore unknown params for forward compat
                }
            }
        }

        let ephemeral_public_key_hex =
            ek.ok_or_else(|| ValidationError::invalid_format("grant link missing ek parameter"))?;
        let expires_str =
            exp.ok_or_else(|| ValidationError::invalid_format("grant link missing exp parameter"))?;
        let expires_at = expires_str.parse::<u64>().map_err(|_| {
            ValidationError::invalid_format("exp must be a valid u64 epoch timestamp")
        })?;
        let issuer_signature =
            sig.ok_or_else(|| ValidationError::invalid_format("grant link missing sig parameter"))?;
        let issuer_persona_id = issuer.ok_or_else(|| {
            ValidationError::invalid_format("grant link missing issuer parameter")
        })?;
        let issuer_public_key_hex =
            ipk.ok_or_else(|| ValidationError::invalid_format("grant link missing ipk parameter"))?;
        // rpk is optional — empty string for open (undirected) offers
        let recipient_pubkey_hex = rpk.unwrap_or_default();

        Ok(GrantLink {
            offer_id: offer_id.to_string(),
            ephemeral_public_key_hex,
            expires_at,
            issuer_signature,
            relay_hint: relay,
            issuer_persona_id,
            issuer_public_key_hex,
            recipient_pubkey_hex,
        })
    }

    /// The canonical payload that the issuer signs to prove link authenticity.
    ///
    /// Format: `<offer_id>|<ephemeral_public_key_hex>|<expires_at>|<relay_hint_or_empty>|<issuer_principal_id>|<issuer_public_key_hex>|<recipient_pubkey_hex_or_empty>`
    ///
    /// Field ordering matches the reading order of the rendered URL.
    /// `relay_hint = None` is encoded as an empty field (GL-H1).
    /// `issuer_public_key_hex` is the key that verifies the signature.
    /// `recipient_pubkey_hex` is empty for open (undirected) offers.
    ///
    /// `issuer_principal_id`, `issuer_public_key_hex`, and `recipient_pubkey_hex`
    /// are bound into the signed bytes so an attacker cannot rewrite those
    /// fields on the wire without breaking the signature.
    pub fn signing_payload(
        offer_id: &str,
        ek_hex: &str,
        expires_at: u64,
        relay_hint: Option<&str>,
        issuer_principal_id: &str,
        issuer_public_key_hex: &str,
        recipient_pubkey_hex: &str,
    ) -> Vec<u8> {
        let relay = relay_hint.unwrap_or("");
        format!(
            "{offer_id}|{ek_hex}|{expires_at}|{relay}|{issuer_principal_id}|{issuer_public_key_hex}|{recipient_pubkey_hex}"
        )
        .into_bytes()
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
            issuer_persona_id: "principal-issuer".to_string(),
            issuer_public_key_hex: "ed25519-issuer-key".to_string(),
            recipient_pubkey_hex: String::new(),
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
        assert_eq!(
            parsed.relay_hint,
            Some("wss://relay.example.com".to_string())
        );

        let web = link.to_web_url();
        assert!(web.contains("?relay=wss://relay.example.com"));
        let parsed_web = GrantLink::parse(&web).unwrap();
        assert_eq!(
            parsed_web.relay_hint,
            Some("wss://relay.example.com".to_string())
        );
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
    fn missing_issuer_public_key_rejected() {
        let url = "emberlink://claim/offer-1?ek=abc&exp=100&sig=xyz&issuer=principal-1";
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
        assert_eq!(
            url,
            "emberlink://claim/offer-abc123?relay=wss://relay.example.com"
        );
        assert!(!url.contains("ek="));
    }

    #[test]
    fn signing_payload_deterministic() {
        let p1 =
            GrantLink::signing_payload("offer-1", "aabb", 12345, None, "principal-x", "pk-x", "");
        let p2 =
            GrantLink::signing_payload("offer-1", "aabb", 12345, None, "principal-x", "pk-x", "");
        assert_eq!(p1, p2);
        assert_eq!(p1, b"offer-1|aabb|12345||principal-x|pk-x|");
    }

    #[test]
    fn signing_payload_binds_relay_hint() {
        // GL-H1: the relay hint must be part of the signed bytes so an
        // on-path attacker cannot swap relay endpoints without breaking
        // the signature.
        let with_relay_a = GrantLink::signing_payload(
            "offer-1",
            "aabb",
            12345,
            Some("wss://honest.example.com"),
            "principal-x",
            "pk-x",
            "",
        );
        let with_relay_b = GrantLink::signing_payload(
            "offer-1",
            "aabb",
            12345,
            Some("wss://evil.example.com"),
            "principal-x",
            "pk-x",
            "",
        );
        let without_relay =
            GrantLink::signing_payload("offer-1", "aabb", 12345, None, "principal-x", "pk-x", "");

        assert_ne!(with_relay_a, with_relay_b);
        assert_ne!(with_relay_a, without_relay);
        assert_ne!(with_relay_b, without_relay);
        assert_eq!(
            with_relay_a,
            b"offer-1|aabb|12345|wss://honest.example.com|principal-x|pk-x|",
        );
        assert_eq!(without_relay, b"offer-1|aabb|12345||principal-x|pk-x|");
    }

    #[test]
    fn relay_hint_tamper_detected() {
        // GL-H1: end-to-end demonstration. Build the signing payload an
        // honest issuer would compute for a link carrying relay_hint_A.
        // An on-path attacker rewrites the link to advertise relay_hint_B.
        // The verifier recomputes the signing payload from the parsed
        // (tampered) link and the bytes no longer match what the issuer
        // signed — so any signature check against `issuer_signed_bytes`
        // will reject `attacker_recomputed_bytes`.
        let mut link = sample_link();
        link.relay_hint = Some("wss://honest.example.com".to_string());

        let issuer_signed_bytes = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );

        // Render, then simulate an on-path swap of the relay query param.
        let url = link.to_url();
        let tampered = url.replace(
            "&relay=wss://honest.example.com",
            "&relay=wss://evil.example.com",
        );
        assert_ne!(url, tampered, "tamper substitution must apply");
        let parsed_tampered = GrantLink::parse(&tampered).unwrap();
        assert_eq!(
            parsed_tampered.relay_hint.as_deref(),
            Some("wss://evil.example.com"),
        );

        let attacker_recomputed_bytes = GrantLink::signing_payload(
            &parsed_tampered.offer_id,
            &parsed_tampered.ephemeral_public_key_hex,
            parsed_tampered.expires_at,
            parsed_tampered.relay_hint.as_deref(),
            &parsed_tampered.issuer_persona_id,
            &parsed_tampered.issuer_public_key_hex,
            &parsed_tampered.recipient_pubkey_hex,
        );
        assert_ne!(
            issuer_signed_bytes, attacker_recomputed_bytes,
            "relay swap must change the signing payload so signature \
             verification fails",
        );
    }

    #[test]
    fn relay_hint_addition_detected() {
        // GL-H1 corollary: an attacker appending `&relay=...` to a link
        // the issuer rendered without one must also break the signature.
        let link = sample_link();
        assert!(link.relay_hint.is_none());

        let issuer_signed_bytes = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );

        let url = link.to_url();
        let tampered = format!("{url}&relay=wss://evil.example.com");
        let parsed_tampered = GrantLink::parse(&tampered).unwrap();
        assert_eq!(
            parsed_tampered.relay_hint.as_deref(),
            Some("wss://evil.example.com"),
        );

        let attacker_recomputed_bytes = GrantLink::signing_payload(
            &parsed_tampered.offer_id,
            &parsed_tampered.ephemeral_public_key_hex,
            parsed_tampered.expires_at,
            parsed_tampered.relay_hint.as_deref(),
            &parsed_tampered.issuer_persona_id,
            &parsed_tampered.issuer_public_key_hex,
            &parsed_tampered.recipient_pubkey_hex,
        );
        assert_ne!(issuer_signed_bytes, attacker_recomputed_bytes);
    }

    // -- ephemeral_public_key_hex and issuer Principal ID tamper detection --

    #[test]
    fn ephemeral_key_rewrite_changes_signing_payload() {
        // The ephemeral public key is bound into the signed bytes.
        // An attacker who rewrites `ek` on the wire causes the verifier to
        // recompute a different payload — signature check rejects the link.
        let link = sample_link();
        let honest_payload = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );

        // Attacker rewrites ek in the rendered URL.
        let url = link.to_url();
        let tampered = url.replace(
            &format!("ek={}", link.ephemeral_public_key_hex),
            "ek=attackerpubkey0011",
        );
        assert_ne!(url, tampered, "tamper substitution must apply");
        let parsed_tampered = GrantLink::parse(&tampered).unwrap();
        assert_eq!(
            parsed_tampered.ephemeral_public_key_hex,
            "attackerpubkey0011"
        );

        let attacker_payload = GrantLink::signing_payload(
            &parsed_tampered.offer_id,
            &parsed_tampered.ephemeral_public_key_hex,
            parsed_tampered.expires_at,
            parsed_tampered.relay_hint.as_deref(),
            &parsed_tampered.issuer_persona_id,
            &parsed_tampered.issuer_public_key_hex,
            &parsed_tampered.recipient_pubkey_hex,
        );
        assert_ne!(
            honest_payload, attacker_payload,
            "ephemeral key rewrite must change the signing payload so \
             signature verification fails",
        );
    }

    #[test]
    fn issuer_principal_id_rewrite_changes_signing_payload() {
        // The issuer Principal ID is bound into the signed bytes.
        // An attacker who rewrites `issuer` on the wire causes the verifier to
        // recompute a different payload — signature check rejects the link.
        let link = sample_link();
        let honest_payload = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );

        // Attacker rewrites the issuer param in the rendered URL.
        let url = link.to_url();
        let tampered = url.replace(
            &format!("issuer={}", link.issuer_persona_id),
            "issuer=principal-attacker",
        );
        assert_ne!(url, tampered, "tamper substitution must apply");
        let parsed_tampered = GrantLink::parse(&tampered).unwrap();
        assert_eq!(parsed_tampered.issuer_persona_id, "principal-attacker");

        let attacker_payload = GrantLink::signing_payload(
            &parsed_tampered.offer_id,
            &parsed_tampered.ephemeral_public_key_hex,
            parsed_tampered.expires_at,
            parsed_tampered.relay_hint.as_deref(),
            &parsed_tampered.issuer_persona_id,
            &parsed_tampered.issuer_public_key_hex,
            &parsed_tampered.recipient_pubkey_hex,
        );
        assert_ne!(
            honest_payload, attacker_payload,
            "issuer Principal ID rewrite must change the signing payload so \
             signature verification fails",
        );
    }

    #[test]
    fn issuer_public_key_rewrite_changes_signing_payload() {
        // The issuer public key is bound into the signed bytes and is also the
        // verification key for the link signature. Rewriting `ipk` therefore
        // changes the payload and makes the old signature unverifiable.
        let link = sample_link();
        let honest_payload = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );

        let url = link.to_url();
        let tampered = url.replace(
            &format!("ipk={}", link.issuer_public_key_hex),
            "ipk=attackerpubkey0011",
        );
        assert_ne!(url, tampered, "tamper substitution must apply");
        let parsed_tampered = GrantLink::parse(&tampered).unwrap();
        assert_eq!(parsed_tampered.issuer_public_key_hex, "attackerpubkey0011");

        let attacker_payload = GrantLink::signing_payload(
            &parsed_tampered.offer_id,
            &parsed_tampered.ephemeral_public_key_hex,
            parsed_tampered.expires_at,
            parsed_tampered.relay_hint.as_deref(),
            &parsed_tampered.issuer_persona_id,
            &parsed_tampered.issuer_public_key_hex,
            &parsed_tampered.recipient_pubkey_hex,
        );
        assert_ne!(
            honest_payload, attacker_payload,
            "issuer public key rewrite must change the signing payload so \
             signature verification fails",
        );
    }
}
