//! CLASSIFICATION: PUBLIC
//!
//! SSRF / metadata-IP destination guard for the forward proxy (ADR 205 §4).
//!
//! The agent supplies the upstream destination via `X-Ember-Target`, and the
//! proxy attaches the operator's brokered credential to the request it forwards
//! there. Without a destination guard a confused-deputy agent can aim that
//! credential — and the proxy's own network position — at the cloud metadata
//! endpoint (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), at
//! loopback, or at an internal RFC-1918 host. This module is the pure
//! classifier that decides whether a resolved destination IP is a permissible
//! proxy upstream.
//!
//! It is **pure** (`std::net` only, no I/O, no DNS) so it is unit-testable in
//! isolation and can be shared by both the pre-flight literal check and the
//! connect-time resolver guard. Two enforcement points consume it
//! (`proxy-forward-runtime`):
//!   1. a pre-flight check on an IP-literal `X-Ember-Target` host (clean 403),
//!   2. a connect-time resolver that filters every DNS-resolved address, so a
//!      hostname that resolves (or *re-resolves*, defeating DNS rebinding) to a
//!      blocked IP cannot be reached.
//!
//! Fail-closed: anything not provably a normal public unicast address is
//! blocked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a destination IP is refused as a proxy upstream. Carried into the 403 /
/// audit log so an operator can see *which* class of address was refused
/// without the guard having to leak the address itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedIpReason {
    /// `127.0.0.0/8`, `::1` — loopback (the proxy itself / local services).
    Loopback,
    /// `0.0.0.0`, `::`, and the `0.0.0.0/8` "this network" block.
    Unspecified,
    /// `169.254.0.0/16` (incl. the `169.254.169.254` cloud metadata IP) and
    /// IPv6 link-local `fe80::/10`.
    LinkLocal,
    /// RFC-1918 private space: `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// `100.64.0.0/10` shared/CGNAT (incl. Alibaba's `100.100.100.200`
    /// metadata IP).
    SharedCgnat,
    /// IPv6 unique-local `fc00::/7` (incl. AWS's `fd00:ec2::254` IPv6 metadata).
    UniqueLocal,
    /// `224.0.0.0/4` / `ff00::/8` multicast.
    Multicast,
    /// `255.255.255.255` limited broadcast.
    Broadcast,
    /// Documentation / example ranges (`192.0.2/24`, `198.51.100/24`,
    /// `203.0.113/24`, `2001:db8::/32`).
    Documentation,
    /// `198.18.0.0/15` benchmarking.
    Benchmarking,
    /// Other IANA-reserved space not safe as a public upstream (`240/4` Class E,
    /// `192.0.0.0/24` IETF protocol assignments).
    Reserved,
}

impl BlockedIpReason {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockedIpReason::Loopback => "loopback",
            BlockedIpReason::Unspecified => "unspecified",
            BlockedIpReason::LinkLocal => "link-local (incl. cloud metadata)",
            BlockedIpReason::Private => "rfc1918-private",
            BlockedIpReason::SharedCgnat => "shared/cgnat (incl. cloud metadata)",
            BlockedIpReason::UniqueLocal => "ipv6-unique-local (incl. cloud metadata)",
            BlockedIpReason::Multicast => "multicast",
            BlockedIpReason::Broadcast => "broadcast",
            BlockedIpReason::Documentation => "documentation",
            BlockedIpReason::Benchmarking => "benchmarking",
            BlockedIpReason::Reserved => "reserved",
        }
    }
}

/// Classify a destination IP. `Some(reason)` ⇒ the proxy MUST NOT forward to it;
/// `None` ⇒ a normal public unicast address that may be reached.
///
/// IPv4-mapped / -compatible IPv6 addresses (`::ffff:a.b.c.d`, `::a.b.c.d`) are
/// unwrapped and classified as the inner IPv4 — a connection to them lands on
/// that IPv4 host, so `::ffff:169.254.169.254` is blocked exactly like its bare
/// form (a classic guard-bypass vector).
pub fn classify_blocked_ip(ip: IpAddr) -> Option<BlockedIpReason> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<BlockedIpReason> {
    let o = ip.octets();
    if ip.is_loopback() {
        return Some(BlockedIpReason::Loopback);
    }
    if o[0] == 0 {
        // 0.0.0.0/8 "this network" (incl. 0.0.0.0 unspecified).
        return Some(BlockedIpReason::Unspecified);
    }
    if ip.is_link_local() {
        // 169.254.0.0/16 — includes the 169.254.169.254 metadata endpoint.
        return Some(BlockedIpReason::LinkLocal);
    }
    if ip.is_private() {
        return Some(BlockedIpReason::Private);
    }
    if ip.is_broadcast() {
        return Some(BlockedIpReason::Broadcast);
    }
    if ip.is_multicast() {
        return Some(BlockedIpReason::Multicast);
    }
    if ip.is_documentation() {
        return Some(BlockedIpReason::Documentation);
    }
    // 100.64.0.0/10 shared address space / CGNAT (Alibaba metadata 100.100.100.200).
    if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        return Some(BlockedIpReason::SharedCgnat);
    }
    // 198.18.0.0/15 benchmarking.
    if o[0] == 198 && (o[1] & 0xfe) == 18 {
        return Some(BlockedIpReason::Benchmarking);
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some(BlockedIpReason::Reserved);
    }
    // 240.0.0.0/4 reserved (Class E), excludes 255.255.255.255 handled above.
    if o[0] >= 240 {
        return Some(BlockedIpReason::Reserved);
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<BlockedIpReason> {
    if ip.is_loopback() {
        return Some(BlockedIpReason::Loopback);
    }
    if ip.is_unspecified() {
        return Some(BlockedIpReason::Unspecified);
    }
    // Unwrap embedded IPv4 (mapped `::ffff:a.b.c.d` and the deprecated
    // compat `::a.b.c.d`) — a connection lands on the inner IPv4 host, so it
    // must be classified there. `to_ipv4()` returns Some only for `::/96` and
    // `::ffff:0:0/96`; loopback/unspecified are already handled above.
    if let Some(v4) = ip.to_ipv4() {
        return classify_v4(v4);
    }
    if ip.is_multicast() {
        return Some(BlockedIpReason::Multicast);
    }
    let segs = ip.segments();
    // fe80::/10 unicast link-local.
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Some(BlockedIpReason::LinkLocal);
    }
    // fc00::/7 unique-local (incl. fd00:ec2::254 AWS IPv6 metadata).
    if (ip.octets()[0] & 0xfe) == 0xfc {
        return Some(BlockedIpReason::UniqueLocal);
    }
    // 2001:db8::/32 documentation.
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return Some(BlockedIpReason::Documentation);
    }
    None
}

/// Pre-flight check on an `X-Ember-Target` host: if the host is an IP *literal*
/// that classifies as blocked, return the reason. A hostname (not an IP
/// literal) returns `None` here — it is the connect-time resolver guard's job
/// to classify whatever that name resolves to. Handles bracketed IPv6 literals
/// (`[::1]`) as they appear in URL authorities.
pub fn host_literal_is_blocked(host: &str) -> Option<BlockedIpReason> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match trimmed.parse::<IpAddr>() {
        Ok(ip) => classify_blocked_ip(ip),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn blocks_cloud_metadata_endpoints() {
        // The three big-cloud metadata IPs — the headline confused-deputy target.
        assert_eq!(
            classify_blocked_ip(v4("169.254.169.254")),
            Some(BlockedIpReason::LinkLocal),
            "AWS/GCP/Azure IMDS"
        );
        assert_eq!(
            classify_blocked_ip(v4("100.100.100.200")),
            Some(BlockedIpReason::SharedCgnat),
            "Alibaba metadata"
        );
        assert_eq!(
            classify_blocked_ip(v6("fd00:ec2::254")),
            Some(BlockedIpReason::UniqueLocal),
            "AWS IPv6 IMDS"
        );
    }

    #[test]
    fn blocks_loopback_private_linklocal() {
        assert_eq!(
            classify_blocked_ip(v4("127.0.0.1")),
            Some(BlockedIpReason::Loopback)
        );
        assert_eq!(
            classify_blocked_ip(v6("::1")),
            Some(BlockedIpReason::Loopback)
        );
        assert_eq!(
            classify_blocked_ip(v4("10.0.0.5")),
            Some(BlockedIpReason::Private)
        );
        assert_eq!(
            classify_blocked_ip(v4("172.16.4.4")),
            Some(BlockedIpReason::Private)
        );
        assert_eq!(
            classify_blocked_ip(v4("192.168.1.1")),
            Some(BlockedIpReason::Private)
        );
        assert_eq!(
            classify_blocked_ip(v4("169.254.1.1")),
            Some(BlockedIpReason::LinkLocal)
        );
        assert_eq!(
            classify_blocked_ip(v6("fe80::1")),
            Some(BlockedIpReason::LinkLocal)
        );
    }

    #[test]
    fn blocks_unspecified_broadcast_multicast_reserved() {
        assert_eq!(
            classify_blocked_ip(v4("0.0.0.0")),
            Some(BlockedIpReason::Unspecified)
        );
        assert_eq!(
            classify_blocked_ip(v4("0.1.2.3")),
            Some(BlockedIpReason::Unspecified)
        );
        assert_eq!(
            classify_blocked_ip(v6("::")),
            Some(BlockedIpReason::Unspecified)
        );
        assert_eq!(
            classify_blocked_ip(v4("255.255.255.255")),
            Some(BlockedIpReason::Broadcast)
        );
        assert_eq!(
            classify_blocked_ip(v4("224.0.0.1")),
            Some(BlockedIpReason::Multicast)
        );
        assert_eq!(
            classify_blocked_ip(v6("ff02::1")),
            Some(BlockedIpReason::Multicast)
        );
        assert_eq!(
            classify_blocked_ip(v4("240.0.0.1")),
            Some(BlockedIpReason::Reserved)
        );
    }

    #[test]
    fn blocks_ipv4_mapped_and_compat_metadata_bypass() {
        // ::ffff:169.254.169.254 connects to 169.254.169.254 — must be blocked.
        assert_eq!(
            classify_blocked_ip(v6("::ffff:169.254.169.254")),
            Some(BlockedIpReason::LinkLocal),
            "ipv4-mapped metadata bypass"
        );
        assert_eq!(
            classify_blocked_ip(v6("::ffff:127.0.0.1")),
            Some(BlockedIpReason::Loopback)
        );
        // Mapped public address is still reachable.
        assert_eq!(classify_blocked_ip(v6("::ffff:8.8.8.8")), None);
    }

    #[test]
    fn allows_normal_public_addresses() {
        assert_eq!(classify_blocked_ip(v4("8.8.8.8")), None);
        assert_eq!(classify_blocked_ip(v4("140.82.112.3")), None, "github.com");
        assert_eq!(classify_blocked_ip(v4("160.79.104.10")), None, "anthropic");
        assert_eq!(
            classify_blocked_ip(v6("2606:4700::1111")),
            None,
            "cloudflare v6"
        );
        // 100.64/10 is shared, but 99/8 and 101/8 are normal.
        assert_eq!(classify_blocked_ip(v4("99.84.0.1")), None);
    }

    #[test]
    fn host_literal_handles_brackets_and_hostnames() {
        assert_eq!(
            host_literal_is_blocked("169.254.169.254"),
            Some(BlockedIpReason::LinkLocal)
        );
        assert_eq!(
            host_literal_is_blocked("[::1]"),
            Some(BlockedIpReason::Loopback)
        );
        assert_eq!(
            host_literal_is_blocked("[fd00:ec2::254]"),
            Some(BlockedIpReason::UniqueLocal)
        );
        // A hostname is not an IP literal — deferred to the resolver guard.
        assert_eq!(host_literal_is_blocked("api.github.com"), None);
        assert_eq!(host_literal_is_blocked("metadata.google.internal"), None);
        assert_eq!(host_literal_is_blocked(""), None);
    }
}
