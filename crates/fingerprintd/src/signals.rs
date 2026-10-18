//! HTTP-layer adapter for the passive network-signal compute (architecture §4.2).
//!
//! The framework-free compute — the UA-vs-TLS consistency cross-check and the
//! IP-reputation classification — lives in [`fingerprintd::signals`] so every
//! deployment target (this native Axum server and the WebAssembly edge build)
//! shares it. This module is the thin HTTP adapter: it owns the trusted-header
//! names, pulls the two header strings off an [`axum::http::HeaderMap`], and
//! delegates to [`fingerprintd::signals::compute`].

use axum::http::HeaderMap;
use fingerprintd::signals::{IpIntel, PassiveSignals, compute};

/// Trusted request header carrying the real client IP, injected by the Cloudflare
/// edge. Standard Cloudflare header (architecture §4.2).
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// Trusted request header carrying the client TLS JA4 fingerprint, injected by
/// the Cloudflare edge (Bot Management → Transform Rule). The origin MUST strip
/// any client-supplied copy and trust only the edge-injected value (architecture §4.2);
/// that strip is wired at the handler/edge layer, not here.
pub const JA4_HEADER: &str = "cf-bot-management-ja4";

/// Extract the passive signals for a request from its trusted headers.
///
/// Pulls the `CF-Connecting-IP` and JA4 header strings and delegates the compute
/// to [`fingerprintd::signals::compute`]: a missing/unparseable IP defaults to
/// [`fingerprintd::signals::IpRisk::Low`], and a missing or unparseable JA4 yields
/// [`fingerprintd::signals::TlsConsistency::Degraded`] (the auto-degrade path, §4.2).
///
/// `claimed_ua` is the client-reported UA (the request body's top-level
/// `user_agent`); it is the value under suspicion, cross-checked against the
/// unforgeable TLS stack.
pub fn extract(
    headers: &HeaderMap,
    claimed_ua: Option<&str>,
    intel: &dyn IpIntel,
) -> PassiveSignals {
    compute(
        header_str(headers, JA4_HEADER),
        header_str(headers, CF_CONNECTING_IP),
        claimed_ua,
        intel,
    )
}

/// Borrow one header's value as a trimmed `&str`, or `None` if absent or non-ASCII.
fn header_str<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name)?.to_str().ok().map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::{CF_CONNECTING_IP, JA4_HEADER, extract};
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use fingerprintd::signals::{IpRisk, StaticIpIntel, TlsConsistency};

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// Build a header map from `(name, value)` pairs.
    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            map.insert(name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn cf_connecting_ip_header_drives_the_ip_band() {
        let intel = StaticIpIntel::new();
        let hdrs = headers(&[(CF_CONNECTING_IP, "34.120.5.6"), (JA4_HEADER, BROWSER_JA4)]);
        let sig = extract(&hdrs, Some(CHROME_UA), &intel);
        assert_eq!(sig.ip_risk, IpRisk::High);
    }

    #[test]
    fn missing_client_ip_header_defaults_low() {
        let intel = StaticIpIntel::new();
        // No CF-Connecting-IP header at all.
        let sig = extract(
            &headers(&[(JA4_HEADER, BROWSER_JA4)]),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn absent_ja4_header_auto_degrades() {
        let intel = StaticIpIntel::new();
        // Bot Management absent: only the IP header is present.
        let sig = extract(
            &headers(&[(CF_CONNECTING_IP, "198.51.100.7")]),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
        // Degrade is neutral: it must not read as an inconsistency (§4.2).
        assert!(sig.tls_consistency.ua_tls_consistent());
    }
}
