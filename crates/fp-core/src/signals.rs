//! Passive network-signal compute (architecture §4.2 / §4.4 / §6).
//!
//! Client-reported `components` are forgeable: a headless browser can self-report
//! any `userAgent` it likes. This module derives the signals a client **cannot**
//! self-report — the real network IP and the TLS JA3/JA4 stack — and cross-checks
//! the TLS stack against the JS/UA-claimed browser. The result feeds `/identify`
//! **confidence only**, never the `visitorId` (JA4 is low-entropy and forgeable,
//! architecture §4.2).
//!
//! This is the framework-free compute: it takes plain values (the JA4 string, the
//! client IP string, the claimed UA), never an HTTP framework type, so every
//! deployment target — the native Axum server and the WebAssembly edge build —
//! reuses it unchanged. The HTTP-layer adapter (`crates/fingerprintd`) pulls the
//! trusted headers and delegates to [`compute`].
//!
//! Three shapes of outcome, mirroring the confidence fusion applied downstream (§6):
//! - [`TlsConsistency::Consistent`] — UA and TLS stack agree → small boost.
//! - [`TlsConsistency::Mismatch`] — Chrome UA over a Python/Go TLS stack → strong
//!   downgrade (the core anti-forgery signal, §4.2).
//! - [`TlsConsistency::Degraded`] — no JA3/JA4 available (Bot Management absent,
//!   or an unparseable value) → neutral, neither boost nor penalty. This is the
//!   mandated **auto-degrade** path: a missing connection-layer signal must not
//!   block or penalise the request (§4.2).
//!
//! **Trust boundary (architecture §4.2 security requirement):** the JA4 signal is trusted
//! only when injected by the Cloudflare edge; the origin must strip any
//! client-supplied copy before this module runs. Enforcing that strip is handler
//! /edge wiring; this module only consumes whatever trusted values it is given.
//!
//! **Scope caveats:** inputs here are mocked. Real JA4 needs Cloudflare Bot
//! Management (may be absent → degrade), and the [`IpIntel`] static classifier is
//! a coarse illustrative placeholder — a production deployment swaps it for a real
//! ASN / proxy / reputation feed (see [`StaticIpIntel`]). No real-data detection
//! rate is claimed here.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;

/// Minimum cipher count in a JA4 fingerprint for the stack to read as a real
/// browser. Browsers advertise a broad cipher list; minimal automation stacks
/// (curl/python/go defaults) advertise few. Coarse structural heuristic, not a
/// fingerprint database (see [`classify_ja4`]).
const BROWSER_MIN_CIPHERS: u32 = 10;
/// Minimum TLS extension count in a JA4 fingerprint for a real-browser read.
/// Browsers carry GREASE + ALPN + `key_share` + `supported_versions` + … ;
/// automation stacks carry far fewer.
const BROWSER_MIN_EXTENSIONS: u32 = 10;

/// Curated set of `JA4_a` structural shapes that real browsers share, each a
/// `(protocol, tls_version, sni, alpn)` tuple — the coarse structural signature
/// deliberately *without* the exact cipher/extension counts (which an automation
/// stack can pad). Each entry below is annotated with the real browser/config that
/// emits it; all negotiate TLS 1.3 (`tls_version = 13`) and send the SNI
/// (`sni = d`), differing only in transport (`protocol`) and negotiated `alpn`.
///
/// This is a curated heuristic, **not** a real JA4 fingerprint database:
/// calibrating this whitelist against a real labelled JA4 corpus — adding or
/// pruning shapes from observed real-browser traffic rather than by hand — is a
/// deferred follow-up, not done here. A shape absent from this list is not proof
/// of automation, only an absence of positive browser evidence (see
/// [`classify_ja4`], and [`StaticIpIntel`] for the same illustrative-placeholder
/// caveat).
const BROWSER_JA4_SHAPES: &[(&str, &str, &str, &str)] = &[
    // Mainstream Chrome/Firefox/Edge/Safari over TCP: TLS 1.3, SNI present, HTTP/2
    // negotiated. The overwhelmingly common real-browser shape.
    ("t", "13", "d", "h2"),
    // The same browsers over QUIC / HTTP-3: QUIC mandates TLS 1.3, still sends the
    // SNI, and advertises the `h3` ALPN. Chrome and Edge default to HTTP/3 where the
    // origin offers it, so a legitimate real user on HTTP/3 must not read as
    // automation (the primary false positive this calibration fixes).
    ("q", "13", "d", "h3"),
    // Deliberately NOT whitelisted: `("t", "13", "d", "h1")` (HTTP/1.1 over
    // TCP+TLS 1.3). `h1` is the dominant automation ALPN, so whitelisting it let a
    // count-padded `h1` stack pass the shape check — the opposite of the check's
    // purpose. Legit `h1`-only-over-TLS-1.3 browsers are rare, and the `h3`/QUIC
    // entry above already covers the real false-positive case, so `h1` stays off
    // the list. This remains a curated heuristic, not a real JA4 database
    // (real-JA4-DB calibration deferred — see the doc-comment above).
];

/// Confidence boost when the UA claim and the observed TLS stack agree — a small
/// positive nudge toward "real browser" (fuzzy-matching §6, "一致 → 加成").
const CONSISTENT_BOOST: f64 = 0.05;
/// Confidence penalty when the UA claim contradicts the observed TLS stack — the
/// strong anti-forgery downgrade (fuzzy-matching §6 / architecture §4.2, "不一致 → 大幅下调").
const MISMATCH_PENALTY: f64 = 0.5;

/// Coarse IP reputation band surfaced to downstream risk consumers (architecture §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRisk {
    /// Residential / unknown / internal address — no adverse signal.
    Low,
    /// Ambiguous (shared proxy / mixed-use range). Reserved for real feeds; the
    /// static classifier never emits it.
    Medium,
    /// Datacenter / hosting space — a real browser rarely originates here.
    High,
}

impl IpRisk {
    /// Stable wire label for the response body (`"low"|"medium"|"high"`).
    pub fn as_str(self) -> &'static str {
        match self {
            IpRisk::Low => "low",
            IpRisk::Medium => "medium",
            IpRisk::High => "high",
        }
    }
}

/// Verdict of cross-checking the JS/UA-claimed browser against the passively
/// observed TLS (JA3/JA4) stack (architecture §4.2 / §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConsistency {
    /// UA and TLS stack agree — a plausibly real browser (confidence boost).
    Consistent,
    /// UA claims one stack, the TLS fingerprint reveals another (e.g. a Chrome
    /// UA riding a Python/Go TLS stack) — strong anomaly (confidence downgrade).
    Mismatch,
    /// No usable JA3/JA4 (Bot Management absent or the value is unparseable) —
    /// connection layer degraded; neither boost nor penalty (auto-degrade, §4.2).
    Degraded,
}

impl TlsConsistency {
    /// Stable wire label for logging / diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsConsistency::Consistent => "consistent",
            TlsConsistency::Mismatch => "mismatch",
            TlsConsistency::Degraded => "degraded",
        }
    }

    /// The boolean `ua_tls_consistent` flag for the response body (architecture §5).
    ///
    /// Only an outright [`Mismatch`] flags as inconsistent; a [`Degraded`] read
    /// carries no evidence of forgery, so it reports consistent-by-default and
    /// must not be treated as a red flag (§4.2 auto-degrade).
    ///
    /// [`Mismatch`]: TlsConsistency::Mismatch
    /// [`Degraded`]: TlsConsistency::Degraded
    pub fn ua_tls_consistent(self) -> bool {
        !matches!(self, TlsConsistency::Mismatch)
    }
}

/// The passive signals extracted for one request (architecture §5 `signals`), fed to the
/// confidence fusion (§6) — never to the `visitorId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassiveSignals {
    /// Coarse IP reputation band.
    pub ip_risk: IpRisk,
    /// UA-vs-TLS-stack cross-check verdict.
    pub tls_consistency: TlsConsistency,
}

impl PassiveSignals {
    /// The passive-signal confidence adjustment fused into `/identify` confidence
    /// (fuzzy-matching §6). The caller adds this to the engine's base confidence and
    /// clamps to `[0, 1]`; positive boosts, negative downgrades.
    ///
    /// Only the UA-vs-TLS consistency verdict moves confidence: agreement gives a
    /// small [`CONSISTENT_BOOST`], an outright [`TlsConsistency::Mismatch`] gives
    /// the strong [`MISMATCH_PENALTY`] downgrade (the anti-forgery core, architecture §4.2),
    /// and a [`TlsConsistency::Degraded`] read is neutral — a missing connection
    /// signal never penalises (auto-degrade, §4.2). The [`IpRisk`] band is
    /// auxiliary and surfaced to downstream risk consumers (§5), not folded into
    /// confidence.
    pub fn confidence_adjustment(self) -> f64 {
        match self.tls_consistency {
            TlsConsistency::Consistent => CONSISTENT_BOOST,
            TlsConsistency::Mismatch => -MISMATCH_PENALTY,
            TlsConsistency::Degraded => 0.0,
        }
    }
}

/// Coarse client-stack family, inferred independently from a UA string and from a
/// JA4 fingerprint; the two are compared to detect forgery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientStack {
    /// Looks like a real interactive browser.
    Browser,
    /// Looks like an automation / scripting HTTP stack (curl/python/go/…).
    Automation,
    /// Not classifiable from the available evidence.
    Unknown,
}

/// IP reputation lookup: maps a real client IP to a coarse [`IpRisk`] band.
///
/// The passive IP signal is auxiliary, not decisive (architecture §4.2). Implementations
/// are the seam for a real ASN / proxy / reputation feed; [`StaticIpIntel`] is the
/// dependency-free placeholder.
pub trait IpIntel: Send + Sync {
    /// Classify one client IP into its reputation band.
    fn assess(&self, ip: IpAddr) -> IpRisk;
}

/// Static, dependency-free [`IpIntel`] — flags a small built-in set of datacenter
/// IPv4 ranges as [`IpRisk::High`] and treats everything else (including all IPv6)
/// as [`IpRisk::Low`].
///
/// The built-in ranges are **illustrative**, not authoritative; a real deployment
/// replaces this with an ASN / proxy reputation feed. (future TODO — real feed.)
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticIpIntel;

impl StaticIpIntel {
    /// Construct the static classifier.
    pub fn new() -> Self {
        Self
    }
}

/// `(network, prefix_len)` IPv4 CIDR blocks the static classifier treats as
/// datacenter / hosting space. Coarse and illustrative (see [`StaticIpIntel`]).
const DATACENTER_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(34, 0, 0, 0), 8),   // Google Cloud
    (Ipv4Addr::new(35, 0, 0, 0), 8),   // Google Cloud
    (Ipv4Addr::new(52, 0, 0, 0), 8),   // AWS
    (Ipv4Addr::new(13, 64, 0, 0), 11), // Azure
];

impl IpIntel for StaticIpIntel {
    fn assess(&self, ip: IpAddr) -> IpRisk {
        match ip {
            IpAddr::V4(v4) => {
                // Internal / non-routable space is not a hosting signal.
                if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                    return IpRisk::Low;
                }
                if DATACENTER_V4
                    .iter()
                    .any(|&(net, prefix)| ipv4_in_block(v4, net, prefix))
                {
                    IpRisk::High
                } else {
                    IpRisk::Low
                }
            }
            // No IPv6 datacenter table yet; a real feed covers both families.
            IpAddr::V6(_) => IpRisk::Low,
        }
    }
}

/// Compute the passive signals for a request from its trusted, framework-free values.
///
/// - IP band: `client_ip` is trimmed and parsed, then classified via
///   [`IpIntel::assess`]; a missing/unparseable IP defaults to [`IpRisk::Low`]
///   (no adverse evidence).
/// - TLS consistency: `ja4` is classified and cross-checked against `claimed_ua`
///   (the JS/UA-reported user agent). A missing (`None`) or unparseable JA4 yields
///   [`TlsConsistency::Degraded`] — the auto-degrade path (§4.2).
///
/// `claimed_ua` is the client-reported UA (from `stable_components` / the HTTP
/// `User-Agent`); it is the value under suspicion, cross-checked against the
/// unforgeable TLS stack.
pub fn compute(
    ja4: Option<&str>,
    client_ip: Option<&str>,
    claimed_ua: Option<&str>,
    intel: &dyn IpIntel,
) -> PassiveSignals {
    let ip_risk = client_ip
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .map_or(IpRisk::Low, |ip| intel.assess(ip));

    let tls_consistency = match ja4 {
        Some(ja4) => consistency(claimed_ua.map(classify_ua), classify_ja4(ja4)),
        None => TlsConsistency::Degraded, // Bot Management absent → auto-degrade.
    };

    PassiveSignals {
        ip_risk,
        tls_consistency,
    }
}

/// Reconcile the UA-claimed stack against the TLS-observed stack (§4.2 / §6).
///
/// An unclassifiable TLS stack degrades (no basis to cross-check). Otherwise a
/// **contradiction** between a browser claim and an automation stack (either
/// direction) is a mismatch; anything else — including a missing/unknown UA claim
/// — is consistent, so a degraded UA never manufactures a penalty.
fn consistency(claimed: Option<ClientStack>, observed: ClientStack) -> TlsConsistency {
    match observed {
        ClientStack::Unknown => TlsConsistency::Degraded,
        ClientStack::Browser => match claimed {
            Some(ClientStack::Automation) => TlsConsistency::Mismatch,
            _ => TlsConsistency::Consistent,
        },
        ClientStack::Automation => match claimed {
            Some(ClientStack::Browser) => TlsConsistency::Mismatch,
            _ => TlsConsistency::Consistent,
        },
    }
}

/// Classify a UA string into a coarse [`ClientStack`] by token markers.
///
/// Automation markers win over browser markers, so a bare `curl/8.0` reads as
/// automation while a spoofed `Mozilla/5.0 … Chrome/120` reads as a browser claim
/// (the value the TLS stack then contradicts on a mismatch).
fn classify_ua(ua: &str) -> ClientStack {
    /// Automation / scripting HTTP client markers.
    const AUTOMATION: &[&str] = &[
        "curl",
        "wget",
        "python",
        "go-http",
        "java",
        "okhttp",
        "libwww",
        "node-fetch",
        "axios",
    ];
    /// Real-browser markers.
    const BROWSER: &[&str] = &["mozilla", "chrome", "firefox", "safari", "edg", "opera"];

    let ua = ua.to_ascii_lowercase();
    if AUTOMATION.iter().any(|m| ua.contains(m)) {
        ClientStack::Automation
    } else if BROWSER.iter().any(|m| ua.contains(m)) {
        ClientStack::Browser
    } else {
        ClientStack::Unknown
    }
}

/// The parsed fields of a `JA4_a` prefix at their fixed offsets.
struct Ja4Shape<'a> {
    protocol: &'a str,
    tls_version: &'a str,
    sni: &'a str,
    ciphers: u32,
    extensions: u32,
    alpn: &'a str,
}

/// Parse a `JA4_a` prefix into its [`Ja4Shape`] fields, or `None` if any field is
/// missing / too short / not a valid count. Offsets follow the JA4 layout:
/// `protocol(1) tls_version(2) sni(1) cipher_count(2) extension_count(2) alpn(2)`.
fn parse_ja4_shape(a: &str) -> Option<Ja4Shape<'_>> {
    Some(Ja4Shape {
        protocol: a.get(0..1)?,
        tls_version: a.get(1..3)?,
        sni: a.get(3..4)?,
        ciphers: a.get(4..6)?.parse().ok()?,
        extensions: a.get(6..8)?.parse().ok()?,
        alpn: a.get(8..10)?,
    })
}

/// Classify a JA4 fingerprint into a coarse [`ClientStack`] from its structure.
///
/// The `JA4_a` prefix (before the first `_`) encodes, at fixed offsets:
/// `protocol(1) tls_version(2) sni(1) cipher_count(2) extension_count(2)
/// alpn(2)`. We parse the *full* prefix (via [`parse_ja4_shape`]) and combine two
/// checks rather than thresholding the counts alone:
///
/// - **counts** — a real browser advertises many ciphers and extensions; a
///   minimal automation stack advertises few ([`BROWSER_MIN_CIPHERS`] /
///   [`BROWSER_MIN_EXTENSIONS`]). Counts below the bar read as automation.
/// - **shape** — the structural `(protocol, tls_version, sni, alpn)` tuple must
///   match a known real-browser signature ([`BROWSER_JA4_SHAPES`]). This closes
///   the count-padding bypass: an automation stack that merely inflates its
///   cipher/extension lists past the thresholds but keeps a non-browser shape
///   (wrong ALPN / TLS-version pattern) reads as [`ClientStack::Automation`],
///   not `Browser`.
///
/// This is a coarse structural heuristic, **not** a JA4→client fingerprint
/// database; a malformed or too-short prefix reads as [`ClientStack::Unknown`]
/// (→ degrade). (future TODO — real JA4 fingerprint database.)
fn classify_ja4(ja4: &str) -> ClientStack {
    let a = ja4.split('_').next().unwrap_or(ja4);
    let Some(shape) = parse_ja4_shape(a) else {
        return ClientStack::Unknown;
    };
    // Counts below the browser bar are a minimal automation stack (unchanged).
    if shape.ciphers < BROWSER_MIN_CIPHERS || shape.extensions < BROWSER_MIN_EXTENSIONS {
        return ClientStack::Automation;
    }
    // Counts clear the bar; only a known real-browser shape confirms Browser.
    // Padded counts on a non-browser shape are the forgery case we now catch.
    let is_browser_shape = BROWSER_JA4_SHAPES
        .iter()
        .any(|&(protocol, tls, sni, alpn)| {
            shape.protocol == protocol
                && shape.tls_version == tls
                && shape.sni == sni
                && shape.alpn == alpn
        });
    if is_browser_shape {
        ClientStack::Browser
    } else {
        ClientStack::Automation
    }
}

/// Derive a coarse, low-cardinality JA4 **class** key for the cross-session
/// new-device velocity signal (PLAN-006 HARDEN-002).
///
/// The key is the structural `JA4_a` shape — `(protocol, tls_version, sni,
/// alpn)` — deliberately **without** the cipher/extension counts (an automation
/// stack can pad those, and a real browser's vary build-to-build). This collapses
/// every real client of one browser family (e.g. all Chrome-over-HTTP/2) into a
/// single shared class, which is exactly the intent: a farm rotating a
/// residential proxy pool but sharing one Chrome JA4 class shows a per-class
/// new-device rate the per-IP key alone cannot see.
///
/// Reuses [`parse_ja4_shape`] (HARDEN-001). Returns `None` when the `JA4_a`
/// prefix is missing / malformed / too short, so the caller records no
/// JA4-class event (cold-start neutral).
pub fn ja4_class(ja4: &str) -> Option<String> {
    let a = ja4.split('_').next().unwrap_or(ja4);
    let shape = parse_ja4_shape(a)?;
    Some(format!(
        "{}{}{}{}",
        shape.protocol, shape.tls_version, shape.sni, shape.alpn
    ))
}

/// Whether IPv4 `ip` falls in the CIDR block `net/prefix`.
fn ipv4_in_block(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// The four known-answer client integrity probes the SDK reports under the
/// request's top-level `integrity` field (`packages/client/src/integrity.ts`),
/// each with a verdict of `ok` | `noise` | `unavailable`.
pub const INTEGRITY_PROBES: [&str; 4] = ["canvas", "webgl", "audio", "rect"];

/// Confidence downgrade applied when the client's integrity probes report
/// [`ClientIntegrity::Noise`] **and** the deployment has opted into the penalty.
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): of the same order
/// as [`MISMATCH_PENALTY`] but softer, because legitimate privacy tooling (Brave
/// farbling, canvas blockers, `resistFingerprinting`) injects the same kind of
/// noise for real users. Deployments keep the penalty off until a real-traffic
/// false-positive rate exists; the verdict is always surfaced regardless.
pub const INTEGRITY_NOISE_PENALTY: f64 = 0.3;

/// Fused verdict of the client's known-answer integrity probes (red-team round 3).
///
/// The SDK asks the browser four questions whose answers are fixed by
/// construction in an unmodified Chromium (lossless canvas round-trip, exact
/// WebGL clear, exact constant audio source, exact 1/64-px layout) and reports
/// `ok` / `noise` / `unavailable` per probe. A fingerprint-noising browser
/// answers wrongly on all four; stock browsers answer exactly. This is the first
/// **single-request** signal that observes such a browser — from inside the
/// collector, without any connection-layer input.
///
/// Trust boundary: the verdicts are client-reported, so like every client value
/// they are hookable; this is depth, not a lock. They ride top-level in the
/// request — never inside `stable_components` — so they can never enter the
/// `visitorId` match. Fusion into confidence is opt-in
/// ([`confidence_adjustment`](ClientIntegrity::confidence_adjustment)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIntegrity {
    /// Every reporting probe returned the known answer.
    Ok,
    /// At least one probe returned a wrong answer — fingerprint noise observed.
    Noise,
    /// No probe reported a usable verdict (field absent, APIs missing, malformed).
    /// Neutral: an absent capability must never manufacture a penalty.
    Unavailable,
}

impl ClientIntegrity {
    /// Stable wire label for the response body (`"ok"|"noise"|"unavailable"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ClientIntegrity::Ok => "ok",
            ClientIntegrity::Noise => "noise",
            ClientIntegrity::Unavailable => "unavailable",
        }
    }

    /// Fold per-probe verdict strings into one verdict: any `noise` wins, else
    /// any `ok` reads [`ClientIntegrity::Ok`], else nothing usable was reported.
    /// Unknown strings count as unavailable, never as noise.
    pub fn from_verdicts<'a>(verdicts: impl IntoIterator<Item = Option<&'a str>>) -> Self {
        let mut saw_ok = false;
        for verdict in verdicts {
            match verdict {
                Some("noise") => return ClientIntegrity::Noise,
                Some("ok") => saw_ok = true,
                _ => {}
            }
        }
        if saw_ok {
            ClientIntegrity::Ok
        } else {
            ClientIntegrity::Unavailable
        }
    }

    /// Read the verdict from the request's top-level `integrity` JSON value,
    /// shaped `{ canvas, webgl, audio, rect }`. An absent field or a non-object
    /// value is [`ClientIntegrity::Unavailable`].
    pub fn from_json(integrity: Option<&Value>) -> Self {
        let Some(object) = integrity.and_then(Value::as_object) else {
            return ClientIntegrity::Unavailable;
        };
        Self::from_verdicts(
            INTEGRITY_PROBES
                .iter()
                .map(|probe| object.get(*probe).and_then(Value::as_str)),
        )
    }

    /// Confidence adjustment fused into `/identify` confidence alongside
    /// [`PassiveSignals::confidence_adjustment`]: `-`[`INTEGRITY_NOISE_PENALTY`]
    /// for [`ClientIntegrity::Noise`] when the deployment has enabled the
    /// penalty, otherwise `0.0`. Off by default so the band stays surfaced-only
    /// until its false-positive rate on real traffic is known.
    pub fn confidence_adjustment(self, penalty_enabled: bool) -> f64 {
        if penalty_enabled && self == ClientIntegrity::Noise {
            -INTEGRITY_NOISE_PENALTY
        } else {
            0.0
        }
    }
}

/// Fonts `FingerprintJS` 5.2 probes that every stock Windows 10/11 install ships
/// (`packages/client` adapts the FJS `fonts` set unchanged). Curated and small on
/// purpose: a Windows persona exposing **none** of these is incoherent.
pub const WINDOWS_CORE_FONTS: [&str; 5] = [
    "Calibri",
    "Segoe UI Light",
    "MS UI Gothic",
    "Marlett",
    "Microsoft Uighur",
];

/// Fonts `FingerprintJS` 5.2 probes that every stock macOS install ships.
pub const MACOS_CORE_FONTS: [&str; 3] = ["Helvetica Neue", "Menlo", "Gill Sans"];

/// Verdict of cross-checking the UA-claimed OS family against the collected
/// `fonts` set (red-team round 3).
///
/// A fingerprint-cloaking browser that borrows a Windows persona on a Linux host
/// reports a Windows UA while its font set lacks every font Windows always has
/// (the free `CloakBrowser` binary in Docker hides the host's Linux fonts but adds
/// none). Surfaced-only: it never moves confidence or the `visitorId`.
///
/// Honest limits, stated plainly: the adversary's Pro preview binary already
/// spoofs Windows font metrics, and its README tells operators to install the
/// Windows font set — this closes the default/container configuration and
/// raises cost, nothing more. Only Windows and macOS personas are checked;
/// everything else (Linux, Android, iOS, unknown) reads `unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaCoherence {
    /// The UA's OS family and the font set agree (≥ 1 core font present).
    Consistent,
    /// The UA claims Windows / macOS but the font set has none of that OS's
    /// core fonts (an empty set counts — a real Windows browser always finds
    /// Calibri).
    Mismatch,
    /// No basis to check: no UA, an OS family outside the curated set, or no
    /// `fonts` array. Neutral.
    Unknown,
}

impl PersonaCoherence {
    /// Stable wire label for the response body (`"consistent"|"mismatch"|"unknown"`).
    pub fn as_str(self) -> &'static str {
        match self {
            PersonaCoherence::Consistent => "consistent",
            PersonaCoherence::Mismatch => "mismatch",
            PersonaCoherence::Unknown => "unknown",
        }
    }
}

/// The core-font list for the OS family a UA claims, or `None` when the family
/// is outside the curated set. `Macintosh` (not the `like Mac OS X` of iOS UAs)
/// marks macOS; `Windows NT` marks desktop Windows.
fn core_fonts_for_ua(claimed_ua: &str) -> Option<&'static [&'static str]> {
    if claimed_ua.contains("Windows NT") {
        Some(&WINDOWS_CORE_FONTS)
    } else if claimed_ua.contains("Macintosh") {
        Some(&MACOS_CORE_FONTS)
    } else {
        None
    }
}

/// Cross-check the UA-claimed OS family against the collected `fonts` set (a
/// JSON array of font names as the SDK sends it). See [`PersonaCoherence`].
pub fn persona_coherence(claimed_ua: Option<&str>, fonts: Option<&Value>) -> PersonaCoherence {
    let Some(core) = claimed_ua.and_then(core_fonts_for_ua) else {
        return PersonaCoherence::Unknown;
    };
    let Some(fonts) = fonts.and_then(Value::as_array) else {
        return PersonaCoherence::Unknown;
    };
    if fonts
        .iter()
        .filter_map(Value::as_str)
        .any(|font| core.contains(&font))
    {
        PersonaCoherence::Consistent
    } else {
        PersonaCoherence::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientIntegrity, INTEGRITY_NOISE_PENALTY, PersonaCoherence, persona_coherence};

    // --- Persona coherence (UA OS family vs fonts, red-team round 3) ---

    const WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36";
    const MAC_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36";
    const IOS_UA: &str =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1";

    #[test]
    fn persona_windows_ua_without_any_windows_core_font_is_a_mismatch() {
        let linux_fonts = json!([
            "Arial",
            "Courier New",
            "Times New Roman",
            "Noto Color Emoji"
        ]);
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(&linux_fonts)),
            PersonaCoherence::Mismatch
        );
        // An empty set is a mismatch too: a real Windows browser always finds Calibri.
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(&json!([]))),
            PersonaCoherence::Mismatch
        );
        let windows_fonts = json!(["Arial", "Calibri", "Segoe UI Light"]);
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(&windows_fonts)),
            PersonaCoherence::Consistent
        );
    }

    #[test]
    fn persona_macos_checks_its_own_core_fonts_and_ios_is_not_macos() {
        let mac_fonts = json!(["Helvetica Neue", "Menlo"]);
        assert_eq!(
            persona_coherence(Some(MAC_UA), Some(&mac_fonts)),
            PersonaCoherence::Consistent
        );
        assert_eq!(
            persona_coherence(Some(MAC_UA), Some(&json!(["Calibri"]))),
            PersonaCoherence::Mismatch
        );
        // `like Mac OS X` (iOS) is outside the curated set → unknown, never mismatch.
        assert_eq!(
            persona_coherence(Some(IOS_UA), Some(&json!([]))),
            PersonaCoherence::Unknown
        );
    }

    #[test]
    fn persona_unknown_without_ua_family_or_fonts_array() {
        assert_eq!(
            persona_coherence(None, Some(&json!([]))),
            PersonaCoherence::Unknown
        );
        assert_eq!(
            persona_coherence(
                Some("Mozilla/5.0 (X11; Linux x86_64) Chrome/149"),
                Some(&json!([]))
            ),
            PersonaCoherence::Unknown
        );
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), None),
            PersonaCoherence::Unknown
        );
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(&json!("Calibri"))),
            PersonaCoherence::Unknown
        );
    }
    use super::{
        ClientStack, IpIntel, IpRisk, PassiveSignals, StaticIpIntel, TlsConsistency, classify_ja4,
        compute, ja4_class,
    };
    use serde_json::json;

    // --- Client integrity probes (red-team round 3) ---

    #[test]
    fn integrity_any_noise_wins_then_ok_then_unavailable() {
        assert_eq!(
            ClientIntegrity::from_verdicts([Some("ok"), Some("ok"), Some("noise"), None]),
            ClientIntegrity::Noise
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([Some("ok"), Some("unavailable"), None, Some("weird")]),
            ClientIntegrity::Ok
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([Some("unavailable"), None, Some("weird")]),
            ClientIntegrity::Unavailable
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([]),
            ClientIntegrity::Unavailable
        );
    }

    #[test]
    fn integrity_from_json_reads_the_four_probes_and_degrades_on_malformed() {
        let noisy = json!({ "canvas": "noise", "webgl": "ok", "audio": "ok", "rect": "ok" });
        assert_eq!(
            ClientIntegrity::from_json(Some(&noisy)),
            ClientIntegrity::Noise
        );
        let clean = json!({ "canvas": "ok", "webgl": "ok", "audio": "ok", "rect": "ok" });
        assert_eq!(
            ClientIntegrity::from_json(Some(&clean)),
            ClientIntegrity::Ok
        );
        // Absent, non-object, empty, non-string and unknown-key shapes are neutral.
        assert_eq!(
            ClientIntegrity::from_json(None),
            ClientIntegrity::Unavailable
        );
        assert_eq!(
            ClientIntegrity::from_json(Some(&json!("noise"))),
            ClientIntegrity::Unavailable
        );
        assert_eq!(
            ClientIntegrity::from_json(Some(&json!({}))),
            ClientIntegrity::Unavailable
        );
        assert_eq!(
            ClientIntegrity::from_json(Some(&json!({ "canvas": 1, "other": "noise" }))),
            ClientIntegrity::Unavailable
        );
    }

    #[test]
    fn integrity_penalty_is_opt_in_and_only_for_noise() {
        let approx = |a: f64, b: f64| (a - b).abs() < 1e-12;
        assert!(approx(
            ClientIntegrity::Noise.confidence_adjustment(false),
            0.0
        ));
        assert!(approx(ClientIntegrity::Ok.confidence_adjustment(true), 0.0));
        assert!(approx(
            ClientIntegrity::Unavailable.confidence_adjustment(true),
            0.0
        ));
        assert!(approx(
            ClientIntegrity::Noise.confidence_adjustment(true),
            -INTEGRITY_NOISE_PENALTY
        ));
    }

    /// A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext).
    const BROWSER_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    /// A JA4 whose structural counts read as a minimal automation stack (3/4).
    const AUTOMATION_JA4: &str = "t13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
    /// A JA4 whose counts are padded past the browser thresholds (15/16) but whose
    /// shape is non-browser: HTTP/1.1 (`alpn = h1`) over TCP+TLS 1.3. `h1` is the
    /// dominant automation ALPN and is deliberately absent from the browser
    /// shape whitelist, so this count-padded stack must not pass the shape check.
    /// The count-only heuristic misread this as `Browser`; the shape check catches
    /// it (closes the count-padding bypass).
    const PADDED_AUTOMATION_JA4: &str = "t13d1516h1_cccccccccccc_dddddddddddd";
    /// A spoofed browser UA (headless automation self-reporting Chrome).
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    /// `CloakBrowser` adversary profile — a real stealth Chromium, not an automation
    /// stack. Its TLS handshake is a genuine Chrome handshake, so its JA4 counts
    /// read as a browser (15 ciphers / 16 extensions, ≥ the browser thresholds).
    const CLOAK_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    /// A genuine, current Chrome desktop UA — a real browser string with no
    /// automation markers (the stealth build ships the honest UA of its engine).
    const CLOAK_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    /// A QUIC / HTTP-3 browser JA4: protocol `q`, TLS 1.3, SNI present, `h3` ALPN,
    /// with real-browser cipher/extension counts (15/16). A legitimate Chrome/Edge
    /// user on HTTP/3 — must classify as a browser, not automation.
    const QUIC_BROWSER_JA4: &str = "q13d1516h3_8daaf6152771_02713d6af862";

    /// A residential (non-datacenter) IPv4 reached over the adversary's residential
    /// proxy. TEST-NET-3, outside every `DATACENTER_V4` block and not private.
    const CLOAK_IP: &str = "203.0.113.55";

    #[test]
    fn static_intel_flags_datacenter_high_and_residential_low() {
        let intel = StaticIpIntel::new();
        // 34.0.0.0/8 is in the built-in datacenter set.
        assert_eq!(intel.assess("34.120.5.6".parse().unwrap()), IpRisk::High);
        // TEST-NET-2, outside every datacenter block.
        assert_eq!(intel.assess("198.51.100.7".parse().unwrap()), IpRisk::Low);
        // Private / loopback are internal, never a hosting signal.
        assert_eq!(intel.assess("10.1.2.3".parse().unwrap()), IpRisk::Low);
        assert_eq!(intel.assess("127.0.0.1".parse().unwrap()), IpRisk::Low);
        // IPv6 has no table yet → low.
        assert_eq!(intel.assess("2001:db8::1".parse().unwrap()), IpRisk::Low);
    }

    #[test]
    fn client_ip_drives_the_ip_band() {
        let intel = StaticIpIntel::new();
        let sig = compute(
            Some(BROWSER_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.ip_risk, IpRisk::High);
    }

    #[test]
    fn missing_client_ip_defaults_low() {
        let intel = StaticIpIntel::new();
        // No client IP at all.
        let sig = compute(Some(BROWSER_JA4), None, Some(CHROME_UA), &intel);
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn absent_ja4_auto_degrades_without_penalty() {
        let intel = StaticIpIntel::new();
        // Bot Management absent: only the IP is present.
        let sig = compute(None, Some("198.51.100.7"), Some(CHROME_UA), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
        // Degrade is neutral: it must not read as an inconsistency (§4.2).
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn browser_ua_over_browser_stack_is_consistent() {
        let intel = StaticIpIntel::new();
        let sig = compute(
            Some(BROWSER_JA4),
            Some("198.51.100.7"),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
        assert!(sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn spoofed_browser_ua_over_automation_stack_is_mismatch() {
        let intel = StaticIpIntel::new();
        // The core anti-forgery case: JS self-reports Chrome, the TLS stack is a
        // minimal automation client.
        let sig = compute(
            Some(AUTOMATION_JA4),
            Some("34.120.5.6"),
            Some(CHROME_UA),
            &intel,
        );
        assert_eq!(
            sig,
            PassiveSignals {
                ip_risk: IpRisk::High,
                tls_consistency: TlsConsistency::Mismatch,
            }
        );
        assert!(!sig.tls_consistency.ua_tls_consistent());
    }

    #[test]
    fn honest_curl_ua_over_automation_stack_is_consistent() {
        let intel = StaticIpIntel::new();
        // An un-spoofed automation client: UA and stack agree, so no mismatch.
        let sig = compute(Some(AUTOMATION_JA4), None, Some("curl/8.4.0"), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
    }

    #[test]
    fn unparseable_ja4_degrades() {
        let intel = StaticIpIntel::new();
        let sig = compute(Some("garbage"), None, Some(CHROME_UA), &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Degraded);
    }

    #[test]
    fn missing_ua_never_manufactures_a_mismatch() {
        // No UA claim to contradict → the strongest verdict is consistent.
        let intel = StaticIpIntel::new();
        let sig = compute(Some(AUTOMATION_JA4), None, None, &intel);
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
    }

    #[test]
    fn ja4_structural_classification() {
        assert_eq!(classify_ja4(BROWSER_JA4), ClientStack::Browser);
        assert_eq!(classify_ja4(AUTOMATION_JA4), ClientStack::Automation);
        // Too short to hold the count fields.
        assert_eq!(classify_ja4("t13d"), ClientStack::Unknown);
    }

    #[test]
    fn quic_h3_browser_ja4_classifies_as_browser() {
        // A real Chrome/Edge user over QUIC / HTTP-3: the widened shape whitelist
        // must accept `(q, 13, d, h3)` so a legitimate HTTP/3 handshake stops
        // false-reading as automation (the false positive this calibration fixes).
        assert_eq!(classify_ja4(QUIC_BROWSER_JA4), ClientStack::Browser);
    }

    #[test]
    fn padded_counts_with_non_browser_shape_reads_as_automation() {
        // An automation stack inflates its cipher/extension lists past the browser
        // thresholds (15/16) but presents the `h1` ALPN — the dominant automation
        // ALPN, kept off the browser shape whitelist. Count-only thresholding
        // misread this as `Browser`; the full-shape check classifies it as
        // automation. The count-padding defense stays intact.
        assert_eq!(classify_ja4(PADDED_AUTOMATION_JA4), ClientStack::Automation);
    }

    #[test]
    fn ja4_class_is_the_coarse_shape_without_counts() {
        // The class is the `(protocol, tls_version, sni, alpn)` shape only, so two
        // JA4s of the same browser family that differ *only* in cipher/extension
        // counts (and in the hash tail) collapse to ONE shared class — the coarse
        // bucket the per-class velocity key counts within.
        assert_eq!(ja4_class(BROWSER_JA4).as_deref(), Some("t13dh2"));
        assert_eq!(ja4_class(CLOAK_JA4).as_deref(), Some("t13dh2"));
        assert_eq!(ja4_class(BROWSER_JA4), ja4_class(CLOAK_JA4));
        // Different transport/ALPN → a different class.
        assert_eq!(ja4_class(QUIC_BROWSER_JA4).as_deref(), Some("q13dh3"));
        // A malformed / too-short prefix yields no class (→ no event recorded).
        assert_eq!(ja4_class("t13d"), None);
    }

    #[test]
    fn confidence_adjustment_boosts_consistent_penalises_mismatch_neutral_degrade() {
        let mk = |ip, c| PassiveSignals {
            ip_risk: ip,
            tls_consistency: c,
        };
        let boost = mk(IpRisk::Low, TlsConsistency::Consistent).confidence_adjustment();
        let penalty = mk(IpRisk::Low, TlsConsistency::Mismatch).confidence_adjustment();
        let degrade = mk(IpRisk::Low, TlsConsistency::Degraded).confidence_adjustment();
        assert!(boost > 0.0);
        assert!(penalty < 0.0);
        assert!(degrade.abs() < f64::EPSILON); // neutral
        // The mismatch downgrade dominates the consistency boost (anti-forgery core).
        assert!(penalty.abs() > boost);
        // The IP band is auxiliary — it never moves the adjustment.
        let degrade_high_ip = mk(IpRisk::High, TlsConsistency::Degraded).confidence_adjustment();
        assert!((degrade - degrade_high_ip).abs() < f64::EPSILON);
    }

    /// KNOWN SINGLE-REQUEST BYPASS — pinned regression baseline, NOT the desired
    /// end state. A `CloakBrowser` (real stealth Chromium: genuine Chrome-shaped TLS,
    /// honest Chrome UA, residential-proxy IP) passes *every* per-request passive
    /// signal: its TLS stack matches its UA (a consistency boost, not a mismatch
    /// penalty) and its residential IP reads as low risk. Nothing in a single
    /// request distinguishes it from an honest user. This is intentional and
    /// documented so any future change that closes or reopens the gap shows up as a
    /// visible test diff rather than folklore. The signal that actually catches this
    /// adversary is the cross-session velocity check (RT-003), not this module.
    #[test]
    fn cloak_browser_passes_every_single_request_signal() {
        let intel = StaticIpIntel::new();
        let sig = compute(Some(CLOAK_JA4), Some(CLOAK_IP), Some(CLOAK_UA), &intel);
        // UA and TLS agree → the per-request check hands out a confidence boost.
        assert_eq!(sig.tls_consistency, TlsConsistency::Consistent);
        assert!(sig.confidence_adjustment() > 0.0);
        // Residential proxy IP is indistinguishable from an honest user's.
        assert_eq!(sig.ip_risk, IpRisk::Low);
    }

    #[test]
    fn ip_risk_wire_labels() {
        assert_eq!(IpRisk::Low.as_str(), "low");
        assert_eq!(IpRisk::Medium.as_str(), "medium");
        assert_eq!(IpRisk::High.as_str(), "high");
    }
}
