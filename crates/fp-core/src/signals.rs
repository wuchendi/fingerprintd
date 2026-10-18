//! Passive network-signal compute (architecture §4.2 / §4.4 / §6).
//!
//! Client-reported `components` are forgeable: a headless browser can self-report
//! any `userAgent` it likes. This module derives the signals a client **cannot**
//! self-report — the real network IP and the TLS JA3/JA4 stack — and cross-checks
//! the TLS stack against the JS/UA-claimed browser. The result feeds `/identify`
//! **confidence only**, never the `visitor_id` (JA4 is low-entropy and forgeable,
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

use serde::{Deserialize, Serialize};

/// Minimum cipher count in a JA4 fingerprint for the stack to read as a real
/// browser. Browsers advertise a broad cipher list; minimal automation stacks
/// (curl/python/go defaults) advertise few. Coarse structural heuristic, not a
/// fingerprint database (see [`ja4_client_stack`]).
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
/// [`ja4_client_stack`], and [`StaticIpIntel`] for the same illustrative-placeholder
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
/// confidence fusion (§6) — never to the `visitor_id`.
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
    /// small `CONSISTENT_BOOST`, an outright [`TlsConsistency::Mismatch`] gives
    /// the strong `MISMATCH_PENALTY` downgrade (the anti-forgery core, architecture §4.2),
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
/// `claimed_ua` is the client-reported UA (the request's top-level
/// `user_agent`); it is the value under suspicion, cross-checked against the
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
        Some(ja4) => consistency(claimed_ua.map(classify_ua), ja4_client_stack(ja4)),
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
fn ja4_client_stack(ja4: &str) -> ClientStack {
    let a = ja4.split('_').next().unwrap_or(ja4);
    let Some(shape) = parse_ja4_shape(a) else {
        return ClientStack::Unknown;
    };
    // Counts below the browser bar are a minimal automation stack.
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

/// Whether IPv4 `ip` falls in the CIDR block `net/prefix`.
fn ipv4_in_block(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// The request's top-level `integrity` object: the verdicts of the four
/// known-answer client integrity probes the SDK reports
/// (`packages/client/src/integrity.ts`). An absent probe did not report.
///
/// Closed: a non-object value, an unknown key, or a verdict outside
/// [`ProbeVerdict`] is a deserialization error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Integrity {
    /// Lossless canvas round-trip probe.
    pub canvas: Option<ProbeVerdict>,
    /// Exact WebGL clear-colour probe.
    pub webgl: Option<ProbeVerdict>,
    /// Exact constant audio-source probe.
    pub audio: Option<ProbeVerdict>,
    /// Exact 1/64-px layout probe.
    pub rect: Option<ProbeVerdict>,
}

crate::object_only_serde!(Integrity);

/// One integrity probe's verdict (`"ok"` | `"noise"` | `"unavailable"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeVerdict {
    /// The probe returned the known answer.
    Ok,
    /// The probe returned a wrong answer.
    Noise,
    /// The probe could not run (API missing or failed).
    Unavailable,
}

/// Confidence downgrade applied when the client's integrity probes report
/// [`ClientIntegrity::Noise`] **and** the deployment has opted into the penalty.
///
/// TUNING PLACEHOLDER (a policy guess, not a measured claim): of the same order
/// as `MISMATCH_PENALTY` but softer, because legitimate privacy tooling (Brave
/// farbling, canvas blockers, `resistFingerprinting`) injects the same kind of
/// noise for real users. Deployments keep the penalty off until a real-traffic
/// false-positive rate exists; the verdict is always surfaced regardless.
pub const INTEGRITY_NOISE_PENALTY: f64 = 0.3;

/// Fused verdict of the client's known-answer integrity probes.
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
/// request — never inside `components` — so they can never enter the
/// `visitor_id` match. Fusion into confidence is opt-in
/// ([`confidence_adjustment`](ClientIntegrity::confidence_adjustment)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIntegrity {
    /// Every reporting probe returned the known answer.
    Ok,
    /// At least one probe returned a wrong answer — fingerprint noise observed.
    Noise,
    /// No probe reported a usable verdict (field absent or every API missing).
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

    /// Fold per-probe verdicts into one verdict: any `noise` wins, else any
    /// `ok` reads [`ClientIntegrity::Ok`], else nothing usable was reported.
    pub fn from_verdicts(verdicts: impl IntoIterator<Item = Option<ProbeVerdict>>) -> Self {
        let mut saw_ok = false;
        for verdict in verdicts {
            match verdict {
                Some(ProbeVerdict::Noise) => return ClientIntegrity::Noise,
                Some(ProbeVerdict::Ok) => saw_ok = true,
                Some(ProbeVerdict::Unavailable) | None => {}
            }
        }
        if saw_ok {
            ClientIntegrity::Ok
        } else {
            ClientIntegrity::Unavailable
        }
    }

    /// Fold the request's top-level [`Integrity`] object into one verdict; an
    /// absent object is [`ClientIntegrity::Unavailable`].
    pub fn from_integrity(integrity: Option<&Integrity>) -> Self {
        let Some(probes) = integrity else {
            return ClientIntegrity::Unavailable;
        };
        Self::from_verdicts([probes.canvas, probes.webgl, probes.audio, probes.rect])
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
/// `fonts` set.
///
/// A fingerprint-cloaking browser that borrows a Windows persona on a Linux host
/// reports a Windows UA while its font set lacks every font Windows always has
/// (the free `CloakBrowser` binary in Docker hides the host's Linux fonts but adds
/// none). Surfaced-only: it never moves confidence or the `visitor_id`.
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
    /// `fonts` component. Neutral.
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

/// Cross-check the UA-claimed OS family against the collected `fonts` set (the
/// `fonts` component). See [`PersonaCoherence`].
pub fn persona_coherence(claimed_ua: Option<&str>, fonts: Option<&[String]>) -> PersonaCoherence {
    let Some(core) = claimed_ua.and_then(core_fonts_for_ua) else {
        return PersonaCoherence::Unknown;
    };
    let Some(fonts) = fonts else {
        return PersonaCoherence::Unknown;
    };
    if fonts.iter().any(|font| core.contains(&font.as_str())) {
        PersonaCoherence::Consistent
    } else {
        PersonaCoherence::Mismatch
    }
}

/// A client-side bot-detection verdict (`BotD`-shaped), sent alongside the
/// components. `kind` names the detected automation framework when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Botd {
    /// Whether the client-side detector flagged the browser as automated.
    pub bot: bool,
    /// The detected automation kind (e.g. `headless_chrome`), if any.
    #[serde(default)]
    pub kind: Option<String>,
}

crate::object_only_serde!(serialize Botd);

/// Automation verdict surfaced from a client-side [`Botd`] result.
/// Surfaced-only: it never affects confidence, the decision, or the `visitor_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Automation {
    /// The detector flagged the browser as automated.
    Detected,
    /// The detector ran and found no automation.
    NotDetected,
    /// No detector result was supplied.
    Unknown,
}

impl Automation {
    /// Map an optional [`Botd`] result: `bot = true` ⇒ detected, `false` ⇒ not
    /// detected, absent ⇒ unknown.
    pub fn from_botd(botd: Option<&Botd>) -> Self {
        match botd {
            Some(Botd { bot: true, .. }) => Automation::Detected,
            Some(Botd { bot: false, .. }) => Automation::NotDetected,
            None => Automation::Unknown,
        }
    }

    /// Stable wire label (`"detected"|"not_detected"|"unknown"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Automation::Detected => "detected",
            Automation::NotDetected => "not_detected",
            Automation::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Automation, Botd, ClientIntegrity, INTEGRITY_NOISE_PENALTY, Integrity, PersonaCoherence,
        ProbeVerdict, persona_coherence,
    };

    // --- Automation (client-side BotD verdict) ---

    #[test]
    fn automation_maps_the_botd_verdict() {
        let bot: Botd = serde_json::from_str(r#"{"bot":true,"kind":"headless_chrome"}"#).unwrap();
        let human: Botd = serde_json::from_str(r#"{"bot":false}"#).unwrap();
        assert_eq!(human.kind, None);
        assert_eq!(Automation::from_botd(Some(&bot)), Automation::Detected);
        assert_eq!(Automation::from_botd(Some(&human)), Automation::NotDetected);
        assert_eq!(Automation::from_botd(None), Automation::Unknown);
        assert_eq!(Automation::Detected.as_str(), "detected");
        assert_eq!(Automation::NotDetected.as_str(), "not_detected");
        assert_eq!(Automation::Unknown.as_str(), "unknown");
    }

    #[test]
    fn botd_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Botd>(r#"{"bot":true,"score":1}"#).is_err());
        assert!(serde_json::from_str::<Botd>(r#"{"kind":"x"}"#).is_err());
    }

    // --- Persona coherence (UA OS family vs fonts) ---

    fn fonts(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    const WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36";
    const MAC_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36";
    const IOS_UA: &str =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1";

    #[test]
    fn persona_windows_ua_without_any_windows_core_font_is_a_mismatch() {
        let linux_fonts = fonts(&[
            "Arial",
            "Courier New",
            "Times New Roman",
            "Noto Color Emoji",
        ]);
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(linux_fonts.as_slice())),
            PersonaCoherence::Mismatch
        );
        // An empty set is a mismatch too: a real Windows browser always finds Calibri.
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(&[][..])),
            PersonaCoherence::Mismatch
        );
        let windows_fonts = fonts(&["Arial", "Calibri", "Segoe UI Light"]);
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), Some(windows_fonts.as_slice())),
            PersonaCoherence::Consistent
        );
    }

    #[test]
    fn persona_macos_checks_its_own_core_fonts_and_ios_is_not_macos() {
        let mac_fonts = fonts(&["Helvetica Neue", "Menlo"]);
        assert_eq!(
            persona_coherence(Some(MAC_UA), Some(mac_fonts.as_slice())),
            PersonaCoherence::Consistent
        );
        assert_eq!(
            persona_coherence(Some(MAC_UA), Some(fonts(&["Calibri"]).as_slice())),
            PersonaCoherence::Mismatch
        );
        // `like Mac OS X` (iOS) is outside the curated set → unknown, never mismatch.
        assert_eq!(
            persona_coherence(Some(IOS_UA), Some(&[][..])),
            PersonaCoherence::Unknown
        );
    }

    #[test]
    fn persona_unknown_without_ua_family_or_fonts() {
        assert_eq!(
            persona_coherence(None, Some(&[][..])),
            PersonaCoherence::Unknown
        );
        assert_eq!(
            persona_coherence(
                Some("Mozilla/5.0 (X11; Linux x86_64) Chrome/149"),
                Some(&[][..])
            ),
            PersonaCoherence::Unknown
        );
        assert_eq!(
            persona_coherence(Some(WINDOWS_UA), None),
            PersonaCoherence::Unknown
        );
    }
    use super::{
        ClientStack, IpIntel, IpRisk, PassiveSignals, StaticIpIntel, TlsConsistency, compute,
        ja4_client_stack,
    };
    use serde_json::json;

    // --- Client integrity probes ---

    #[test]
    fn integrity_any_noise_wins_then_ok_then_unavailable() {
        assert_eq!(
            ClientIntegrity::from_verdicts([
                Some(ProbeVerdict::Ok),
                Some(ProbeVerdict::Ok),
                Some(ProbeVerdict::Noise),
                None
            ]),
            ClientIntegrity::Noise
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([
                Some(ProbeVerdict::Ok),
                Some(ProbeVerdict::Unavailable),
                None
            ]),
            ClientIntegrity::Ok
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([Some(ProbeVerdict::Unavailable), None]),
            ClientIntegrity::Unavailable
        );
        assert_eq!(
            ClientIntegrity::from_verdicts([]),
            ClientIntegrity::Unavailable
        );
    }

    fn integrity(value: serde_json::Value) -> Result<Integrity, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn integrity_from_typed_verdicts() {
        let noisy =
            integrity(json!({ "canvas": "noise", "webgl": "ok", "audio": "ok", "rect": "ok" }))
                .unwrap();
        assert_eq!(
            ClientIntegrity::from_integrity(Some(&noisy)),
            ClientIntegrity::Noise
        );
        let clean =
            integrity(json!({ "canvas": "ok", "webgl": "ok", "audio": "ok", "rect": "ok" }))
                .unwrap();
        assert_eq!(
            ClientIntegrity::from_integrity(Some(&clean)),
            ClientIntegrity::Ok
        );
        let partial = integrity(json!({ "canvas": "unavailable", "rect": "ok" })).unwrap();
        assert_eq!(
            ClientIntegrity::from_integrity(Some(&partial)),
            ClientIntegrity::Ok
        );
        // Absent or empty is neutral.
        assert_eq!(
            ClientIntegrity::from_integrity(None),
            ClientIntegrity::Unavailable
        );
        let empty = integrity(json!({})).unwrap();
        assert_eq!(
            ClientIntegrity::from_integrity(Some(&empty)),
            ClientIntegrity::Unavailable
        );
    }

    #[test]
    fn integrity_rejects_unknown_keys_bad_values_and_non_objects() {
        for value in [
            json!({ "canvas": "ok", "fonts": "ok" }),
            json!({ "canvas": 1 }),
            json!({ "canvas": "weird" }),
            json!([]),
            json!(["ok", "ok", "ok", "ok"]),
            json!("noise"),
            json!(null),
        ] {
            assert!(integrity(value.clone()).is_err(), "{value}");
        }
    }

    #[test]
    fn botd_rejects_non_objects() {
        for value in [json!([]), json!([true]), json!(true), json!(null)] {
            assert!(
                serde_json::from_value::<Botd>(value.clone()).is_err(),
                "{value}"
            );
        }
        let botd: Botd = serde_json::from_value(json!({ "bot": true })).unwrap();
        assert_eq!(
            botd,
            Botd {
                bot: true,
                kind: None
            }
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
        assert_eq!(ja4_client_stack(BROWSER_JA4), ClientStack::Browser);
        assert_eq!(ja4_client_stack(AUTOMATION_JA4), ClientStack::Automation);
        // Too short to hold the count fields.
        assert_eq!(ja4_client_stack("t13d"), ClientStack::Unknown);
    }

    #[test]
    fn quic_h3_browser_ja4_classifies_as_browser() {
        // A real Chrome/Edge user over QUIC / HTTP-3: the widened shape whitelist
        // must accept `(q, 13, d, h3)` so a legitimate HTTP/3 handshake stops
        // false-reading as automation (the false positive this calibration fixes).
        assert_eq!(ja4_client_stack(QUIC_BROWSER_JA4), ClientStack::Browser);
    }

    #[test]
    fn padded_counts_with_non_browser_shape_reads_as_automation() {
        // An automation stack inflates its cipher/extension lists past the browser
        // thresholds (15/16) but presents the `h1` ALPN — the dominant automation
        // ALPN, kept off the browser shape whitelist. Count-only thresholding
        // misread this as `Browser`; the full-shape check classifies it as
        // automation. The count-padding defense stays intact.
        assert_eq!(
            ja4_client_stack(PADDED_AUTOMATION_JA4),
            ClientStack::Automation
        );
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
    /// adversary is the cross-session velocity check, not this module.
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
