//! Compliance-preserving stored representations of fingerprint components
//! (fuzzy-matching §3) and the cold-start stability priors (fuzzy-matching §2/§9).
//!
//! Per architecture §7 data minimization, raw values are never retained: category and
//! set values are salted-hashed before storage while still supporting equality
//! comparison, frequency counting, and set similarity.

use std::collections::BTreeSet;

#[cfg(feature = "rng")]
use rand::{Rng, rng};
use sha2::{Digest, Sha256};

/// A 256-bit salted digest — the on-store form of a scalar value or a set element.
pub type Hash32 = [u8; 32];

/// Per-instance secret prepended before hashing every stored value.
///
/// A random salt makes stored hashes non-reversible via precomputed tables
/// while still permitting equality comparison and frequency counting within one
/// instance (fuzzy-matching §3). It is fixed for the store's lifetime, so a given value
/// hashes identically across observations.
#[derive(Clone)]
pub struct Salt([u8; 16]);

impl Salt {
    /// Generate a fresh random salt.
    #[cfg(feature = "rng")]
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive a deterministic salt from a configured secret.
    ///
    /// A stateless edge deployment cannot use a per-instance [`Salt::random`]
    /// salt: stored hashes and blocking keys must be identical across isolate
    /// instances so a key derived on one request matches one persisted on
    /// another. The salt is the first 16 bytes of `SHA-256(secret)`; a
    /// deployment supplies the same secret (a Worker Secret) to every instance.
    /// The secret is never stored, so it remains as non-reversible as the random
    /// salt while being reproducible.
    pub fn from_secret(secret: &[u8]) -> Self {
        let digest = Sha256::digest(secret);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(bytes)
    }

    /// Salted category hash `H(salt || value)`.
    pub fn hash(&self, value: &str) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    /// Salted per-element hashes of a set component.
    ///
    /// Hashing each element independently preserves the set structure — and
    /// therefore `Jaccard` similarity — while storing no raw element (fuzzy-matching §3).
    pub fn hash_set<I, S>(&self, elements: I) -> BTreeSet<Hash32>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        elements
            .into_iter()
            .map(|e| self.hash(e.as_ref()))
            .collect()
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the salt bytes.
        f.debug_struct("Salt").finish_non_exhaustive()
    }
}

/// The stored form of one fingerprint component (fuzzy-matching §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// A category value, kept as its salted hash for equality + frequency use.
    Category(Hash32),
    /// A set component (e.g. fonts), kept as per-element salted hashes so that
    /// set similarity survives storage.
    Set(BTreeSet<Hash32>),
    /// A numeric component, kept as an (optionally bucketed) integer.
    Numeric(i64),
}

/// Order-independent digest of a stored hash set — the frequency key that lets
/// a whole set (e.g. the constant Android font probe) be counted like a
/// category value when estimating its `u_i`.
pub fn set_digest(set: &BTreeSet<Hash32>) -> Hash32 {
    let mut hasher = Sha256::new();
    for element in set {
        hasher.update(element);
    }
    hasher.finalize().into()
}

/// `Jaccard` similarity `|A ∩ B| / |A ∪ B|` between two stored hash sets.
///
/// Two empty sets are defined as identical (`1.0`). Because elements are hashed
/// independently, this equals the `Jaccard` similarity of the raw sets.
#[allow(clippy::cast_precision_loss)] // ratio of small counts; precision loss is immaterial
pub fn jaccard(a: &BTreeSet<Hash32>, b: &BTreeSet<Hash32>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.len() + b.len() - intersection;
    intersection as f64 / union as f64
}

/// Stability tier of a component — the source of its cold-start `m_i` prior
/// (fuzzy-matching §2/§9). `m_i` is `P(agree | same device)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    /// Rarely changes for the same device (`WebGL`, audio, timezone, `CPU`).
    High,
    /// Changes occasionally (canvas, fonts, screen).
    Medium,
    /// Changes frequently — the avalanche source (`UA` / browser version).
    Low,
}

impl Stability {
    /// Cold-start prior for `m_i` (fuzzy-matching §9): high `0.95`, medium `0.80`,
    /// low `0.50`. Refined post-launch via `EM` over high-confidence revisits.
    pub fn m_prior(self) -> f64 {
        match self {
            Stability::High => 0.95,
            Stability::Medium => 0.80,
            Stability::Low => 0.50,
        }
    }
}

/// A component's storage kind, driving how a raw value is represented (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Salted single-value hash.
    Category,
    /// Per-element salted hash set.
    Set,
    /// Bucketed integer.
    Numeric,
}

/// Schema entry for one component name: its stored [`Kind`] (§3) and its
/// [`Stability`] tier — the source of the `m_i` prior the scorer uses (§2/§9).
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    /// Stability tier, source of the `m_i` prior (§2/§9).
    pub stability: Stability,
    /// How the value is stored (§3).
    pub kind: Kind,
}

/// Classify a component name into its schema entry (fuzzy-matching §2 component table).
///
/// Unknown names default to a medium-stability category value.
pub fn classify(name: &str) -> FieldSpec {
    let (stability, kind) = match name {
        "webgl" | "platform" | "timezone" | "audio" | "languages" => {
            (Stability::High, Kind::Category)
        }
        "cpu_cores" | "device_memory" => (Stability::High, Kind::Numeric),
        "fonts" | "plugins" => (Stability::Medium, Kind::Set),
        // Canvas is noised per session by privacy / anti-detect browsers, so a
        // mismatch must weigh less than a medium component.
        "user_agent" | "canvas" => (Stability::Low, Kind::Category),
        // `screen` (the SDK's `"WxH"` string, longer side first),
        // `webgl_extensions`, and unknown names are medium-stability categories.
        _ => (Stability::Medium, Kind::Category),
    };
    FieldSpec { stability, kind }
}

/// Cold-start prior for `u_i = P(agree | different device)` — how often two
/// unrelated devices share this component's value (fuzzy-matching §5/§9).
///
/// The frequency table refines it per component as observations accumulate
/// (`FuzzyStore::u_estimate`). TUNING PLACEHOLDERS (judgement, not measured):
/// device-distinctive renders and hardware strings are rare, locale-level
/// values are common, and names the schema does not know — mostly
/// `FingerprintJS` booleans and small enums — are treated as near-universal so
/// that agreeing on them is no evidence until data says otherwise.
pub fn u_prior(name: &str) -> f64 {
    match name {
        "canvas" => 0.02,
        "webgl" | "webgl_extensions" | "audio" | "userAgentData" | "fonts" => 0.05,
        "fontPreferences" | "screen" | "user_agent" => 0.1,
        "timezone" | "screenFrame" => 0.2,
        "languages" | "platform" | "cpu_cores" | "plugins" => 0.3,
        "device_memory" => 0.4,
        "math" | "touchSupport" | "domBlockers" => 0.5,
        _ => 0.8,
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, Salt, Stability, classify, jaccard};

    #[test]
    fn screen_is_a_category_and_canvas_is_low_stability() {
        // FJS screenResolution arrives as "WxH": a Numeric kind could not store it.
        assert_eq!(classify("screen").kind, Kind::Category);
        assert_eq!(classify("screen").stability, Stability::Medium);
        // Canvas is noised by privacy/anti-detect browsers: low tier.
        assert_eq!(classify("canvas").kind, Kind::Category);
        assert_eq!(classify("canvas").stability, Stability::Low);
        assert_eq!(classify("webgl_extensions").stability, Stability::Medium);
    }

    #[test]
    fn same_value_hashes_stably_under_one_salt() {
        let salt = Salt::random();
        assert_eq!(salt.hash("Chrome/120"), salt.hash("Chrome/120"));
        assert_ne!(salt.hash("Chrome/120"), salt.hash("Chrome/121"));
    }

    #[test]
    fn different_salts_diverge() {
        // Compliance: without the salt a value is not linkable across instances.
        assert_ne!(Salt::random().hash("UTC"), Salt::random().hash("UTC"));
    }

    #[test]
    fn per_element_hashing_preserves_jaccard() {
        let salt = Salt::random();
        let a = salt.hash_set(["Arial", "Helvetica", "Courier", "Times"]);
        // One font added, one removed: raw Jaccard = 3/5 = 0.6.
        let b = salt.hash_set(["Arial", "Helvetica", "Courier", "Verdana"]);
        assert!((jaccard(&a, &b) - 0.6).abs() < 1e-9);
        assert!((jaccard(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_sets_are_identical() {
        let empty = Salt::random().hash_set(Vec::<String>::new());
        assert!((jaccard(&empty, &empty) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn priors_follow_stability_tier() {
        assert!(Stability::High.m_prior() > Stability::Medium.m_prior());
        assert!(Stability::Medium.m_prior() > Stability::Low.m_prior());
    }

    #[test]
    fn schema_maps_known_components() {
        use super::{Kind, classify};
        use crate::fuzzy::component::Stability;

        assert_eq!(classify("user_agent").stability, Stability::Low);
        assert_eq!(classify("webgl").stability, Stability::High);
        assert_eq!(classify("fonts").kind, Kind::Set);
        assert_eq!(classify("cpu_cores").kind, Kind::Numeric);
        // Unknown -> medium-stability category default.
        let unknown = classify("something_new");
        assert_eq!(unknown.stability, Stability::Medium);
        assert_eq!(unknown.kind, Kind::Category);
    }
}
