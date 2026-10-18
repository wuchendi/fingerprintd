//! Compliance-preserving stored representations of fingerprint components
//! (fuzzy-matching §3) and the cold-start stability priors (fuzzy-matching §2/§9).
//!
//! Per architecture §7 data minimization, raw values are never retained: category and
//! set values are salted-hashed before storage while still supporting equality
//! comparison, frequency counting, and set similarity.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "rng")]
use rand::{Rng, rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
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
///
/// Wire form (serde JSON, stable — a stateless host persists it verbatim): one
/// single-key object per component,
/// - `{"category": "<64 lowercase hex>"}` — the salted value hash;
/// - `{"numeric": <i64>}`;
/// - `{"set": ["<64 lowercase hex>", ..]}` — salted element hashes, sorted.
///
/// Deserialization accepts only these shapes: an unknown tag, a hash that is not
/// 64 hex digits, or a non-integer number is an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stored {
    /// A category value, kept as its salted hash for equality + frequency use.
    #[serde(with = "hex_hash")]
    Category(Hash32),
    /// A set component (e.g. fonts), kept as per-element salted hashes so that
    /// set similarity survives storage.
    #[serde(with = "hex_hash_set")]
    Set(BTreeSet<Hash32>),
    /// A numeric component, kept as an (optionally bucketed) integer.
    Numeric(i64),
}

impl Stored {
    /// The storage [`Kind`] this value has.
    pub fn kind(&self) -> Kind {
        match self {
            Stored::Category(_) => Kind::Category,
            Stored::Set(_) => Kind::Set,
            Stored::Numeric(_) => Kind::Numeric,
        }
    }
}

/// Serde for a [`Hash32`] as 64 lowercase hex digits.
mod hex_hash {
    use super::{Deserialize, Deserializer, Hash32, Serializer};
    use serde::de::Error as _;

    pub(super) fn serialize<S: Serializer>(
        hash: &Hash32,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(hash))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Hash32, D::Error> {
        let raw = String::deserialize(deserializer)?;
        decode(&raw).map_err(D::Error::custom)
    }

    /// Decode one 64-hex-digit hash.
    pub(super) fn decode(raw: &str) -> Result<Hash32, String> {
        let mut hash = [0u8; 32];
        hex::decode_to_slice(raw, &mut hash)
            .map_err(|e| format!("invalid stored hash {raw:?}: {e}"))?;
        Ok(hash)
    }
}

/// Serde for a set of [`Hash32`] as a sorted array of 64-hex-digit strings.
mod hex_hash_set {
    use super::{BTreeSet, Deserialize, Deserializer, Hash32, Serializer};
    use serde::de::Error as _;
    use serde::ser::SerializeSeq as _;

    pub(super) fn serialize<S: Serializer>(
        set: &BTreeSet<Hash32>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(set.len()))?;
        for hash in set {
            seq.serialize_element(&hex::encode(hash))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeSet<Hash32>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|raw| super::hex_hash::decode(raw).map_err(D::Error::custom))
            .collect()
    }
}

/// The salted stored form of one fingerprint: component wire name → [`Stored`].
///
/// This is all a stateless host persists for a device — never a raw value.
/// Wire form: a JSON object keyed by [`COMPONENT_KEYS`] names, each value a
/// [`Stored`] of that component's [`Kind`], e.g.
/// `{"cpu_cores": {"numeric": 8}, "fonts": {"set": ["<hex>", ..]}, "webgl":
/// {"category": "<hex>"}}`. Absent components are omitted. Deserialization
/// rejects a name outside the schema and a value of the wrong kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StoredComponents(BTreeMap<String, Stored>);

impl StoredComponents {
    /// The stored values keyed by component name.
    pub fn as_map(&self) -> &BTreeMap<String, Stored> {
        &self.0
    }

    /// Unwrap into the stored values keyed by component name.
    pub fn into_map(self) -> BTreeMap<String, Stored> {
        self.0
    }

    /// `self` drifted toward `observation` exactly as the record library folds
    /// an observation into a template (fuzzy-matching §7): every component
    /// present in `observation` overwrites the template's value, every other
    /// template component is kept.
    #[must_use]
    pub fn merged(&self, observation: &StoredComponents) -> StoredComponents {
        let mut merged = self.0.clone();
        merged.extend(
            observation
                .0
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        StoredComponents(merged)
    }
}

impl From<BTreeMap<String, Stored>> for StoredComponents {
    fn from(map: BTreeMap<String, Stored>) -> Self {
        Self(map)
    }
}

impl<'de> Deserialize<'de> for StoredComponents {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<String, Stored>::deserialize(deserializer)?;
        for (name, value) in &map {
            let component = Component::from_name(name)
                .ok_or_else(|| D::Error::custom(format!("unknown component {name:?}")))?;
            if component.kind() != value.kind() {
                return Err(D::Error::custom(format!(
                    "component {name:?} must be stored as {:?}, got {:?}",
                    component.kind(),
                    value.kind()
                )));
            }
        }
        Ok(Self(map))
    }
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
    /// Changes occasionally (fonts, screen, `WebGL` extensions).
    Medium,
    /// Changes frequently or is noised per session (canvas).
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

/// One fingerprint component of the closed matching schema (fuzzy-matching §2
/// component table).
///
/// This table is the single source of truth for every component the matcher
/// knows: its wire name, stored [`Kind`], [`Stability`] tier (the `m_i` prior),
/// and cold-start `u_i` prior. There is no catch-all — a name outside this
/// table is not a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Component {
    /// `WebGL` vendor/renderer string.
    Webgl,
    /// Digest of the supported `WebGL` extensions.
    WebglExtensions,
    /// `navigator.platform`.
    Platform,
    /// IANA timezone name.
    Timezone,
    /// Preferred languages, comma-joined.
    Languages,
    /// Audio-stack render fingerprint.
    Audio,
    /// Canvas render digest. Noised per session by privacy / anti-detect
    /// browsers, so a mismatch weighs less than a medium component.
    Canvas,
    /// Logical CPU core count.
    CpuCores,
    /// Device memory in GiB.
    DeviceMemory,
    /// Screen resolution `"WxH"`, longer side first.
    Screen,
    /// Detected font names.
    Fonts,
    /// Plugin names.
    Plugins,
    /// Default font-size preferences digest.
    FontPreferences,
    /// Screen frame (taskbar/dock insets) digest.
    ScreenFrame,
    /// `Math` function output digest.
    Math,
    /// Touch-support digest.
    TouchSupport,
    /// Content-blocker detection digest.
    DomBlockers,
    /// User-Agent Client Hints digest.
    UserAgentData,
}

/// The wire names of every [`Component`], in [`Component::ALL`] order.
///
/// This is THE list of keys the SDK adapter must emit; the matcher rejects any
/// other key.
pub const COMPONENT_KEYS: [&str; 18] = [
    "webgl",
    "webgl_extensions",
    "platform",
    "timezone",
    "languages",
    "audio",
    "canvas",
    "cpu_cores",
    "device_memory",
    "screen",
    "fonts",
    "plugins",
    "font_preferences",
    "screen_frame",
    "math",
    "touch_support",
    "dom_blockers",
    "user_agent_data",
];

impl Component {
    /// Every component, in schema order.
    pub const ALL: [Component; 18] = [
        Component::Webgl,
        Component::WebglExtensions,
        Component::Platform,
        Component::Timezone,
        Component::Languages,
        Component::Audio,
        Component::Canvas,
        Component::CpuCores,
        Component::DeviceMemory,
        Component::Screen,
        Component::Fonts,
        Component::Plugins,
        Component::FontPreferences,
        Component::ScreenFrame,
        Component::Math,
        Component::TouchSupport,
        Component::DomBlockers,
        Component::UserAgentData,
    ];

    /// The component's wire name (a [`COMPONENT_KEYS`] entry).
    pub fn name(self) -> &'static str {
        match self {
            Component::Webgl => "webgl",
            Component::WebglExtensions => "webgl_extensions",
            Component::Platform => "platform",
            Component::Timezone => "timezone",
            Component::Languages => "languages",
            Component::Audio => "audio",
            Component::Canvas => "canvas",
            Component::CpuCores => "cpu_cores",
            Component::DeviceMemory => "device_memory",
            Component::Screen => "screen",
            Component::Fonts => "fonts",
            Component::Plugins => "plugins",
            Component::FontPreferences => "font_preferences",
            Component::ScreenFrame => "screen_frame",
            Component::Math => "math",
            Component::TouchSupport => "touch_support",
            Component::DomBlockers => "dom_blockers",
            Component::UserAgentData => "user_agent_data",
        }
    }

    /// The component whose wire name is `name`, if it is in the schema.
    pub fn from_name(name: &str) -> Option<Component> {
        Component::ALL.into_iter().find(|c| c.name() == name)
    }

    /// How the component's value is stored (§3).
    pub fn kind(self) -> Kind {
        match self {
            Component::CpuCores | Component::DeviceMemory => Kind::Numeric,
            Component::Fonts | Component::Plugins => Kind::Set,
            Component::Webgl
            | Component::WebglExtensions
            | Component::Platform
            | Component::Timezone
            | Component::Languages
            | Component::Audio
            | Component::Canvas
            | Component::Screen
            | Component::FontPreferences
            | Component::ScreenFrame
            | Component::Math
            | Component::TouchSupport
            | Component::DomBlockers
            | Component::UserAgentData => Kind::Category,
        }
    }

    /// Stability tier, the source of the `m_i` prior (§2/§9).
    pub fn stability(self) -> Stability {
        match self {
            Component::Webgl
            | Component::Platform
            | Component::Timezone
            | Component::Languages
            | Component::Audio
            | Component::CpuCores
            | Component::DeviceMemory => Stability::High,
            Component::Canvas => Stability::Low,
            Component::WebglExtensions
            | Component::Screen
            | Component::Fonts
            | Component::Plugins
            | Component::FontPreferences
            | Component::ScreenFrame
            | Component::Math
            | Component::TouchSupport
            | Component::DomBlockers
            | Component::UserAgentData => Stability::Medium,
        }
    }

    /// Cold-start prior for `u_i = P(agree | different device)` — how often two
    /// unrelated devices share this component's value (fuzzy-matching §5/§9).
    ///
    /// The frequency table refines it per component as observations accumulate
    /// (`FuzzyStore::u_estimate`). TUNING PLACEHOLDERS (judgement, not measured):
    /// device-distinctive renders and hardware strings are rare, locale-level
    /// values are common, and small enums are near-even.
    pub fn u_prior(self) -> f64 {
        match self {
            Component::Canvas => 0.02,
            Component::Webgl
            | Component::WebglExtensions
            | Component::Audio
            | Component::Fonts
            | Component::UserAgentData => 0.05,
            Component::Screen | Component::FontPreferences => 0.1,
            Component::Timezone | Component::ScreenFrame => 0.2,
            Component::Platform
            | Component::Languages
            | Component::CpuCores
            | Component::Plugins => 0.3,
            Component::DeviceMemory => 0.4,
            Component::Math | Component::TouchSupport | Component::DomBlockers => 0.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{COMPONENT_KEYS, Component, Kind, Salt, Stability, jaccard};

    #[test]
    fn screen_is_a_category_and_canvas_is_low_stability() {
        // FJS screenResolution arrives as "WxH": a Numeric kind could not store it.
        assert_eq!(Component::Screen.kind(), Kind::Category);
        assert_eq!(Component::Screen.stability(), Stability::Medium);
        // Canvas is noised by privacy/anti-detect browsers: low tier.
        assert_eq!(Component::Canvas.kind(), Kind::Category);
        assert_eq!(Component::Canvas.stability(), Stability::Low);
        assert_eq!(Component::WebglExtensions.stability(), Stability::Medium);
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
        assert_eq!(Component::Webgl.stability(), Stability::High);
        assert_eq!(Component::Fonts.kind(), Kind::Set);
        assert_eq!(Component::Plugins.kind(), Kind::Set);
        assert_eq!(Component::CpuCores.kind(), Kind::Numeric);
        assert_eq!(Component::DeviceMemory.kind(), Kind::Numeric);
        assert!((Component::UserAgentData.u_prior() - 0.05).abs() < f64::EPSILON);
        assert!((Component::DomBlockers.u_prior() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn component_keys_match_all_in_order() {
        let names: Vec<&str> = Component::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names, COMPONENT_KEYS);
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), COMPONENT_KEYS.len());
    }
}
