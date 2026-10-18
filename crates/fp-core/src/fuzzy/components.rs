//! The typed, closed component payload the matcher consumes (fuzzy-matching §2).
//!
//! [`Components`] has exactly one optional field per [`Component`], named by its
//! wire key. Deserialization is strict: a non-object payload, an unknown key, or
//! a value of the wrong JSON type for its key, is an error rather than being
//! silently dropped.
//! `null` or an absent key means "not collected" (fuzzy-matching §8).
//!
//! Per [`Kind`](super::Kind):
//! - **Category** accepts a JSON string, number, or bool, canonicalized to a
//!   string (a number keeps its JSON text, a bool is `true`/`false`).
//! - **Numeric** accepts a JSON number, rounded to the nearest `i64`.
//! - **Set** accepts an array of strings.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

use super::component::Component;

/// One collected fingerprint: every field is a [`Component`] of the closed
/// schema, `None` when the client did not collect it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Components {
    /// [`Component::Webgl`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub webgl: Option<String>,
    /// [`Component::WebglExtensions`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub webgl_extensions: Option<String>,
    /// [`Component::Platform`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub platform: Option<String>,
    /// [`Component::Timezone`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub timezone: Option<String>,
    /// [`Component::Languages`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub languages: Option<String>,
    /// [`Component::Audio`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub audio: Option<String>,
    /// [`Component::Canvas`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub canvas: Option<String>,
    /// [`Component::CpuCores`].
    #[serde(
        default,
        deserialize_with = "numeric",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_cores: Option<i64>,
    /// [`Component::DeviceMemory`].
    #[serde(
        default,
        deserialize_with = "numeric",
        skip_serializing_if = "Option::is_none"
    )]
    pub device_memory: Option<i64>,
    /// [`Component::Screen`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub screen: Option<String>,
    /// [`Component::Fonts`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fonts: Option<Vec<String>>,
    /// [`Component::Plugins`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugins: Option<Vec<String>>,
    /// [`Component::FontPreferences`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub font_preferences: Option<String>,
    /// [`Component::ScreenFrame`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub screen_frame: Option<String>,
    /// [`Component::Math`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub math: Option<String>,
    /// [`Component::TouchSupport`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub touch_support: Option<String>,
    /// [`Component::DomBlockers`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub dom_blockers: Option<String>,
    /// [`Component::UserAgentData`].
    #[serde(
        default,
        deserialize_with = "category",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_agent_data: Option<String>,
}

crate::object_only_serde!(serialize Components);

/// A borrowed, present component value, shaped by its [`Kind`](super::Kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentValue<'a> {
    /// A canonicalized category value.
    Category(&'a str),
    /// A rounded numeric value.
    Numeric(i64),
    /// A set of strings.
    Set(&'a [String]),
}

impl Components {
    /// The present components, in [`Component::ALL`] order.
    pub fn entries(&self) -> impl Iterator<Item = (Component, ComponentValue<'_>)> {
        Component::ALL
            .into_iter()
            .filter_map(|component| self.get(component).map(|value| (component, value)))
    }

    /// The value of `component`, or `None` when it was not collected.
    pub fn get(&self, component: Component) -> Option<ComponentValue<'_>> {
        match component {
            Component::Webgl => self.webgl.as_deref().map(ComponentValue::Category),
            Component::WebglExtensions => self
                .webgl_extensions
                .as_deref()
                .map(ComponentValue::Category),
            Component::Platform => self.platform.as_deref().map(ComponentValue::Category),
            Component::Timezone => self.timezone.as_deref().map(ComponentValue::Category),
            Component::Languages => self.languages.as_deref().map(ComponentValue::Category),
            Component::Audio => self.audio.as_deref().map(ComponentValue::Category),
            Component::Canvas => self.canvas.as_deref().map(ComponentValue::Category),
            Component::CpuCores => self.cpu_cores.map(ComponentValue::Numeric),
            Component::DeviceMemory => self.device_memory.map(ComponentValue::Numeric),
            Component::Screen => self.screen.as_deref().map(ComponentValue::Category),
            Component::Fonts => self.fonts.as_deref().map(ComponentValue::Set),
            Component::Plugins => self.plugins.as_deref().map(ComponentValue::Set),
            Component::FontPreferences => self
                .font_preferences
                .as_deref()
                .map(ComponentValue::Category),
            Component::ScreenFrame => self.screen_frame.as_deref().map(ComponentValue::Category),
            Component::Math => self.math.as_deref().map(ComponentValue::Category),
            Component::TouchSupport => self.touch_support.as_deref().map(ComponentValue::Category),
            Component::DomBlockers => self.dom_blockers.as_deref().map(ComponentValue::Category),
            Component::UserAgentData => self
                .user_agent_data
                .as_deref()
                .map(ComponentValue::Category),
        }
    }
}

/// Deserialize a Category value: string, number, or bool canonicalized to a
/// string; `null` is absent; any other JSON type is an error.
fn category<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err(D::Error::custom(
            "a category component must be a string, number, or bool",
        )),
    }
}

/// Deserialize a Numeric value: a JSON number rounded to `i64`; `null` is
/// absent; any other JSON type is an error.
#[allow(clippy::cast_possible_truncation)] // fingerprint numerics (cores, memory) are small
fn numeric<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f.round() as i64))
            .map(Some)
            .ok_or_else(|| D::Error::custom("a numeric component must fit in i64")),
        Some(_) => Err(D::Error::custom("a numeric component must be a number")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Component, ComponentValue, Components};
    use crate::fuzzy::Kind;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<Components, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn non_object_is_rejected() {
        for value in [
            json!([]),
            json!(["x"]),
            json!(null),
            json!("webgl"),
            json!(1),
        ] {
            assert!(parse(value.clone()).is_err(), "{value}");
        }
        assert_eq!(parse(json!({})).unwrap(), Components::default());
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert!(parse(json!({ "webgl": "x", "user_agent": "Chrome/120" })).is_err());
        assert!(parse(json!({ "touchSupport": "x" })).is_err());
    }

    #[test]
    fn object_value_for_a_category_key_is_rejected() {
        assert!(parse(json!({ "touch_support": { "maxTouchPoints": 5 } })).is_err());
        assert!(parse(json!({ "math": [1, 2] })).is_err());
    }

    #[test]
    fn wrong_type_for_numeric_and_set_keys_is_rejected() {
        assert!(parse(json!({ "cpu_cores": "8" })).is_err());
        assert!(parse(json!({ "fonts": "Arial" })).is_err());
        assert!(parse(json!({ "fonts": ["Arial", 1] })).is_err());
    }

    #[test]
    fn null_is_accepted_as_absent() {
        let parsed = parse(json!({ "canvas": null, "cpu_cores": null, "fonts": null })).unwrap();
        assert_eq!(parsed, Components::default());
        assert_eq!(parsed.entries().count(), 0);
    }

    #[test]
    fn category_values_are_canonicalized_and_numerics_rounded() {
        let parsed = parse(json!({
            "audio": 124.04,
            "math": true,
            "platform": "Win32",
            "cpu_cores": 8,
            "device_memory": 7.6,
            "plugins": ["PDF Viewer"],
        }))
        .unwrap();
        assert_eq!(parsed.audio.as_deref(), Some("124.04"));
        assert_eq!(parsed.math.as_deref(), Some("true"));
        assert_eq!(parsed.device_memory, Some(8));
        assert_eq!(
            parsed.get(Component::CpuCores),
            Some(ComponentValue::Numeric(8))
        );
    }

    #[test]
    fn every_field_value_matches_its_component_kind() {
        let full = parse(json!({
            "webgl": "a", "webgl_extensions": "a", "platform": "a", "timezone": "a",
            "languages": "a", "audio": "a", "canvas": "a", "cpu_cores": 1,
            "device_memory": 1, "screen": "a", "fonts": ["a"], "plugins": ["a"],
            "font_preferences": "a", "screen_frame": "a", "math": "a",
            "touch_support": "a", "dom_blockers": "a", "user_agent_data": "a",
        }))
        .unwrap();
        let entries: Vec<_> = full.entries().collect();
        assert_eq!(entries.len(), Component::ALL.len());
        for (component, value) in entries {
            let kind = match value {
                ComponentValue::Category(_) => Kind::Category,
                ComponentValue::Numeric(_) => Kind::Numeric,
                ComponentValue::Set(_) => Kind::Set,
            };
            assert_eq!(kind, component.kind(), "{}", component.name());
        }
        // Serialization round-trips through the same wire keys.
        let round: Components =
            serde_json::from_value(serde_json::to_value(&full).unwrap()).unwrap();
        assert_eq!(round, full);
    }
}
