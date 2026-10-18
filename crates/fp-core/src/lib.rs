//! `fingerprintd` — the framework-free device-fingerprinting core.
//!
//! This crate holds the pure compute and the in-memory matching state shared by every
//! deployment target: the native Axum server (`crates/fingerprintd`) depends on
//! it directly, and the WebAssembly build (`crates/fp-wasm`) exposes the same
//! pure functions to a JavaScript host (the edge Worker).
//!
//! The split is deliberate:
//! - **Pure compute** — blocking-key derivation, the Fellegi–Sunter scorer and
//!   double-threshold decision, confidence fusion ([`fuzzy`]), and the passive
//!   network / client-integrity signals ([`signals`]). None of it touches an
//!   HTTP framework, an async runtime, or a socket, so it runs unchanged on a
//!   V8 isolate.
//! - **In-memory state** — [`fuzzy::FuzzyStore`] keeps the record library,
//!   blocking index, and frequency / agreement / velocity material behind one
//!   lock; the native-only `nonce` module (behind the default `rng` feature)
//!   adds the one-time challenge store.
//!
//! [`fuzzy::FuzzyStore`] ties the compute and that state together behind one
//! observe/identify surface. A stateless host instead persists the salted
//! [`fuzzy::StoredComponents`] wire form itself and scores recalled templates
//! through the same store.

#![forbid(unsafe_code)]

pub mod fuzzy;
// The in-memory nonce store needs OS entropy and a wall clock
// (`std::time::Instant`), neither available on `wasm32-unknown-unknown`; on the
// edge the nonce lifecycle is a Durable Object, so the WASM build omits it.
#[cfg(feature = "rng")]
pub mod nonce;
pub mod signals;

/// Implement `Deserialize` (and, with the `serialize` prefix, `Serialize`) for
/// a struct whose serde derives carry `#[serde(remote = "Self")]`, so it
/// deserializes **only from a map** (a JSON object).
///
/// serde's derived struct impl also accepts the sequence form (a JSON array of
/// field values), which would let `[]` stand in for an all-default object and
/// bypass `deny_unknown_fields`; the generated impl rejects every non-map input
/// and delegates the map to the derived (inherent) impl.
#[macro_export]
macro_rules! object_only_serde {
    (serialize $ty:ty) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                <$ty>::serialize(self, serializer)
            }
        }
        $crate::object_only_serde!($ty);
    };
    ($ty:ty) => {
        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct ObjectVisitor;

                impl<'de> ::serde::de::Visitor<'de> for ObjectVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str("a JSON object")
                    }

                    fn visit_map<A: ::serde::de::MapAccess<'de>>(
                        self,
                        map: A,
                    ) -> Result<$ty, A::Error> {
                        <$ty>::deserialize(::serde::de::value::MapAccessDeserializer::new(map))
                    }
                }

                deserializer.deserialize_map(ObjectVisitor)
            }
        }
    };
}
