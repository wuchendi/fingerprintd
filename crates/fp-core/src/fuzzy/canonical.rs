//! Blocking-key derivation for the fuzzy store (fuzzy-matching §4).
//!
//! These helpers fold stored-component subsets into the composite blocking keys
//! used for stage-one recall (§4).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::blocking::BlockingKey;
use super::component::Stored;

/// Length-prefixed digest of an ordered member group into one blocking key.
///
/// Returns `None` if any member is absent or is a set (sets recall via
/// `MinHash` bands, not composite keys).
pub(super) fn group_key(
    stored: &BTreeMap<String, Stored>,
    namespace: &[u8],
    members: &[&str],
) -> Option<BlockingKey> {
    let mut hasher = Sha256::new();
    hasher.update(namespace);
    for member in members {
        let bytes = scalar_bytes(stored.get(*member)?)?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Some(hasher.finalize().into())
}

/// Length-prefixed digest of every present scalar component into one catch-all
/// blocking key (K0). Returns `None` when the map holds no scalar value (only
/// sets, or nothing), since there is then no scalar identity to key on.
///
/// Names are folded in alongside values (the map iterates in sorted name order)
/// so two probes collide here only when their scalar components match exactly.
pub(super) fn all_scalar_key(stored: &BTreeMap<String, Stored>) -> Option<BlockingKey> {
    let mut hasher = Sha256::new();
    hasher.update(b"K0");
    let mut any = false;
    for (name, value) in stored {
        let Some(bytes) = scalar_bytes(value) else {
            continue;
        };
        any = true;
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    any.then(|| hasher.finalize().into())
}

/// Keying bytes for a scalar stored value; `None` for set components.
fn scalar_bytes(stored: &Stored) -> Option<Vec<u8>> {
    match stored {
        Stored::Category(hash) => Some(hash.to_vec()),
        Stored::Numeric(n) => Some(n.to_le_bytes().to_vec()),
        Stored::Set(_) => None,
    }
}
