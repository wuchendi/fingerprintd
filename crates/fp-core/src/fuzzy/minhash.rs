//! `MinHash`-`LSH` band keys for set components (fuzzy-matching §4 K3 / §11).
//!
//! Exact hashing of a font set breaks the moment one font is added, so a set is
//! reduced to a `MinHash` signature and split into bands. Two sets that share
//! any band collide on a [`BlockingKey`], giving recall that tolerates
//! incremental set change. The band keys are inserted into the shared
//! [`super::blocking::BlockingIndex`] alongside the scalar keys, so `MinHash`
//! recall unions naturally with the other blocking keys.

use std::collections::BTreeSet;

#[cfg(feature = "rng")]
use rand::{Rng, rng};
use sha2::{Digest, Sha256};

use super::{blocking::BlockingKey, component::Hash32};

/// Number of `MinHash` permutations (signature length).
const NUM_PERM: usize = 16;
/// Rows per band; `NUM_PERM / ROWS` bands are produced.
const ROWS: usize = 2;
/// Number of bands emitted per set.
const BANDS: usize = NUM_PERM / ROWS;

/// Odd multiplier used to keep the affine permutation a bijection over `u64`.
const ODD_MASK: u64 = 1;

/// A `MinHash`-`LSH` band-key generator with a fixed random permutation family.
///
/// The coefficients are drawn once at construction and reused for every set, so
/// a given set yields the same signature across observations within one instance.
#[derive(Debug)]
pub struct MinHashLsh {
    /// `(a, b)` coefficients of the affine hash `a·x + b` per permutation.
    coefficients: [(u64, u64); NUM_PERM],
}

#[cfg(feature = "rng")]
impl Default for MinHashLsh {
    fn default() -> Self {
        Self::new()
    }
}

impl MinHashLsh {
    /// Build an index with a fresh random permutation family.
    #[cfg(feature = "rng")]
    pub fn new() -> Self {
        let mut rng = rng();
        let mut coefficients = [(0u64, 0u64); NUM_PERM];
        for slot in &mut coefficients {
            // Force `a` odd so `a·x + b` is a bijection over the `u64` ring.
            *slot = (rng.next_u64() | ODD_MASK, rng.next_u64());
        }
        Self { coefficients }
    }

    /// Build an index with a **deterministic** permutation family derived from
    /// `seed`.
    ///
    /// The random [`MinHashLsh::new`] family differs per instance, which breaks
    /// set recall for a stateless edge deployment where band keys are persisted
    /// and re-derived across isolates. Seeding makes the family reproducible:
    /// each permutation's `(a, b)` is read from `SHA-256(seed || index)`, with
    /// `a` forced odd so `a·x + b` stays a bijection over the `u64` ring.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut coefficients = [(0u64, 0u64); NUM_PERM];
        for (index, slot) in coefficients.iter_mut().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update((index as u64).to_le_bytes());
            let digest = hasher.finalize();
            let a = u64::from_le_bytes(digest[..8].try_into().unwrap_or_default()) | ODD_MASK;
            let b = u64::from_le_bytes(digest[8..16].try_into().unwrap_or_default());
            *slot = (a, b);
        }
        Self { coefficients }
    }

    /// Band keys for `elements` — one [`BlockingKey`] per band.
    ///
    /// Returns an empty vector for an empty set (nothing to recall on). Each key
    /// is namespaced by its band index so bands cannot collide with one another.
    pub fn band_keys(&self, elements: &BTreeSet<Hash32>) -> Vec<BlockingKey> {
        if elements.is_empty() {
            return Vec::new();
        }
        let signature = self.signature(elements);
        (0..BANDS)
            .map(|band| {
                let start = band * ROWS;
                band_key(band, &signature[start..start + ROWS])
            })
            .collect()
    }

    /// Compute the `MinHash` signature: the per-permutation minimum over elements.
    fn signature(&self, elements: &BTreeSet<Hash32>) -> [u64; NUM_PERM] {
        let mut signature = [u64::MAX; NUM_PERM];
        for element in elements {
            let x = leading_u64(element);
            for (slot, &(a, b)) in signature.iter_mut().zip(self.coefficients.iter()) {
                let hashed = a.wrapping_mul(x).wrapping_add(b);
                if hashed < *slot {
                    *slot = hashed;
                }
            }
        }
        signature
    }
}

/// Interpret the first eight bytes of an element hash as a `u64`.
fn leading_u64(hash: &Hash32) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(buf)
}

/// Hash a band index and its signature slice into a namespaced [`BlockingKey`].
fn band_key(band: usize, rows: &[u64]) -> BlockingKey {
    let mut hasher = Sha256::new();
    hasher.update(b"minhash-band");
    hasher.update((band as u64).to_le_bytes());
    for &row in rows {
        hasher.update(row.to_le_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::MinHashLsh;
    use crate::fuzzy::component::Salt;

    #[test]
    fn similar_sets_share_a_band() {
        let salt = Salt::random();
        let lsh = MinHashLsh::new();
        // Large, highly overlapping sets: differ by one element out of ~30.
        let base: Vec<String> = (0..30).map(|i| format!("font-{i}")).collect();
        let mut changed = base.clone();
        changed[0] = "font-new".to_string();

        let a = lsh.band_keys(&salt.hash_set(&base));
        let b = lsh.band_keys(&salt.hash_set(&changed));
        assert!(
            a.iter().any(|k| b.contains(k)),
            "near-identical sets must collide in at least one band",
        );
    }

    #[test]
    fn identical_sets_share_every_band() {
        let salt = Salt::random();
        let lsh = MinHashLsh::new();
        let set = salt.hash_set(["a", "b", "c", "d"]);
        assert_eq!(lsh.band_keys(&set), lsh.band_keys(&set));
    }

    #[test]
    fn disjoint_sets_do_not_collide() {
        let salt = Salt::random();
        let lsh = MinHashLsh::new();
        let a = lsh.band_keys(&salt.hash_set(["a1", "a2", "a3", "a4"]));
        let b = lsh.band_keys(&salt.hash_set(["z1", "z2", "z3", "z4"]));
        assert!(a.iter().all(|k| !b.contains(k)));
    }

    #[test]
    fn empty_set_yields_no_keys() {
        let lsh = MinHashLsh::new();
        let keys = lsh.band_keys(&Salt::random().hash_set(Vec::<String>::new()));
        assert_eq!(keys.len(), 0);
    }
}
