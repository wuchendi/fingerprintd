//! Stage-one candidate generation: a `key → set<visitor_id>` inverted index
//! (fuzzy-matching §4/§11).
//!
//! Recall is prioritized over precision: several independent blocking keys are
//! queried and their hits unioned, so a single changed component does not drop
//! the true match. Popular configurations (e.g. stock iPhone Safari) inflate a
//! block; over-capacity blocks carry little information and — per the architecture's
//! no-silent-truncation rule — dropped members are logged, never hidden.

use std::collections::{HashMap, HashSet};

/// A blocking key: a 256-bit digest of a stable-component subset (fuzzy-matching §4).
pub type BlockingKey = [u8; 32];

/// Default per-block size cap. Blocks larger than this are low-information and
/// left to stage-two scoring to disambiguate (fuzzy-matching §4).
pub const DEFAULT_MAX_BLOCK: usize = 1024;

/// Inverted index mapping each blocking key to the visitors that hash into it.
///
/// Memberships are added and removed one `(key, visitor)` pair at a time; the
/// caller tracks each visitor's keys, so removing a visitor costs O(its keys)
/// and an emptied block is deleted immediately.
#[derive(Debug)]
pub struct BlockingIndex {
    /// Maximum visitors retained per block before over-capacity drops begin.
    max_block: usize,
    /// `blocking key → visitors`.
    index: HashMap<BlockingKey, HashSet<String>>,
    /// Total `(key, visitor)` memberships across every block.
    rows: usize,
    /// Count of over-capacity insertions dropped (observability, not silent).
    dropped: u64,
}

impl Default for BlockingIndex {
    fn default() -> Self {
        Self::with_max_block(DEFAULT_MAX_BLOCK)
    }
}

impl BlockingIndex {
    /// Create an index with the default block-size cap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an index with an explicit block-size cap.
    pub fn with_max_block(max_block: usize) -> Self {
        Self {
            max_block,
            index: HashMap::new(),
            rows: 0,
            dropped: 0,
        }
    }

    /// Add `visitor` under `key`, returning whether it is now a member.
    ///
    /// If the block is already at capacity and does not yet contain `visitor`,
    /// the insertion is dropped and counted (see [`BlockingIndex::dropped`]); a
    /// `warn` is emitted so over-capacity blocks are visible rather than silent.
    pub fn insert(&mut self, key: BlockingKey, visitor: &str) -> bool {
        let block = self.index.entry(key).or_default();
        if block.contains(visitor) {
            return true;
        }
        if block.len() >= self.max_block {
            self.dropped += 1;
            tracing::warn!(
                block_size = block.len(),
                max_block = self.max_block,
                "blocking block over capacity; dropped visitor (not silently truncated)",
            );
            if block.is_empty() {
                self.index.remove(&key);
            }
            return false;
        }
        block.insert(visitor.to_owned());
        self.rows += 1;
        true
    }

    /// Remove `visitor` from `key`'s block, deleting the block once empty.
    /// Idempotent: an absent membership is a no-op.
    pub fn remove(&mut self, key: &BlockingKey, visitor: &str) {
        let Some(block) = self.index.get_mut(key) else {
            return;
        };
        if block.remove(visitor) {
            self.rows -= 1;
        }
        if block.is_empty() {
            self.index.remove(key);
        }
    }

    /// Union of visitors across every supplied `key` — the candidate set (fuzzy-matching §4).
    pub fn candidates(&self, keys: &[BlockingKey]) -> HashSet<&str> {
        let mut candidates = HashSet::new();
        for key in keys {
            if let Some(block) = self.index.get(key) {
                candidates.extend(block.iter().map(String::as_str));
            }
        }
        candidates
    }

    /// Total over-capacity insertions dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Total `(key, visitor)` memberships currently indexed.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of non-empty blocks.
    pub fn blocks(&self) -> usize {
        self.index.len()
    }

    /// Whether any block holds `visitor` (a full scan, for tests only).
    #[cfg(test)]
    pub(super) fn indexes(&self, visitor: &str) -> bool {
        self.index.values().any(|block| block.contains(visitor))
    }
}

#[cfg(test)]
mod tests {
    use super::BlockingIndex;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn candidates_union_across_keys() {
        let mut index = BlockingIndex::new();
        index.insert(key(1), "alice");
        index.insert(key(2), "bob");
        index.insert(key(2), "carol");

        // A probe touching both keys recalls every visitor behind either.
        let got = index.candidates(&[key(1), key(2)]);
        assert_eq!(got.len(), 3);
        assert!(got.contains("alice") && got.contains("bob") && got.contains("carol"));

        // A miss key contributes nothing.
        assert!(index.candidates(&[key(9)]).is_empty());
    }

    #[test]
    fn recall_survives_one_changed_key() {
        // alice indexed under two independent keys; if the K1 key changes, the
        // K2 key still recalls her.
        let mut index = BlockingIndex::new();
        index.insert(key(1), "alice");
        index.insert(key(2), "alice");

        let recalled = index.candidates(&[key(7), key(2)]);
        assert!(recalled.contains("alice"));
    }

    #[test]
    fn over_capacity_is_dropped_and_counted() {
        let mut index = BlockingIndex::with_max_block(2);
        assert!(index.insert(key(0), "a"));
        assert!(index.insert(key(0), "b"));
        assert!(!index.insert(key(0), "c")); // over cap -> dropped

        let block = index.candidates(&[key(0)]);
        assert_eq!(block.len(), 2);
        assert!(!block.contains("c"));
        assert_eq!(index.dropped(), 1);
        assert_eq!(index.rows(), 2);
    }

    #[test]
    fn remove_frees_capacity_and_drops_empty_blocks() {
        let mut index = BlockingIndex::with_max_block(1);
        index.insert(key(1), "alice");
        index.insert(key(2), "alice");
        index.remove(&key(1), "alice");

        // The emptied block is gone and its slot is free for a newcomer.
        assert_eq!(index.blocks(), 1);
        assert!(index.insert(key(1), "bob"));
        assert_eq!(index.candidates(&[key(1)]).len(), 1);
        assert_eq!(index.rows(), 2);
        // Idempotent: removing an absent membership is a no-op.
        index.remove(&key(1), "alice");
        index.remove(&key(9), "alice");
        assert_eq!(index.rows(), 2);
    }

    #[test]
    fn re_inserting_existing_member_at_capacity_is_not_dropped() {
        let mut index = BlockingIndex::with_max_block(2);
        index.insert(key(0), "a");
        index.insert(key(0), "b");
        assert!(index.insert(key(0), "a")); // already present -> not a drop
        assert_eq!(index.dropped(), 0);
        assert_eq!(index.rows(), 2);
    }
}
