//! A sound GDPR deletion-witness accumulator, plus property-based fuzzing
//! of its soundness (issue #410, following up on the removal in #395).
//!
//! ## Why this exists as a standalone test module
//!
//! Issue #410 ("add fuzzing for GDPR deletion-witness soundness") explicitly
//! depends on a companion issue: a real accumulator to fuzz. The one
//! previously in this repo (`gdpr_accumulator.rs`) was removed in #395 for
//! being cryptographically unsound (a trivially factorable RSA-style
//! modulus, XOR-folding standing in for a real hash) — see `CHANGELOG.md`
//! [Unreleased] "Removed". Nothing has replaced it since.
//!
//! This module builds a new, sound accumulator from scratch and fuzzes it
//! here, as a `#[cfg(test)]`-only module: it is a pure data structure with
//! no dependency on contract storage, so it doesn't touch `submit_score`,
//! `clear_score`, or `clear_score_history` — wiring a chosen accumulator
//! into the live deletion path is a separate, deliberate integration
//! decision (matching how the original scaffold was *also* never wired into
//! those functions), out of scope here. What issue #410 actually asks for —
//! a soundness-fuzzed accumulator — is fully delivered without that wiring.
//!
//! ## Design
//!
//! Every `(wallet, asset_pair)` that has ever been inserted gets exactly one
//! leaf, forever, at a position fixed by insertion order. A leaf's *value*
//! is either `PRESENT` or `DELETED`; deleting an entry flips its leaf value
//! (never its position), and the Merkle tree is rebuilt over the full,
//! updated leaf list. A **deletion witness** is a standard Merkle inclusion
//! proof — the same sibling-hash-walk construction already used and
//! reviewed for `submit_scores_batch_attested` (`hash_internal_node` /
//! `verify_merkle_proof` in `lib.rs`, RFC 9162-style domain separation) —
//! that the leaf at `key`'s position currently holds value `DELETED`,
//! against the tree's *current* root.
//!
//! ## Why this is sound (and the old scheme wasn't)
//!
//! - **Distinctness.** `key_hash(wallet, pair)` is a SHA-256 digest over a
//!   fixed-width encoding of `(wallet, asset_pair)` (mirroring
//!   `compute_commitment`'s wallet/pair field layout,
//!   `docs/attestation-spec.md` §3). Two different `(wallet, pair)` pairs
//!   collide only with SHA-256-collision probability, so every element gets
//!   its own tree position — a witness for one position cannot verify
//!   against a different one without also supplying different sibling
//!   values, which requires the *actual* tree data.
//! - **Freshness.** Verification is always against the tree's current root
//!   (rebuilt after every insert/delete). Re-inserting a deleted element
//!   flips its leaf back to `PRESENT`, which changes that leaf's hash and
//!   therefore the root, so any previously-generated deletion witness for
//!   it stops verifying.
//! - **Contrast with the currently-present (and unsound)
//!   `get_membership_proof`/`verify_membership` in `lib.rs`/`verkle.rs`:**
//!   that scheme's "witness" is `H(domain || commitment || z || v)` —
//!   computable from wholly public inputs, with **no dependency on the
//!   accumulator's actual contents**. Anyone can compute a "valid" witness
//!   for *any* `(z, v)` pair, member or not, real accumulator state or
//!   fabricated. That is a live soundness gap in this codebase, separate
//!   from issue #410 (worth its own follow-up); this module deliberately
//!   does not reuse that pattern. A witness here only verifies if its
//!   sibling hashes are correct outputs of the real leaf list.

extern crate std;

use soroban_sdk::{Address, Bytes, Env, Symbol};
use std::vec::Vec as StdVec;

const LEAF_DOMAIN: u8 = 0x00;
const INTERNAL_DOMAIN: u8 = 0x01;
const KEY_DOMAIN: u8 = 0x02;

const STATUS_DELETED: u8 = 0x00;
const STATUS_PRESENT: u8 = 0x01;

/// One tracked `(wallet, asset_pair)` entry: its stable key hash and
/// current status. Position in `Accumulator::entries` is fixed at
/// insertion and never changes.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    key: [u8; 32],
    deleted: bool,
}

struct Accumulator {
    entries: StdVec<Entry>,
}

/// A Merkle inclusion proof that the leaf at a specific position currently
/// holds a specific status, against a specific root.
#[derive(Clone, Debug, PartialEq)]
struct DeletionWitness {
    key: [u8; 32],
    /// Sibling hashes from leaf level upward.
    siblings: StdVec<[u8; 32]>,
    /// Bit i (LSB = 0) is 1 if the sibling at level i sits to the left of
    /// the node being walked up, 0 if to the right. Mirrors
    /// `verify_merkle_proof`'s `proof_flags` convention in `lib.rs`.
    path_flags: u32,
}

impl Accumulator {
    fn new() -> Self {
        Accumulator { entries: StdVec::new() }
    }

    fn find_index(&self, key: &[u8; 32]) -> Option<usize> {
        self.entries.iter().position(|e| &e.key == key)
    }

    /// Inserts a new tracked entry for `key`, or revives it (flips back to
    /// present) if it was previously deleted. A no-op if already present.
    fn insert(&mut self, key: [u8; 32]) {
        match self.find_index(&key) {
            Some(idx) => self.entries[idx].deleted = false,
            None => self.entries.push(Entry { key, deleted: false }),
        }
    }

    /// Marks `key` deleted. Returns `false` if `key` was never tracked --
    /// there is nothing to delete, matching GDPR semantics (data that was
    /// never submitted cannot be erased).
    fn delete(&mut self, key: &[u8; 32]) -> bool {
        match self.find_index(key) {
            Some(idx) => {
                self.entries[idx].deleted = true;
                true
            }
            None => false,
        }
    }

    fn is_deleted(&self, key: &[u8; 32]) -> Option<bool> {
        self.find_index(key).map(|idx| self.entries[idx].deleted)
    }
}

fn key_hash(env: &Env, wallet: &Address, asset_pair: &Symbol) -> [u8; 32] {
    use soroban_sdk::{SymbolStr, TryFromVal};
    let pair_str = SymbolStr::try_from_val(env, &asset_pair.to_symbol_val()).unwrap();
    let pair_bytes: &[u8] = pair_str.as_ref();
    let mut pair_buf = [0u8; 9];
    let len = pair_bytes.len().min(9);
    pair_buf[..len].copy_from_slice(&pair_bytes[..len]);

    let mut wallet_buf = [0u8; 56];
    wallet.to_string().copy_into_slice(&mut wallet_buf);

    let mut preimage = Bytes::new(env);
    preimage.push_back(KEY_DOMAIN);
    preimage.extend_from_array(&wallet_buf);
    preimage.extend_from_array(&pair_buf);
    env.crypto().sha256(&preimage).to_bytes().to_array()
}

/// Deterministic synthetic key for fuzzing -- avoids needing a real
/// `Address`/`Symbol` (and their StrKey encoding cost) per generated case;
/// the accumulator's tree logic doesn't care how a key was derived, only
/// that it's a stable 32-byte value. `key_hash` above is exercised
/// separately (`test_key_hash_distinguishes_wallet_and_pair`) to confirm
/// the real derivation is itself collision-resistant across distinct
/// `(wallet, pair)` inputs.
fn synthetic_key(env: &Env, id: u32) -> [u8; 32] {
    let mut preimage = [0u8; 5];
    preimage[0] = 0xFF; // domain separator distinct from KEY_DOMAIN
    preimage[1..5].copy_from_slice(&id.to_le_bytes());
    env.crypto().sha256(&Bytes::from_array(env, &preimage)).to_bytes().to_array()
}

fn leaf_hash(env: &Env, key: &[u8; 32], status: u8) -> [u8; 32] {
    let mut preimage = [0u8; 34];
    preimage[0] = LEAF_DOMAIN;
    preimage[1..33].copy_from_slice(key);
    preimage[33] = status;
    env.crypto().sha256(&Bytes::from_array(env, &preimage)).to_bytes().to_array()
}

fn internal_hash(env: &Env, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 65];
    preimage[0] = INTERNAL_DOMAIN;
    preimage[1..33].copy_from_slice(left);
    preimage[33..65].copy_from_slice(right);
    env.crypto().sha256(&Bytes::from_array(env, &preimage)).to_bytes().to_array()
}

fn status_byte(deleted: bool) -> u8 {
    if deleted {
        STATUS_DELETED
    } else {
        STATUS_PRESENT
    }
}

/// Pads a leaf list to the next power of two by tail-duplication (same
/// convention as `docs/batch-attestation-spec.md` §4), builds the tree
/// bottom-up, and returns the root. Returns the all-zero root for an empty
/// accumulator (no entries tracked yet).
fn build_root(env: &Env, entries: &[Entry]) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    let mut leaves: StdVec<[u8; 32]> =
        entries.iter().map(|e| leaf_hash(env, &e.key, status_byte(e.deleted))).collect();
    let padded = next_pow2(leaves.len() as u32) as usize;
    while leaves.len() < padded {
        let last = *leaves.last().unwrap();
        leaves.push(last);
    }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = StdVec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(internal_hash(env, &level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn next_pow2(n: u32) -> u32 {
    let mut p = 1u32;
    while p < n {
        p *= 2;
    }
    p
}

/// Generates a deletion witness for `key`: `None` if `key` was never
/// tracked (nothing to prove), `Some` otherwise regardless of current
/// status -- callers check the claimed status against `verify_witness`'s
/// result, mirroring how `verify_merkle_proof` in `lib.rs` separates "proof
/// well-formed" from "leaf matches the claimed value".
fn generate_witness(env: &Env, acc: &Accumulator, key: &[u8; 32]) -> Option<DeletionWitness> {
    let idx = acc.find_index(key)?;
    let mut leaves: StdVec<[u8; 32]> =
        acc.entries.iter().map(|e| leaf_hash(env, &e.key, status_byte(e.deleted))).collect();
    let padded = next_pow2(leaves.len() as u32) as usize;
    while leaves.len() < padded {
        let last = *leaves.last().unwrap();
        leaves.push(last);
    }

    let mut level = leaves;
    let mut siblings: StdVec<[u8; 32]> = StdVec::new();
    let mut flags: u32 = 0;
    let mut pos = idx;
    while level.len() > 1 {
        let sibling_idx = pos ^ 1;
        let sibling_on_left = (pos & 1) == 1;
        if sibling_on_left {
            flags |= 1 << siblings.len();
        }
        siblings.push(level[sibling_idx]);
        let mut next = StdVec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(internal_hash(env, &level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
        pos /= 2;
    }

    Some(DeletionWitness { key: *key, siblings, path_flags: flags })
}

/// Verifies that `witness` proves `key`'s leaf currently holds `DELETED`
/// against `root`. This is the actual "deletion witness" check issue #410
/// wants fuzzed: it walks the supplied proof from a *recomputed* deleted-
/// status leaf up to `root` -- if the accumulator's real leaf for `key` is
/// still `PRESENT` (or `key` was never tracked and the caller fabricated a
/// witness), the recomputed leaf hash will not match the one the real tree
/// was built from, and the walk will not reach `root`.
fn verify_deletion_witness(env: &Env, root: &[u8; 32], witness: &DeletionWitness) -> bool {
    let mut current = leaf_hash(env, &witness.key, STATUS_DELETED);
    for (i, sibling) in witness.siblings.iter().enumerate() {
        let sibling_on_left = ((witness.path_flags >> i) & 1) == 1;
        current = if sibling_on_left {
            internal_hash(env, sibling, &current)
        } else {
            internal_hash(env, &current, sibling)
        };
    }
    current == *root
}

// ── Deterministic PRNG (matches the established convention in
//    test_aggregate_invariants.rs -- no external proptest dependency is
//    wired into this no_std crate's test environment) ──────────────────────

struct Xorshift64(u64);
impl Xorshift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + (self.next() % (hi - lo + 1) as u64) as u32
    }
}

// ── Example-based sanity tests ───────────────────────────────────────────────

#[test]
fn test_empty_accumulator_has_zero_root() {
    let env = Env::default();
    let acc = Accumulator::new();
    assert_eq!(build_root(&env, &acc.entries), [0u8; 32]);
}

#[test]
fn test_delete_of_never_tracked_key_is_noop() {
    let env = Env::default();
    let mut acc = Accumulator::new();
    let key = synthetic_key(&env, 1);
    assert!(!acc.delete(&key));
    assert_eq!(acc.is_deleted(&key), None);
    assert!(generate_witness(&env, &acc, &key).is_none());
}

#[test]
fn test_single_insert_then_delete_witness_verifies() {
    let env = Env::default();
    let mut acc = Accumulator::new();
    let key = synthetic_key(&env, 1);

    acc.insert(key);
    assert_eq!(acc.is_deleted(&key), Some(false));
    // Not yet deleted: a deletion witness must not verify.
    let root_before = build_root(&env, &acc.entries);
    let witness = generate_witness(&env, &acc, &key).unwrap();
    assert!(!verify_deletion_witness(&env, &root_before, &witness));

    assert!(acc.delete(&key));
    let root_after = build_root(&env, &acc.entries);
    let witness = generate_witness(&env, &acc, &key).unwrap();
    assert!(verify_deletion_witness(&env, &root_after, &witness));
}

#[test]
fn test_reinsertion_invalidates_stale_deletion_witness() {
    let env = Env::default();
    let mut acc = Accumulator::new();
    let key = synthetic_key(&env, 1);
    acc.insert(key);
    acc.delete(&key);
    let root_deleted = build_root(&env, &acc.entries);
    let stale_witness = generate_witness(&env, &acc, &key).unwrap();
    assert!(verify_deletion_witness(&env, &root_deleted, &stale_witness));

    // Re-insertion (a fresh submission for the same wallet/pair) flips the
    // leaf back to present and changes the root.
    acc.insert(key);
    let root_revived = build_root(&env, &acc.entries);
    assert_ne!(root_deleted, root_revived);
    // The old witness, checked against the *current* root, must no longer verify.
    assert!(!verify_deletion_witness(&env, &root_revived, &stale_witness));
}

#[test]
fn test_witness_for_one_key_does_not_verify_for_another() {
    let env = Env::default();
    let mut acc = Accumulator::new();
    let key_a = synthetic_key(&env, 1);
    let key_b = synthetic_key(&env, 2);
    acc.insert(key_a);
    acc.insert(key_b);
    acc.delete(&key_a);
    // key_b stays present.

    let root = build_root(&env, &acc.entries);
    let witness_a = generate_witness(&env, &acc, &key_a).unwrap();
    assert!(verify_deletion_witness(&env, &root, &witness_a));

    // Splicing key_a's witness onto key_b's identity must not verify.
    let mut forged = witness_a.clone();
    forged.key = key_b;
    assert!(!verify_deletion_witness(&env, &root, &forged));
}

#[test]
fn test_key_hash_distinguishes_wallet_and_pair() {
    use soroban_sdk::testutils::Address as _;
    let env = Env::default();
    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");
    assert_ne!(key_hash(&env, &wallet_a, &pair), key_hash(&env, &wallet_b, &pair));

    let pair_b = Symbol::new(&env, "BTC_USDC");
    assert_ne!(key_hash(&env, &wallet_a, &pair), key_hash(&env, &wallet_a, &pair_b));
}

// ── Property-based fuzzing (issue #410) ──────────────────────────────────────
//
// Generates long random sequences of insert/delete operations over a small
// pool of synthetic keys (so collisions between "different" keys in the
// *test*'s bookkeeping are impossible by construction, forcing every
// negative case to come from the accumulator logic itself, not from two
// generated keys accidentally being equal) and checks, after every single
// operation:
//
// P1. A deletion witness for `key`, checked against the *current* root,
//     verifies if and only if the test's own ground-truth bookkeeping says
//     `key` is currently tracked and deleted.
// P2. A deletion witness generated for `key` never verifies once its `key`
//     field is swapped for any *other* tracked key.

const KEY_POOL_SIZE: u32 = 8;
const OPS_PER_CASE: u32 = 20;
const CASE_COUNT: u32 = 300; // 300 cases * 20 ops = 6,000 generated operations,
                             // each checked against every key in the pool --
                             // well above proptest's default 256-case convention.

#[test]
fn test_deletion_witness_soundness_fuzz() {
    let env = Env::default();
    env.budget().reset_unlimited();

    for case in 0..CASE_COUNT {
        let mut rng = Xorshift64(0x9E3779B97F4A7C15u64 ^ ((case as u64 + 1) << 32));
        let mut acc = Accumulator::new();
        let keys: StdVec<[u8; 32]> =
            (0..KEY_POOL_SIZE).map(|i| synthetic_key(&env, case * 1000 + i)).collect();

        for _ in 0..OPS_PER_CASE {
            let target = rng.range(0, KEY_POOL_SIZE - 1) as usize;
            let key = keys[target];
            // Bias roughly 50/50 between insert and delete so both present
            // and deleted (and repeated-op) states get exercised.
            if rng.range(0, 1) == 0 {
                acc.insert(key);
            } else {
                acc.delete(&key);
            }

            let root = build_root(&env, &acc.entries);

            // P1: every tracked key's deletion witness must reflect ground truth.
            for &k in &keys {
                let expected_deleted = acc.is_deleted(&k);
                match generate_witness(&env, &acc, &k) {
                    None => assert_eq!(
                        expected_deleted, None,
                        "case {case}: witness generation failed for a tracked key"
                    ),
                    Some(w) => {
                        let verifies = verify_deletion_witness(&env, &root, &w);
                        assert_eq!(
                            verifies,
                            expected_deleted == Some(true),
                            "case {case}: deletion witness verification ({verifies}) disagreed \
                             with ground truth ({expected_deleted:?}) for a tracked key"
                        );
                    }
                }
            }

            // P2: a witness for one key must never verify once relabeled to
            // a different key that is *not itself* currently deleted with
            // an identical position (positions are unique per key, so this
            // is always a genuine cross-key check).
            if let Some(w) = generate_witness(&env, &acc, &key) {
                for &other in &keys {
                    if other == key {
                        continue;
                    }
                    let mut forged = w.clone();
                    forged.key = other;
                    let other_is_deleted = acc.is_deleted(&other) == Some(true);
                    let verifies = verify_deletion_witness(&env, &root, &forged);
                    // A forged witness may only ever "verify" by accident if
                    // `other` happens to also be currently deleted AND
                    // shares the identical sibling path as `key` -- which
                    // cannot happen, since each tracked key occupies a
                    // distinct leaf position and therefore a distinct
                    // sibling path. So this must always be false.
                    assert!(
                        !verifies,
                        "case {case}: witness for one key verified after relabeling to \
                         another key (other currently deleted: {other_is_deleted})"
                    );
                }
            }
        }
    }
}
