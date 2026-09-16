//! Criterion benchmarks for `submit_scores_batch_attested` at varying batch
//! sizes, profiled against plain `submit_scores_batch` (`batch_submit.rs`)
//! at the same batch sizes (issue #419).
//!
//! Run: `cargo bench -p scoregate-score --bench batch_attested`
//!
//! Benches are separate binaries that only see the crate's public API, so
//! this can't call the contract's private `compute_commitment` directly
//! (unlike `src/test_batch_attestation.rs`, an in-crate test module). It
//! instead reimplements the exact 243-byte preimage from
//! `docs/attestation-spec.md` §3 using only public `soroban_sdk` APIs --
//! precisely what a real off-chain attestation pipeline has to do, since it
//! has no access to the Rust source either. Batch entries always fold in
//! zeroed `contract_id`/`contract_version` trailing fields, matching
//! `compute_merkle_leaf`'s own hardcoded arguments for those two positions
//! (batch entries are bound by the single whole-batch root signature, not a
//! per-entry contract/version binding -- that's only for the single-score
//! `ScoreAttestation` path).
//!
//! ## Findings (issue #419)
//!
//! - The lazy-TTL-extension optimization in `storage::set_score` /
//!   `touch_score_entry` is shared verbatim by `submit_scores_batch_attested`
//!   -- both batch entry points call the identical `storage::set_score` for
//!   each accepted entry, so there was no separate "eager" code path on this
//!   route that needed fixing.
//! - `verify_merkle_proof` walks a per-entry Merkle *inclusion* proof
//!   (`O(proof.len())`, hard-capped at `MAX_MERKLE_PROOF_DEPTH` = 30 SHA-256
//!   calls), not a full-tree recomputation -- its cost scales with tree
//!   *depth* (`ceil(log2(batch size))`), not batch size directly, so it
//!   isn't "re-hashing more than necessary" at any batch size up to
//!   `MAX_BATCH_SIZE` (20, i.e. depth <= 5).
//! - See the PR description for issue #419 for the actual measured
//!   instruction counts this benchmark produced, compared against
//!   `submit_scores_batch`'s numbers at the same sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use k256::ecdsa::SigningKey;
use scoregate_score::{
    BatchAttestation, ScoreGateScoreContract, ScoreGateScoreContractClient, ScoreSubmission,
    ScoreSubmissionWithProof,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Bytes, BytesN, Env, Symbol, SymbolStr, TryFromVal, Vec,
};

const MAX_BATCH: u32 = 20;

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    bytes[0] = 1; // avoid an all-zero scalar
    SigningKey::from_bytes((&bytes).into()).unwrap()
}

fn pubkey_bytes(env: &Env, key: &SigningKey) -> Bytes {
    let point = key.verifying_key().to_encoded_point(true); // compressed
    Bytes::from_slice(env, point.as_bytes())
}

/// Reproduces `compute_commitment`'s exact 243-byte preimage
/// (`docs/attestation-spec.md` §3) using only public `soroban_sdk` APIs.
/// `contract_id`/`contract_version` are always zeroed, matching
/// `compute_merkle_leaf`'s own hardcoded arguments for batch entries.
fn commitment(
    env: &Env,
    contract_addr: &Address,
    wallet: &Address,
    pair: &Symbol,
    score: u32,
    ts: u64,
) -> [u8; 32] {
    let pair_str = SymbolStr::try_from_val(env, &pair.to_symbol_val()).unwrap();
    let pair_bytes: &[u8] = pair_str.as_ref();
    let mut pair_buf = [0u8; 9];
    pair_buf[..pair_bytes.len()].copy_from_slice(pair_bytes);

    let mut wallet_buf = [0u8; 56];
    wallet.to_string().copy_into_slice(&mut wallet_buf);

    let mut contract_buf = [0u8; 56];
    contract_addr.to_string().copy_into_slice(&mut contract_buf);

    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&wallet_buf);
    preimage.extend_from_array(&pair_buf);
    preimage.extend_from_array(&score.to_le_bytes());
    preimage.push_back(0u8); // benford_flag
    preimage.push_back(0u8); // ml_flag
    preimage.extend_from_array(&ts.to_le_bytes());
    preimage.extend_from_array(&90u32.to_le_bytes()); // confidence
    preimage.extend_from_array(&1u32.to_le_bytes()); // model_version
    preimage.extend_from_array(&contract_buf);
    preimage.extend_from_array(&env.ledger().network_id().to_array());
    preimage.extend_from_array(&[0u8; 32]); // contract_id (zeroed for batch entries)
    preimage.extend_from_array(&0u32.to_le_bytes()); // contract_version (zeroed for batch entries)

    env.crypto().sha256(&preimage).to_bytes().to_array()
}

fn merkle_leaf(env: &Env, commitment_bytes: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 33];
    preimage[0] = 0x00;
    preimage[1..33].copy_from_slice(commitment_bytes);
    env.crypto().sha256(&Bytes::from_array(env, &preimage)).to_bytes().to_array()
}

fn merkle_internal(env: &Env, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 65];
    preimage[0] = 0x01;
    preimage[1..33].copy_from_slice(left);
    preimage[33..65].copy_from_slice(right);
    env.crypto().sha256(&Bytes::from_array(env, &preimage)).to_bytes().to_array()
}

fn build_merkle_root(env: &Env, leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut current_level: std::vec::Vec<[u8; 32]> = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            next_level.push(merkle_internal(env, &current_level[i], &current_level[i + 1]));
            i += 2;
        }
        current_level = next_level;
    }
    current_level[0]
}

fn build_merkle_proof(
    env: &Env,
    leaves: &[[u8; 32]],
    index: u32,
) -> (std::vec::Vec<[u8; 32]>, u32) {
    let mut current_level: std::vec::Vec<[u8; 32]> = leaves.to_vec();
    let mut proof: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
    let mut flags: u32 = 0;
    let mut idx = index as usize;
    while current_level.len() > 1 {
        let sibling_idx = idx ^ 1;
        let sibling_on_left = (idx & 1) == 1;
        if sibling_on_left {
            flags |= 1 << proof.len();
        }
        proof.push(current_level[sibling_idx]);
        let mut next_level: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            next_level.push(merkle_internal(env, &current_level[i], &current_level[i + 1]));
            i += 2;
        }
        current_level = next_level;
        idx /= 2;
    }
    (proof, flags)
}

fn attest(env: &Env, key: &SigningKey, root: &[u8; 32]) -> BatchAttestation {
    let verified_digest = env.crypto().sha256(&Bytes::from_array(env, root)).to_bytes().to_array();
    let (sig, recid) = key.sign_prehash_recoverable(&verified_digest).unwrap();
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = recid.to_byte();
    BatchAttestation {
        merkle_root: BytesN::from_array(env, root),
        signature: BytesN::from_array(env, &sig_bytes),
    }
}

fn next_pow2(n: u32) -> u32 {
    let mut p = 1u32;
    while p < n {
        p *= 2;
    }
    p
}

fn setup(env: &Env) -> (ScoreGateScoreContractClient<'_>, Symbol, SigningKey) {
    env.mock_all_auths();
    env.budget().reset_unlimited();
    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let service = Address::generate(env);
    client.initialize(&admin, &service);

    let key = signing_key(1);
    client.set_service_pubkey(&Vec::new(env), &pubkey_bytes(env, &key));

    let asset_pair = Symbol::new(env, "XLM_USDC");
    (client, asset_pair, key)
}

/// Builds one chunk's worth (<= `MAX_BATCH`) of attested submissions,
/// padding the Merkle tree to the next power of two by tail-duplication
/// exactly as a real off-chain pipeline would (`docs/batch-attestation-spec.md`
/// §4) -- padding leaves are never submitted/proven, only used to complete
/// the tree shape.
fn build_chunk(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    asset_pair: &Symbol,
    key: &SigningKey,
    count: u32,
    batch_index: u32,
) -> (Vec<ScoreSubmissionWithProof>, BatchAttestation) {
    let padded = next_pow2(count) as usize;

    let mut submissions_vec: std::vec::Vec<ScoreSubmission> = std::vec::Vec::new();
    let mut leaves: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();

    for i in 0..count {
        let wallet = Address::generate(env);
        let score = 30 + ((batch_index + i) % 50);
        let ts = 1_700_000_000u64 + (batch_index as u64) * 10_000 + i as u64;
        let c = commitment(env, &client.address, &wallet, asset_pair, score, ts);
        submissions_vec.push(ScoreSubmission {
            wallet,
            asset_pair: asset_pair.clone(),
            score,
            benford_flag: false,
            ml_flag: false,
            timestamp: ts,
            confidence: 90,
            model_version: 1,
        });
        leaves.push(merkle_leaf(env, &c));
    }
    while leaves.len() < padded {
        let last = *leaves.last().unwrap();
        leaves.push(last);
    }

    let root = build_merkle_root(env, &leaves);
    let attestation = attest(env, key, &root);

    let mut submissions: Vec<ScoreSubmissionWithProof> = Vec::new(env);
    for (i, sub) in submissions_vec.into_iter().enumerate() {
        let (proof_bytes, flags) = build_merkle_proof(env, &leaves, i as u32);
        let mut proof: Vec<BytesN<32>> = Vec::new(env);
        for p in proof_bytes {
            proof.push_back(BytesN::from_array(env, &p));
        }
        submissions.push_back(ScoreSubmissionWithProof {
            submission: sub,
            proof,
            proof_flags: flags,
        });
    }

    (submissions, attestation)
}

/// Builds every chunk's Merkle tree/signature up front (off-chain work in
/// the real world, not on-chain cost), then measures only the contract
/// execution cost of the `submit_scores_batch_attested` calls themselves.
fn submit_n_entries(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    asset_pair: &Symbol,
    key: &SigningKey,
    total: u32,
) -> (u64, u64) {
    let mut remaining = total;
    let mut batch_index = 0u32;
    let mut chunks: std::vec::Vec<(Vec<ScoreSubmissionWithProof>, BatchAttestation)> =
        std::vec::Vec::new();
    while remaining > 0 {
        let chunk = remaining.min(MAX_BATCH);
        chunks.push(build_chunk(env, client, asset_pair, key, chunk, batch_index));
        remaining -= chunk;
        batch_index += 1;
    }

    // The benchmark aggregates multiple contract calls; keep the cost
    // tracker active without imposing a single-call host budget ceiling.
    env.budget().reset_unlimited();
    env.budget().reset_tracker();

    for (submissions, attestation) in chunks {
        black_box(client.submit_scores_batch_attested(&Vec::new(env), &submissions, &attestation));
        env.ledger().with_mut(|l| l.timestamp += 3_601);
    }

    (env.budget().cpu_instruction_cost(), env.budget().memory_bytes_cost())
}

fn bench_batch_attested(c: &mut Criterion) {
    let mut group = c.benchmark_group("submit_scores_batch_attested");
    group.sample_size(10);

    for size in [1u32, 10, 50, 100] {
        group.bench_with_input(BenchmarkId::new("entries", size), &size, |b, &size| {
            b.iter(|| {
                let env = Env::default();
                let (client, asset_pair, key) = setup(&env);
                black_box(submit_n_entries(&env, &client, &asset_pair, &key, size))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_batch_attested);
criterion_main!(benches);
