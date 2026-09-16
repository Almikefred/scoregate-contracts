//! Tests for the Verkle / KZG polynomial commitment system.
//!
//! Covers:
//! * `get_state_commitment` — initial zero state, changes after each write.
//! * `get_membership_proof` + `verify_membership` — inclusion proofs.
//! * Non-membership proofs for wallets/pairs with no score.
//! * Commitment update correctness: adding, updating, and multiple entries.
//! * Tamper-resistance: wrong score, wrong wallet, wrong pair → verify fails.
//! * Batch path (`submit_scores_batch`) updates commitment identically.

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, Symbol, SymbolStr, TryFromVal, Vec,
};

use crate::{verkle, ScoreGateScoreContract, ScoreGateScoreContractClient, ScoreSubmission};

// ── Test infrastructure ──────────────────────────────────────────────────────

fn setup<'a>() -> (Env, ScoreGateScoreContractClient<'a>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    (env, client, admin, service)
}

fn initialized<'a>() -> (Env, ScoreGateScoreContractClient<'a>, Address, Address) {
    let (env, client, admin, service) = setup();
    client.initialize(&admin, &service);
    (env, client, admin, service)
}

/// `Bytes` has no fixed-size array conversion; unpack the 97-byte proof
/// payload manually for byte-level assertions in these tests.
fn proof_to_array(proof: &Bytes) -> [u8; 97] {
    let mut arr = [0u8; 97];
    for i in 0..97u32 {
        arr[i as usize] = proof.get(i).unwrap();
    }
    arr
}

// ── Commitment structure tests ───────────────────────────────────────────────

#[test]
fn commitment_is_48_bytes_from_the_start() {
    let (_env, client, admin, service) = initialized();
    let c = client.get_state_commitment();
    assert_eq!(c.len(), 48, "commitment must be exactly 48 bytes");
}

#[test]
fn commitment_has_protocol_prefix() {
    let (env, client, admin, service) = initialized();
    let c = client.get_state_commitment();
    let arr = c.to_array();
    // First 16 bytes = b"SCOREGATE_KZG_V1"
    let expected_prefix = b"SCOREGATE_KZG_V1";
    assert_eq!(
        &arr[..16],
        expected_prefix,
        "commitment must carry the SCOREGATE_KZG_V1 protocol prefix"
    );
}

#[test]
fn commitment_changes_after_score_write() {
    let (env, client, admin, service) = initialized();

    let before = client.get_state_commitment();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");
    client.submit_score(&Vec::new(&env), &wallet, &pair, &50, &false, &false, &1, &90, &1, &None);

    let after = client.get_state_commitment();
    assert_ne!(before.to_array(), after.to_array(), "commitment must change after a score write");
}

#[test]
fn commitment_changes_on_score_update() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &30, &false, &false, &1, &80, &1, &None);
    let c1 = client.get_state_commitment();

    // Advance past cooldown.
    env.ledger().with_mut(|l| l.timestamp += 3_601);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &70,
        &false,
        &false,
        &3_602,
        &90,
        &1,
        &None,
    );
    let c2 = client.get_state_commitment();

    assert_ne!(c1.to_array(), c2.to_array(), "commitment must change when a score is updated");
}

// ── Membership proof tests ───────────────────────────────────────────────────

#[test]
fn membership_proof_is_97_bytes() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");
    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let proof = client.get_membership_proof(&wallet, &pair);
    assert_eq!(proof.len(), 97, "proof must be exactly 97 bytes");
}

#[test]
fn membership_proof_type_byte_is_member() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");
    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let proof = client.get_membership_proof(&wallet, &pair);
    let arr = proof_to_array(&proof);
    assert_eq!(arr[0], 0x01, "proof type byte must be 0x01 (member)");
}

#[test]
fn verify_membership_returns_true_for_valid_proof() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");
    let score: u32 = 42;

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &None,
    );

    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);
    let timestamp = client.get_score(&wallet, &pair).timestamp;

    // Membership proof must verify with the correct score.
    assert!(
        client.verify_membership(&commitment, &wallet, &pair, &score, &timestamp, &proof),
        "valid membership proof must verify"
    );
}

#[test]
fn verify_membership_fails_for_wrong_score() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);
    let timestamp = client.get_score(&wallet, &pair).timestamp;

    // Wrong score with the correct timestamp must fail: v is bound to
    // (score, timestamp), so a mismatched score changes the recomputed v.
    assert!(
        !client.verify_membership(&commitment, &wallet, &pair, &99, &timestamp, &proof),
        "proof must not verify for a different score"
    );

    // Wrong wallet must also fail (key binding via z).
    let wrong_wallet = Address::generate(&env);
    assert!(
        !client.verify_membership(&commitment, &wrong_wallet, &pair, &42, &timestamp, &proof),
        "proof must not verify for a different wallet"
    );
}

#[test]
fn verify_membership_fails_for_wrong_pair() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");
    let other_pair = symbol_short!("BTC_USDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);
    let timestamp = client.get_score(&wallet, &pair).timestamp;

    assert!(
        !client.verify_membership(&commitment, &wallet, &other_pair, &42, &timestamp, &proof),
        "proof must not verify for a different asset pair"
    );
}

#[test]
fn verify_membership_fails_for_tampered_proof() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);
    let timestamp = client.get_score(&wallet, &pair).timestamp;

    // Flip the last byte of the witness.
    let mut arr = proof_to_array(&proof);
    arr[96] ^= 0xFF;
    let tampered = Bytes::from_array(&env, &arr);

    assert!(
        !client.verify_membership(&commitment, &wallet, &pair, &42, &timestamp, &tampered),
        "tampered proof witness must not verify"
    );
}

#[test]
fn verify_membership_fails_for_stale_commitment() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    // Snapshot commitment and proof BEFORE the update.
    let old_commitment = client.get_state_commitment();
    let old_proof = client.get_membership_proof(&wallet, &pair);
    let old_timestamp = client.get_score(&wallet, &pair).timestamp;

    // Update the score (past cooldown).
    env.ledger().with_mut(|l| l.timestamp += 3_601);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &75,
        &false,
        &false,
        &3_602,
        &90,
        &1,
        &None,
    );

    // A new proof against the new commitment should work.
    let new_commitment = client.get_state_commitment();
    let new_proof = client.get_membership_proof(&wallet, &pair);
    let new_timestamp = client.get_score(&wallet, &pair).timestamp;
    assert!(client.verify_membership(
        &new_commitment,
        &wallet,
        &pair,
        &75,
        &new_timestamp,
        &new_proof
    ));

    // Old proof against new commitment must fail (commitment changed).
    assert!(
        !client.verify_membership(&new_commitment, &wallet, &pair, &42, &old_timestamp, &old_proof),
        "old proof must not verify against new commitment"
    );

    // Old proof against old commitment still verifies (snapshot integrity).
    assert!(
        client.verify_membership(&old_commitment, &wallet, &pair, &42, &old_timestamp, &old_proof),
        "old proof must still verify against the old commitment snapshot"
    );
}

// ── Non-membership proof tests ───────────────────────────────────────────────

#[test]
fn nonmember_proof_type_byte_is_nonmember() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    // No score submitted — wallet has no entry.
    let proof = client.get_membership_proof(&wallet, &pair);
    assert_eq!(proof.len(), 97);
    let arr = proof_to_array(&proof);
    assert_eq!(arr[0], 0x02, "proof type byte must be 0x02 (non-member)");
}

#[test]
fn nonmember_proof_v_is_all_zeros() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    let proof = client.get_membership_proof(&wallet, &pair);
    let arr = proof_to_array(&proof);
    // v occupies bytes [33..65] — must be all-zeros sentinel.
    assert_eq!(&arr[33..65], &[0u8; 32], "non-member proof v must be the all-zeros sentinel");
}

#[test]
fn verify_membership_with_score_zero_accepts_nonmember_proof() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    // No score — get non-membership proof.
    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);

    assert!(
        client.verify_membership(&commitment, &wallet, &pair, &0, &0, &proof),
        "non-membership proof must verify when score=0"
    );
}

#[test]
fn verify_membership_with_nonzero_score_rejects_nonmember_proof() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    let commitment = client.get_state_commitment();
    let proof = client.get_membership_proof(&wallet, &pair);

    // Passing a non-zero score with a non-member proof must fail.
    assert!(
        !client.verify_membership(&commitment, &wallet, &pair, &1, &0, &proof),
        "non-membership proof must not accept non-zero score"
    );
}

#[test]
fn nonmember_proof_fails_for_different_wallet() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let other_wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    let commitment = client.get_state_commitment();
    // Proof for wallet
    let proof = client.get_membership_proof(&wallet, &pair);

    // Presenting wallet's non-member proof as proof for other_wallet must fail.
    assert!(
        !client.verify_membership(&commitment, &other_wallet, &pair, &0, &0, &proof),
        "non-member proof must not verify for a different wallet"
    );
}

// ── Multiple entries tests ───────────────────────────────────────────────────

#[test]
fn commitment_reflects_multiple_independent_entries() {
    let (env, client, admin, service) = initialized();

    let pair = symbol_short!("XLMUSDC");
    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);

    client.submit_score(&Vec::new(&env), &wallet_a, &pair, &20, &false, &false, &1, &80, &1, &None);
    let c1 = client.get_state_commitment();

    client.submit_score(&Vec::new(&env), &wallet_b, &pair, &80, &true, &false, &2, &90, &1, &None);
    let c2 = client.get_state_commitment();

    // Commitment must have changed again.
    assert_ne!(c1.to_array(), c2.to_array());

    // Both wallets must produce valid membership proofs against c2.
    let proof_a = client.get_membership_proof(&wallet_a, &pair);
    let proof_b = client.get_membership_proof(&wallet_b, &pair);
    let timestamp_a = client.get_score(&wallet_a, &pair).timestamp;
    let timestamp_b = client.get_score(&wallet_b, &pair).timestamp;

    assert!(
        client.verify_membership(&c2, &wallet_a, &pair, &20, &timestamp_a, &proof_a),
        "wallet_a membership proof must verify against latest commitment"
    );
    assert!(
        client.verify_membership(&c2, &wallet_b, &pair, &80, &timestamp_b, &proof_b),
        "wallet_b membership proof must verify against latest commitment"
    );
}

#[test]
fn nonmember_proof_for_unknown_pair_works_alongside_known_entries() {
    let (env, client, admin, service) = initialized();

    let pair = symbol_short!("XLMUSDC");
    let absent_pair = symbol_short!("ETH_USDC");
    let wallet = Address::generate(&env);

    client.submit_score(&Vec::new(&env), &wallet, &pair, &55, &false, &false, &1, &85, &1, &None);

    let commitment = client.get_state_commitment();

    // Non-member proof for the absent pair.
    let proof = client.get_membership_proof(&wallet, &absent_pair);
    let arr = proof_to_array(&proof);
    assert_eq!(arr[0], 0x02, "should be non-member proof");

    assert!(
        client.verify_membership(&commitment, &wallet, &absent_pair, &0, &0, &proof),
        "non-member proof for absent pair must verify"
    );

    // The existing pair's membership proof must still hold.
    let member_proof = client.get_membership_proof(&wallet, &pair);
    let member_timestamp = client.get_score(&wallet, &pair).timestamp;
    assert!(
        client.verify_membership(
            &commitment,
            &wallet,
            &pair,
            &55,
            &member_timestamp,
            &member_proof
        ),
        "member proof must still verify alongside non-member proof"
    );
}

// ── Batch submission path tests ──────────────────────────────────────────────

#[test]
fn batch_submission_updates_commitment() {
    let (env, client, admin, service) = initialized();

    let pair = symbol_short!("XLMUSDC");
    let wallet1 = Address::generate(&env);
    let wallet2 = Address::generate(&env);

    let before = client.get_state_commitment();

    let mut batch = Vec::new(&env);
    batch.push_back(ScoreSubmission {
        wallet: wallet1.clone(),
        asset_pair: pair.clone(),
        score: 30,
        benford_flag: false,
        ml_flag: false,
        timestamp: 100,
        confidence: 80,
        model_version: 1,
    });
    batch.push_back(ScoreSubmission {
        wallet: wallet2.clone(),
        asset_pair: pair.clone(),
        score: 70,
        benford_flag: true,
        ml_flag: false,
        timestamp: 200,
        confidence: 90,
        model_version: 1,
    });

    let result = client.submit_scores_batch(&batch);
    assert_eq!(result.accepted_count, 2);

    let after = client.get_state_commitment();
    assert_ne!(before.to_array(), after.to_array(), "batch must update commitment");

    // Both entries must be provable.
    let proof1 = client.get_membership_proof(&wallet1, &pair);
    let proof2 = client.get_membership_proof(&wallet2, &pair);
    let timestamp1 = client.get_score(&wallet1, &pair).timestamp;
    let timestamp2 = client.get_score(&wallet2, &pair).timestamp;

    assert!(client.verify_membership(&after, &wallet1, &pair, &30, &timestamp1, &proof1));
    assert!(client.verify_membership(&after, &wallet2, &pair, &70, &timestamp2, &proof2));
}

// ── Proof format edge cases ──────────────────────────────────────────────────

#[test]
fn verify_membership_returns_false_for_empty_proof() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let commitment = client.get_state_commitment();
    let timestamp = client.get_score(&wallet, &pair).timestamp;
    let empty = Bytes::new(&env);

    assert!(
        !client.verify_membership(&commitment, &wallet, &pair, &42, &timestamp, &empty),
        "empty proof bytes must not verify"
    );
}

#[test]
fn verify_membership_returns_false_for_wrong_commitment_prefix() {
    let (env, client, admin, service) = initialized();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &42, &false, &false, &1, &90, &1, &None);

    let proof = client.get_membership_proof(&wallet, &pair);
    let commitment = client.get_state_commitment();
    let timestamp = client.get_score(&wallet, &pair).timestamp;

    // Corrupt the prefix of the commitment.
    let mut arr = commitment.to_array();
    arr[0] ^= 0xFF;
    let bad_commitment = BytesN::<48>::from_array(&env, &arr);

    assert!(
        !client.verify_membership(&bad_commitment, &wallet, &pair, &42, &timestamp, &proof),
        "corrupt commitment prefix must cause verify to return false"
    );
}

// ── Range proof helper (off-chain pattern) ───────────────────────────────────
//
// Range proofs are validated off-chain by collecting per-entry membership
// proofs and checking each. We demonstrate the pattern in-test to verify
// the API contract: "all scores for pair P with wallet_a and wallet_b are < 80".

#[test]
fn range_proof_all_scores_below_80() {
    let (env, client, admin, service) = initialized();

    let pair = symbol_short!("XLMUSDC");
    let wallets = [Address::generate(&env), Address::generate(&env), Address::generate(&env)];
    let scores = [10u32, 45u32, 79u32];

    for (w, s) in wallets.iter().zip(scores.iter()) {
        client.submit_score(&Vec::new(&env), w, &pair, s, &false, &false, &1, &80, &1, &None);
        // Advance past cooldown so each submission is accepted.
        env.ledger().with_mut(|l| l.timestamp += 3_601);
    }

    let commitment = client.get_state_commitment();

    // Collect and verify all membership proofs; check score bound.
    let mut all_below_80 = true;
    for (w, _s) in wallets.iter().zip(scores.iter()) {
        let proof = client.get_membership_proof(w, &pair);
        let arr = proof_to_array(&proof);
        assert_eq!(arr[0], 0x01, "expected member proof for each wallet");

        // True range check: verify with each score value — all must pass
        // for each wallet, and each known score must be < 80.
        let actual_score_entry = client.get_score(w, &pair);
        assert!(actual_score_entry.score < 80, "all scores in the range proof must be below 80");
        // Membership proof is valid.
        assert!(
            client.verify_membership(
                &commitment,
                w,
                &pair,
                &actual_score_entry.score,
                &actual_score_entry.timestamp,
                &proof
            ),
            "membership proof must verify for range proof participant"
        );

        if actual_score_entry.score >= 80 {
            all_below_80 = false;
        }
    }

    assert!(all_below_80, "range claim 'all < 80' must hold");
}

// ── Differential commitment recomputation tests ─────────────────────────────
//
// The reference recomputation scans all live leaves and computes the
// commitment as H(DOMAIN_COMMIT || xor_of_all_leaves) — a single hash pass
// that is independent of the incremental update code path.  If the
// incrementally-maintained commitment ever drifts from this reference, the
// test catches it.

fn compute_leaf(
    env: &Env,
    wallet: &Address,
    pair: &Symbol,
    score: u32,
    timestamp: u64,
) -> [u8; 32] {
    let mut wallet_buf = [0u8; 56];
    wallet.to_string().copy_into_slice(&mut wallet_buf);

    let pair_str = SymbolStr::try_from_val(env, &pair.to_symbol_val()).unwrap();
    let pair_bytes_ref: &[u8] = pair_str.as_ref();
    let mut pair_buf = [0u8; 9];
    let len = pair_bytes_ref.len().min(9);
    pair_buf[..len].copy_from_slice(&pair_bytes_ref[..len]);

    let z = verkle::derive_evaluation_point(env, &wallet_buf, &pair_buf);
    let v = verkle::derive_value_element(env, score, timestamp, &z);
    verkle::hash_leaf(env, &z, &v)
}

fn reference_commitment(env: &Env, leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for leaf in leaves {
        for i in 0..32 {
            acc[i] ^= leaf[i];
        }
    }
    let mut buf = [0u8; 33];
    buf[0] = 0x06;
    buf[1..33].copy_from_slice(&acc);
    env.crypto().sha256(&Bytes::from_array(env, &buf)).to_bytes().to_array()
}

fn raw_commitment(env: &Env, client: &ScoreGateScoreContractClient) -> [u8; 32] {
    let b48 = client.get_state_commitment();
    let arr = b48.to_array();
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&arr[16..48]);
    raw
}

#[test]
fn differential_single_entry() {
    let (env, client, admin, service) = initialized();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &50, &false, &false, &1, &90, &1, &None);

    let leaf = compute_leaf(&env, &wallet, &pair, 50, 1);
    let expected = reference_commitment(&env, &[leaf]);
    let actual = raw_commitment(&env, &client);
    assert_eq!(expected, actual, "single-entry commitment must match reference recomputation");
}

#[test]
fn differential_multiple_entries() {
    let (env, client, admin, service) = initialized();
    let pair = symbol_short!("XLMUSDC");
    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);

    client.submit_score(&Vec::new(&env), &wallet_a, &pair, &20, &false, &false, &1, &80, &1, &None);
    let leaf_a = compute_leaf(&env, &wallet_a, &pair, 20, 1);

    client.submit_score(&Vec::new(&env), &wallet_b, &pair, &80, &true, &false, &2, &90, &1, &None);
    let leaf_b = compute_leaf(&env, &wallet_b, &pair, 80, 2);

    let expected = reference_commitment(&env, &[leaf_a, leaf_b]);
    let actual = raw_commitment(&env, &client);
    assert_eq!(expected, actual, "two-entry commitment must match reference recomputation");
}

#[test]
fn differential_after_update() {
    let (env, client, admin, service) = initialized();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLMUSDC");

    client.submit_score(&Vec::new(&env), &wallet, &pair, &30, &false, &false, &1, &80, &1, &None);
    let leaf_old = compute_leaf(&env, &wallet, &pair, 30, 1);

    assert_eq!(
        reference_commitment(&env, &[leaf_old]),
        raw_commitment(&env, &client),
        "commitment must match after first write"
    );

    // Advance past cooldown and update.
    env.ledger().with_mut(|l| l.timestamp += 3_601);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &70,
        &false,
        &false,
        &3_602,
        &90,
        &1,
        &None,
    );
    let leaf_new = compute_leaf(&env, &wallet, &pair, 70, 3_602);

    // After update the old leaf is gone, only the new leaf remains.
    assert_eq!(
        reference_commitment(&env, &[leaf_new]),
        raw_commitment(&env, &client),
        "commitment must match after score update (old leaf removed, new leaf added)"
    );
}

#[test]
fn differential_multiple_pairs() {
    let (env, client, admin, service) = initialized();
    let wallet = Address::generate(&env);
    let pair_a = symbol_short!("XLMUSDC");
    let pair_b = symbol_short!("ETHUSDC");

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair_a,
        &50,
        &false,
        &false,
        &10,
        &90,
        &1,
        &None,
    );
    let leaf_a = compute_leaf(&env, &wallet, &pair_a, 50, 10);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair_b,
        &30,
        &false,
        &false,
        &20,
        &85,
        &1,
        &None,
    );
    let leaf_b = compute_leaf(&env, &wallet, &pair_b, 30, 20);

    let expected = reference_commitment(&env, &[leaf_a, leaf_b]);
    let actual = raw_commitment(&env, &client);
    assert_eq!(expected, actual, "multi-pair commitment must match reference recomputation");
}

#[test]
fn differential_sequence_mixed_operations() {
    let (env, client, admin, service) = initialized();
    let wallets = [
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];
    let pair = symbol_short!("XLMUSDC");
    let mut leaves = std::vec::Vec::new();

    // Submit 5 scores, check after each.
    for (i, w) in wallets.iter().enumerate() {
        let ts = (i + 1) as u64;
        let score = (20 + i * 10) as u32;
        client.submit_score(&Vec::new(&env), w, &pair, &score, &false, &false, &ts, &85, &1, &None);
        let leaf = compute_leaf(&env, w, &pair, score, ts);
        leaves.push(leaf);

        assert_eq!(
            reference_commitment(&env, &leaves),
            raw_commitment(&env, &client),
            "commitment must match after {}-th submission",
            i + 1
        );

        // Advance past cooldown so next submission is accepted.
        env.ledger().with_mut(|l| l.timestamp += 3_601);
    }

    // Update wallet[2]'s score (remove old leaf, add new).
    env.ledger().with_mut(|l| l.timestamp += 3_601);
    let ts_update = 100u64;
    let score_update = 99u32;
    client.submit_score(
        &Vec::new(&env),
        &wallets[2],
        &pair,
        &score_update,
        &true,
        &true,
        &ts_update,
        &95,
        &2,
        &None,
    );
    let new_leaf = compute_leaf(&env, &wallets[2], &pair, score_update, ts_update);
    leaves[2] = new_leaf;

    assert_eq!(
        reference_commitment(&env, &leaves),
        raw_commitment(&env, &client),
        "commitment must match after score replacement in sequence"
    );
}
