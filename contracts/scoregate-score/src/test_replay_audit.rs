//! Comprehensive replay protection audit tests for consensus commit-reveal
//! and finality-buffer pending score mechanisms.

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

use crate::{
    Error, ScoreGateScoreContract, ScoreGateScoreContractClient, MaybeScoreAttestation,
    MaybeThresholdAttestation, ModelSubmission, ScoreAttestation, ScoreAttestationInput,
};

const START_TS: u64 = 1_000_000;

fn setup<'a>() -> (Env, ScoreGateScoreContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    env.budget().reset_unlimited();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    env.ledger().with_mut(|l| l.timestamp = START_TS);
    client.initialize(&admin, &service);
    // Set consensus threshold k=1 so a single model submission reaches consensus
    client.set_consensus_config(&1, &10);

    (env, client)
}

fn dummy_submission(env: &Env, model: &Address, score: u32) -> ModelSubmission {
    ModelSubmission {
        model: model.clone(),
        score,
        confidence: 80,
        benford_flag: false,
        ml_flag: false,
        model_version: 1,
        attestation: ScoreAttestation {
            commitment: BytesN::from_array(env, &[0u8; 32]),
            signature: BytesN::from_array(env, &[0u8; 65]),
            contract_id: BytesN::from_array(env, &[0u8; 32]),
            contract_version: 1,
            nonce: 0,
        },
    }
}

// ── Scenario 1: Replaying in a later reveal window or twice ─────────────────

#[test]
fn test_replay_consensus_twice_fails() {
    let (env, client) = setup();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let model = Address::generate(&env);

    let sub = dummy_submission(&env, &model, 70);

    let nonce = 12345u64;
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&sub.score.to_be_bytes());
    buf[4..12].copy_from_slice(&nonce.to_be_bytes());
    let hash = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf));

    client.commit_consensus(&model, &wallet, &pair, &hash.to_bytes());

    let mut submissions = Vec::new(&env);
    submissions.push_back(sub);
    let mut nonces = Vec::new(&env);
    nonces.push_back(nonce);

    // First reveal succeeds
    client.reveal_consensus(&Vec::new(&env), &wallet, &pair, &submissions, &nonces, &START_TS);

    // Second reveal (replay) fails with RevealWindowExpired because commitment was removed
    let res = client.try_reveal_consensus(
        &Vec::new(&env),
        &wallet,
        &pair,
        &submissions,
        &nonces,
        &START_TS,
    );
    assert_eq!(res, Err(Ok(Error::RevealWindowExpired)));
}

#[test]
fn test_replay_consensus_old_commitment_in_new_window_fails() {
    let (env, client) = setup();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let model = Address::generate(&env);

    // Old submission score 70, nonce 100
    let sub_old = dummy_submission(&env, &model, 70);
    let nonce_old = 100u64;

    // New submission score 80, nonce 200
    let sub_new = dummy_submission(&env, &model, 80);
    let nonce_new = 200u64;

    // Commit new submission hash in new window
    let mut buf_new = [0u8; 12];
    buf_new[0..4].copy_from_slice(&sub_new.score.to_be_bytes());
    buf_new[4..12].copy_from_slice(&nonce_new.to_be_bytes());
    let hash_new = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf_new));
    client.commit_consensus(&model, &wallet, &pair, &hash_new.to_bytes());

    // Attacker attempts to reveal using old submission & old nonce against new commitment
    let mut submissions_old = Vec::new(&env);
    submissions_old.push_back(sub_old);
    let mut nonces_old = Vec::new(&env);
    nonces_old.push_back(nonce_old);

    let res = client.try_reveal_consensus(
        &Vec::new(&env),
        &wallet,
        &pair,
        &submissions_old,
        &nonces_old,
        &START_TS,
    );
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
}

#[test]
fn test_replay_consensus_after_reveal_window_closed_fails() {
    let (env, client) = setup();

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let model = Address::generate(&env);

    let sub = dummy_submission(&env, &model, 70);
    let nonce = 12345u64;
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&sub.score.to_be_bytes());
    buf[4..12].copy_from_slice(&nonce.to_be_bytes());
    let hash = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf));

    client.commit_consensus(&model, &wallet, &pair, &hash.to_bytes());

    // Fast forward ledger sequence / time past reveal window (default 3600 seconds, 720 ledgers)
    env.ledger().with_mut(|l| {
        l.timestamp += 3601;
        l.sequence_number += 1000;
    });

    let mut submissions = Vec::new(&env);
    submissions.push_back(sub);
    let mut nonces = Vec::new(&env);
    nonces.push_back(nonce);

    let res = client.try_reveal_consensus(
        &Vec::new(&env),
        &wallet,
        &pair,
        &submissions,
        &nonces,
        &START_TS,
    );
    assert_eq!(res, Err(Ok(Error::RevealWindowExpired)));
}

#[test]
fn test_replay_pending_score_twice_fails() {
    let (env, client) = setup();
    client.set_finality_buffer(&Vec::new(&env), &300);

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    // submit score to finality buffer
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &true,
        &false,
        &START_TS,
        &85,
        &1,
        &None,
    );

    // Fast forward past finality buffer window
    env.ledger().with_mut(|l| l.timestamp = START_TS + 300);

    // First commit succeeds
    client.commit_pending_score(&wallet, &pair);
    assert_eq!(client.get_score(&wallet, &pair).score, 50);

    // Replaying commit_pending_score fails with NoPendingScore
    let res = client.try_commit_pending_score(&wallet, &pair);
    assert_eq!(res, Err(Ok(Error::NoPendingScore)));
}

// ── Scenario 2: Replaying against a different asset pair ────────────────────

#[test]
fn test_replay_consensus_different_asset_pair_fails() {
    let (env, client) = setup();

    let wallet = Address::generate(&env);
    let pair_a = symbol_short!("XLM_USDC");
    let pair_b = symbol_short!("BTC_USDC");
    let model = Address::generate(&env);

    let sub_a = dummy_submission(&env, &model, 70);
    let nonce_a = 12345u64;
    let mut buf_a = [0u8; 12];
    buf_a[0..4].copy_from_slice(&sub_a.score.to_be_bytes());
    buf_a[4..12].copy_from_slice(&nonce_a.to_be_bytes());
    let hash_a = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf_a));

    let sub_b = dummy_submission(&env, &model, 85);
    let nonce_b = 67890u64;
    let mut buf_b = [0u8; 12];
    buf_b[0..4].copy_from_slice(&sub_b.score.to_be_bytes());
    buf_b[4..12].copy_from_slice(&nonce_b.to_be_bytes());
    let hash_b = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf_b));

    // Valid commitments registered for both pair_a and pair_b
    client.commit_consensus(&model, &wallet, &pair_a, &hash_a.to_bytes());
    client.commit_consensus(&model, &wallet, &pair_b, &hash_b.to_bytes());

    let mut submissions_a = Vec::new(&env);
    submissions_a.push_back(sub_a);
    let mut nonces_a = Vec::new(&env);
    nonces_a.push_back(nonce_a);

    // Adversarial attempt: try to satisfy pair_b's active reveal using pair_a's score/nonce/hash
    let res = client.try_reveal_consensus(
        &Vec::new(&env),
        &wallet,
        &pair_b,
        &submissions_a,
        &nonces_a,
        &START_TS,
    );
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
}

#[test]
fn test_replay_pending_score_different_asset_pair_fails() {
    let (env, client) = setup();
    client.set_finality_buffer(&Vec::new(&env), &300);

    let wallet = Address::generate(&env);
    let pair_a = symbol_short!("XLM_USDC");
    let pair_b = symbol_short!("BTC_USDC");

    // Valid pending scores submitted for both pair_a (score=50) and pair_b (score=90)
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair_a,
        &50,
        &true,
        &false,
        &START_TS,
        &85,
        &1,
        &None,
    );

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair_b,
        &90,
        &true,
        &false,
        &START_TS,
        &95,
        &1,
        &None,
    );

    env.ledger().with_mut(|l| l.timestamp = START_TS + 300);

    // Committing pending score for pair_b processes pair_b's pending score (90), not pair_a's (50)
    client.commit_pending_score(&wallet, &pair_b);
    assert_eq!(client.get_score(&wallet, &pair_b).score, 90);

    // pair_a's pending score remains uncommitted until committed for pair_a
    assert_eq!(client.get_pending_score(&wallet, &pair_a).unwrap().score, 50);
}

// ── Scenario 3: Cross-mechanism replay ───────────────────────────────────────

#[test]
fn test_replay_consensus_commitment_into_pending_score_fails() {
    let (env, client) = setup();
    client.set_finality_buffer(&Vec::new(&env), &300);

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let model = Address::generate(&env);

    // 1. Model commits score=90 via commit_consensus
    let sub_consensus = dummy_submission(&env, &model, 90);
    let nonce_consensus = 12345u64;
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&sub_consensus.score.to_be_bytes());
    buf[4..12].copy_from_slice(&nonce_consensus.to_be_bytes());
    let hash_consensus = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf));
    client.commit_consensus(&model, &wallet, &pair, &hash_consensus.to_bytes());

    // 2. Service submits score=50 to finality buffer carrying the consensus hash
    let att_input_1 = ScoreAttestationInput {
        attestation: MaybeScoreAttestation::None,
        threshold_attestation: MaybeThresholdAttestation::None,
        commitment: Some(soroban_sdk::Bytes::from_array(
            &env,
            &hash_consensus.to_bytes().to_array(),
        )),
    };

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &true,
        &false,
        &START_TS,
        &85,
        &1,
        &Some(att_input_1),
    );

    env.ledger().with_mut(|l| l.timestamp = START_TS + 300);

    // Adversarial attempt: call commit_pending_score expecting it might commit the consensus score (90)
    client.commit_pending_score(&wallet, &pair);

    // Verify commit_pending_score committed the pending score (50), NOT the consensus score (90)
    assert_eq!(client.get_score(&wallet, &pair).score, 50);

    // Verify consensus commitment is intact in temporary storage and unaffected by commit_pending_score
    assert!(client.get_pending_score(&wallet, &pair).is_none());
}

#[test]
fn test_replay_pending_score_into_consensus_reveal_fails() {
    let (env, client) = setup();
    client.set_finality_buffer(&Vec::new(&env), &300);

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let model = Address::generate(&env);

    // 1. Submit score=50 into finality buffer with commitment hash_pending
    let nonce_pending = 11111u64;
    let sub_pending = dummy_submission(&env, &model, 50);
    let mut buf_p = [0u8; 12];
    buf_p[0..4].copy_from_slice(&sub_pending.score.to_be_bytes());
    buf_p[4..12].copy_from_slice(&nonce_pending.to_be_bytes());
    let hash_pending = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf_p));

    let att_input_2 = ScoreAttestationInput {
        attestation: MaybeScoreAttestation::None,
        threshold_attestation: MaybeThresholdAttestation::None,
        commitment: Some(soroban_sdk::Bytes::from_array(&env, &hash_pending.to_bytes().to_array())),
    };

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &true,
        &false,
        &START_TS,
        &85,
        &1,
        &Some(att_input_2),
    );

    // 2. Model commits score=90 via commit_consensus
    let nonce_consensus = 99999u64;
    let sub_consensus = dummy_submission(&env, &model, 90);
    let mut buf_c = [0u8; 12];
    buf_c[0..4].copy_from_slice(&sub_consensus.score.to_be_bytes());
    buf_c[4..12].copy_from_slice(&nonce_consensus.to_be_bytes());
    let hash_consensus = env.crypto().sha256(&soroban_sdk::Bytes::from_array(&env, &buf_c));
    client.commit_consensus(&model, &wallet, &pair, &hash_consensus.to_bytes());

    // Adversarial attempt: try to reveal consensus using the pending score payload (score=50, nonce_pending)
    let mut submissions_pending = Vec::new(&env);
    submissions_pending.push_back(sub_pending);
    let mut nonces_pending = Vec::new(&env);
    nonces_pending.push_back(nonce_pending);

    let res = client.try_reveal_consensus(
        &Vec::new(&env),
        &wallet,
        &pair,
        &submissions_pending,
        &nonces_pending,
        &START_TS,
    );
    assert_eq!(res, Err(Ok(Error::CommitmentMismatch)));
}
