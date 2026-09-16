//! Tests for the model version registry feature.
//!
//! Covers: register_model_version, deprecate_model_version,
//! is_model_version_active, get_model_versions, and version enforcement inside
//! submit_score / submit_scores_batch.

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Bytes, Env, Vec,
};

use crate::{
    constants::{DEFAULT_UPGRADE_DELAY_SECS, MAX_MODEL_VERSIONS},
    types::ModelVersionStatus,
    BatchResult, Error, ScoreGateScoreContract, ScoreGateScoreContractClient, ScoreSubmission,
};

const START_TS: u64 = 1_700_000_000;

fn setup<'a>() -> (Env, ScoreGateScoreContractClient<'a>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START_TS);
    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);
    (env, client, admin)
}

// ── Empty registry ────────────────────────────────────────────────────────────

#[test]
fn test_empty_registry_allows_any_version() {
    let (env, client, _) = setup();
    let wallet = Address::generate(&env);
    // With no versions registered, any model_version value must be accepted.
    let result = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &symbol_short!("XLM_USDC"),
        &42,
        &false,
        &false,
        &START_TS,
        &90,
        &999,
        &None,
    );
    assert!(result.is_ok());
    assert_eq!(client.get_score(&wallet, &symbol_short!("XLM_USDC")).model_version, 999);
}

// ── Active version ────────────────────────────────────────────────────────────

#[test]
fn test_active_version_accepted() {
    let (env, client, _) = setup();
    let wallet = Address::generate(&env);
    client.register_model_version(&Vec::new(&env), &1);
    assert!(client.is_model_version_active(&1));

    let result = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &symbol_short!("XLM_USDC"),
        &42,
        &false,
        &false,
        &START_TS,
        &90,
        &1,
        &None,
    );
    assert!(result.is_ok());
    assert_eq!(client.get_score(&wallet, &symbol_short!("XLM_USDC")).model_version, 1);
}

// ── Unregistered version ──────────────────────────────────────────────────────

#[test]
fn test_unregistered_version_rejected() {
    let (env, client, _) = setup();
    let wallet = Address::generate(&env);
    // Register only version 1 — version 2 has never been registered.
    client.register_model_version(&Vec::new(&env), &1);

    let result = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &symbol_short!("XLM_USDC"),
        &42,
        &false,
        &false,
        &START_TS,
        &90,
        &2,
        &None,
    );
    assert_eq!(result, Err(Ok(Error::ModelVersionNotRegistered)));
}

// ── Deprecated version ────────────────────────────────────────────────────────

#[test]
fn test_deprecated_version_rejected() {
    let (env, client, _) = setup();
    let wallet = Address::generate(&env);
    client.register_model_version(&Vec::new(&env), &1);
    client.deprecate_model_version(&Vec::new(&env), &1);
    assert!(!client.is_model_version_active(&1));

    let result = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &symbol_short!("XLM_USDC"),
        &42,
        &false,
        &false,
        &START_TS,
        &90,
        &1,
        &None,
    );
    assert_eq!(result, Err(Ok(Error::ModelVersionDeprecated)));
}

// ── Irreversible deprecation ──────────────────────────────────────────────────

#[test]
fn test_deprecation_is_irreversible() {
    let (env, client, _) = setup();
    client.register_model_version(&Vec::new(&env), &1);
    client.deprecate_model_version(&Vec::new(&env), &1);

    // Attempting to deprecate again must fail.
    let result = client.try_deprecate_model_version(&Vec::new(&env), &1);
    assert_eq!(result, Err(Ok(Error::ModelVersionAlreadyDeprecated)));

    // Attempting to re-register a deprecated version must also fail.
    let result2 = client.try_register_model_version(&Vec::new(&env), &1);
    assert_eq!(result2, Err(Ok(Error::ModelVersionAlreadyRegistered)));

    // The version stays inactive after both failed operations.
    assert!(!client.is_model_version_active(&1));
}

// ── Registry cap ──────────────────────────────────────────────────────────────

#[test]
fn test_registry_cap_enforced() {
    let (env, client, _) = setup();
    // Fill the registry up to the cap.
    for i in 0..MAX_MODEL_VERSIONS {
        client.register_model_version(&Vec::new(&env), &i);
    }
    // One more registration must be rejected.
    let result = client.try_register_model_version(&Vec::new(&env), &MAX_MODEL_VERSIONS);
    assert_eq!(result, Err(Ok(Error::ModelVersionRegistryFull)));
}

// ── Batch: per-entry deprecated-version rejection ─────────────────────────────

#[test]
fn test_batch_deprecated_version_entry_rejected() {
    let (env, client, _) = setup();
    client.register_model_version(&Vec::new(&env), &1);
    client.register_model_version(&Vec::new(&env), &2);
    client.deprecate_model_version(&Vec::new(&env), &1);

    let wallet1 = Address::generate(&env);
    let wallet2 = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    let mut batch: Vec<ScoreSubmission> = Vec::new(&env);
    // Entry 0: deprecated version — should be per-entry rejected.
    batch.push_back(ScoreSubmission {
        wallet: wallet1.clone(),
        asset_pair: pair.clone(),
        score: 50,
        benford_flag: false,
        ml_flag: false,
        timestamp: START_TS,
        confidence: 90,
        model_version: 1,
    });
    // Entry 1: active version — should be accepted.
    batch.push_back(ScoreSubmission {
        wallet: wallet2.clone(),
        asset_pair: pair.clone(),
        score: 30,
        benford_flag: false,
        ml_flag: false,
        timestamp: START_TS,
        confidence: 90,
        model_version: 2,
    });

    let result: BatchResult = client.submit_scores_batch(&batch);
    assert_eq!(result.accepted_count, 1);
    assert_eq!(result.rejected_count, 1);

    let entry0 = result.results.get(0).unwrap();
    assert!(!entry0.accepted);
    assert_eq!(entry0.rejection_code, Error::ModelVersionDeprecated as u32);

    let entry1 = result.results.get(1).unwrap();
    assert!(entry1.accepted);
    assert_eq!(entry1.rejection_code, 0);

    // Rejected entry must not have stored a score.
    assert_eq!(client.try_get_score(&wallet1, &pair), Err(Ok(Error::ScoreNotFound)));
    // Accepted entry's score is readable.
    assert_eq!(client.get_score(&wallet2, &pair).score, 30);
    assert_eq!(client.get_score(&wallet2, &pair).model_version, 2);
}

// ── Snapshot: full lifecycle ───────────────────────────────────────────────────

#[test]
fn test_model_version_snapshot() {
    let (env, client, _) = setup();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    // Register versions 1 and 2, then deprecate 1.
    client.register_model_version(&Vec::new(&env), &1);
    client.register_model_version(&Vec::new(&env), &2);
    client.deprecate_model_version(&Vec::new(&env), &1);

    // Submit a score under the still-active version 2.
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &55,
        &false,
        &false,
        &START_TS,
        &90,
        &2,
        &None,
    );

    // Registry must report version 1 as deprecated and version 2 as active.
    let versions = client.get_model_versions();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions.get(0).unwrap(), (1_u32, false));
    assert_eq!(versions.get(1).unwrap(), (2_u32, true));

    assert!(!client.is_model_version_active(&1));
    assert!(client.is_model_version_active(&2));

    // The submitted score is stored with the correct model_version.
    let score = client.get_score(&wallet, &pair);
    assert_eq!(score.score, 55);
    assert_eq!(score.model_version, 2);
}

// ── get_model_version_list / get_model_version_count ──────────────────────────

#[test]
fn test_model_version_list_empty_initially() {
    let (env, client, _admin) = setup();
    assert_eq!(client.get_model_version_list().len(), 0);
    assert_eq!(client.get_model_version_count(), 0);
}

#[test]
fn test_model_version_list_grows_with_submissions() {
    let (env, client, _admin) = setup();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    // Submit with version 1
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &false,
        &false,
        &START_TS,
        &90,
        &1,
        &None,
    );
    let versions = client.get_model_version_list();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions.get(0).unwrap(), 1);

    // Submit with version 2 (advance ledger to pass cooldown)
    env.ledger().with_mut(|l| l.timestamp = START_TS + 3_601);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &60,
        &false,
        &false,
        &(START_TS + 1),
        &95,
        &2,
        &None,
    );
    let versions = client.get_model_version_list();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions.get(0).unwrap(), 1);
    assert_eq!(versions.get(1).unwrap(), 2);

    // Submit with version 1 again (duplicate — not added)
    env.ledger().with_mut(|l| l.timestamp = START_TS + 7_202);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &55,
        &false,
        &false,
        &(START_TS + 2),
        &92,
        &1,
        &None,
    );
    let versions = client.get_model_version_list();
    assert_eq!(versions.len(), 2); // still 2 — no duplicate entry
    assert_eq!(client.get_model_version_count(), 2);
}

#[test]
fn test_model_version_list_multiple_wallets_and_pairs() {
    let (env, client, _admin) = setup();
    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);
    let pair_x = symbol_short!("XLM_USDC");
    let pair_y = symbol_short!("XLM_BTC");

    // Different wallets/pairs all contribute to the same global index
    client.submit_score(
        &Vec::new(&env),
        &wallet_a,
        &pair_x,
        &50,
        &false,
        &false,
        &START_TS,
        &90,
        &1,
        &None,
    );
    client.submit_score(
        &Vec::new(&env),
        &wallet_a,
        &pair_y,
        &60,
        &false,
        &false,
        &START_TS,
        &90,
        &3,
        &None,
    );
    env.ledger().with_mut(|l| l.timestamp = START_TS + 3_601);
    client.submit_score(
        &Vec::new(&env),
        &wallet_b,
        &pair_x,
        &70,
        &false,
        &false,
        &(START_TS + 1),
        &90,
        &1,
        &None,
    );

    let versions = client.get_model_version_list();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions.get(0).unwrap(), 1);
    assert_eq!(versions.get(1).unwrap(), 3);
    assert_eq!(client.get_model_version_count(), 2);
}

// ── Model Version Governance Lifecycle ───────────────────────────────────────

#[test]
fn test_model_version_governance_full_lifecycle() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    let version = 100u32;
    let desc = Bytes::from_slice(&env, b"ML Model v1.0.0");

    // 1. Propose model version
    client.propose_model_version(&Vec::new(&env), &version, &desc);
    assert_eq!(
        client.get_model_version_status(&version),
        Some(ModelVersionStatus::Proposed)
    );
    assert!(!client.is_model_version_active(&version));

    // 2. Submission with Proposed version must be rejected
    let res_prop = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &false,
        &false,
        &START_TS,
        &90,
        &version,
        &None,
    );
    assert_eq!(res_prop, Err(Ok(Error::ModelVersionNotReady)));

    // 3. Approve before timelock elapses must fail
    let res_too_early = client.try_approve_model_version(&Vec::new(&env), &version);
    assert_eq!(res_too_early, Err(Ok(Error::UpgradeNotReady)));

    // 4. Advance time past timelock delay
    let future_ts = START_TS + DEFAULT_UPGRADE_DELAY_SECS + 1;
    env.ledger().with_mut(|l| l.timestamp = future_ts);

    // 5. Approve model version
    client.approve_model_version(&Vec::new(&env), &version);
    assert_eq!(
        client.get_model_version_status(&version),
        Some(ModelVersionStatus::Active)
    );
    assert!(client.is_model_version_active(&version));

    // 6. Submission with Active version succeeds
    let res_active = client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &75,
        &false,
        &false,
        &future_ts,
        &90,
        &version,
        &None,
    );
    assert!(res_active.is_ok());
    assert_eq!(client.get_score(&wallet, &pair).score, 75);

    // 7. Deprecate model version
    client.deprecate_model_version(&Vec::new(&env), &version);
    assert_eq!(
        client.get_model_version_status(&version),
        Some(ModelVersionStatus::Deprecated)
    );
    assert!(!client.is_model_version_active(&version));

    // 8. Submission with Deprecated version must be rejected
    let after_depr_ts = future_ts + 3601;
    env.ledger().with_mut(|l| l.timestamp = after_depr_ts);
    let res_depr = client.try_submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &80,
        &false,
        &false,
        &after_depr_ts,
        &90,
        &version,
        &None,
    );
    assert_eq!(res_depr, Err(Ok(Error::ModelVersionDeprecated)));
}

#[test]
fn test_deprecate_proposed_version_directly() {
    let (env, client, _) = setup();
    let version = 200u32;
    let desc = Bytes::from_slice(&env, b"Experimental model");

    client.propose_model_version(&Vec::new(&env), &version, &desc);
    assert_eq!(
        client.get_model_version_status(&version),
        Some(ModelVersionStatus::Proposed)
    );

    // Directly deprecate proposed version
    client.deprecate_model_version(&Vec::new(&env), &version);
    assert_eq!(
        client.get_model_version_status(&version),
        Some(ModelVersionStatus::Deprecated)
    );
}

#[test]
fn test_batch_submission_rejection_for_proposed_and_deprecated() {
    let (env, client, _) = setup();
    let wallet1 = Address::generate(&env);
    let wallet2 = Address::generate(&env);
    let wallet3 = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    // Version 1: Proposed
    client.propose_model_version(&Vec::new(&env), &1, &Bytes::from_slice(&env, b"v1"));
    // Version 2: Active
    client.register_model_version(&Vec::new(&env), &2);
    // Version 3: Deprecated
    client.register_model_version(&Vec::new(&env), &3);
    client.deprecate_model_version(&Vec::new(&env), &3);

    let mut batch: Vec<ScoreSubmission> = Vec::new(&env);
    batch.push_back(ScoreSubmission {
        wallet: wallet1,
        asset_pair: pair.clone(),
        score: 50,
        benford_flag: false,
        ml_flag: false,
        timestamp: START_TS,
        confidence: 90,
        model_version: 1, // Proposed -> reject
    });
    batch.push_back(ScoreSubmission {
        wallet: wallet2,
        asset_pair: pair.clone(),
        score: 50,
        benford_flag: false,
        ml_flag: false,
        timestamp: START_TS,
        confidence: 90,
        model_version: 2, // Active -> accept
    });
    batch.push_back(ScoreSubmission {
        wallet: wallet3,
        asset_pair: pair.clone(),
        score: 50,
        benford_flag: false,
        ml_flag: false,
        timestamp: START_TS,
        confidence: 90,
        model_version: 3, // Deprecated -> reject
    });

    let result: BatchResult = client.submit_scores_batch(&batch);
    assert_eq!(result.accepted_count, 1);
    assert_eq!(result.rejected_count, 2);

    let e0 = result.results.get(0).unwrap();
    assert!(!e0.accepted);
    assert_eq!(e0.rejection_code, Error::ModelVersionNotReady as u32);

    let e1 = result.results.get(1).unwrap();
    assert!(e1.accepted);

    let e2 = result.results.get(2).unwrap();
    assert!(!e2.accepted);
    assert_eq!(e2.rejection_code, Error::ModelVersionDeprecated as u32);
}

