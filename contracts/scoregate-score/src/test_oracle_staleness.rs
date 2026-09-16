//! Tests for oracle price-feed staleness handling (issue #429).
//!
//! Covers:
//! * Fresh oracle — confidence_floor is applied normally.
//! * Stale oracle — get_effective_score falls back to zero confidence_floor
//!   and emits an `orc_stale` event.
//! * Never-consulted oracle — treated as stale on the very first is_oracle_stale query.
//! * is_oracle_stale read function — fresh and stale cases.
//! * set/get_oracle_staleness_threshold round-trip and zero-rejection.
//! * remove_oracle clears last-updated metadata.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Env, IntoVal, Symbol, Vec,
};

use crate::{Error, ScoreGateScoreContract, ScoreGateScoreContractClient};

const START_TS: u64 = 1_700_000_000;

// ── Minimal mock oracle ───────────────────────────────────────────────────────

#[contracttype]
pub enum StaleOracleKey {
    Price(Symbol),
}

#[contract]
pub struct StaleTestOracle;

#[contractimpl]
impl StaleTestOracle {
    pub fn set_price(env: Env, asset_pair: Symbol, price: i128) {
        env.storage().instance().set(&StaleOracleKey::Price(asset_pair), &price);
    }
    pub fn get_price(env: Env, asset_pair: Symbol) -> i128 {
        env.storage().instance().get(&StaleOracleKey::Price(asset_pair)).unwrap_or(0i128)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup<'a>() -> (Env, ScoreGateScoreContractClient<'a>) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START_TS);
    let cid = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &cid);
    client.initialize(&Address::generate(&env), &Address::generate(&env));
    (env, client)
}

fn deploy_oracle(env: &Env) -> Address {
    env.register_contract(None, StaleTestOracle)
}

fn set_oracle_price(env: &Env, oracle: &Address, pair: &Symbol, price: i128) {
    let client = StaleTestOracleClient::new(env, oracle);
    client.set_price(pair, &price);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// Default threshold is 3 600 s.
#[test]
fn test_get_oracle_staleness_threshold_default() {
    let (_env, client) = setup();
    assert_eq!(
        client.get_oracle_staleness_threshold(),
        crate::constants::DEFAULT_ORACLE_STALENESS_THRESHOLD_SECS
    );
}

#[test]
fn test_set_oracle_staleness_threshold_round_trip() {
    let (_env, client) = setup();
    client.set_oracle_staleness_threshold(&Vec::new(&_env), &7_200u64);
    assert_eq!(client.get_oracle_staleness_threshold(), 7_200);
}

#[test]
fn test_set_oracle_staleness_threshold_zero_rejected() {
    let (env, client) = setup();
    let result = client.try_set_oracle_staleness_threshold(&Vec::new(&env), &0u64);
    assert_eq!(result, Err(Ok(Error::InvalidStalenessWindow)));
}

// ── Fresh oracle path ─────────────────────────────────────────────────────────

/// On the very first get_effective_score call the last_updated slot is empty
/// (0).  The staleness guard treats last_updated == 0 as "never consulted" and
/// skips the stale branch, proceeding to invoke the oracle and populating the
/// slot.  On *subsequent* calls within the threshold the oracle is used normally.
#[test]
fn test_fresh_oracle_applies_confidence_floor() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    // 400_000 / 20_000 = 20
    set_oracle_price(&env, &oracle, &pair, 400_000i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &60,
        &false,
        &false,
        &START_TS,
        &85,
        &1,
        &None,
    );

    // First call: last_updated is 0 → not stale, oracle consulted, floor applied.
    let eff = client.get_effective_score(&wallet, &pair);
    assert_eq!(eff.confidence_floor, 20);
    assert_eq!(eff.original_score, 60);

    // is_oracle_stale should now return false (we just recorded the timestamp).
    assert!(!client.is_oracle_stale(&pair));
}

// ── Stale oracle fallback path ────────────────────────────────────────────────

#[test]
fn test_stale_oracle_falls_back_to_zero_floor() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    set_oracle_price(&env, &oracle, &pair, 600_000i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &55,
        &false,
        &false,
        &START_TS,
        &80,
        &1,
        &None,
    );

    // Use a tight threshold (60 s) so it's easy to exceed.
    client.set_oracle_staleness_threshold(&Vec::new(&env), &60u64);

    // First call at START_TS populates last_updated.
    let eff1 = client.get_effective_score(&wallet, &pair);
    assert_eq!(eff1.confidence_floor, 30); // 600_000 / 20_000 = 30

    // Advance time past the threshold.
    env.ledger().with_mut(|l| l.timestamp = START_TS + 61);

    // Second call: age = 61 s > 60 s threshold → stale fallback.
    let eff2 = client.get_effective_score(&wallet, &pair);
    assert_eq!(eff2.confidence_floor, 0, "stale oracle must produce zero floor");
    assert_eq!(eff2.original_score, 55, "stored score must be unchanged");
}

#[test]
fn test_stale_oracle_emits_orc_stale_event() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    set_oracle_price(&env, &oracle, &pair, 200_000i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &false,
        &false,
        &START_TS,
        &80,
        &1,
        &None,
    );

    client.set_oracle_staleness_threshold(&Vec::new(&env), &30u64);

    // First call — fresh, populate timestamp.
    let _ = client.get_effective_score(&wallet, &pair);

    // Advance past threshold.
    env.ledger().with_mut(|l| l.timestamp = START_TS + 31);

    // Second call — stale, should emit orc_stale event.
    let _ = client.get_effective_score(&wallet, &pair);

    let events = env.events().all();
    let topic = (symbol_short!("orc_stale"), pair);
    let found =
        events.iter().any(|(_address, topics, _data)| topics == topic.clone().into_val(&env));
    assert!(found, "orc_stale event must be emitted on stale fallback");
}

// ── is_oracle_stale ───────────────────────────────────────────────────────────

#[test]
fn test_is_oracle_stale_no_oracle_returns_false() {
    let (env, client) = setup();
    let pair = symbol_short!("XLM_USDC");
    // No oracle registered → not stale (nothing to be stale).
    assert!(!client.is_oracle_stale(&pair));
}

#[test]
fn test_is_oracle_stale_never_consulted_returns_true() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    client.register_oracle(&Vec::new(&env), &pair, &oracle);
    // Oracle registered but get_effective_score never called → last_updated = 0 → stale.
    assert!(client.is_oracle_stale(&pair));
}

#[test]
fn test_is_oracle_stale_within_threshold_returns_false() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    set_oracle_price(&env, &oracle, &pair, 0i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);
    client.set_oracle_staleness_threshold(&Vec::new(&env), &3_600u64);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &40,
        &false,
        &false,
        &START_TS,
        &70,
        &1,
        &None,
    );
    // Populate last_updated.
    let _ = client.get_effective_score(&wallet, &pair);

    // Advance within threshold.
    env.ledger().with_mut(|l| l.timestamp = START_TS + 3_600);
    assert!(!client.is_oracle_stale(&pair));
}

#[test]
fn test_is_oracle_stale_past_threshold_returns_true() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    set_oracle_price(&env, &oracle, &pair, 100_000i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);
    client.set_oracle_staleness_threshold(&Vec::new(&env), &120u64);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &40,
        &false,
        &false,
        &START_TS,
        &70,
        &1,
        &None,
    );
    // Populate last_updated.
    let _ = client.get_effective_score(&wallet, &pair);

    // Advance past threshold.
    env.ledger().with_mut(|l| l.timestamp = START_TS + 121);
    assert!(client.is_oracle_stale(&pair));
}

// ── remove_oracle clears last-updated metadata ────────────────────────────────

#[test]
fn test_remove_oracle_clears_last_updated() {
    let (env, client) = setup();
    let oracle = deploy_oracle(&env);
    let pair = symbol_short!("XLM_USDC");

    set_oracle_price(&env, &oracle, &pair, 200_000i128);
    client.register_oracle(&Vec::new(&env), &pair, &oracle);

    let wallet = Address::generate(&env);
    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &50,
        &false,
        &false,
        &START_TS,
        &80,
        &1,
        &None,
    );
    // Populate last_updated.
    let _ = client.get_effective_score(&wallet, &pair);

    // Remove oracle — should also clear last_updated.
    client.remove_oracle(&Vec::new(&env), &pair);

    // After removal, no oracle is registered → is_oracle_stale returns false.
    assert!(!client.is_oracle_stale(&pair));
    // And get_effective_score reverts to zero confidence floor.
    let eff = client.get_effective_score(&wallet, &pair);
    assert_eq!(eff.confidence_floor, 0);
}

// ── Staleness threshold update emits event ────────────────────────────────────

#[test]
fn test_set_oracle_staleness_threshold_emits_event() {
    let (env, client) = setup();
    client.set_oracle_staleness_threshold(&Vec::new(&env), &1_800u64);

    let events = env.events().all();
    let topic = (symbol_short!("orc_sthr"),);
    let found = events.iter().any(|(_address, topics, _data)| topics == topic.into_val(&env));
    assert!(found, "orc_sthr event must be emitted on threshold update");
}
