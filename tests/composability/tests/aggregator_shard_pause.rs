//! Aggregator/shard cross-contract integration tests (issue #411).
//!
//! `ScoreGateAggregator::query_risk_gate` ANDs the result across every
//! registered shard: if any shard rejects (or the call to it fails outright),
//! the whole aggregated query fails closed, even when every other shard is
//! perfectly healthy. That's a real operational scenario — one shard
//! undergoing maintenance (globally paused via `pause()`) or simply
//! unreachable (a bad/unregistered contract id) — and until now nothing
//! exercised it against a real multi-shard deployment.
//!
//! These tests deploy `ScoreGateAggregator` alongside two real
//! `ScoreGateScoreContract` shards in the same Soroban test `Env` and drive
//! the real cross-contract call path (`aggregator.query_risk_gate(...)`
//! invoking each shard), rather than asserting on the AND logic in isolation.

use scoregate_aggregator::{
    Error as AggregatorError, ScoreGateAggregator, ScoreGateAggregatorClient,
};
use scoregate_score::{ScoreGateScoreContract, ScoreGateScoreContractClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Env, Symbol, Vec,
};

const GATE_THRESHOLD: u32 = 75;

struct Fixture<'a> {
    env: Env,
    aggregator: ScoreGateAggregatorClient<'a>,
    shard_a: ScoreGateScoreContractClient<'a>,
    shard_b: ScoreGateScoreContractClient<'a>,
    wallet: Address,
    pair: Symbol,
}

/// Deploys an aggregator with two healthy shards already registered, and
/// submits a low-risk, high-confidence score for `wallet` on both shards so
/// `query_risk_gate` passes at baseline (both shards individually agree the
/// wallet is safe).
fn setup<'a>() -> Fixture<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 100_000);

    let agg_id = env.register_contract(None, ScoreGateAggregator);
    let aggregator = ScoreGateAggregatorClient::new(&env, &agg_id);
    let agg_admin = Address::generate(&env);
    aggregator.initialize(&agg_admin);

    let shard_a_id = env.register_contract(None, ScoreGateScoreContract);
    let shard_a = ScoreGateScoreContractClient::new(&env, &shard_a_id);
    shard_a.initialize(&Address::generate(&env), &Address::generate(&env));

    let shard_b_id = env.register_contract(None, ScoreGateScoreContract);
    let shard_b = ScoreGateScoreContractClient::new(&env, &shard_b_id);
    shard_b.initialize(&Address::generate(&env), &Address::generate(&env));

    aggregator.add_shard(&shard_a_id);
    aggregator.add_shard(&shard_b_id);

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");
    for shard in [&shard_a, &shard_b] {
        shard.submit_score(
            &Vec::new(&env),
            &wallet,
            &pair,
            &10u32, // well under GATE_THRESHOLD
            &false,
            &false,
            &env.ledger().timestamp(),
            &90u32, // comfortably above any confidence floor
            &1u32,
            &None,
        );
    }

    Fixture { env, aggregator, shard_a, shard_b, wallet, pair }
}

/// Baseline: two healthy shards both agreeing the wallet is safe → gate passes.
#[test]
fn query_risk_gate_passes_when_all_shards_healthy() {
    let f = setup();
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));
}

/// Core scenario from issue #411: one shard is globally paused (maintenance),
/// the other is untouched and healthy. The aggregator's AND semantics mean
/// the *entire* query now fails closed, for this wallet, on this pair —
/// exactly as `query_risk_gate`'s fail-closed match arm (`_ => return false`)
/// implies. Un-pausing restores the passing result.
#[test]
fn query_risk_gate_fails_closed_when_one_shard_globally_paused() {
    let f = setup();

    // Sanity: still healthy before the pause.
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));

    f.shard_a.pause(&Vec::new(&f.env));
    assert!(f.shard_a.is_paused());
    assert!(!f.shard_b.is_paused());

    // shard_b is completely healthy and would pass on its own, but the
    // aggregator's AND-across-shards logic rejects the whole query.
    assert!(!f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));

    // Recovery: unpausing the shard restores the aggregated result.
    f.shard_a.unpause(&Vec::new(&f.env));
    assert!(!f.shard_a.is_paused());
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));
}

/// An unreachable shard is rejected at registration because it cannot
/// advertise the required aggregator interface.
#[test]
fn unreachable_shard_is_rejected_before_gate_queries() {
    let f = setup();
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));

    let unreachable_shard = Address::generate(&f.env); // never deployed as a contract
    assert_eq!(
        f.aggregator.try_add_shard(&unreachable_shard),
        Err(Ok(AggregatorError::IncompatibleInterface))
    );
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));
}

/// Documents a mismatch worth flagging rather than silently "fixing" here
/// (per the issue's own instructions): a *pair-level* pause on a shard
/// (`set_pair_paused`) does NOT affect `query_risk_gate` at all. Reading
/// `scoregate-score`'s `query_risk_gate_with_confidence`, `is_pair_paused`
/// is only consulted by the write path (`submit_score`) — the read/gate
/// path only checks the *global* `is_paused` flag. So, unlike the global
/// pause scenario above, pausing just the pair leaves the aggregator's gate
/// completely unaffected. If per-pair pause is meant to also freeze reads
/// for that pair, that's a real gap — but changing it is out of scope here.
#[test]
fn query_risk_gate_unaffected_by_shard_pair_level_pause() {
    let f = setup();
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));

    f.shard_a.set_pair_paused(&f.pair, &true);
    assert!(f.shard_a.is_pair_paused(&f.pair));

    // Current behavior: still passes. `set_pair_paused` only gates
    // submit_score, not query_risk_gate — see doc comment above.
    assert!(f.aggregator.query_risk_gate(&f.wallet, &f.pair, &GATE_THRESHOLD));
}
