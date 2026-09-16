//! Composability test for the scoregate-aggregator fallback pattern
//! (issue #434): distinguishing "the aggregator is unavailable" (no shards
//! registered, or a shard's cross-contract call itself failed) from "the
//! aggregator's shards genuinely agree this wallet is too risky" — both of
//! which collapse to the same `query_risk_gate() == false` if an integrator
//! only looks at that one boolean.
//!
//! See `examples/aggregator_gate_example.rs` (`AggregatorGatedAmm::swap`) for
//! the full reference pattern this test exercises directly against a real
//! deployed `ScoreGateAggregator` and `ScoreGateScoreContract` shard.

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

/// The gate outcome an integrator should act on: a genuine risk-based
/// rejection vs. the aggregator being unable to meaningfully answer at all.
#[derive(Debug, PartialEq)]
enum GateOutcome {
    Passed,
    RejectedHighRisk,
    Unavailable,
}

/// The recommended fallback-policy pattern (issue #434): distinguishes a
/// genuine risk-based rejection from aggregator unavailability using only
/// the aggregator's public API (`get_shards`, `get_last_shard_failure`,
/// `query_risk_gate`). Fails closed (`Unavailable`) whenever the aggregator
/// cannot meaningfully answer, matching the recommendation documented in
/// `docs/aggregator-error-mapping.md`.
fn gated_query(
    aggregator: &ScoreGateAggregatorClient,
    wallet: &Address,
    pair: &Symbol,
) -> GateOutcome {
    if aggregator.get_shards().is_empty() {
        return GateOutcome::Unavailable;
    }

    let failure_before = aggregator.get_last_shard_failure();
    let passes = aggregator.query_risk_gate(wallet, pair, &GATE_THRESHOLD);

    if passes {
        return GateOutcome::Passed;
    }

    // A `false` result is ambiguous on its own: it's what both a genuine
    // rejection *and* a shard failure look like. Comparing the failure
    // marker before/after this exact call resolves the ambiguity.
    let failure_after = aggregator.get_last_shard_failure();
    if failure_after != failure_before {
        GateOutcome::Unavailable
    } else {
        GateOutcome::RejectedHighRisk
    }
}

struct Fixture<'a> {
    env: Env,
    aggregator: ScoreGateAggregatorClient<'a>,
    shard: ScoreGateScoreContractClient<'a>,
    wallet: Address,
    pair: Symbol,
}

/// Deploys an aggregator and a real `ScoreGateScoreContract` shard, but does
/// **not** register the shard with the aggregator — callers opt in via
/// `f.aggregator.add_shard(&f.shard.address)` so each test controls exactly
/// which "unavailable" scenario it exercises.
fn setup<'a>() -> Fixture<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 100_000);

    let agg_id = env.register_contract(None, ScoreGateAggregator);
    let aggregator = ScoreGateAggregatorClient::new(&env, &agg_id);
    aggregator.initialize(&Address::generate(&env));

    let shard_id = env.register_contract(None, ScoreGateScoreContract);
    let shard = ScoreGateScoreContractClient::new(&env, &shard_id);
    shard.initialize(&Address::generate(&env), &Address::generate(&env));

    let wallet = Address::generate(&env);
    let pair = symbol_short!("XLM_USDC");

    Fixture { env, aggregator, shard, wallet, pair }
}

fn submit_score(f: &Fixture, score: u32) {
    f.shard.submit_score(
        &Vec::new(&f.env),
        &f.wallet,
        &f.pair,
        &score,
        &false,
        &false,
        &f.env.ledger().timestamp(),
        &90,
        &1,
        &None,
    );
}

#[test]
fn no_shards_registered_is_unavailable_not_rejection() {
    let f = setup(); // shard deployed but never added to the aggregator
    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::Unavailable);
}

#[test]
fn healthy_low_risk_wallet_passes() {
    let f = setup();
    f.aggregator.add_shard(&f.shard.address);
    submit_score(&f, 10); // well under GATE_THRESHOLD

    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::Passed);
}

#[test]
fn healthy_high_risk_wallet_is_genuine_rejection() {
    let f = setup();
    f.aggregator.add_shard(&f.shard.address);
    submit_score(&f, 90); // at/above GATE_THRESHOLD

    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::RejectedHighRisk);
}

/// A paused score shard returns a normal `false` gate result, rather than a
/// cross-contract failure. The public fallback pattern therefore cannot
/// distinguish it from a genuine risk rejection.
#[test]
fn paused_shard_is_indistinguishable_from_rejection() {
    let f = setup();
    f.aggregator.add_shard(&f.shard.address);
    submit_score(&f, 10); // would pass on a healthy shard

    f.shard.pause(&Vec::new(&f.env));
    assert!(f.shard.is_paused());

    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::RejectedHighRisk);

    // Recovery: unpausing restores the genuine (passing) verdict.
    f.shard.unpause(&Vec::new(&f.env));
    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::Passed);
}

/// Unreachable addresses are rejected during registration by the aggregator's
/// required-interface check, so they cannot poison later gate queries.
#[test]
fn unreachable_shard_is_rejected_at_registration() {
    let f = setup();
    let unreachable = Address::generate(&f.env); // never deployed as a contract
    assert_eq!(
        f.aggregator.try_add_shard(&unreachable),
        Err(Ok(AggregatorError::IncompatibleInterface))
    );

    assert_eq!(gated_query(&f.aggregator, &f.wallet, &f.pair), GateOutcome::Unavailable);
}
