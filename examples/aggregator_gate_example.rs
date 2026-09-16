//! Reference integration: gating a swap on `scoregate-aggregator`, with an
//! explicit, documented fallback policy for when the aggregator can't
//! meaningfully answer at all — as opposed to answering "reject".
//!
//! ## The problem this solves
//!
//! `ScoreGateAggregator::query_risk_gate` is infallible: every failure case
//! (no shards registered, a shard's cross-contract call trapping, a shard
//! being globally paused) collapses to the same `false` a genuinely
//! high-risk wallet would produce (see `contracts/scoregate-aggregator/src/lib.rs`
//! and `tests/composability/tests/aggregator_shard_pause.rs`, issue #411). An
//! integrator that only inspects that one boolean cannot tell "this wallet
//! is risky" apart from "the risk oracle is currently unavailable" — two
//! situations that usually call for different handling.
//!
//! ## The pattern
//!
//! 1. `get_shards()` empty => nothing is configured to consult at all, so
//!    treat this as **unavailable**, not as a rejection.
//! 2. Snapshot `get_last_shard_failure()` *before* calling `query_risk_gate`,
//!    call the gate, then read it again *after*. If it changed, this exact
//!    call is what caused a new shard failure, so the `false` reflects an
//!    unhealthy/unreachable shard rather than a genuine risk verdict.
//! 3. Otherwise, a `false` result is a genuine, risk-based rejection.
//!
//! ## Recommended fallback policy: fail closed
//!
//! This example — and the recommendation for integrators generally — is to
//! **fail closed** when the aggregator is unavailable: refuse the swap
//! rather than proceeding on missing information. A protocol that would
//! rather fail open (accept the risk of a temporarily-unavailable oracle
//! over blocking legitimate users) can substitute its own policy at the
//! single `AggregatorUnavailable` branch in `swap` below. The point of this
//! example is making that a **deliberate, visible choice** rather than an
//! accident of "well, `false` came back, so we rejected it."
//!
//! Build it as part of the workspace:
//!
//! ```text
//! cargo build --example aggregator_gate_example -p scoregate-aggregator
//! ```

#![no_std]

use scoregate_aggregator::ScoreGateAggregatorClient;
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Symbol};

/// Errors surfaced by the gated AMM. `AggregatorUnavailable` is the
/// fallback-policy branch (the aggregator could not meaningfully answer at
/// all); `UserHighRisk` is a genuine, risk-based rejection.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AmmError {
    /// The aggregator has no shards registered, or the `query_risk_gate`
    /// call that just ran is what caused a *new* shard failure (per
    /// `get_last_shard_failure`). Fallback policy applied here: fail closed.
    AggregatorUnavailable = 1,
    /// The aggregator's healthy shards agree this wallet does not clear
    /// `gate_threshold` — a genuine, risk-based rejection.
    UserHighRisk = 2,
}

#[contract]
pub struct AggregatorGatedAmm;

#[contractimpl]
impl AggregatorGatedAmm {
    /// Execute a swap gated on `scoregate-aggregator`, distinguishing a
    /// genuine risk-based rejection from the aggregator being unavailable.
    pub fn swap(
        env: Env,
        user: Address,
        asset_pair: Symbol,
        amount_in: u64,
        aggregator_id: Address,
        gate_threshold: u32,
    ) -> Result<u64, AmmError> {
        let aggregator = ScoreGateAggregatorClient::new(&env, &aggregator_id);

        // 1. Nothing registered to consult at all: unavailable, not a verdict.
        if aggregator.get_shards().is_empty() {
            return Err(AmmError::AggregatorUnavailable);
        }

        // 2. Snapshot the failure marker before the call so we can tell
        // whether *this* call is what tripped it, versus a stale failure
        // from some earlier, unrelated query.
        let failure_before = aggregator.get_last_shard_failure();

        let passes_gate = aggregator.query_risk_gate(&user, &asset_pair, &gate_threshold);

        if !passes_gate {
            let failure_after = aggregator.get_last_shard_failure();
            if failure_after != failure_before {
                // This exact call is what caused a new shard failure — the
                // `false` reflects an unhealthy/unreachable shard, not the
                // wallet's actual risk. Fallback policy: fail closed.
                return Err(AmmError::AggregatorUnavailable);
            }
            return Err(AmmError::UserHighRisk);
        }

        // 3. User passed the gate; proceed with swap logic.
        // (In a real AMM, this would include pool checks, reserve calculations, etc.)
        let output_amount = Self::compute_swap_output(amount_in);
        Ok(output_amount)
    }

    /// Simplified swap output calculation (not production logic).
    fn compute_swap_output(amount_in: u64) -> u64 {
        (amount_in * 997) / 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoregate_aggregator::{ScoreGateAggregator, ScoreGateAggregatorClient};
    use scoregate_score::{ScoreGateScoreContract, ScoreGateScoreContractClient};
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Ledger as _},
        Vec,
    };

    const GATE_THRESHOLD: u32 = 75;

    struct Fixture<'a> {
        env: Env,
        aggregator_id: Address,
        amm: AggregatorGatedAmmClient<'a>,
    }

    fn setup<'a>() -> Fixture<'a> {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| l.timestamp = 100_000);

        let aggregator_id = env.register_contract(None, ScoreGateAggregator);
        let aggregator = ScoreGateAggregatorClient::new(&env, &aggregator_id);
        aggregator.initialize(&Address::generate(&env));

        let amm_id = env.register_contract(None, AggregatorGatedAmm);
        let amm = AggregatorGatedAmmClient::new(&env, &amm_id);

        Fixture { env, aggregator_id, amm }
    }

    fn add_shard<'a>(fixture: &'a Fixture<'_>) -> ScoreGateScoreContractClient<'a> {
        let aggregator = ScoreGateAggregatorClient::new(&fixture.env, &fixture.aggregator_id);
        let shard_id = fixture.env.register_contract(None, ScoreGateScoreContract);
        let shard = ScoreGateScoreContractClient::new(&fixture.env, &shard_id);
        shard.initialize(&Address::generate(&fixture.env), &Address::generate(&fixture.env));
        aggregator.add_shard(&shard_id);
        shard
    }

    #[test]
    fn test_swap_with_passing_gate() {
        let fixture = setup();
        let shard = add_shard(&fixture);
        let user = Address::generate(&fixture.env);
        let pair = symbol_short!("XLM_USDC");
        shard.submit_score(
            &Vec::new(&fixture.env),
            &user,
            &pair,
            &10, // well under GATE_THRESHOLD
            &false,
            &false,
            &fixture.env.ledger().timestamp(),
            &90,
            &1,
            &None,
        );

        let result =
            fixture.amm.try_swap(&user, &pair, &1_000_000, &fixture.aggregator_id, &GATE_THRESHOLD);
        assert_eq!(result, Ok(Ok(997_000)));
    }

    #[test]
    fn test_swap_rejected_for_high_risk_wallet() {
        let fixture = setup();
        let shard = add_shard(&fixture);
        let user = Address::generate(&fixture.env);
        let pair = symbol_short!("XLM_USDC");
        shard.submit_score(
            &Vec::new(&fixture.env),
            &user,
            &pair,
            &90, // at/above GATE_THRESHOLD
            &false,
            &false,
            &fixture.env.ledger().timestamp(),
            &90,
            &1,
            &None,
        );

        let result =
            fixture.amm.try_swap(&user, &pair, &1_000_000, &fixture.aggregator_id, &GATE_THRESHOLD);
        assert_eq!(result, Err(Ok(AmmError::UserHighRisk)));
    }

    #[test]
    fn test_swap_reports_unavailable_when_no_shards_registered() {
        let fixture = setup(); // no add_shard() call
        let user = Address::generate(&fixture.env);
        let pair = symbol_short!("XLM_USDC");

        let result =
            fixture.amm.try_swap(&user, &pair, &1_000_000, &fixture.aggregator_id, &GATE_THRESHOLD);
        assert_eq!(result, Err(Ok(AmmError::AggregatorUnavailable)));
    }
}
