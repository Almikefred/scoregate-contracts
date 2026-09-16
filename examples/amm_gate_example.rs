// Example only — not production code

//! Minimal AMM swap implementation with ScoreGate risk gating.
//!
//! This example demonstrates:
//! - Importing the ScoreGate contract client.
//! - Calling `query_risk_gate` from within a swap function.
//! - Handling the gate result and rejecting high-risk wallets.

#![no_std]

use scoregate_score::ScoreGateScoreContractClient;
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Symbol};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AmmError {
    UserHighRisk = 1,
}

#[contract]
pub struct SimpleAMM;

#[contractimpl]
impl SimpleAMM {
    /// Execute a swap between two tokens, enforcing ScoreGate risk gating.
    ///
    /// Before proceeding with the swap, this function calls `query_risk_gate`
    /// to verify that the user's risk score is below the specified threshold.
    /// If the gate returns `false` (user is too risky, embargoed, or unknown),
    /// the swap is rejected.
    pub fn swap(
        env: Env,
        user: Address,
        asset_pair: Symbol,
        amount_in: u64,
        scoregate_id: Address,
        gate_threshold: u32,
    ) -> Result<u64, AmmError> {
        // 1. Build the ScoreGate client
        let client = ScoreGateScoreContractClient::new(&env, &scoregate_id);

        // 2. Call query_risk_gate to check the user's risk score
        // This function returns bool: true if score < threshold, false otherwise.
        // It never panics and never raises an error — all failure cases collapse to false.
        let passes_gate = client.query_risk_gate(&user, &asset_pair, &gate_threshold);

        // 3. Reject the swap if the user's risk gate fails
        if !passes_gate {
            return Err(AmmError::UserHighRisk);
        }

        // 4. User passed the gate; proceed with swap logic
        // (In a real AMM, this would include pool checks, reserve calculations, etc.)
        let output_amount = Self::compute_swap_output(amount_in);

        Ok(output_amount)
    }

    /// Simplified swap output calculation (not production logic).
    fn compute_swap_output(amount_in: u64) -> u64 {
        // Example: simple 1:1 swap with a 0.3% fee
        (amount_in * 997) / 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoregate_score::ScoreGateScoreContract;
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{symbol_short, Vec};

    const GATE_THRESHOLD: u32 = 75;

    struct Fixture<'a> {
        env: Env,
        scoregate: ScoreGateScoreContractClient<'a>,
        scoregate_id: Address,
        amm: SimpleAMMClient<'a>,
    }

    /// Deploys a real `ScoreGateScoreContract` plus a real `SimpleAMM` in the
    /// same `Env`, so `swap` exercises the actual cross-contract call to
    /// `query_risk_gate` rather than a mocked gate check.
    fn setup<'a>() -> Fixture<'a> {
        let env = Env::default();
        env.mock_all_auths();

        let scoregate_id = env.register_contract(None, ScoreGateScoreContract);
        let scoregate = ScoreGateScoreContractClient::new(&env, &scoregate_id);
        let admin = Address::generate(&env);
        let service = Address::generate(&env);
        scoregate.initialize(&admin, &service);

        let amm_id = env.register_contract(None, SimpleAMM);
        let amm = SimpleAMMClient::new(&env, &amm_id);

        Fixture { env, scoregate, scoregate_id, amm }
    }

    /// Submits a score for `wallet`, advancing the ledger past the 1-hour
    /// cooldown first so repeated submissions in the same test never collide.
    fn submit_score(fixture: &Fixture, wallet: &Address, score: u32) {
        fixture.env.ledger().with_mut(|l| l.timestamp += 3_601);
        fixture.scoregate.submit_score(
            &Vec::new(&fixture.env),
            wallet,
            &symbol_short!("XLM_USDC"),
            &score,
            &false,
            &false,
            &fixture.env.ledger().timestamp(),
            &95,
            &1,
            &None,
        );
    }

    #[test]
    fn test_swap_with_passing_gate() {
        let fixture = setup();
        let user = Address::generate(&fixture.env);
        submit_score(&fixture, &user, 10); // 10 < GATE_THRESHOLD(75)

        let result = fixture.amm.try_swap(
            &user,
            &symbol_short!("XLM_USDC"),
            &1_000_000,
            &fixture.scoregate_id,
            &GATE_THRESHOLD,
        );

        assert_eq!(result, Ok(Ok(997_000)));
    }

    #[test]
    fn test_swap_with_failing_gate() {
        let fixture = setup();
        let user = Address::generate(&fixture.env);
        submit_score(&fixture, &user, 90); // 90 >= GATE_THRESHOLD(75)

        let result = fixture.amm.try_swap(
            &user,
            &symbol_short!("XLM_USDC"),
            &1_000_000,
            &fixture.scoregate_id,
            &GATE_THRESHOLD,
        );

        assert_eq!(result, Err(Ok(AmmError::UserHighRisk)));
    }

    #[test]
    fn test_swap_with_unknown_wallet() {
        let fixture = setup();
        let user = Address::generate(&fixture.env); // never scored

        let result = fixture.amm.try_swap(
            &user,
            &symbol_short!("XLM_USDC"),
            &1_000_000,
            &fixture.scoregate_id,
            &GATE_THRESHOLD,
        );

        assert_eq!(result, Err(Ok(AmmError::UserHighRisk)));
    }
}
