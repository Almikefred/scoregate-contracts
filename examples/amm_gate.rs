//! Reference integration: gating an AMM swap on a ScoreGate risk score.
//!
//! `ScoreGateGatedAmm` is a deliberately minimal contract — it is **not** a
//! real AMM. It exists purely to demonstrate the canonical composability
//! pattern from `docs/interface-spec.md`: call [`query_risk_gate`] inside your
//! guard clause and refuse to proceed for risky wallets.
//!
//! The key property exercised here is that `query_risk_gate` is **infallible**
//! and **side-effect free**. The AMM can call it from inside `swap` without a
//! `try_*` wrapper, without worrying about error propagation, and without any
//! risk that ScoreGate could panic and burn the AMM's gas or brick its guard.
//! A consumer can also discover the published capability surface via
//! `get_interface_metadata` and use the `fail_closed` constraint to reason
//! about how unknown wallets and low-confidence scores should be handled.
//!
//! Build it as part of the workspace:
//!
//! ```text
//! cargo build --example amm_gate -p scoregate-score
//! ```
//!
//! [`query_risk_gate`]: scoregate_score::ScoreGateScoreContract::query_risk_gate

#![no_std]

use scoregate_score::ScoreGateScoreContractClient;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env,
};

/// Errors surfaced by the gated AMM. `HighRiskWallet` is the one produced by
/// the ScoreGate guard clause; the rest are ordinary AMM bookkeeping.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AmmError {
    /// The contract has not been pointed at a ScoreGate deployment yet.
    NotConfigured = 1,
    /// ScoreGate reports this wallet's risk score is at or above the gate
    /// threshold (or no score exists) — the swap is refused.
    HighRiskWallet = 2,
    /// Swap amount must be positive.
    InvalidAmount = 3,
}

#[contracttype]
enum DataKey {
    /// Contract ID of the ScoreGate score registry this AMM trusts.
    ScoreGate,
}

/// The risk threshold this AMM enforces: wallets scoring `>= 75` (out of 100)
/// are turned away. Chosen to match ScoreGate's own default risk threshold.
const GATE_THRESHOLD: u32 = 75;

#[contract]
pub struct ScoreGateGatedAmm;

#[contractimpl]
impl ScoreGateGatedAmm {
    /// One-time wiring: record which ScoreGate deployment to consult.
    ///
    /// A production AMM would protect this behind admin auth; omitted here to
    /// keep the example focused on the gating pattern.
    pub fn initialize(env: Env, scoregate: Address) {
        env.storage().instance().set(&DataKey::ScoreGate, &scoregate);
    }

    /// Process a swap, but only after clearing the swapper through ScoreGate.
    ///
    /// This is the pattern integrators should copy: build the generated client
    /// for the ScoreGate contract, ask `query_risk_gate`, and bail out with
    /// your own domain error if the wallet is not safe. Note there is no
    /// `try_query_risk_gate` and no `?` — the gate cannot fail.
    pub fn swap(env: Env, user: Address, amount: i128) -> Result<(), AmmError> {
        if amount <= 0 {
            return Err(AmmError::InvalidAmount);
        }

        let llens_contract: Address =
            env.storage().instance().get(&DataKey::ScoreGate).ok_or(AmmError::NotConfigured)?;

        let client = ScoreGateScoreContractClient::new(&env, &llens_contract);

        let is_safe = client.query_risk_gate(&user, &symbol_short!("XLM_USDC"), &GATE_THRESHOLD);
        if !is_safe {
            return Err(AmmError::HighRiskWallet);
        }

        // ... rest of swap logic (reserves, pricing, transfers) would go here.
        Ok(())
    }
}
