//! Criterion benchmark comparing the worst-case score-history ring eviction
//! against the steady-state cost of an ordinary ring push (issue #424).
//!
//! Run: `cargo bench -p scoregate-score --bench history_eviction`
//!
//! `push_score_history` (see `storage.rs`) evicts from the front of the ring
//! whenever it exceeds `HistoryMaxDepth`. In steady state that is at most one
//! `Vec::remove(0)` per submission. But `set_history_max_depth` lets an admin
//! drop the cap by up to 49 in one time-locked change (50 -> 1, the extremes
//! allowed by `MAX_HISTORY_DEPTH`); the *next* submission for that
//! `(wallet, asset_pair)` then pays for evicting all 49 excess entries in a
//! single pass. This benchmark measures both costs so the worst case is a
//! known, regression-tested number rather than an assumption.
//!
//! Findings / chosen tradeoff: the single-pass eviction loop is kept as-is
//! (not spread across multiple calls). `push_score_history` and
//! `set_history_max_depth` (`lib.rs`) already document that the ring is
//! bounded and deterministic on the very next write; splitting the eviction
//! across calls would break that documented, tested guarantee (see
//! `test_set_history_max_depth_decreases_ring_on_next_write` in `test.rs`)
//! for a cost that is already capped by `MAX_HISTORY_DEPTH` (50) — the worst
//! case can never exceed evicting 49 entries from a 50-entry `Vec`,
//! regardless of submission history, so the spike is small and fixed rather
//! than unbounded.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use scoregate_score::{ScoreGateScoreContract, ScoreGateScoreContractClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Env, Symbol, Vec,
};

const MAX_HISTORY_DEPTH: u32 = 50;
const PARAM_CHANGE_DELAY: u64 = 86_401;

fn setup(env: &Env) -> (ScoreGateScoreContractClient<'_>, Address, Symbol) {
    env.mock_all_auths();
    env.budget().reset_unlimited();
    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let service = Address::generate(env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(env);
    let asset_pair = Symbol::new(env, "XLM_USDC");
    (client, wallet, asset_pair)
}

fn fill_history(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    wallet: &Address,
    asset_pair: &Symbol,
    count: u32,
) {
    for i in 0..count {
        client.submit_score(
            &Vec::new(env),
            wallet,
            asset_pair,
            &(30 + (i % 50)),
            &false,
            &false,
            &env.ledger().timestamp(),
            &90,
            &1,
            &None,
        );
        env.ledger().with_mut(|l| l.timestamp += 3_601);
    }
}

fn submit_one(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    wallet: &Address,
    asset_pair: &Symbol,
) -> (u64, u64) {
    env.budget().reset_unlimited();
    env.budget().reset_tracker();
    client.submit_score(
        &Vec::new(env),
        wallet,
        asset_pair,
        &50,
        &false,
        &false,
        &env.ledger().timestamp(),
        &90,
        &1,
        &None,
    );
    black_box(());
    (env.budget().cpu_instruction_cost(), env.budget().memory_bytes_cost())
}

/// Steady state: ring already at max depth (50), one more submission pushes
/// and evicts exactly one entry — the ordinary per-call cost.
fn steady_state_cost(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    wallet: &Address,
    asset_pair: &Symbol,
) -> (u64, u64) {
    fill_history(env, client, wallet, asset_pair, MAX_HISTORY_DEPTH);
    submit_one(env, client, wallet, asset_pair)
}

/// Worst case: ring filled to 50, depth dropped to 1 via the time-locked
/// `set_history_max_depth` / `apply_param_change` path, so the next
/// submission's eviction loop removes 49 entries in a single pass.
fn worst_case_cost(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    wallet: &Address,
    asset_pair: &Symbol,
) -> (u64, u64) {
    fill_history(env, client, wallet, asset_pair, MAX_HISTORY_DEPTH);

    client.set_history_max_depth(&Vec::new(env), &1);
    env.ledger().with_mut(|l| l.timestamp += PARAM_CHANGE_DELAY);
    client.apply_param_change(&symbol_short!("hist_dep"));

    submit_one(env, client, wallet, asset_pair)
}

fn bench_history_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("history_eviction");
    group.sample_size(10);

    group.bench_function("steady_state_single_push", |b| {
        b.iter(|| {
            let env = Env::default();
            let (client, wallet, asset_pair) = setup(&env);
            black_box(steady_state_cost(&env, &client, &wallet, &asset_pair))
        });
    });

    group.bench_function("worst_case_depth_50_to_1", |b| {
        b.iter(|| {
            let env = Env::default();
            let (client, wallet, asset_pair) = setup(&env);
            black_box(worst_case_cost(&env, &client, &wallet, &asset_pair))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_history_eviction);
criterion_main!(benches);
