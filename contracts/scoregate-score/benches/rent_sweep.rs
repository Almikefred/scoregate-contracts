//! Criterion benchmarks for the proactive TTL rent-management sweep
//! (`get_expiring_entries`) at varying tracked-entry-set sizes.
//!
//! Run: `cargo bench -p scoregate-score --bench rent_sweep`
//!
//! Profiles the realistic worst case for the sweep: the tracked-entry index
//! filled to `size` entries, all touched immediately before the call (so
//! none are actually due). Since the index is maintained in
//! least-to-most-recently-touched order, the scan should stop after the
//! very first entry it examines regardless of `size` — this benchmark
//! exists to lock that in as a regression guard (see issue #422).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use scoregate_score::{ScoreGateScoreContract, ScoreGateScoreContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Env, Symbol, Vec,
};

fn setup(env: &Env) -> (ScoreGateScoreContractClient<'_>, Symbol) {
    env.mock_all_auths();
    env.budget().reset_unlimited();
    env.ledger().with_mut(|l| l.timestamp = 1_700_000_000);

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let service = Address::generate(env);
    client.initialize(&admin, &service);

    let asset_pair = Symbol::new(env, "XLM_USDC");
    (client, asset_pair)
}

/// Populates `size` tracked entries, then measures the CPU/memory cost of a
/// single `get_expiring_entries` sweep over that index.
fn sweep_cost(
    env: &Env,
    client: &ScoreGateScoreContractClient,
    asset_pair: &Symbol,
    size: u32,
) -> (u64, u64) {
    for i in 0..size {
        let wallet = Address::generate(env);
        client.submit_score(
            &Vec::new(env),
            &wallet,
            asset_pair,
            &(30 + (i % 50)),
            &false,
            &false,
            &(1_700_000_000 + i as u64),
            &90,
            &1,
            &None,
        );
    }

    env.budget().reset_unlimited();
    env.budget().reset_tracker();
    black_box(client.get_expiring_entries(&50));

    (env.budget().cpu_instruction_cost(), env.budget().memory_bytes_cost())
}

fn bench_rent_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_expiring_entries");
    group.sample_size(10);

    for size in [0u32, 100, 500] {
        group.bench_with_input(BenchmarkId::new("tracked_entries", size), &size, |b, &size| {
            b.iter(|| {
                let env = Env::default();
                let (client, asset_pair) = setup(&env);
                black_box(sweep_cost(&env, &client, &asset_pair, size))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_rent_sweep);
criterion_main!(benches);
