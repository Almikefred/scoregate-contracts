extern crate std;

use crate::{
    zk_range_proof::{Fe, Pt, Sc, SeededPrng, Bulletproof, get_generators, compress_pt, decompress_pt_32, is_on_curve, prove_range_proof},
    ScoreGateScoreContract, ScoreGateScoreContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Symbol, Vec};

#[test]
fn test_verify_score_range_proof_success() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Score = 40, Threshold = 50. Since 40 < 50, the proof should verify.
    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators();
    
    // C = g^score * h^r
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);
    std::println!("G_PT IS ON CURVE: {:?}", crate::zk_range_proof::is_on_curve(g_pt.x, g_pt.y, d));
    std::println!("C_PT IS ON CURVE: {:?}", crate::zk_range_proof::is_on_curve(c_pt.x, c_pt.y, d));

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    // Prover generates range proof showing T - 1 - v >= 0
    // T - 1 - v = 50 - 1 - 40 = 9
    // Blinding factor is -r
    let v_prime = threshold - 1 - score; // 9
    let r_prime = r.neg();
    
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_invalid_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Score = 60. Try to verify proof for threshold = 50 (which requires 60 < 50, invalid).
    let score = 60u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators();
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    // Prover tries to generate a range proof for v' = threshold - 1 - score = -11 (out of range [0, 256))
    // We pass a dummy/invalid proof or a proof generated for a different value.
    let prng = SeededPrng::new([1u8; 32]);
    // Try to prove 9 instead of -11 (which would be for score 40)
    let proof = prove_range_proof(&env, 9, r.neg(), prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    // Should fail because the commitment C' computed on-chain won't match the proof
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_tampered_commitment() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators();
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Tamper with commitment
    let mut tampered_bytes = commitment.to_array();
    tampered_bytes[0] ^= 1;
    let tampered_commitment = BytesN::from_array(&env, &tampered_bytes);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &tampered_commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_tampered_proof() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;
    
    let r = Sc::from_u64(987654321);
    let (g_pt, h_pt, d) = get_generators();
    
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Tamper with proof bytes
    let mut arr = [0u8; 800];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = proof_bytes.get(i as u32).unwrap();
    }
    arr[200] ^= 1; // tamper with one byte
    let tampered_proof = Bytes::from_array(&env, &arr);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &tampered_proof,
        &threshold,
    );
    assert!(!result);
}

// ── Adversarial / negative test vectors (issue #397) ─────────────────────────
//
// The tests above only cover byte-level corruption of the commitment and the
// raw proof buffer. The tests below target specific soundness properties of
// the verifier: boundary values of the committed score, forged proofs that
// are internally well-formed but statement-mismatched, cross-wallet replay,
// replay under a different public statement (threshold), and tampering with
// a value that specifically feeds a Fiat-Shamir challenge rather than being
// arbitrary byte noise.

#[test]
fn test_verify_score_range_proof_boundary_score_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Boundary: score = 0 (minimum valid score), threshold = 1.
    // v' = threshold - 1 - score = 0, the smallest legal range-proof value.
    let score = 0u32;
    let threshold = 1u32;

    let r = Sc::from_u64(11223344);
    let (g_pt, h_pt, d) = get_generators();
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_boundary_score_max() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // Boundary: score = 100 (maximum valid score), threshold = 101.
    let score = 100u32;
    let threshold = 101u32;

    let r = Sc::from_u64(55667788);
    let (g_pt, h_pt, d) = get_generators();
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(result);
}

#[test]
fn test_verify_score_range_proof_boundary_score_equals_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    // score == threshold: the honest statement "score < threshold" is false,
    // and the honest exponent (threshold - 1 - score = -1) does not exist in
    // u32. An attacker who knows the real blinding factor `r` still cannot
    // forge a proof by substituting the smallest in-range value (0) for the
    // impossible one, because the verifier derives the committed value from
    // the on-chain commitment and threshold, not from the prover's claim.
    let score = 50u32;
    let threshold = 50u32;

    let r = Sc::from_u64(24681357);
    let (g_pt, h_pt, d) = get_generators();
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let forged_v_prime = 0u32;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, forged_v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_cross_wallet_commitment_mismatch() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet_a = Address::generate(&env);
    let wallet_b = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let threshold = 50u32;
    let (g_pt, h_pt, d) = get_generators();

    // Wallet A's own score/commitment.
    let score_a = 40u32;
    let r_a = Sc::from_u64(555666777);
    let c_pt_a = g_pt.mul(Sc::from_u64(score_a as u64), d).add(h_pt.mul(r_a, d), d);
    let commitment_a = compress_pt(&env, &c_pt_a);
    client.submit_score(
        &Vec::new(&env),
        &wallet_a,
        &pair,
        &score_a,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment_a.clone().into()),
        }),
    );

    // Wallet B's own, distinct score/commitment.
    let score_b = 20u32;
    let r_b = Sc::from_u64(999888777);
    let c_pt_b = g_pt.mul(Sc::from_u64(score_b as u64), d).add(h_pt.mul(r_b, d), d);
    let commitment_b = compress_pt(&env, &c_pt_b);
    client.submit_score(
        &Vec::new(&env),
        &wallet_b,
        &pair,
        &score_b,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment_b.clone().into()),
        }),
    );

    // A genuinely valid range proof for wallet A's own commitment.
    let v_prime = threshold - 1 - score_a;
    let r_prime = r_a.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Attempt to present wallet A's commitment + valid proof against wallet
    // B's identity. Must fail: wallet B's stored commitment is commitment_b,
    // not commitment_a.
    let result = client.verify_score_range_proof(
        &wallet_b,
        &pair,
        &commitment_a,
        &proof_bytes,
        &threshold,
    );
    assert!(!result);
}

#[test]
fn test_verify_score_range_proof_replayed_across_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let original_threshold = 50u32;

    let r = Sc::from_u64(135792468);
    let (g_pt, h_pt, d) = get_generators();
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = original_threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    // Sanity check: the proof is genuinely valid for the threshold it was
    // generated against.
    let valid_result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &original_threshold,
    );
    assert!(valid_result);

    // Replay the same commitment + proof against a different threshold
    // (a different public statement). Must fail even though nothing about
    // the commitment or proof bytes was touched.
    let replayed_threshold = 60u32;
    let replay_result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &proof_bytes,
        &replayed_threshold,
    );
    assert!(!replay_result);
}

#[test]
fn test_verify_score_range_proof_tampered_fs_challenge() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ScoreGateScoreContract);
    let client = ScoreGateScoreContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);

    let wallet = Address::generate(&env);
    let pair = Symbol::new(&env, "XLM_USDC");

    let score = 40u32;
    let threshold = 50u32;

    let r = Sc::from_u64(19283746);
    let (g_pt, h_pt, d) = get_generators();
    let c_pt = g_pt.mul(Sc::from_u64(score as u64), d).add(h_pt.mul(r, d), d);
    let commitment = compress_pt(&env, &c_pt);

    client.submit_score(
        &Vec::new(&env),
        &wallet,
        &pair,
        &score,
        &false,
        &false,
        &1,
        &90,
        &1,
        &Some(crate::ScoreAttestationInput {
            attestation: crate::MaybeScoreAttestation::None,
            threshold_attestation: crate::MaybeThresholdAttestation::None,
            commitment: Some(commitment.clone().into()),
        }),
    );

    let v_prime = threshold - 1 - score;
    let r_prime = r.neg();
    let prng = SeededPrng::new([1u8; 32]);
    let proof = prove_range_proof(&env, v_prime, r_prime, prng);
    let proof_bytes = proof.to_bytes(&env);

    let mut arr = [0u8; 800];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = proof_bytes.get(i as u32).unwrap();
    }
    // Bytes [352..416) encode L[0], the first inner-product-argument point.
    // The verifier recomputes round 0's Fiat-Shamir challenge as
    // u = H("ip", 0, L[0], R[0]); flipping a bit here changes that challenge
    // without touching any other field, so this specifically targets
    // Fiat-Shamir-challenge tampering rather than generic byte corruption.
    arr[352] ^= 1;
    let tampered_proof = Bytes::from_array(&env, &arr);

    let result = client.verify_score_range_proof(
        &wallet,
        &pair,
        &commitment,
        &tampered_proof,
        &threshold,
    );
    assert!(!result);
}
