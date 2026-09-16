# Constant-Time Audit — secp256k1 / Attestation Signature Verification

**Date:** 2026-07-20  
**Issue:** #398  
**Auditor:** ciynthia  

---

## Scope

Every signature-verification code path in `contracts/scoregate-score/src/`:

1. `verify_attestation` — per-score `ScoreAttestation` verification
2. `verify_signature` — shared secp256k1 recovery + pubkey comparison
3. `verify_threshold_attestation` — t-of-n `ThresholdAttestation` verification
4. `verify_merkle_proof` — Merkle inclusion proof (batch attestation)
5. `pubkeys_match` — shared pubkey comparison helper

Excludes Soroban host intrinsics (`secp256k1_recover`, `require_auth`), whose timing properties are inherited from the host environment.

---

## Path-by-Path Findings

### 1. `verify_signature` (`lib.rs:9776`)

| Step | Constant-time? | Notes |
|------|---------------|-------|
| `recovery_id > 1` guard | **Safe** | Rejects invalid format; recovery_id is public in ECDSA |
| `secp256k1_recover` | **Host intrinsic** | Timing inherited from Soroban host |
| Pubkey comparison (65B) | **`ct_eq`** at line 9804 | Fixed-size array comparison via `subtle` |
| Pubkey comparison (33B) | **`ct_eq`** at line 9813 | Fixed-size array comparison via `subtle` |
| `pubkey.len()` branch (33 vs 65) | **Safe** | Stored key length is public, determined at `set_service_pubkey` time |
| Pending-key fallback | **`pubkeys_match`** (see below) | Called only after active key fails |

### 2. `verify_attestation` (`lib.rs:9729`)

| Step | Constant-time? | Notes |
|------|---------------|-------|
| Commitment recomputation | **Deterministic** | SHA-256 over public inputs |
| Commitment comparison | **`ct_eq`** at line 9762 | Fixed-size 32B comparison |
| Signature verification | **Delegates to `verify_signature`** | See above |

### 3. `verify_threshold_attestation` (`lib.rs:9846`)

| Step | Constant-time? | Notes |
|------|---------------|-------|
| `contract_version` check | **Safe** | Public integer comparison |
| Commitment recomputation | **Deterministic** | Same as `verify_attestation` |
| Commitment comparison | **`ct_eq`** at line 9878 | Fixed-size 32B comparison |
| `secp256k1_recover` | **Host intrinsic** | Same as `verify_signature` |
| Pubkey comparison (65B) | **`ct_eq`** at line 9900 | Fixed-size |
| Pubkey comparison (33B) | **`ct_eq`** at line 9909 | Fixed-size |

### 4. `verify_merkle_proof` (`lib.rs:10150`)

| Step | Constant-time? | Notes |
|------|---------------|-------|
| Depth guard (`proof_len > MAX_MERKLE_PROOF_DEPTH`) | **Safe** | Public input bound check |
| Hash chain loop | **Fixed iterations** | Always runs `proof_len` iterations; no early exit on mismatch |
| Final `current == root` | **Public operands** | Both `current` (computed from public leaf + public proof) and `root` (from attestation) are public values. Timing leak would only reveal what the function is already designed to return. |

**Verdict:** The loop runs to completion regardless of intermediate hash values, so there is no variable-time oracle within the hash chain itself. The final equality uses `==` but both operands are public (the root is obtained from the `BatchAttestation` struct which the caller provides, and the computed `current` is derived from public inputs). No fix needed.

### 5. `pubkeys_match` (`storage.rs:2597`)

| Step | Constant-time? | Notes |
|------|---------------|-------|
| Recovered (65B) vs stored (65B) | **`ct_eq`** at line 2603 | |
| Recovered compressed (33B) vs stored (33B) | **`ct_eq`** at line 2612 | |
| Length branch (33 vs 65) | **Safe** | Stored key length is public |

---

## Non-production Code

`test_cooldown.rs:57,97` uses plain `==` for pubkey comparison in test assertions. This is acceptable — test code is not reachable from production paths.

---

## Summary

| Path | File & Line | Custom logic? | Constant-time? |
|------|-------------|---------------|----------------|
| `verify_signature` | `lib.rs:9776` | Pubkey comparison | ✓ (all `ct_eq`) |
| `verify_attestation` | `lib.rs:9729` | Commitment comparison | ✓ (`ct_eq`) |
| `verify_threshold_attestation` | `lib.rs:9846` | Commitment + pubkey comparison | ✓ (all `ct_eq`) |
| `verify_merkle_proof` | `lib.rs:10150` | Hash chain + final comparison | ✓ (fixed loop, public final op) |
| `pubkeys_match` | `storage.rs:2597` | Pubkey comparison | ✓ (all `ct_eq`) |

**No timing side-channels found in any production signature-verification path.**

All secret-dependent comparisons use `subtle::ConstantTimeEq`. The only custom logic layered on top of the host's `secp256k1_recover` is pubkey-format detection (33 vs 65 bytes), which depends on a publicly-known stored length. The Merkle proof verification runs a fixed-iteration loop before a public-value comparison at the end.

The crate has been fully compliant with constant-time requirements since before this audit. No code changes were necessary.
