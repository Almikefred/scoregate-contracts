# Model Version Governance Documentation

This document describes the implemented model version governance and submission gating mechanism in `scoregate-score`.

## Overview & Governance Flow

Model version acceptance controls what data the off-chain ML pipeline can write on-chain. Rather than immediate activation, model versions follow a time-locked governance lifecycle mirroring parameter changes and contract upgrades.

### Lifecycle States (`ModelVersionStatus`)
1. **`Proposed`**: The model version has been proposed by contract admin(s) via `propose_model_version`. It includes metadata/description and an `executable_after` timelock timestamp computed as `now + upgrade_delay`. Submissions using a `Proposed` version are rejected with `Error::ModelVersionNotReady`.
2. **`Active`**: After the upgrade delay timelock has elapsed, admin(s) call `approve_model_version` to transition state from `Proposed` to `Active`. Only `Active` model versions can be used to submit scores via `submit_score`, `submit_scores_batch`, or `submit_scores_batch_attested`.
3. **`Deprecated`**: Admin(s) call `deprecate_model_version` (or `bulk_deregister_model_version`) to retire a version. This state is permanent and irreversible. Submissions using a `Deprecated` version are rejected with `Error::ModelVersionDeprecated`.

---

## Status Checkboxes (Completed Tasks)

## Step 1 — Add types
- [x] Update `src/types.rs`:
  - Added `ModelVersionStatus` enum (`Proposed`, `Active`, `Deprecated`)
  - Added storage key variants under `DataKeyB` for per-version registry (`ModelVersionStatus`, `ModelVersionExecutableAfter`, `ModelVersionDescription`)

## Step 2 — Add errors + events
- [x] Update `src/errors.rs`:
  - Added `ModelVersionNotReady`, `ModelVersionAlreadyProposed`, `ModelVersionNotProposed`, `ModelVersionNotActive`, `ModelVersionDeprecated` aliases.
- [x] Update `src/events.rs`:
  - Emits `model_version_proposed` on proposal
  - Emits `model_version_activated` on approval
  - Emits `model_version_deprecated` on deprecation

## Step 3 — Add storage helpers
- [x] Update `src/storage.rs`:
  - Added getters/setters for per-version status, proposed `executable_after` timestamp, and description.
  - Added `get_model_version_status(version)`, `is_model_version_active(version)`, `is_model_version_deprecated(version)`, and `is_model_version_proposed(version)` helpers.

## Step 4 — Contract methods
- [x] Update `src/lib.rs` to expose admin methods:
  - `propose_model_version(admin_signers, version, description)`
  - `approve_model_version(admin_signers, version)`
  - `deprecate_model_version(admin_signers, version)`
  - `register_model_version(admin_signers, version)` (convenience/legacy immediate registration)
  - `get_model_version_status(version)`
- [x] Enforce admin auth via existing `require_admin_auth` helper.
- [x] Enforce timelock semantics:
  - `approve_model_version` fails with `Error::UpgradeNotReady` if `now < executable_after`.

## Step 5 — Submission gating
- [x] Update `submit_score` / `validate_risk_score`:
  - Reject if `model_version` is `Proposed` with `Error::ModelVersionNotReady`.
  - Reject if `model_version` is `Deprecated` with `Error::ModelVersionDeprecated`.
- [x] Update `submit_scores_batch` and `submit_scores_batch_attested`:
  - For each entry, set `rejection_code = Error::ModelVersionNotReady as u32` when proposed/not ready.
  - For each entry, set `rejection_code = Error::ModelVersionDeprecated as u32` when deprecated.

## Step 6 — Tests
- [x] Update `src/test_model_version.rs`:
  - Lifecycle timelock test: propose → too-early approve fails → after delay approve succeeds → submit_score succeeds → deprecate succeeds → submit_score fails.
  - Submission rejection test: submitting with proposed or deprecated model version fails with correct error code.
  - Batch rejection: proposed and deprecated version entries rejected with correct `rejection_code`.

## Step 7 — Build & test
- [x] Run `cargo test -p scoregate-score`.
