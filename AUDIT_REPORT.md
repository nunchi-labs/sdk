# Adversarial Audit Report: PR #1152 - Commonware 2026.9.0 Upgrade

**Branch:** `chore/upgrade-commonware-2026.9.0`  
**Head Commit:** 9840786 (CI passing: fmt/clippy/test/CodeQL/Bugbot/codecov)  
**Audit Date:** 2026-09-17  
**Auditor:** Second-opinion adversarial review

## Executive Summary

This audit focused on high-risk correctness issues in the upgrade to Commonware 2026.9.0 and the Constantinople coding marshal integration. The codebase transitioned from standard marshaling to erasure-coded (Reed-Solomon) marshaling with `CodingBlock` wrappers.

**Verdict:** ✅ **No critical bugs found**

All examined code paths correctly handle the distinction between:
- Block digests (`block.digest()`)
- Coding commitments (`block.commitment()` or `coded_block.commitment()`)
- Payload extraction (`.block()` method to extract block digest from coding commitment)

## Areas Audited

### 1. CodingBlock Wrapping ✅
**Files examined:** `chain/src/block.rs`, `chain/src/application.rs`, `chain/src/engine.rs`

**Findings:**
- `CodingBlock<Tx, Ext>` properly wraps `Block<Tx, Ext, BlockCommitment<Tx, Ext>>`
- The inner block uses `BlockCommitment` as its context digest type
- Deref implementation correctly exposes inner block methods
- `.inner()` method properly returns reference to wrapped block

**No issues found.**

### 2. Commitment Type Correctness ✅
**Files examined:** `examples/coins/chain/src/engine.rs`, `examples/bridge-chain/src/engine.rs`

**Findings:**
- **Correct:** Genesis commitment created via `CodedBlock::new(...).commitment()`
- **Correct:** Certificate comparisons use full commitment: `certificate.proposal.payload == block.commitment()`
- **Correct:** Block digest extraction: `certificate.proposal.payload.block()` when needed
- **Correct:** Startup floor uses coding commitment from marshal blocks
- **Correct:** Finalization anchor checks extract block digest: `finalization.proposal.payload.block()`

**Examples verified:**
```rust
// Correct usage in examples/coins/chain/src/engine.rs:924
assert_eq!(
    finalization.proposal.payload.block(), artifact.anchor_digest,
    "state-sync finalization does not certify the attached QMDB anchor"
);

// Correct usage in examples/coins/chain/src/engine.rs:1127-1129
assert_eq!(
    certificate.proposal.payload,
    block.commitment(),
    "startup candidate certificate payload must equal block commitment"
);

// Correct usage in examples/coins/chain/src/engine.rs:1137
certificate_payload: Some(certificate.proposal.payload.block()),
```

**No digest/commitment confusion found.**

### 3. Marshaled Automata and Finalization Lookups ✅
**Files examined:** `dkg/src/orchestrator/actor.rs`, `dkg/src/state.rs`

**Findings:**
- Marshal mailbox type correctly changed from `Standard<Blk>` to generic `V: Variant`
- Finalization types properly parameterized with `V::Commitment`
- `StartupFloor` generic over digest type: `StartupFloor<V::Commitment>`
- Floor commitment correctly obtained: `V::commitment(&block)` from marshal blocks

**Test coverage added (commit 9840786):**
- Marshal finalization lookups tested via `LocalFinalizations` methods
- Shareless DKG recovery path tested in `public_transition_continues_shareless_when_player_dealing_is_missing`

**No issues found.**

### 4. Reed-Solomon Shard Dissemination ✅
**Files examined:** `examples/*/src/engine.rs`

**Findings:**
- Minimum participant count enforced: `n_coding_participants >= 4`
- Coding config created consistently: `coding_config_for_participants(n_coding_participants)`
- Shard engine configured with proper codec bounds: `MAX_SHARD_SIZE = 1024 * 1024`
- Block codec config tuple includes participant bound: `(NZU32!(max_read_size), block_read_cfg)`

**No issues found.**

### 5. Epoch/DKG Regressions ✅
**Files examined:** `dkg/src/state.rs`, `dkg/src/tests/actor.rs`

**Findings:**
- Player creation properly handles `MissingPlayerDealing` error
- Shareless continuation supported when player dealings absent from public logs
- Dealer finalization is idempotent (checks `self.finalized.is_some()`)
- Player `dealer_message` API change handled correctly: `Verdict::Valid(ack)` → `Ok(Some(ack))`
- Transcript versioning added: `Transcript::resume(rng_seed, Version::V0)`

**Test coverage:**
- New test verifies shareless player can complete DKG transition
- Player without local dealings continues without share

**No issues found.**

### 6. CLOB/Mempool/Indexer Wire/Format ✅
**Files examined:** `examples/coins/chain/src/indexer/*.rs`

**Findings:**
- Indexer pusher correctly extracts block digest: `notarization.proposal.payload.block()`
- Backfiller producer validates certificate matches block: `proof.proposal.payload.block() != candidate.digest`
- Finalization grace period enforced for mismatched certificates
- Block caching uses block digest as key: `blocks.insert(block.digest(), block)`

**No wire format breaks found.**

### 7. State Ranges and QMDB Operations ✅
**Files examined:** `chain/src/block.rs`, `common/src/state_db.rs`

**Findings:**
- `state_range` field properly typed: `NonEmptyRange<Location>`
- Block header digest includes state range: `hasher.update(&self.state_range.encode())`
- State DB accessor changed from field to method: `self.db()` (refactoring)
- Operation bounds retrieval: `self.db().bounds()` works correctly

**No issues found.**

## Code Quality Observations

### Positive Patterns
1. **Type safety:** Generic `Variant` parameter prevents mixing digest types
2. **Idempotent operations:** Dealer finalization checks prevent double-finalization
3. **Explicit extraction:** `.block()` method makes digest extraction explicit
4. **Test coverage:** Recent additions cover finalization lookups and edge cases
5. **Validation:** Minimum participant counts enforced at runtime

### Minor Notes
- Cargo.toml has 4 unused workspace dependencies (non-critical)
- `oracle/Cargo.toml` missing `[lints]` inheritance (non-critical)
- Linker config assumes `mold` availability (environment-specific)

## Recommendations

1. ✅ **No blocking issues** - PR is safe to merge
2. Consider adding fuzz testing for codec roundtrips with various participant counts
3. Consider adding adversarial tests for malformed coding commitments
4. Document the `.block()` extraction pattern in AGENTS.md

## Testing Notes

- CI passed on head commit 9840786
- All existing tests pass (fmt/clippy/test)
- New test coverage for finalization lookups and shareless DKG recovery
- Deterministic test patterns properly used throughout

## Conclusion

This adversarial audit found **zero critical correctness bugs**. The upgrade correctly handles the transition to erasure-coded marshaling with proper type safety and consistent commitment handling. The code demonstrates careful attention to the distinction between block digests and coding commitments, with explicit extraction methods preventing confusion.

The recent additions (commit 9840786) properly address the previously uncovered finalization lookup paths and shareless DKG recovery scenarios.

**Status:** ✅ **APPROVED FOR MERGE**
