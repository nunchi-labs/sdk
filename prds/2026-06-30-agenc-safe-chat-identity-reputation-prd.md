---
title: "AgenC-safe chat, identity, and reputation refactor"
date: 2026-06-30
version: "0.1"
status: draft
owner: Jae Lee
domain: sdk / chat / identity / reputation
related:
  - "https://github.com/Nunchi-trade/research/pull/46"
  - "https://github.com/Nunchi-trade/research/pull/53"
tags: [agenc, chat, identity, reputation, prompt-injection, signer-policy, prd]
---

# AgenC-safe chat, identity, and reputation refactor

> Status: draft PRD. This is a spec for the SDK module boundary and launch controls. It does not implement the modules yet.

## 1. Summary

Refactor the chat plan around the AgenC security model: every marketplace job spec, user prompt, docs excerpt, Telegram message, chat message, and artifact body is untrusted input. Chat should carry structured, signed data and durable knowledge artifacts, but it must not be a hidden control plane for wallet mutation.

The SDK should split the work into three coupled modules:

- `nunchi-chat`: structured rooms, signed messages, artifact commitments, and public knowledge persistence.
- `nunchi-identity`: agent passports, transport-key binding, wallet/controller binding, and signer-policy subjects.
- `nunchi-reputation`: reputation events derived from signed work, settlement outcomes, moderation, and prompt-injection safety outcomes.

The key product decision is that prompt-injection protection is primarily enforced at the runtime, CLI, gateway, and signer-policy boundary for official agents. Protocol logic still protects task state and settlement, but it cannot stop arbitrary external wallets from calling public program entry points directly. Protocol launch controls must cover those external callers.

## 2. Inputs and context

This PRD supersedes the chat assumptions in:

- Research PR #46, "Rules of Chat - Done vs Not Done": locked the chat rules, including signed messages, no bus history, settle-on-binding, and the boundary between chat and chain.
- Research PR #53, "Chat-module knowledge persistence": specified hash-on-chain, bytes-off-chain persistence with forum/search surfacing.

It also incorporates the AgenC threat-model controls for prompt injection:

| Control | Requirement |
| --- | --- |
| Default built-in tools are read-only | Official agents must be safe to expose to untrusted chat by default. |
| Mutation tools must be explicitly enabled | Any write-capable tool must require deliberate runtime/operator opt-in. |
| Signer-backed mutation tools | Wallet mutations must pass signer-policy checks before signing. |

The enforcement model is layered:

| Layer | Protects | Mechanism |
| --- | --- | --- |
| Protocol-enforced | Task state integrity and escrow settlement | On-chain program logic, `protocol_paused`, and `disabled_task_type_mask`. |
| Runtime/signer-policy enforced | Official agent and wallet safety | Runtime tool registry plus signer policy restricting which wallets can sign which mutations. |
| Operator procedure | Visibility, alerting, response | Explorer visibility, monitoring, manual pause/disable workflows, incident runbooks. |

Important distinction: signer policy does not restrict arbitrary external wallets that call the program directly. Protocol launch controls do.

## 3. Problem

The original chat specs focused on transport, rooms, settlement, and persistence. That is not enough for AgenC. Once chat contains marketplace job specs, prompt text, docs excerpts, Telegram-originated instructions, and artifact text, it becomes an adversarial input stream into agents that may have wallet access.

The dangerous failure mode is not "a bad message is published." The dangerous failure mode is "a bad message is interpreted as authority to call a mutation tool or sign a transaction."

The SDK needs a chat design where:

- Messages and artifacts are authenticated and replay-resistant.
- Untrusted content can be stored, searched, quoted, and summarized without gaining authority.
- Identity determines who said something, not what the runtime is allowed to do.
- Reputation affects discovery and weighting, not direct signing authority.
- Mutations are routed through explicit runtime tool enablement and signer policy.
- Protocol pause/disable controls remain available for external callers and incident response.

## 4. Goals

1. Define the SDK boundaries for chat, identity, and reputation as first-class modules.
2. Make prompt-injection safety a launch requirement, not a later runtime patch.
3. Preserve the useful parts of prior chat work: signed messages, no bus history, settle-on-binding, and hash-on-chain knowledge persistence.
4. Provide enough schema detail for implementation PRs to split cleanly across modules.
5. Define the official-agent boundary separately from arbitrary external wallet behavior.

## 5. Non-goals

- Do not build private ZK marketplace tasks in this scope.
- Do not build storefront checkout in this scope.
- Do not build AgenC Lab in this scope.
- Do not build Telegram buyer rails in this scope.
- Do not make reputation a wallet authorization mechanism.
- Do not store raw transcripts on-chain.
- Do not assume signer policy protects direct external program calls.

## 6. Product principles

### P1. Chat is data, not authority

A chat message can request, describe, quote, summarize, or attach an artifact. It cannot grant permission to mutate state or spend funds. The runtime may convert a message into a candidate action, but the action must pass the tool registry, approval policy, and signer policy.

### P2. Identity binds authorship

Every message, board entry, and reputation event must bind to an agent identity. The identity module proves "who authored this," "which controller/wallet owns this agent," and "which transport key signed this message." It does not prove that the content is safe to execute.

### P3. Reputation ranks and weights

Reputation gates discovery, room admission, job routing, and scoring. It must not bypass runtime approvals or signer checks. A high-reputation agent can still be compromised or prompted into producing malicious text.

### P4. Durable knowledge uses commitments

Chat-derived knowledge should be persisted as content-addressed artifacts. The chain stores a compact commitment, while full bytes live in an off-chain archive and optional IPFS pin set. Retrieval verifies the content hash before use.

### P5. Protocol controls cover public callers

Official agents get runtime/signer protection. Direct callers get protocol controls: task validation, paused flags, disabled task types, escrow invariants, replay protection, and settlement checks.

## 7. Scope

### In scope

- Public or permissioned chat rooms for agent coordination.
- Signed chat messages and typed message envelopes.
- Agent identity/passport binding for controller wallet and transport keys.
- Reputation event schema and scoring inputs.
- Artifact commitment schema for knowledge persistence.
- Runtime-facing metadata that lets official agents classify messages as untrusted.
- Protocol-level controls needed for canary launch safety.

### Out of scope for this PRD

- Private ZK marketplace tasks.
- Storefront checkout.
- AgenC Lab.
- Telegram buyer rails.
- Full Gateway session manager implementation. This PRD reserves the API surface for gateway approval policies, but the gateway phase should own its own implementation PRD.

## 8. Proposed module architecture

### 8.1 `nunchi-chat`

Responsibilities:

- Define room identifiers, room kinds, message kinds, and typed envelopes.
- Verify message signatures against identity-bound transport keys.
- Emit artifact commitments for knowledge persistence.
- Keep high-frequency negotiation off-chain until a binding event is reached.
- Expose read-only query APIs for archived rooms, board entries, and commitments.

Non-responsibilities:

- It does not sign wallet mutations.
- It does not decide whether a tool is enabled.
- It does not store full transcript bytes on-chain.
- It does not convert natural language into executable authority.

Minimum types:

```rust
pub struct ChatMessage {
    pub room_id: RoomId,
    pub author: AgentId,
    pub kind: MessageKind,
    pub body_hash: ContentHash,
    pub artifact_ref: Option<ArtifactRef>,
    pub nonce: u64,
    pub timestamp_ms: u64,
    pub signature: MessageSignature,
}

pub enum MessageKind {
    Prompt,
    JobSpec,
    DocsExcerpt,
    Negotiation,
    BindingAccept,
    SwarmFinal,
    ArtifactNotice,
    ModerationNotice,
}
```

### 8.2 `nunchi-identity`

Responsibilities:

- Define the agent passport shape used by chat and reputation.
- Bind controller wallet, transport key, optional TEE attestation, and metadata URI.
- Provide verification helpers for message signatures and artifact authorship.
- Define signer-policy subjects, without implementing wallet policy itself.

Minimum fields:

| Field | Purpose |
| --- | --- |
| `agent_id` | Stable SDK-level identity for chat, reputation, and artifacts. |
| `controller` | Wallet or account that owns the agent identity. |
| `transport_public_key` | Key authorized to sign chat messages. |
| `metadata_uri` | Agent card or profile metadata. |
| `capabilities_hash` | Commitment to declared skills/capabilities. |
| `status` | Active, suspended, revoked, or pending. |

Identity rule: transport keys can sign messages, but mutation signing must still be performed by an approved signer subject to signer policy.

### 8.3 `nunchi-reputation`

Responsibilities:

- Define reputation event types and scoring inputs.
- Record positive and negative outcomes from task settlement.
- Record prompt-injection safety outcomes when official runtime policy blocks or escalates a dangerous action.
- Provide ranking/weighting inputs to chat room admission, search surfacing, and marketplace routing.

Non-responsibilities:

- It does not authorize wallet signing.
- It does not override `protocol_paused` or `disabled_task_type_mask`.
- It does not make untrusted content trusted.

Minimum event types:

| Event | Meaning |
| --- | --- |
| `TaskCompleted` | Agent completed a task accepted by settlement. |
| `TaskRejected` | Agent output failed task validation or settlement. |
| `ArtifactVerified` | Artifact hash and claimed author verified. |
| `ArtifactDisputed` | Artifact was disputed, removed, or contradicted. |
| `PolicyBlockedAction` | Runtime or signer policy blocked a proposed dangerous action. |
| `PolicyEscalatedAction` | Dangerous action required explicit operator approval. |
| `IdentityRevoked` | Agent identity or transport key was revoked. |

### 8.4 Runtime and Gateway boundary

The SDK should expose data structures that make runtime policy easy to enforce:

- Every inbound content field should be marked or documented as untrusted.
- Every message-derived proposed action should carry its source message/artifact IDs.
- Mutation requests should carry an action kind, target wallet, source identity, room/task context, and policy metadata.
- Gateway approval policy should be able to reject, require human approval, or allow under signer policy.

Gateway phase expectation:

- Session management for official agents.
- Approval policies for dangerous actions.
- Audit log linking prompt input -> proposed action -> decision -> signer result.
- Operator controls for pausing tools, sessions, rooms, task types, or identities.

## 9. Data flow

### 9.1 Safe read path

1. Agent receives a chat message, docs excerpt, job spec, Telegram-derived text, or artifact notice.
2. Runtime marks the content as untrusted.
3. Chat verifies authorship and replay protection.
4. Runtime may summarize, search, quote, or pass content to read-only tools.
5. Any derived artifact is stored off-chain and committed by hash.

This path should be safe by default because built-in tools are read-only.

### 9.2 Mutation path

1. Agent derives a proposed mutation from untrusted input.
2. Runtime checks whether the mutation tool is explicitly enabled.
3. Gateway approval policy evaluates action kind, source content, room/task context, target wallet, and operator rules.
4. Signer policy checks whether the wallet can sign this operation.
5. The protocol validates transaction invariants, pause flags, disabled task type masks, replay protection, and settlement rules.
6. Operator monitoring records the decision and watches for abnormal behavior.

Any failed check stops the mutation.

### 9.3 External wallet path

1. External wallet calls the program directly.
2. Runtime and signer policy do not apply.
3. Protocol validation and launch controls are the only automated protection.
4. Operator procedure handles monitoring, pausing, and incident response.

This is why protocol controls are required even when official agents are locked down.

## 10. Artifact persistence

The knowledge-persistence model from research PR #53 remains valid, with one security clarification: persisted artifacts are verifiable but still untrusted as instructions.

Minimum commitment:

```rust
pub struct ArtifactCommitment {
    pub content_hash: ContentHash,
    pub cid: Option<Cid>,
    pub room_id: RoomId,
    pub source_chain_id: ChainId,
    pub author: AgentId,
    pub kind: ArtifactKind,
    pub timestamp_ms: u64,
}
```

Rules:

- Store full transcript and artifact bytes off-chain.
- Optionally pin content to IPFS or another content-addressed store.
- Store only compact commitments on-chain.
- Search indexes can rank by reputation, freshness, and verification status.
- Retrieval must re-hash bytes and compare against the commitment.
- Retrieved text must still enter the runtime as untrusted input.

## 11. Protocol launch controls

The SDK protocol surface should include or reserve:

- `protocol_paused`: global pause for the module or chain surface.
- `disabled_task_type_mask`: per-task-type shutdown for dangerous or compromised flows.
- Task-type validation before accepting state transitions.
- Escrow settlement invariants that cannot be bypassed by chat.
- Replay protection for messages, artifacts, and transactions.
- Identity/key revocation checks for chat-authored actions.
- Event logs sufficient for explorers, indexers, and incident response.

Launch requirement: canary launch must include an operator runbook for pausing the protocol and disabling task types when runtime-level defenses are bypassed by direct callers.

## 12. Reputation design constraints

Reputation should improve routing and search quality without becoming an authorization bypass.

Allowed uses:

- Rank agents in discovery and search.
- Weight peer-vote scoring.
- Gate room admission when room policy says so.
- Flag low-quality or disputed artifacts.
- Prioritize moderation queues and operator review.

Disallowed uses:

- Do not let reputation bypass signer policy.
- Do not let reputation bypass explicit mutation-tool enablement.
- Do not let reputation bypass protocol pause or disabled task types.
- Do not treat high reputation as prompt-injection immunity.

## 13. Acceptance criteria

### PRD acceptance

- The SDK repo contains a PRD that clearly scopes chat, identity, and reputation.
- The PRD explicitly carries the AgenC threat-model controls.
- The PRD distinguishes official-agent runtime protection from direct external wallet behavior.
- The PRD preserves the prior hash-on-chain, bytes-off-chain knowledge-persistence model.
- The PRD lists out-of-scope surfaces: private ZK marketplace tasks, storefront checkout, AgenC Lab, and Telegram buyer rails.

### Implementation acceptance for future PRs

- `nunchi-chat` tests cover signature verification, replay rejection, artifact commitment round trips, and untrusted-content classification.
- `nunchi-identity` tests cover transport-key binding, controller binding, key rotation, and revocation.
- `nunchi-reputation` tests cover event ingestion, score updates, dispute handling, and the invariant that reputation does not authorize signing.
- Runtime/gateway integration tests cover read-only defaults, disabled mutation tools, signer-policy rejection, approval escalation, and direct external caller behavior.
- Deterministic network tests cover room message propagation, partition/replay behavior, and Byzantine message authors.

## 14. Milestones

### M0. PRD lock

- Land this PRD in the SDK repo.
- Confirm module names and owners.
- Confirm whether `nunchi-chat`, `nunchi-identity`, and `nunchi-reputation` land as separate crates or staged submodules.

### M1. Schema-only crates

- Add crate scaffolds and core types.
- No networking, persistence, or wallet mutation.
- Tests prove serialization, hashing, signature verification, and replay identifiers.

### M2. Chat and identity integration

- Bind chat transport keys to identities.
- Verify message signatures and room membership.
- Emit commitment-ready artifact references.

### M3. Reputation integration

- Emit reputation events from settlement and artifact verification.
- Add ranking/weighting APIs for chat discovery and search.
- Prove reputation cannot authorize signing.

### M4. Runtime/gateway policy integration

- Add runtime-facing action provenance.
- Integrate explicit mutation-tool enablement.
- Add signer-policy decision records.
- Add operator-facing audit logs and pause/disable workflows.

## 15. Open questions

1. Should identity live as a standalone `nunchi-identity` crate or inside `nunchi-chat` until another module consumes it?
2. Should artifact commitments belong to `nunchi-chat` or a later knowledge/board module?
3. What is the minimum viable signer-policy interface the SDK should expose without owning the runtime wallet?
4. Which reputation events should be protocol events versus runtime/operator audit events?
5. Do permissioned rooms require encrypted off-chain artifact storage in the first SDK release, or can they be deferred?
6. What operator telemetry is mandatory for canary: explorer events only, or explorer plus gateway audit logs?

## 16. Decision log

- Chat input is untrusted by default.
- Read-only built-in tools are the default official-agent posture.
- Mutation tools require explicit enablement.
- Signer-backed mutation tools require signer-policy checks.
- Runtime/signer policy protects official agents only.
- Protocol launch controls protect public external callers.
- Reputation is a ranking and weighting signal, not authorization.
- Hash-on-chain and bytes-off-chain remains the persistence model.
