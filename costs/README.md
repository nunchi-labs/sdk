# nunchi-costs

`nunchi-costs` is an account-scoped custodial credit-accounting primitive for
Nunchi chains. It has no dependency on any product UI, billing provider,
event schema, data warehouse, accounting system, or client wallet.

The module owns only opaque `account_id` account state:

- active/suspended accounts, available credit, and reserved credit;
- backend writer capabilities (`Admin`, `Ingest`, `Billing`, `Adjustment`);
- idempotent top-ups, grants, reversals, normalized spend, and reservations;
- a registry for untracked/shared sources that has no automatic debit path;
- staged, atomic effective-at rate-card changes with global and exact-account
  precedence; and
- finality-outbox envelopes derived after a transaction is finalized.

All chain writes require an allowlisted backend signer. Client applications and
end users never receive a chain key or submit a raw transaction.

## Local proof

```sh
cargo test -p nunchi-costs
```

The test suite validates rate activation, payment-rail top-ups, reservation and
settlement, duplicate-event suppression, post-finality journal facts, stored
value provenance, refunds, and untracked-cost zero-debit behavior.

## Deliberate boundaries

This module is not a billing-provider integration. External event decoding,
pricing-policy approval, user interfaces, credentials, and production adapters
remain outside the ledger. Applications must preserve the module's idempotency,
authorization, provenance, and finality semantics.
