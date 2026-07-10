# Queen One V1 — Open Questions

Every assumption the [V1 module map](v1-module-map.md) rests on, phrased as a question with an owner. Owners: **Ian** = event infrastructure, **Erik** = ML/data, **Fred** = billing, **Namek** = access/architecture. Questions marked **[Jul 17 gate]** must be answered at the discovery sign-off or the schedule slips.

## Ian — event infrastructure

1. **[Jul 17 gate]** When do the dedicated Pub/Sub subscription, IAM service account, and a BigQuery dataset slot land? Access hard-blocks the transactor, deployment, and staging integration tracks — we need it by ~Jul 24 at the latest.
2. **[Jul 17 gate]** Can we get your proto definitions under a CI-pinnable import (buf registry or repo access) so the normalizer builds against pinned schema versions? Assumed yes in the design.
3. **[Jul 17 gate]** Do Infobip delivery receipts flow on the event bus, or webhook-only into your system? This decides whether undelivered-send cost back-out is an event-driven adjustment record (in-product) or a reconciliation-only output (see D4 in the module map).
4. What are the exact CloudEvent `type` strings for the send events (SMS/email), `llm_inference_call`, and the AI decision events? We assumed illustrative names.
5. Can we consume the **staging** topic during the last week of August as a canary against the Labor-Day validation-layer release? Assumed yes; it is the main de-risking step for go-live week.
6. Is ~7-day retention confirmed on the new route you create for us? The failure model treats Pub/Sub as a 7-day buffer.
7. What is the Kafka Connect fan-out lag under load? Our freshness numbers assume it is small relative to our own pipeline.
8. Confirm: you create the subscription and grant our service account `roles/pubsub.subscriber` (plus DLQ publish and `bigquery.dataViewer`), so our posture stays cleanly read-only. We would like this sentence in the integration doc.

## Erik — ML / data

9. When does the training cost event (sites involved, rows per site, duration, data size, instance) land in the schema project, and who on your side reviews our proposed message shape ([spend-event-schema-v0.proto](spend-event-schema-v0.proto), `TrainingCost`)? Until it ships, training servers stay a registered untracked source.
10. Which prediction paths emit AI decision events **today**? We need the honest list to seed the coverage monitor's expectations (you asked for exactly this alerting — we need the baseline to alert against).
11. ETA for the instance/duration fields being added to prediction events?
12. What per-source minimum event rates / quiet windows should trigger a Slack alert without being noisy? (Straw man: alert if a seeded source is silent for 6h during business hours.)
13. Is there a labeling plan for BigQuery/Dataform jobs on your side? Labels are the prerequisite for ever pricing that spend into the rate card rather than leaving it dark.

## Fred — billing

14. Green Arrow email rate card: the actual flat rates and their effective dates, so `SetCostParams` v1 can be loaded with real numbers.
15. What currency is the Infobip combined price delivered in, and is it already normalized by your enrichment? The ledger stores micro-USD only; the normalizer must never guess conversions.
16. Does September invoicing need **provable historical** site→agency/customer attribution from the ledger alone ("site X belonged to agency Y in March")? V1 ships the mapping as versioned config; a yes here triggers the on-ledger attribution registry fast-follow.
17. Is a BigQuery dataset the right V1 read interface for Cratchit (it reads Dataform materialized views today, so we assumed yes)? V1 is read-only for Cratchit either way.
18. ETA for invoice sent/paid/voided events — reserved as the `RecordInvoiceEvent` extension point, not built in V1.

## Namek — access / architecture

19. **[Jul 17 gate]** Which GCP project(s) do our components live in — one of yours (your stated preference) or a dedicated project you own and we operate in? Decides Secret Manager custody, VPC layout, and whose CI deploys the transactor.
20. Ops ownership: who is on call for the validators and the ingest binary? Our proposal: we operate through production + 30 days, then hand over with a runbook.
21. PII/DLP sign-off: staging events are sampled from production, and our ledger is append-only and unprunable. We need your explicit confirmation that post-enrichment events contain only opaque identifiers before staging integration begins.
22. Confirm V1 scope excludes per-user metering: we deliberately store **no** user-level identifiers on the ledger (GDPR posture for append-only replicated state). If per-user rollups become a requirement, the design answer is keyed hashing with off-ledger key custody — a scope change, not a tweak.
23. Validator footprint approval: 5 nodes (GCE, raw TCP/UDP 30000 between them, private VPC RPC) with 4 TB NVMe-class disk each, plus one small VM for the ingest binary. State growth is ~9–12 GB/day/validator at current volume.
24. Private connectivity between the ingest binary and the validators (VPC peering / Private Service Connect) — which pattern does your platform team prefer?

## Internal (Nunchi — not for Queen One)

25. **Burst SLO decision:** at 100x burst (12.7k events/s) the observed configuration ingests at ~2.5–4.1k events/s and drains the backlog from Pub/Sub afterwards (a 10-minute full burst clears in ~42 minutes). Is delayed-inclusion-under-burst acceptable for V1, or must `max_message_size` be raised (>= 8 MiB) and validated in the load test? Owner: Jacob.
26. **Do not restate "25k TPS @ 300 ms" in shareable artifacts.** It reproduces only with 45-byte toy records; canonical records give 2.5–4.1k events/s on the observed config. The load test (build item 9) produces the number we can stand behind. Owner: Jack/Jacob.
27. Initial `micro_usd_per_token` rate and who sets/rotates it (this is the client-visible "token" denomination). Owner: Jack.
28. Does the Ethena 10% revenue share apply to Queen One licensing revenue? (It is scoped to Hyperliquid-derived revenue; assumed no.) Owner: Jack.
29. Validator count contradiction: internal devnet runs 4; production ruling is >= 5. The 5-node DKG resharing rehearsal before Sep 4 is the gate. Owner: Jacob.
30. Devnet key hygiene: validator private keys and DKG shares are committed in plaintext in the devnet repo — treat as burned; production keys are generated fresh into Secret Manager and never touch a repo. Owner: Jacob.
