use std::collections::BTreeMap;

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{ed25519, sha256::Digest, Signer as _};
use commonware_runtime::Runner as _;
use nunchi_common::{state_db::StateStore, Event, EventBuffer, StateError};
use nunchi_crypto::PrivateKey;

use crate::{
    db::AuthorityDB, types::normalize, AuthorityError, AuthorityLedger, AuthorityOperation,
    EpochNumber, MultisigPolicy, RegistryChange, Transaction, ValidatorId, MAX_EPOCH_LOOKAHEAD,
};

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<Digest, Vec<u8>>,
}

impl StateStore for MemoryState {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, value);
    }

    fn remove(&mut self, key: Digest) {
        self.values.remove(&key);
    }
}

fn owner(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn validator(seed: u64) -> ValidatorId {
    ed25519::PrivateKey::from_seed(seed).public_key()
}

fn policy(owners: &[PrivateKey], threshold: u16) -> MultisigPolicy {
    MultisigPolicy {
        owners: owners.iter().map(PrivateKey::public_key).collect(),
        threshold,
    }
}

fn attr(event: &Event, key: &[u8]) -> Bytes {
    event
        .attributes
        .iter()
        .find(|attribute| attribute.key.as_ref() == key)
        .unwrap_or_else(|| panic!("missing event attribute: {}", String::from_utf8_lossy(key)))
        .value
        .clone()
}

fn assert_event(event: &Event, kind: &[u8], keys: &[&[u8]]) {
    assert_eq!(event.module.as_ref(), b"authority");
    assert_eq!(event.kind.as_ref(), kind);
    assert_eq!(event.version, 1);
    assert_eq!(event.attributes.len(), keys.len());
    for (attribute, expected) in event.attributes.iter().zip(keys.iter()) {
        assert_eq!(attribute.key.as_ref(), *expected);
    }
}

async fn configured() -> (
    AuthorityLedger<MemoryState>,
    Vec<PrivateKey>,
    Vec<ValidatorId>,
) {
    let owners = vec![owner(1), owner(2), owner(3)];
    let validators = vec![validator(10), validator(11)];
    let configure = Transaction::sign(
        &owners[0],
        0,
        AuthorityOperation::Configure {
            policy: policy(&owners, 2),
            initial_validators: validators.clone(),
            epoch: 0,
        },
    );
    let mut ledger = AuthorityLedger::new(MemoryState::default());
    ledger.apply_transaction(&configure, 0).await.unwrap();
    (ledger, owners, validators)
}

async fn submit(
    ledger: &mut AuthorityLedger<MemoryState>,
    owner: &PrivateKey,
    operation: AuthorityOperation,
    current_epoch: EpochNumber,
) -> Result<(), AuthorityError> {
    let nonce = ledger.db().nonce(&owner.public_key()).await.unwrap();
    ledger
        .apply_transaction(&Transaction::sign(owner, nonce, operation), current_epoch)
        .await
}

async fn govern(
    ledger: &mut AuthorityLedger<MemoryState>,
    owners: &[PrivateKey],
    change: RegistryChange,
    effective_epoch: EpochNumber,
    current_epoch: EpochNumber,
) {
    let proposal = crate::proposal_id(&change, effective_epoch);
    submit(
        ledger,
        &owners[0],
        AuthorityOperation::Propose {
            change,
            effective_epoch,
        },
        current_epoch,
    )
    .await
    .unwrap();
    submit(
        ledger,
        &owners[1],
        AuthorityOperation::Approve { proposal },
        current_epoch,
    )
    .await
    .unwrap();
    submit(
        ledger,
        &owners[2],
        AuthorityOperation::Execute { proposal },
        current_epoch,
    )
    .await
    .unwrap();
}

#[test]
fn transactions_emit_authority_events() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let owners = vec![owner(1), owner(2), owner(3)];
        let validators = vec![validator(10), validator(11)];
        let mut ledger = AuthorityLedger::new(MemoryState::default());

        let configure = Transaction::sign(
            &owners[0],
            0,
            AuthorityOperation::Configure {
                policy: policy(&owners, 2),
                initial_validators: validators,
                epoch: 0,
            },
        );
        let mut events = EventBuffer::default();
        ledger
            .apply_transaction_with_events(&configure, 0, &mut events)
            .await
            .expect("configure");
        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        let configured_policy = ledger.policy().await.unwrap().unwrap();
        let initial_validators = ledger.db().validator_index().await.unwrap();
        assert_event(
            event,
            b"configured",
            &[b"signer", b"policy", b"initial_validators", b"epoch"],
        );
        assert_eq!(attr(event, b"signer"), owners[0].public_key().encode());
        assert_eq!(attr(event, b"policy"), configured_policy.encode());
        assert_eq!(
            attr(event, b"initial_validators"),
            initial_validators.encode()
        );
        assert_eq!(attr(event, b"epoch"), 0u64.encode());

        let added = validator(12);
        let add = RegistryChange::AddValidator {
            validator: added.clone(),
        };
        let add_proposal = crate::proposal_id(&add, 3);
        let mut events = EventBuffer::default();
        let tx = Transaction::sign(
            &owners[0],
            1,
            AuthorityOperation::Propose {
                change: add.clone(),
                effective_epoch: 3,
            },
        );
        ledger
            .apply_transaction_with_events(&tx, 3, &mut events)
            .await
            .expect("propose add");
        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_event(
            event,
            b"proposal_created",
            &[b"proposal", b"proposer", b"change", b"effective_epoch"],
        );
        assert_eq!(attr(event, b"proposal"), add_proposal.encode());
        assert_eq!(attr(event, b"proposer"), owners[0].public_key().encode());
        assert_eq!(attr(event, b"change"), add.encode());
        assert_eq!(attr(event, b"effective_epoch"), 3u64.encode());

        let tx = Transaction::sign(
            &owners[1],
            0,
            AuthorityOperation::Approve {
                proposal: add_proposal,
            },
        );
        let mut events = EventBuffer::default();
        ledger
            .apply_transaction_with_events(&tx, 3, &mut events)
            .await
            .expect("approve add");
        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_event(event, b"proposal_approved", &[b"proposal", b"approver"]);
        assert_eq!(attr(event, b"proposal"), add_proposal.encode());
        assert_eq!(attr(event, b"approver"), owners[1].public_key().encode());

        let tx = Transaction::sign(
            &owners[2],
            0,
            AuthorityOperation::Execute {
                proposal: add_proposal,
            },
        );
        let mut events = EventBuffer::default();
        ledger
            .apply_transaction_with_events(&tx, 3, &mut events)
            .await
            .expect("execute add");
        assert_eq!(events.len(), 2);
        let event = &events.events()[0];
        assert_event(
            event,
            b"proposal_executed",
            &[b"proposal", b"executor", b"effective_epoch"],
        );
        assert_eq!(attr(event, b"proposal"), add_proposal.encode());
        assert_eq!(attr(event, b"executor"), owners[2].public_key().encode());
        assert_eq!(attr(event, b"effective_epoch"), 3u64.encode());
        let event = &events.events()[1];
        assert_event(
            event,
            b"validator_added",
            &[
                b"validator",
                b"effective_epoch",
                b"player_from",
                b"dealer_from",
            ],
        );
        assert_eq!(attr(event, b"validator"), added.encode());
        assert_eq!(attr(event, b"effective_epoch"), 3u64.encode());
        assert_eq!(attr(event, b"player_from"), 4u64.encode());
        assert_eq!(attr(event, b"dealer_from"), 5u64.encode());

        let remove = RegistryChange::RemoveValidator {
            validator: added.clone(),
        };
        let remove_proposal = crate::proposal_id(&remove, 4);
        let tx = Transaction::sign(
            &owners[0],
            2,
            AuthorityOperation::Propose {
                change: remove,
                effective_epoch: 4,
            },
        );
        ledger
            .apply_transaction(&tx, 4)
            .await
            .expect("propose remove");
        let tx = Transaction::sign(
            &owners[1],
            1,
            AuthorityOperation::Approve {
                proposal: remove_proposal,
            },
        );
        ledger
            .apply_transaction(&tx, 4)
            .await
            .expect("approve remove");
        let tx = Transaction::sign(
            &owners[2],
            1,
            AuthorityOperation::Execute {
                proposal: remove_proposal,
            },
        );
        let mut events = EventBuffer::default();
        ledger
            .apply_transaction_with_events(&tx, 4, &mut events)
            .await
            .expect("execute remove");
        assert_eq!(events.len(), 2);
        let event = &events.events()[0];
        assert_event(
            event,
            b"proposal_executed",
            &[b"proposal", b"executor", b"effective_epoch"],
        );
        assert_eq!(attr(event, b"proposal"), remove_proposal.encode());
        assert_eq!(attr(event, b"executor"), owners[2].public_key().encode());
        assert_eq!(attr(event, b"effective_epoch"), 4u64.encode());
        let event = &events.events()[1];
        assert_event(
            event,
            b"validator_removed",
            &[b"validator", b"effective_epoch", b"removed_from"],
        );
        assert_eq!(attr(event, b"validator"), added.encode());
        assert_eq!(attr(event, b"effective_epoch"), 4u64.encode());
        assert_eq!(attr(event, b"removed_from"), 5u64.encode());
    });
}

#[test]
fn configure_indexes_initial_dealers_and_players() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (ledger, _, validators) = configured().await;
        let registry = ledger.epoch_registry(0).await.unwrap().unwrap();
        assert_eq!(registry.players, validators);
        assert_eq!(registry.dealers, validators);
    });
}

#[test]
fn add_validator_becomes_player_before_dealer() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, validators) = configured().await;
        let added = validator(12);
        let change = RegistryChange::AddValidator {
            validator: added.clone(),
        };
        govern(&mut ledger, &owners, change, 3, 3).await;

        let epoch_4 = ledger.epoch_registry(4).await.unwrap().unwrap();
        let epoch_5 = ledger.epoch_registry(5).await.unwrap().unwrap();
        let mut expected_players = validators.clone();
        expected_players.push(added.clone());
        expected_players = normalize(expected_players);

        assert_eq!(epoch_4.players, expected_players);
        assert_eq!(epoch_4.dealers, validators);
        assert_eq!(epoch_5.players, expected_players);
        assert_eq!(epoch_5.dealers, expected_players);
    });
}

#[test]
fn remove_validator_drops_from_next_epoch() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, validators) = configured().await;
        let removed = validators[0].clone();
        let change = RegistryChange::RemoveValidator {
            validator: removed.clone(),
        };
        govern(&mut ledger, &owners, change, 2, 2).await;

        let epoch_3 = ledger.epoch_registry(3).await.unwrap().unwrap();
        assert!(!epoch_3.players.contains(&removed));
        assert!(!epoch_3.dealers.contains(&removed));
    });
}

#[test]
fn change_refreshes_previously_materialized_epochs() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, validators) = configured().await;

        let added = validator(12);
        let add = RegistryChange::AddValidator {
            validator: added.clone(),
        };
        govern(&mut ledger, &owners, add, 3, 3).await;

        let removed = validators[0].clone();
        let remove = RegistryChange::RemoveValidator {
            validator: removed.clone(),
        };
        govern(&mut ledger, &owners, remove, 3, 3).await;

        for epoch in [4, 5] {
            let registry = ledger.epoch_registry(epoch).await.unwrap().unwrap();
            assert!(!registry.players.contains(&removed));
            assert!(!registry.dealers.contains(&removed));
            assert!(registry.players.contains(&added));
        }
    });
}

#[test]
fn removed_validator_can_be_readded() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, validators) = configured().await;
        let target = validators[0].clone();

        let remove = RegistryChange::RemoveValidator {
            validator: target.clone(),
        };
        govern(&mut ledger, &owners, remove, 0, 0).await;
        let epoch_1 = ledger.epoch_registry(1).await.unwrap().unwrap();
        assert!(!epoch_1.players.contains(&target));

        let add = RegistryChange::AddValidator {
            validator: target.clone(),
        };
        govern(&mut ledger, &owners, add, 1, 1).await;

        let epoch_2 = ledger.epoch_registry(2).await.unwrap().unwrap();
        let epoch_3 = ledger.epoch_registry(3).await.unwrap().unwrap();
        assert!(epoch_2.players.contains(&target));
        assert!(!epoch_2.dealers.contains(&target));
        assert!(epoch_3.players.contains(&target));
        assert!(epoch_3.dealers.contains(&target));
    });
}

#[test]
fn execute_after_effective_epoch_is_rejected() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, _) = configured().await;
        let change = RegistryChange::AddValidator {
            validator: validator(12),
        };
        let proposal = crate::proposal_id(&change, 1);
        submit(
            &mut ledger,
            &owners[0],
            AuthorityOperation::Propose {
                change,
                effective_epoch: 1,
            },
            1,
        )
        .await
        .unwrap();
        submit(
            &mut ledger,
            &owners[1],
            AuthorityOperation::Approve { proposal },
            1,
        )
        .await
        .unwrap();

        let result = submit(
            &mut ledger,
            &owners[2],
            AuthorityOperation::Execute { proposal },
            2,
        )
        .await;
        assert_eq!(result, Err(AuthorityError::InvalidEpoch));
    });
}

#[test]
fn propose_outside_epoch_window_is_rejected() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, _) = configured().await;
        for effective_epoch in [0, 2 + MAX_EPOCH_LOOKAHEAD] {
            let result = submit(
                &mut ledger,
                &owners[0],
                AuthorityOperation::Propose {
                    change: RegistryChange::AddValidator {
                        validator: validator(12),
                    },
                    effective_epoch,
                },
                1,
            )
            .await;
            assert_eq!(result, Err(AuthorityError::InvalidEpoch));
        }
    });
}

#[test]
fn duplicate_approval_is_rejected() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, _) = configured().await;
        let change = RegistryChange::AddValidator {
            validator: validator(12),
        };
        let proposal = crate::proposal_id(&change, 0);
        submit(
            &mut ledger,
            &owners[0],
            AuthorityOperation::Propose {
                change,
                effective_epoch: 0,
            },
            0,
        )
        .await
        .unwrap();

        let result = submit(
            &mut ledger,
            &owners[0],
            AuthorityOperation::Approve { proposal },
            0,
        )
        .await;
        assert_eq!(result, Err(AuthorityError::ApprovalAlreadyRecorded));
    });
}

#[test]
fn execute_below_threshold_is_rejected() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, _) = configured().await;
        let change = RegistryChange::AddValidator {
            validator: validator(12),
        };
        let proposal = crate::proposal_id(&change, 0);
        submit(
            &mut ledger,
            &owners[0],
            AuthorityOperation::Propose {
                change,
                effective_epoch: 0,
            },
            0,
        )
        .await
        .unwrap();

        let result = submit(
            &mut ledger,
            &owners[1],
            AuthorityOperation::Execute { proposal },
            0,
        )
        .await;
        assert_eq!(
            result,
            Err(AuthorityError::InsufficientApprovals {
                required: 2,
                actual: 1,
            })
        );
    });
}

#[test]
fn nonce_mismatch_is_rejected() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let (mut ledger, owners, _) = configured().await;
        let result = ledger
            .apply_transaction(
                &Transaction::sign(
                    &owners[0],
                    5,
                    AuthorityOperation::Propose {
                        change: RegistryChange::AddValidator {
                            validator: validator(12),
                        },
                        effective_epoch: 0,
                    },
                ),
                0,
            )
            .await;
        assert_eq!(
            result,
            Err(AuthorityError::NonceMismatch {
                owner: Box::new(owners[0].public_key()),
                expected: 1,
                actual: 5,
            })
        );
    });
}
