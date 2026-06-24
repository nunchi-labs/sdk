use bytes::Bytes;
use commonware_codec::Encode;
use nunchi_common::{Event, EventAttribute};

use crate::{EpochNumber, MultisigPolicy, OwnerId, ProposalId, RegistryChange, ValidatorId};

const MODULE: &[u8] = b"authority";
const VERSION: u16 = 1;

pub(crate) fn configured(
    signer: &OwnerId,
    policy: &MultisigPolicy,
    initial_validators: &Vec<ValidatorId>,
    epoch: &EpochNumber,
) -> Event {
    event(
        b"configured",
        vec![
            attr(b"signer", signer),
            attr(b"policy", policy),
            attr(b"initial_validators", initial_validators),
            attr(b"epoch", epoch),
        ],
    )
}

pub(crate) fn proposal_created(
    proposal: &ProposalId,
    proposer: &OwnerId,
    change: &RegistryChange,
    effective_epoch: &EpochNumber,
) -> Event {
    event(
        b"proposal_created",
        vec![
            attr(b"proposal", proposal),
            attr(b"proposer", proposer),
            attr(b"change", change),
            attr(b"effective_epoch", effective_epoch),
        ],
    )
}

pub(crate) fn proposal_approved(proposal: &ProposalId, approver: &OwnerId) -> Event {
    event(
        b"proposal_approved",
        vec![attr(b"proposal", proposal), attr(b"approver", approver)],
    )
}

pub(crate) fn proposal_executed(
    proposal: &ProposalId,
    executor: &OwnerId,
    effective_epoch: &EpochNumber,
) -> Event {
    event(
        b"proposal_executed",
        vec![
            attr(b"proposal", proposal),
            attr(b"executor", executor),
            attr(b"effective_epoch", effective_epoch),
        ],
    )
}

pub(crate) fn validator_added(
    validator: &ValidatorId,
    effective_epoch: &EpochNumber,
    player_from: &EpochNumber,
    dealer_from: &EpochNumber,
) -> Event {
    event(
        b"validator_added",
        vec![
            attr(b"validator", validator),
            attr(b"effective_epoch", effective_epoch),
            attr(b"player_from", player_from),
            attr(b"dealer_from", dealer_from),
        ],
    )
}

pub(crate) fn validator_removed(
    validator: &ValidatorId,
    effective_epoch: &EpochNumber,
    removed_from: &EpochNumber,
) -> Event {
    event(
        b"validator_removed",
        vec![
            attr(b"validator", validator),
            attr(b"effective_epoch", effective_epoch),
            attr(b"removed_from", removed_from),
        ],
    )
}

fn event(kind: &'static [u8], attributes: Vec<EventAttribute>) -> Event {
    Event::new(
        Bytes::from_static(MODULE),
        Bytes::from_static(kind),
        VERSION,
        attributes,
    )
}

fn attr<T: Encode>(key: &'static [u8], value: &T) -> EventAttribute {
    EventAttribute::new(Bytes::from_static(key), value.encode())
}
