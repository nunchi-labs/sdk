use commonware_codec::{DecodeExt, Encode};
use nunchi_common::MAX_MULTISIG_SIGNERS;

use crate::account::{
    external_account_id, multisig_account_id, Account, AccountPolicy, AccountPolicyError,
    AccountType, MultisigPolicy, PrivateKey,
};

#[test]
fn account_roundtrips_with_external_id() {
    let id = external_account_id(&PrivateKey::ed25519_from_seed(1).public_key());
    let account = Account::new(id, AccountType::External, 42);

    assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
}

#[test]
fn account_roundtrips_with_multisig_kind() {
    let key = PrivateKey::secp256r1_from_seed(1);
    let policy = MultisigPolicy::new(1, vec![key.public_key()]).unwrap();
    let id = multisig_account_id(&policy);
    let account = Account::new(id, AccountType::Multisig, 42);

    assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
}

#[test]
fn multisig_policy_canonicalizes_signer_order() {
    let ed = PrivateKey::ed25519_from_seed(1).public_key();
    let secp = PrivateKey::secp256r1_from_seed(2).public_key();

    let first = MultisigPolicy::new(2, vec![ed.clone(), secp.clone()]).unwrap();
    let second = MultisigPolicy::new(2, vec![secp, ed]).unwrap();

    assert_eq!(first, second);
    assert_eq!(multisig_account_id(&first), multisig_account_id(&second));
}

#[test]
fn multisig_policy_rejects_invalid_thresholds() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();

    assert_eq!(
        MultisigPolicy::new(0, vec![signer.clone()]),
        Err(AccountPolicyError::ZeroThreshold)
    );
    assert_eq!(
        MultisigPolicy::new(2, vec![signer]),
        Err(AccountPolicyError::ThresholdExceedsSigners {
            threshold: 2,
            signers: 1
        })
    );
}

#[test]
fn multisig_policy_rejects_duplicate_signers() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();

    assert_eq!(
        MultisigPolicy::new(1, vec![signer.clone(), signer]),
        Err(AccountPolicyError::DuplicateSigner)
    );
}

#[test]
fn multisig_policy_rejects_too_many_signers() {
    let signers = (0..=MAX_MULTISIG_SIGNERS)
        .map(|seed| PrivateKey::ed25519_from_seed(seed as u64).public_key())
        .collect();

    assert_eq!(
        MultisigPolicy::new(1, signers),
        Err(AccountPolicyError::TooManySigners {
            max: MAX_MULTISIG_SIGNERS,
            actual: MAX_MULTISIG_SIGNERS + 1
        })
    );
}

#[test]
fn account_policy_roundtrips_with_mixed_curve_multisig() {
    let policy = AccountPolicy::multisig(
        2,
        vec![
            PrivateKey::ed25519_from_seed(1).public_key(),
            PrivateKey::secp256r1_from_seed(2).public_key(),
        ],
    )
    .unwrap();

    assert_eq!(
        AccountPolicy::decode(policy.encode().as_ref()).unwrap(),
        policy
    );
}
