use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_crypto::{PrivateKey, SignatureError};

use crate::{AccountSignature, Address, Authorization, MultisigPolicy, Operation, Transaction};

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestOperation(u8);

impl Write for TestOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for TestOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(u8::read(buf)?))
    }
}

impl EncodeSize for TestOperation {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Operation for TestOperation {
    const NAMESPACE: &'static [u8] = b"nunchi-common/test-operation";
}

#[test]
fn ed25519_transaction_signs_verifies_and_roundtrips() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let tx = Transaction::sign(&signer, 3, TestOperation(42));

    assert_eq!(tx.account_id, Address::external(&signer.public_key()));
    assert_eq!(tx.verify(), Ok(()));
    assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
}

#[test]
fn secp256r1_transaction_signs_verifies_and_roundtrips() {
    let signer = PrivateKey::secp256r1_from_seed(7);
    let tx = Transaction::sign(&signer, 3, TestOperation(42));

    assert_eq!(tx.account_id, Address::external(&signer.public_key()));
    assert_eq!(tx.verify(), Ok(()));
    assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
}

#[test]
fn transaction_verification_rejects_tampered_payload() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
    tx.payload.operation = TestOperation(43);

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::InvalidSignature)
    );
}

#[test]
fn transaction_verification_rejects_mismatched_signature_curve() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let other = PrivateKey::secp256r1_from_seed(9);
    let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
    tx.authorization = Authorization::Single {
        signer: Box::new(signer.public_key()),
        signature: other.sign(TestOperation::NAMESPACE, &tx.payload.encode()),
    };

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::IncompatibleKey)
    );
}

#[test]
fn transaction_decode_rejects_mismatched_signature_curve() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let other = PrivateKey::secp256r1_from_seed(9);
    let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
    tx.authorization = Authorization::Single {
        signer: Box::new(signer.public_key()),
        signature: other.sign(TestOperation::NAMESPACE, &tx.payload.encode()),
    };

    assert!(Transaction::<TestOperation>::decode(tx.encode().as_ref()).is_err());
}

#[test]
fn multisig_transaction_signs_verifies_and_roundtrips() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let bob = PrivateKey::secp256r1_from_seed(2);
    let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);
    let tx = Transaction::sign_multisig(account_id, policy, &[&alice, &bob], 0, TestOperation(42));

    assert_eq!(tx.verify(), Ok(()));
    assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
}

#[test]
fn multisig_authorization_rejects_non_canonical_signature_order() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let bob = PrivateKey::secp256r1_from_seed(2);
    let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);
    let mut tx =
        Transaction::sign_multisig(account_id, policy, &[&alice, &bob], 0, TestOperation(42));

    let Authorization::Multisig { signatures, .. } = &mut tx.authorization else {
        panic!("expected multisig authorization");
    };
    signatures.reverse();

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::IncompatibleKey)
    );
}

#[test]
fn single_authorization_rejects_wrong_address() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let bob = PrivateKey::ed25519_from_seed(2);
    let mut tx = Transaction::sign(&alice, 0, TestOperation(42));
    tx.account_id = Address::external(&bob.public_key());

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::IncompatibleKey)
    );
}

#[test]
fn single_signature_cannot_be_repackaged_as_multisig_authorization() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let mut tx = Transaction::sign(&alice, 0, TestOperation(42));
    let Authorization::Single { signer, signature } = tx.authorization else {
        panic!("expected single authorization");
    };
    let policy = MultisigPolicy::new(1, vec![(*signer).clone()]).unwrap();
    tx.authorization = Authorization::Multisig {
        policy,
        signatures: vec![AccountSignature {
            signer: *signer,
            signature,
        }],
    };

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::InvalidSignature)
    );
}

#[test]
fn multisig_authorization_supports_policy_rotation_under_stable_address() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let bob = PrivateKey::secp256r1_from_seed(2);
    let initial = MultisigPolicy::new(1, vec![alice.public_key()]).unwrap();
    let rotated = MultisigPolicy::new(1, vec![bob.public_key()]).unwrap();
    let account_id = Address::multisig(&initial);

    let tx = Transaction::sign_multisig(account_id, rotated, &[&bob], 0, TestOperation(42));

    assert_eq!(tx.verify(), Ok(()));
}

#[test]
fn multisig_1_of_2_with_one_signer_succeeds() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let bob = PrivateKey::secp256r1_from_seed(2);
    let policy = MultisigPolicy::new(1, vec![alice.public_key(), bob.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);

    // Sign with only alice (threshold is 1)
    let tx = Transaction::sign_multisig(account_id, policy, &[&alice], 0, TestOperation(42));
    assert_eq!(tx.verify(), Ok(()));
}

#[test]
fn multisig_2_of_3_with_exactly_2_signers_succeeds() {
    let k1 = PrivateKey::ed25519_from_seed(1);
    let k2 = PrivateKey::ed25519_from_seed(2);
    let k3 = PrivateKey::ed25519_from_seed(3);
    let policy =
        MultisigPolicy::new(2, vec![k1.public_key(), k2.public_key(), k3.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);

    let tx = Transaction::sign_multisig(account_id, policy, &[&k1, &k3], 0, TestOperation(42));
    assert_eq!(tx.verify(), Ok(()));
}

#[test]
fn multisig_2_of_3_below_threshold_fails() {
    let k1 = PrivateKey::ed25519_from_seed(1);
    let k2 = PrivateKey::ed25519_from_seed(2);
    let k3 = PrivateKey::ed25519_from_seed(3);
    let policy =
        MultisigPolicy::new(2, vec![k1.public_key(), k2.public_key(), k3.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);

    // Sign with only 1 key (below threshold of 2)
    let tx = Transaction::sign_multisig(account_id, policy, &[&k1], 0, TestOperation(42));
    assert_eq!(tx.verify(), Err(SignatureError::InvalidSignature));
}

#[test]
fn multisig_with_zero_signatures_fails() {
    let k1 = PrivateKey::ed25519_from_seed(1);
    let k2 = PrivateKey::ed25519_from_seed(2);
    let policy = MultisigPolicy::new(1, vec![k1.public_key(), k2.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);

    // Provide no signatures at all
    let tx =
        Transaction::sign_multisig(account_id, policy, &[] as &[&PrivateKey], 0, TestOperation(42));
    assert_eq!(tx.verify(), Err(SignatureError::InvalidSignature));
}

#[test]
fn multisig_non_member_signer_rejected() {
    let k1 = PrivateKey::ed25519_from_seed(1);
    let k2 = PrivateKey::ed25519_from_seed(2);
    let outsider = PrivateKey::ed25519_from_seed(3);
    let policy = MultisigPolicy::new(1, vec![k1.public_key(), k2.public_key()]).unwrap();
    let account_id = Address::multisig(&policy);

    // outsider is not in the policy
    let tx = Transaction::sign_multisig(account_id, policy, &[&outsider], 0, TestOperation(42));
    assert_eq!(tx.verify(), Err(SignatureError::IncompatibleKey));
}

#[test]
fn transaction_digest_is_deterministic() {
    let sk = PrivateKey::ed25519_from_seed(1);
    let tx1 = Transaction::sign(&sk, 0, TestOperation(42));
    let tx2 = Transaction::sign(&sk, 0, TestOperation(42));
    assert_eq!(tx1.digest(), tx2.digest());

    // Different nonce produces a different digest
    let tx3 = Transaction::sign(&sk, 1, TestOperation(42));
    assert_ne!(tx1.digest(), tx3.digest());

    // Different operation produces a different digest
    let tx4 = Transaction::sign(&sk, 0, TestOperation(99));
    assert_ne!(tx1.digest(), tx4.digest());
}
