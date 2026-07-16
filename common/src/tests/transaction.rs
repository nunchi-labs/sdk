use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_crypto::PrivateKey;

use crate::{AccountSignature, Address, Authorization, MultisigPolicy, Operation, Transaction, DEFAULT_CHAIN_ID};

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
    let tx = Transaction::sign(&signer, DEFAULT_CHAIN_ID, 3, TestOperation(42));

    assert_eq!(tx.account_id, Address::external(&signer.public_key()));
    assert_eq!(tx.verify(), Ok(()));
    assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
}

#[test]
fn secp256r1_transaction_signs_verifies_and_roundtrips() {
    let signer = PrivateKey::secp256r1_from_seed(7);
    let tx = Transaction::sign(&signer, DEFAULT_CHAIN_ID, 3, TestOperation(42));

    assert_eq!(tx.account_id, Address::external(&signer.public_key()));
    assert_eq!(tx.verify(), Ok(()));
    assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
}

#[test]
fn transaction_verification_rejects_tampered_payload() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let mut tx = Transaction::sign(&signer, DEFAULT_CHAIN_ID, 3, TestOperation(42));
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
    let mut tx = Transaction::sign(&signer, DEFAULT_CHAIN_ID, 3, TestOperation(42));
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
    let mut tx = Transaction::sign(&signer, DEFAULT_CHAIN_ID, 3, TestOperation(42));
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
    let tx = Transaction::sign_multisig(account_id, policy, &[&alice, &bob], DEFAULT_CHAIN_ID, 0, TestOperation(42));

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
        Transaction::sign_multisig(account_id, policy, &[&alice, &bob], DEFAULT_CHAIN_ID, 0, TestOperation(42));

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
    let mut tx = Transaction::sign(&alice, DEFAULT_CHAIN_ID, 0, TestOperation(42));
    tx.account_id = Address::external(&bob.public_key());

    assert_eq!(
        tx.verify(),
        Err(nunchi_crypto::SignatureError::IncompatibleKey)
    );
}

#[test]
fn single_signature_cannot_be_repackaged_as_multisig_authorization() {
    let alice = PrivateKey::ed25519_from_seed(1);
    let mut tx = Transaction::sign(&alice, DEFAULT_CHAIN_ID, 0, TestOperation(42));
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
fn transaction_verification_rejects_cross_chain_replay() {
    let signer = PrivateKey::ed25519_from_seed(7);
    let tx = Transaction::sign(&signer, 1, 3, TestOperation(42));
    let mut replay = tx.clone();
    replay.payload.chain_id = 2;

    assert_eq!(
        replay.verify(),
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

    let tx = Transaction::sign_multisig(account_id, rotated, &[&bob], DEFAULT_CHAIN_ID, 0, TestOperation(42));

    assert_eq!(tx.verify(), Ok(()));
}
