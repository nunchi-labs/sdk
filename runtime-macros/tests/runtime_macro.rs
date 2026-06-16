use std::collections::BTreeMap;

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::sha256::Digest;
use futures::executor::block_on;
use nunchi_common::{PoolTransaction, Runtime, RuntimeContext, StateError, StateStore};

nunchi_runtime_macros::nunchi_runtime! {
    pub runtime TestRuntime {
        transaction: RuntimeTransaction,
        error: RuntimeError,
        modules: {
            Alpha: modules::Alpha {
                transaction: modules::AlphaTransaction,
                storage: modules::AlphaError::Storage,
            },
            Beta: modules::Beta {
                transaction: modules::BetaTransaction,
                storage: modules::BetaError::Storage,
            },
        },
    }
}

const EPOCH: u64 = 7;
const OK_CODE: u8 = 11;
const OTHER_CODE: u8 = 12;
const INVALID_CODE: u8 = 250;
const STORAGE_CODE: u8 = 251;
const VERIFY_REJECT_CODE: u8 = 252;

#[derive(Default)]
struct TestState {
    values: BTreeMap<Digest, Vec<u8>>,
}

impl StateStore for TestState {
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

fn address(seed: u64) -> nunchi_common::Address {
    nunchi_crypto::PrivateKey::ed25519_from_seed(seed)
        .public_key()
        .into()
}

#[test]
fn generated_runtime_encodes_and_decodes_module_tags() {
    let alpha = RuntimeTransaction::from(modules::AlphaTransaction::new(address(1), 3, OK_CODE));
    let beta = RuntimeTransaction::from(modules::BetaTransaction::new(address(1), 3, OK_CODE));

    let alpha_encoded = alpha.encode();
    let beta_encoded = beta.encode();

    assert_eq!(alpha_encoded[0], 0);
    assert_eq!(beta_encoded[0], 1);
    assert_eq!(
        RuntimeTransaction::decode(alpha_encoded.as_ref()).unwrap(),
        alpha
    );
    assert_eq!(
        RuntimeTransaction::decode(beta_encoded.as_ref()).unwrap(),
        beta
    );
    assert!(RuntimeTransaction::decode([99].as_slice()).is_err());
}

#[test]
fn generated_pool_transaction_forwards_to_inner_transaction() {
    let inner = modules::AlphaTransaction::new(address(2), 9, OK_CODE);
    let runtime = RuntimeTransaction::from(inner.clone());

    assert_eq!(
        nunchi_common::PoolTransaction::digest(&runtime),
        inner.digest()
    );
    assert_eq!(
        nunchi_common::PoolTransaction::account_id(&runtime),
        inner.account_id()
    );
    assert_eq!(
        nunchi_common::PoolTransaction::nonce(&runtime),
        inner.nonce()
    );
    assert!(nunchi_common::PoolTransaction::verify(&runtime).is_ok());

    let rejected = RuntimeTransaction::from(modules::AlphaTransaction::new(
        address(2),
        10,
        VERIFY_REJECT_CODE,
    ));
    assert!(nunchi_common::PoolTransaction::verify(&rejected).is_err());
}

#[test]
fn generated_runtime_validate_dispatches_to_selected_module() {
    let mut state = TestState::default();
    let context = RuntimeContext { epoch: EPOCH };
    let alpha = RuntimeTransaction::from(modules::AlphaTransaction::new(address(1), 0, OK_CODE));
    let beta = RuntimeTransaction::from(modules::BetaTransaction::new(address(2), 0, OTHER_CODE));

    block_on(<TestRuntime as Runtime>::validate(
        &mut state, context, &alpha,
    ))
    .unwrap();
    block_on(<TestRuntime as Runtime>::validate(
        &mut state, context, &beta,
    ))
    .unwrap();

    assert_eq!(
        state.values.get(&modules::alpha_validate_key(OK_CODE)),
        Some(&modules::marker(b'A', b'V', OK_CODE, EPOCH)),
    );
    assert_eq!(
        state.values.get(&modules::beta_validate_key(OTHER_CODE)),
        Some(&modules::marker(b'B', b'V', OTHER_CODE, EPOCH)),
    );
    assert!(!state
        .values
        .contains_key(&modules::beta_validate_key(OK_CODE)));
}

#[test]
fn generated_runtime_apply_dispatches_to_selected_module() {
    let mut state = TestState::default();
    let context = RuntimeContext { epoch: EPOCH };
    let alpha = RuntimeTransaction::from(modules::AlphaTransaction::new(address(1), 0, OK_CODE));
    let beta = RuntimeTransaction::from(modules::BetaTransaction::new(address(2), 0, OTHER_CODE));

    block_on(<TestRuntime as Runtime>::apply(&mut state, context, &alpha)).unwrap();
    block_on(<TestRuntime as Runtime>::apply(&mut state, context, &beta)).unwrap();

    assert_eq!(
        state.values.get(&modules::alpha_apply_key(OK_CODE)),
        Some(&modules::marker(b'A', b'A', OK_CODE, EPOCH)),
    );
    assert_eq!(
        state.values.get(&modules::beta_apply_key(OTHER_CODE)),
        Some(&modules::marker(b'B', b'A', OTHER_CODE, EPOCH)),
    );
    assert!(!state
        .values
        .contains_key(&modules::alpha_apply_key(OTHER_CODE)));
}

#[test]
fn generated_runtime_classifies_storage_errors_per_module() {
    let mut state = TestState::default();
    let context = RuntimeContext { epoch: EPOCH };
    let alpha_invalid =
        RuntimeTransaction::from(modules::AlphaTransaction::new(address(1), 0, INVALID_CODE));
    let alpha_storage =
        RuntimeTransaction::from(modules::AlphaTransaction::new(address(1), 0, STORAGE_CODE));
    let beta_invalid =
        RuntimeTransaction::from(modules::BetaTransaction::new(address(2), 0, INVALID_CODE));
    let beta_storage =
        RuntimeTransaction::from(modules::BetaTransaction::new(address(2), 0, STORAGE_CODE));

    let alpha_invalid = block_on(<TestRuntime as Runtime>::validate(
        &mut state,
        context,
        &alpha_invalid,
    ))
    .unwrap_err();
    let alpha_storage = block_on(<TestRuntime as Runtime>::validate(
        &mut state,
        context,
        &alpha_storage,
    ))
    .unwrap_err();
    let beta_invalid = block_on(<TestRuntime as Runtime>::validate(
        &mut state,
        context,
        &beta_invalid,
    ))
    .unwrap_err();
    let beta_storage = block_on(<TestRuntime as Runtime>::validate(
        &mut state,
        context,
        &beta_storage,
    ))
    .unwrap_err();

    assert!(matches!(
        alpha_invalid,
        RuntimeError::Alpha(modules::AlphaError::Invalid)
    ));
    assert!(!<TestRuntime as Runtime>::is_storage_error(&alpha_invalid));
    assert!(matches!(
        alpha_storage,
        RuntimeError::Alpha(modules::AlphaError::Storage)
    ));
    assert!(<TestRuntime as Runtime>::is_storage_error(&alpha_storage));
    assert!(matches!(
        beta_invalid,
        RuntimeError::Beta(modules::BetaError::Invalid)
    ));
    assert!(!<TestRuntime as Runtime>::is_storage_error(&beta_invalid));
    assert!(matches!(
        beta_storage,
        RuntimeError::Beta(modules::BetaError::Storage)
    ));
    assert!(<TestRuntime as Runtime>::is_storage_error(&beta_storage));
    assert!(beta_storage.to_string().contains("beta module error"));
}

pub mod modules {
    use std::{error::Error, fmt};

    use bytes::BufMut;
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use nunchi_common::{
        Address, ChainModule, Namespace, PoolTransaction, RuntimeContext, StateDb, StateStore,
    };

    use super::{INVALID_CODE, STORAGE_CODE, VERIFY_REJECT_CODE};

    const VALIDATE_TABLE: u8 = 0;
    const APPLY_TABLE: u8 = 1;

    pub fn marker(module: u8, action: u8, code: u8, epoch: u64) -> Vec<u8> {
        vec![module, action, code, epoch as u8]
    }

    pub fn alpha_validate_key(code: u8) -> Digest {
        <Alpha as ChainModule>::NAMESPACE.key(VALIDATE_TABLE, &[code])
    }

    pub fn alpha_apply_key(code: u8) -> Digest {
        <Alpha as ChainModule>::NAMESPACE.key(APPLY_TABLE, &[code])
    }

    pub fn beta_validate_key(code: u8) -> Digest {
        <Beta as ChainModule>::NAMESPACE.key(VALIDATE_TABLE, &[code])
    }

    pub fn beta_apply_key(code: u8) -> Digest {
        <Beta as ChainModule>::NAMESPACE.key(APPLY_TABLE, &[code])
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum AlphaError {
        Invalid,
        Storage,
    }

    impl fmt::Display for AlphaError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Invalid => f.write_str("alpha invalid"),
                Self::Storage => f.write_str("alpha storage"),
            }
        }
    }

    impl Error for AlphaError {}

    #[derive(Debug, Eq, PartialEq)]
    pub enum BetaError {
        Invalid,
        Storage,
    }

    impl fmt::Display for BetaError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Invalid => f.write_str("beta invalid"),
                Self::Storage => f.write_str("beta storage"),
            }
        }
    }

    impl Error for BetaError {}

    #[derive(Debug)]
    pub struct VerificationError;

    impl fmt::Display for VerificationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("verification failed")
        }
    }

    macro_rules! transaction_type {
        ($name:ident, $digest_domain:expr) => {
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct $name {
                account: Address,
                nonce: u64,
                code: u8,
            }

            impl $name {
                pub fn new(account: Address, nonce: u64, code: u8) -> Self {
                    Self {
                        account,
                        nonce,
                        code,
                    }
                }

                fn code(&self) -> u8 {
                    self.code
                }
            }

            impl Write for $name {
                fn write(&self, buf: &mut impl BufMut) {
                    self.account.write(buf);
                    self.nonce.write(buf);
                    self.code.write(buf);
                }
            }

            impl Read for $name {
                type Cfg = ();

                fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self {
                        account: Address::read(buf)?,
                        nonce: u64::read(buf)?,
                        code: u8::read(buf)?,
                    })
                }
            }

            impl EncodeSize for $name {
                fn encode_size(&self) -> usize {
                    self.account.encode_size() + self.nonce.encode_size() + self.code.encode_size()
                }
            }

            impl PoolTransaction for $name {
                type VerificationError = VerificationError;

                fn digest(&self) -> Digest {
                    let mut hasher = Sha256::new();
                    hasher.update($digest_domain);
                    hasher.update(self.account.encode().as_ref());
                    hasher.update(&self.nonce.to_be_bytes());
                    hasher.update(&[self.code]);
                    hasher.finalize()
                }

                fn verify(&self) -> Result<(), Self::VerificationError> {
                    if self.code == VERIFY_REJECT_CODE {
                        Err(VerificationError)
                    } else {
                        Ok(())
                    }
                }

                fn account_id(&self) -> &Address {
                    &self.account
                }

                fn nonce(&self) -> u64 {
                    self.nonce
                }
            }
        };
    }

    transaction_type!(AlphaTransaction, b"alpha");
    transaction_type!(BetaTransaction, b"beta");

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Alpha;

    impl ChainModule for Alpha {
        const NAME: &'static str = "alpha";
        const NAMESPACE: Namespace = Namespace::new(b"runtime-macro-test-alpha");

        type Transaction = AlphaTransaction;
        type Config = ();
        type Event = ();
        type Error = AlphaError;

        async fn genesis<S>(
            _state: &mut S,
            _config: Self::Config,
        ) -> Result<Vec<Self::Event>, Self::Error>
        where
            S: StateDb + Send + Sync,
        {
            Ok(Vec::new())
        }

        async fn validate<S>(
            state: &mut S,
            context: RuntimeContext,
            transaction: &Self::Transaction,
        ) -> Result<(), Self::Error>
        where
            S: StateStore + Send + Sync,
        {
            match transaction.code() {
                INVALID_CODE => Err(AlphaError::Invalid),
                STORAGE_CODE => Err(AlphaError::Storage),
                code => {
                    state.set(
                        alpha_validate_key(code),
                        marker(b'A', b'V', code, context.epoch),
                    );
                    Ok(())
                }
            }
        }

        async fn apply<S>(
            state: &mut S,
            context: RuntimeContext,
            transaction: Self::Transaction,
        ) -> Result<Vec<Self::Event>, Self::Error>
        where
            S: StateStore + Send + Sync,
        {
            match transaction.code() {
                INVALID_CODE => Err(AlphaError::Invalid),
                STORAGE_CODE => Err(AlphaError::Storage),
                code => {
                    state.set(
                        alpha_apply_key(code),
                        marker(b'A', b'A', code, context.epoch),
                    );
                    Ok(Vec::new())
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Beta;

    impl ChainModule for Beta {
        const NAME: &'static str = "beta";
        const NAMESPACE: Namespace = Namespace::new(b"runtime-macro-test-beta");

        type Transaction = BetaTransaction;
        type Config = ();
        type Event = ();
        type Error = BetaError;

        async fn genesis<S>(
            _state: &mut S,
            _config: Self::Config,
        ) -> Result<Vec<Self::Event>, Self::Error>
        where
            S: StateDb + Send + Sync,
        {
            Ok(Vec::new())
        }

        async fn validate<S>(
            state: &mut S,
            context: RuntimeContext,
            transaction: &Self::Transaction,
        ) -> Result<(), Self::Error>
        where
            S: StateStore + Send + Sync,
        {
            match transaction.code() {
                INVALID_CODE => Err(BetaError::Invalid),
                STORAGE_CODE => Err(BetaError::Storage),
                code => {
                    state.set(
                        beta_validate_key(code),
                        marker(b'B', b'V', code, context.epoch),
                    );
                    Ok(())
                }
            }
        }

        async fn apply<S>(
            state: &mut S,
            context: RuntimeContext,
            transaction: Self::Transaction,
        ) -> Result<Vec<Self::Event>, Self::Error>
        where
            S: StateStore + Send + Sync,
        {
            match transaction.code() {
                INVALID_CODE => Err(BetaError::Invalid),
                STORAGE_CODE => Err(BetaError::Storage),
                code => {
                    state.set(
                        beta_apply_key(code),
                        marker(b'B', b'A', code, context.epoch),
                    );
                    Ok(Vec::new())
                }
            }
        }
    }
}
