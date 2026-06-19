//! Minimal bridge-extension chain example.
//!
//! # Status
//!
//! This example shows how to install [`nunchi_bridge::BridgeExtension`] into a
//! [`nunchi_chain::Application`] without owning bridge transport, storage, or
//! local-finalization publication.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_bridge::BridgeExtension;
use nunchi_chain::{SharedAppliedHeight, StateCommitment};
use nunchi_common::{Address, Runtime, RuntimeContext, StateStore};
use nunchi_mempool::{Mempool, MempoolHandle, NonceKey, PoolTransaction};

const NOOP_TX_NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_CHAIN_NOOP_TX";

pub type Block = nunchi_bridge::BridgeBlock<NoopTransaction>;
pub type Application = nunchi_chain::Application<NoopRuntime, BridgeExtension>;
pub type Submitter = MempoolHandle<NoopTransaction>;
pub type TxPool = Mempool<NoopTransaction>;

/// Transaction placeholder for blocks whose only useful payload is the bridge extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoopTransaction {
    account: Address,
    nonce: u64,
}

/// Runtime used by this example chain.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRuntime;

#[derive(Debug, thiserror::Error)]
#[error("noop transaction verification failed")]
pub struct NoopVerificationError;

#[derive(Debug, thiserror::Error)]
#[error("noop runtime execution failed")]
pub struct NoopRuntimeError;

/// Build a chain application that carries bridge finalizations as its consensus extension.
pub fn application(
    submitter: Submitter,
    bridge: BridgeExtension,
    applied_height: SharedAppliedHeight,
    genesis_state: StateCommitment,
    genesis_payload: Digest,
) -> Application {
    nunchi_chain::Application::with_consensus(
        submitter,
        0,
        bridge,
        None,
        applied_height,
        genesis_state,
        genesis_payload,
    )
}

impl Write for NoopTransaction {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for NoopTransaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let account = Address::read(buf)?;
        let nonce = u64::read(buf)?;
        Ok(Self { account, nonce })
    }
}

impl EncodeSize for NoopTransaction {
    fn encode_size(&self) -> usize {
        self.account.encode_size() + self.nonce.encode_size()
    }
}

impl PoolTransaction for NoopTransaction {
    type Digest = Digest;
    type NonceKey = NonceKey;
    type VerifyError = NoopVerificationError;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
    }

    fn nonce_key(&self) -> Self::NonceKey {
        NonceKey::new(NOOP_TX_NAMESPACE, self.account.clone())
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn encoded_size(&self) -> usize {
        EncodeSize::encode_size(self)
    }

    fn verify(&self) -> Result<(), Self::VerifyError> {
        Ok(())
    }
}

impl Runtime for NoopRuntime {
    type Transaction = NoopTransaction;
    type Error = NoopRuntimeError;

    async fn validate<S>(
        _state: &mut S,
        _context: RuntimeContext,
        _transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        Ok(())
    }

    async fn apply<S>(
        _state: &mut S,
        _context: RuntimeContext,
        _transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        Ok(())
    }

    fn is_storage_error(_error: &Self::Error) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
