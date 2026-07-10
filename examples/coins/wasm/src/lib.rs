use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Decode, DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write,
};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::{Scheme, Seed},
        types::{Context, Finalization, Notarization},
    },
    types::Height,
    Viewable,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::SignedDealerLog,
        primitives::variant::{MinSig, Variant},
    },
    ed25519,
    sha256::Digest,
    Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::union;
use js_sys::{Object, Reflect, Uint8Array};
use nunchi_authority::Transaction as AuthorityTransaction;
use nunchi_coins::Transaction as CoinTransaction;
use nunchi_common::{Address, Operation, Transaction as CommonTransaction};
use nunchi_oracle::Transaction as OracleTransaction;
use rand::rngs::OsRng;
use std::num::NonZeroU32;
use wasm_bindgen::prelude::*;

type BlockCfg = (NonZeroU32, ());
type Identity = <MinSig as Variant>::Public;
type PublicKey = ed25519::PublicKey;
type CoinsScheme = Scheme<PublicKey, MinSig>;
type CoinsSeed = Seed<MinSig>;
type CoinsContext = Context<Digest, PublicKey>;
type CoinsNotarization = Notarization<CoinsScheme, Digest>;
type CoinsFinalization = Finalization<CoinsScheme, Digest>;
type DealerLog = SignedDealerLog<MinSig, ed25519::PrivateKey>;
type BridgeTransaction = CommonTransaction<BridgeOperation>;

const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";
const KIND_SEED: u8 = 0;
const KIND_NOTARIZATION: u8 = 1;
const KIND_FINALIZATION: u8 = 2;
const TX_COIN: u8 = 0;
const TX_AUTHORITY: u8 = 1;
const TX_ORACLE: u8 = 2;
const TX_BRIDGE: u8 = 3;
const MAX_TRANSACTIONS: u64 = 4_096;
const BRIDGE_NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE";

#[derive(Clone, Debug, Eq, PartialEq)]
enum BridgeOperation {
    Lock {
        destination_chain_id: Digest,
        local_asset: Digest,
        amount: u128,
        recipient: Address,
    },
}

enum Transaction {
    Coin(Box<CoinTransaction>),
    Authority(Box<AuthorityTransaction>),
    Oracle(Box<OracleTransaction>),
    Bridge(Box<BridgeTransaction>),
}

impl Operation for BridgeOperation {
    const NAMESPACE: &'static [u8] = BRIDGE_NAMESPACE;
}

impl Write for BridgeOperation {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Lock {
                destination_chain_id,
                local_asset,
                amount,
                recipient,
            } => {
                0u8.write(buf);
                destination_chain_id.write(buf);
                local_asset.write(buf);
                amount.write(buf);
                recipient.write(buf);
            }
        }
    }
}

impl Read for BridgeOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Lock {
                destination_chain_id: Digest::read(buf)?,
                local_asset: Digest::read(buf)?,
                amount: u128::read(buf)?,
                recipient: Address::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for BridgeOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Lock {
                destination_chain_id,
                local_asset,
                amount,
                recipient,
            } => {
                destination_chain_id.encode_size()
                    + local_asset.encode_size()
                    + amount.encode_size()
                    + recipient.encode_size()
            }
        }
    }
}

struct Block {
    context: CoinsContext,
    parent: Digest,
    height: Height,
    timestamp: u64,
    transactions: Vec<Transaction>,
    reshare_log: Option<DealerLog>,
    state_root: Digest,
    digest: Digest,
}

struct Notarized {
    proof: CoinsNotarization,
    block: Block,
}

struct Finalized {
    proof: CoinsFinalization,
    block: Block,
}

#[wasm_bindgen]
pub fn parse_seed(identity: Vec<u8>, bytes: Vec<u8>) -> JsValue {
    let Some(scheme) = scheme(identity) else {
        return JsValue::NULL;
    };
    let Ok(seed) = CoinsSeed::decode(bytes.as_ref()) else {
        return JsValue::NULL;
    };
    if !seed.verify(&scheme) {
        return JsValue::NULL;
    }
    seed_js(&seed)
}

#[wasm_bindgen]
pub fn parse_notarized(identity: Vec<u8>, participants: u32, bytes: Vec<u8>) -> JsValue {
    let Some(cfg) = block_cfg(participants) else {
        return JsValue::NULL;
    };
    let Some(notarized) = verified_notarized(identity, &bytes, &cfg) else {
        return JsValue::NULL;
    };
    notarized_js(&notarized)
}

#[wasm_bindgen]
pub fn parse_finalized(identity: Vec<u8>, participants: u32, bytes: Vec<u8>) -> JsValue {
    let Some(cfg) = block_cfg(participants) else {
        return JsValue::NULL;
    };
    let Some(finalized) = verified_finalized(identity, &bytes, &cfg) else {
        return JsValue::NULL;
    };
    finalized_js(&finalized)
}

#[wasm_bindgen]
pub fn parse_block(participants: u32, bytes: Vec<u8>) -> JsValue {
    let Some(cfg) = block_cfg(participants) else {
        return JsValue::NULL;
    };
    let Ok(block) = Block::decode_cfg(bytes.as_ref(), &cfg) else {
        return JsValue::NULL;
    };
    block_js(&block)
}

#[wasm_bindgen]
pub fn parse_consensus_message(identity: Vec<u8>, participants: u32, bytes: Vec<u8>) -> JsValue {
    let Some((kind, payload)) = bytes.split_first() else {
        return JsValue::NULL;
    };
    let (kind_name, parsed) = match *kind {
        KIND_SEED => ("seed", parse_seed(identity, payload.to_vec())),
        KIND_NOTARIZATION => (
            "notarization",
            parse_notarized(identity, participants, payload.to_vec()),
        ),
        KIND_FINALIZATION => (
            "finalization",
            parse_finalized(identity, participants, payload.to_vec()),
        ),
        _ => return JsValue::NULL,
    };
    if parsed.is_null() {
        return JsValue::NULL;
    }
    let object = Object::new();
    set_str(&object, "kind", kind_name);
    set_value(&object, "payload", parsed);
    object.into()
}

fn block_cfg(participants: u32) -> Option<BlockCfg> {
    Some((NonZeroU32::new(participants)?, ()))
}

fn scheme(identity: Vec<u8>) -> Option<CoinsScheme> {
    let identity = Identity::decode(identity.as_ref()).ok()?;
    let namespace = union(NAMESPACE, b"_CONSENSUS");
    Some(CoinsScheme::certificate_verifier(&namespace, identity))
}

fn verified_notarized(identity: Vec<u8>, bytes: &[u8], cfg: &BlockCfg) -> Option<Notarized> {
    let scheme = scheme(identity)?;
    let notarized = Notarized::decode_cfg(bytes, cfg).ok()?;
    if notarized.proof.round() != notarized.block.context.round
        || !notarized.proof.verify(&mut OsRng, &scheme, &Sequential)
    {
        return None;
    }
    Some(notarized)
}

fn verified_finalized(identity: Vec<u8>, bytes: &[u8], cfg: &BlockCfg) -> Option<Finalized> {
    let scheme = scheme(identity)?;
    let finalized = Finalized::decode_cfg(bytes, cfg).ok()?;
    if finalized.proof.round() != finalized.block.context.round
        || !finalized.proof.verify(&mut OsRng, &scheme, &Sequential)
    {
        return None;
    }
    Some(finalized)
}

fn seed_js(seed: &CoinsSeed) -> JsValue {
    let object = Object::new();
    set_number(&object, "view", seed.view().get());
    set_bytes(&object, "signature", seed.signature.encode().as_ref());
    object.into()
}

fn notarized_js(notarized: &Notarized) -> JsValue {
    let object = Object::new();
    set_value(&object, "proof", notarization_proof_js(&notarized.proof));
    set_value(&object, "block", block_js(&notarized.block));
    object.into()
}

fn finalized_js(finalized: &Finalized) -> JsValue {
    let object = Object::new();
    set_value(&object, "proof", finalization_proof_js(&finalized.proof));
    set_value(&object, "block", block_js(&finalized.block));
    object.into()
}

fn notarization_proof_js(proof: &CoinsNotarization) -> JsValue {
    proof_fields_js(
        proof.view().get(),
        proof.proposal.parent.get(),
        proof.proposal.payload.as_ref(),
        proof
            .certificate
            .get()
            .map(|certificate| certificate.vote_signature.encode()),
    )
}

fn finalization_proof_js(proof: &CoinsFinalization) -> JsValue {
    proof_fields_js(
        proof.view().get(),
        proof.proposal.parent.get(),
        proof.proposal.payload.as_ref(),
        proof
            .certificate
            .get()
            .map(|certificate| certificate.vote_signature.encode()),
    )
}

fn proof_fields_js(
    view: u64,
    parent_view: u64,
    payload: &[u8],
    signature: Option<impl AsRef<[u8]>>,
) -> JsValue {
    let object = Object::new();
    set_number(&object, "view", view);
    set_number(&object, "parentView", parent_view);
    set_bytes(&object, "payload", payload);
    if let Some(signature) = signature {
        set_bytes(&object, "signature", signature.as_ref());
    }
    object.into()
}

fn block_js(block: &Block) -> JsValue {
    let object = Object::new();
    set_number(&object, "height", block.height.get());
    set_number(&object, "timestamp", block.timestamp);
    set_number(&object, "transactionCount", block.transactions.len() as u64);
    set_bool(&object, "hasReshare", block.reshare_log.is_some());
    set_bytes(&object, "digest", block.digest.as_ref());
    set_bytes(&object, "parent", block.parent.as_ref());
    set_bytes(&object, "stateRoot", block.state_root.as_ref());
    set_number(&object, "view", block.context.round.view().get());
    set_bytes(&object, "leader", block.context.leader.encode().as_ref());
    object.into()
}

fn set_value(object: &Object, key: &str, value: JsValue) {
    Reflect::set(object, &JsValue::from_str(key), &value).expect("set property");
}

fn set_str(object: &Object, key: &str, value: &str) {
    set_value(object, key, JsValue::from_str(value));
}

fn set_number(object: &Object, key: &str, value: u64) {
    set_value(object, key, JsValue::from_f64(value as f64));
}

fn set_bool(object: &Object, key: &str, value: bool) {
    set_value(object, key, JsValue::from_bool(value));
}

fn set_bytes(object: &Object, key: &str, bytes: &[u8]) {
    let array = Uint8Array::from(bytes);
    set_value(object, key, array.into());
}

impl Read for Block {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = CoinsContext::read(buf)?;
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let timestamp = UInt::<u64>::read(buf)?.0;
        let transaction_count = UInt::<u64>::read(buf)?.0;
        if transaction_count > MAX_TRANSACTIONS {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Block",
                "transaction count exceeds maximum",
            ));
        }
        let mut transactions = Vec::with_capacity(transaction_count as usize);
        for _ in 0..transaction_count {
            transactions.push(Transaction::read(buf)?);
        }
        let reshare_log = Option::<DealerLog>::read_cfg(buf, &cfg.0)?;
        <()>::read(buf)?;
        let state_root = Digest::read(buf)?;
        let state_range_start = UInt::<u64>::read(buf)?.0;
        let state_range_end = UInt::<u64>::read(buf)?.0;
        if state_range_start >= state_range_end {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Block",
                "state range must be non-empty",
            ));
        }

        let mut state_range = Vec::new();
        UInt(state_range_start).write(&mut state_range);
        UInt(state_range_end).write(&mut state_range);
        let digest = compute_block_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &reshare_log,
            &state_root,
            &state_range,
        );

        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            state_root,
            digest,
        })
    }
}

impl Read for Notarized {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = CoinsNotarization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;
        if proof.proposal.payload != block.digest {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Notarized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl Read for Finalized {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = CoinsFinalization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;
        if proof.proposal.payload != block.digest {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Finalized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

fn compute_block_digest(
    context: &CoinsContext,
    parent: &Digest,
    height: Height,
    timestamp: u64,
    transactions: &[Transaction],
    reshare_log: &Option<DealerLog>,
    state_root: &Digest,
    state_range: &[u8],
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(&context.encode());
    hasher.update(parent);
    hasher.update(&height.get().to_be_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(&(transactions.len() as u64).to_be_bytes());
    for transaction in transactions {
        hasher.update(&transaction.encode());
    }
    hasher.update(&reshare_log.encode());
    hasher.update(&().encode());
    hasher.update(state_root);
    hasher.update(state_range);
    hasher.finalize()
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Coin(transaction) => {
                TX_COIN.write(buf);
                transaction.write(buf);
            }
            Self::Authority(transaction) => {
                TX_AUTHORITY.write(buf);
                transaction.write(buf);
            }
            Self::Oracle(transaction) => {
                TX_ORACLE.write(buf);
                transaction.write(buf);
            }
            Self::Bridge(transaction) => {
                TX_BRIDGE.write(buf);
                transaction.write(buf);
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            TX_COIN => Ok(Self::Coin(Box::new(CoinTransaction::read(buf)?))),
            TX_AUTHORITY => Ok(Self::Authority(Box::new(AuthorityTransaction::read(buf)?))),
            TX_ORACLE => Ok(Self::Oracle(Box::new(OracleTransaction::read(buf)?))),
            TX_BRIDGE => Ok(Self::Bridge(Box::new(BridgeTransaction::read(buf)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Coin(transaction) => transaction.encode_size(),
            Self::Authority(transaction) => transaction.encode_size(),
            Self::Oracle(transaction) => transaction.encode_size(),
            Self::Bridge(transaction) => transaction.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold,
            types::{
                Finalization as ConsensusFinalization, Finalize,
                Notarization as ConsensusNotarization, Notarize, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        certificate::mocks::Fixture, sha256::Digest as Sha256Digest, Digest, Digestible, Signer,
    };
    use commonware_storage::mmr::Location;
    use commonware_utils::{range::NonEmptyRange, test_rng, test_rng_seeded, NZU32};
    use nunchi_coins::{
        Address, CoinId, CoinOperation, PrivateKey, Transaction as CanonicalCoinTransaction,
    };
    use nunchi_coins_chain::StateCommitment;

    fn schemes(seed: u64) -> Vec<CoinsScheme> {
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let Fixture { schemes, .. } = if seed == 0 {
            bls12381_threshold::fixture::<MinSig, _>(&mut test_rng(), &namespace, 4)
        } else {
            bls12381_threshold::fixture::<MinSig, _>(&mut test_rng_seeded(seed), &namespace, 4)
        };
        schemes
    }

    fn block() -> nunchi_coins_chain::Block {
        let sender = PrivateKey::ed25519_from_seed(1);
        let receiver = PrivateKey::ed25519_from_seed(2);
        let sender_address = Address::external(&sender.public_key());
        let transaction = CanonicalCoinTransaction::sign(
            &sender,
            0,
            CoinOperation::Transfer {
                coin: CoinId(Sha256::hash(b"coin")),
                from: sender_address,
                to: Address::external(&receiver.public_key()),
                amount: 1,
            },
        );
        let round = Round::new(Epoch::zero(), View::new(1));
        nunchi_coins_chain::Block::new(
            CoinsContext {
                round,
                leader: ed25519::PrivateKey::from_seed(3).public_key(),
                parent: (View::zero(), Sha256Digest::EMPTY),
            },
            Sha256::hash(b"parent"),
            Height::new(1),
            1_000,
            vec![transaction.into()],
            None,
            (),
            StateCommitment {
                root: Sha256::hash(b"state"),
                range: NonEmptyRange::new(Location::new(1)..Location::new(2)).unwrap(),
            },
        )
    }

    #[test]
    fn decodes_transaction_bearing_block_with_canonical_digest() {
        let canonical = block();
        let decoded = Block::decode_cfg(canonical.encode(), &(NZU32!(4), ())).unwrap();

        assert_eq!(decoded.transactions.len(), 1);
        assert_eq!(decoded.digest, canonical.digest());
    }

    #[test]
    fn verifies_notarized_and_finalized_artifacts() {
        let schemes = schemes(0);
        let block = block();
        let proposal = Proposal::new(block.context.round, View::zero(), block.digest());
        let notarizes = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let notarized = nunchi_coins_chain::Notarized::new(
            ConsensusNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap(),
            block.clone(),
        );
        let finalized = nunchi_coins_chain::Finalized::new(
            ConsensusFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap(),
            block,
        );
        let identity = schemes[0].identity().encode().to_vec();
        let cfg = (NZU32!(4), ());

        assert!(verified_notarized(identity.clone(), notarized.encode().as_ref(), &cfg).is_some());
        assert!(verified_finalized(identity.clone(), finalized.encode().as_ref(), &cfg).is_some());

        let mut tampered = finalized;
        tampered.block.transactions.clear();
        assert!(verified_finalized(identity, tampered.encode().as_ref(), &cfg).is_none());
    }

    #[test]
    fn rejects_wrong_identity_and_mismatched_round() {
        let schemes = schemes(0);
        let wrong_schemes = self::schemes(1);
        let block = block();
        let wrong_round = Round::new(Epoch::zero(), View::new(2));
        let proposal = Proposal::new(wrong_round, View::new(1), block.digest());
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let finalized = nunchi_coins_chain::Finalized::new(
            ConsensusFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap(),
            block,
        );
        let cfg = (NZU32!(4), ());

        assert!(verified_finalized(
            wrong_schemes[0].identity().encode().to_vec(),
            finalized.encode().as_ref(),
            &cfg,
        )
        .is_none());
        assert!(verified_finalized(
            schemes[0].identity().encode().to_vec(),
            finalized.encode().as_ref(),
            &cfg,
        )
        .is_none());
    }
}
