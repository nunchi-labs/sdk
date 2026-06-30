use bytes::Buf;
use commonware_codec::{varint::UInt, Decode, DecodeExt, Encode, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::{Scheme, Seed},
        types::{Context, Finalization, Notarization},
    },
    types::Height,
    Viewable,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519,
    sha256::Digest,
    Hasher, Sha256,
};
use commonware_utils::union;
use js_sys::{Object, Reflect, Uint8Array};
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

const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";
const KIND_SEED: u8 = 0;
const KIND_NOTARIZATION: u8 = 1;
const KIND_FINALIZATION: u8 = 2;

struct Block {
    context: CoinsContext,
    parent: Digest,
    height: Height,
    timestamp: u64,
    transaction_count: u64,
    has_reshare: bool,
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
    if scheme(identity).is_none() {
        return JsValue::NULL;
    }
    let Some(cfg) = block_cfg(participants) else {
        return JsValue::NULL;
    };
    let Ok(notarized) = Notarized::decode_cfg(bytes.as_ref(), &cfg) else {
        return JsValue::NULL;
    };
    notarized_js(&notarized)
}

#[wasm_bindgen]
pub fn parse_finalized(identity: Vec<u8>, participants: u32, bytes: Vec<u8>) -> JsValue {
    if scheme(identity).is_none() {
        return JsValue::NULL;
    }
    let Some(cfg) = block_cfg(participants) else {
        return JsValue::NULL;
    };
    let Ok(finalized) = Finalized::decode_cfg(bytes.as_ref(), &cfg) else {
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
    set_number(&object, "transactionCount", block.transaction_count);
    set_bool(&object, "hasReshare", block.has_reshare);
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

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let context = CoinsContext::read(buf)?;
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let timestamp = UInt::<u64>::read(buf)?.0;
        let transaction_count = UInt::<u64>::read(buf)?.0;
        if transaction_count != 0 {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Block",
                "transactions are not supported by the browser decoder yet",
            ));
        }
        let has_reshare = bool::read(buf)?;
        if has_reshare {
            return Err(Error::Invalid(
                "nunchi_coins_wasm::Block",
                "reshare logs are not supported by the browser decoder yet",
            ));
        }
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
            &state_root,
            &state_range,
        );

        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transaction_count,
            has_reshare,
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
    state_root: &Digest,
    state_range: &[u8],
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(&context.encode());
    hasher.update(parent);
    hasher.update(&height.get().to_be_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(&0u64.to_be_bytes());
    hasher.update(&false.encode());
    hasher.update(&().encode());
    hasher.update(state_root);
    hasher.update(state_range);
    hasher.finalize()
}
