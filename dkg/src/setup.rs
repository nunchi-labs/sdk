//! Peer selection configuration for template-chain resharing.

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{ed25519::PublicKey as Ed25519PublicKey, PublicKey};
use commonware_formatting::{from_hex, hex};
use commonware_utils::{ordered::Set, TryCollect};
use rand::{rngs::StdRng, seq::IteratorRandom, SeedableRng};
use serde::{Deserialize, Serialize};

/// A list of all peers' public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig<P: PublicKey = Ed25519PublicKey> {
    /// The number of participants per round.
    ///
    /// This is a vec which cycles through different numbers in each round.
    ///
    /// This MUST be non-empty.
    ///
    /// E.g. `vec![3, 4]` will start with 3 participants, then use 4, then use
    /// 3, etc.
    pub num_participants_per_round: Vec<u32>,
    /// All active peer public keys.
    #[serde(with = "serde_hex_ordered")]
    pub participants: Set<P>,
}

impl<P: PublicKey> PeerConfig<P> {
    /// Returns the maximum number of participants per round.
    pub fn max_participants_per_round(&self) -> u32 {
        self.num_participants_per_round
            .iter()
            .copied()
            .max()
            .expect("num_participants_per_round must not be empty")
    }

    /// Returns the number of participants in the given round.
    pub fn num_participants_in_round(&self, round: u64) -> u32 {
        self.num_participants_per_round
            [(round % self.num_participants_per_round.len() as u64) as usize]
    }

    /// Pick the dealers for a particular round.
    ///
    /// The first round will use the first [`Self::num_participants_in_round`] players
    /// as the dealers.
    ///
    /// Subsequent rounds use a deterministic sample of the corresponding size.
    pub fn dealers(&self, round: u64) -> Set<P> {
        let p_iter = self.participants.iter().cloned();
        let to_choose = self.num_participants_in_round(round) as usize;
        if round == 0 {
            return p_iter.take(to_choose).try_collect().unwrap();
        }
        let mut rng = StdRng::seed_from_u64(round);
        p_iter
            .choose_multiple(&mut rng, to_choose)
            .into_iter()
            .try_collect()
            .unwrap()
    }
}

mod serde_hex_ordered {
    use super::*;
    use core::fmt;
    use serde::{
        de::{SeqAccess, Visitor},
        Deserializer, Serializer,
    };

    pub fn serialize<T, S>(value: &Set<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|v| hex(&v.encode())))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Set<T>, D::Error>
    where
        T: Ord + DecodeExt<()>,
        D: Deserializer<'de>,
    {
        struct HexVecVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for HexVecVisitor<T>
        where
            T: Ord + DecodeExt<()>,
        {
            type Value = Set<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of hex strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(hex_str) = seq.next_element::<String>()? {
                    let bytes = from_hex(&hex_str).ok_or_else(|| {
                        serde::de::Error::custom("failed to deserialize: invalid hex string")
                    })?;
                    let item = T::decode(&mut bytes.as_slice())
                        .map_err(|_| serde::de::Error::custom("failed to decode bytes"))?;
                    items.push(item);
                }
                Set::try_from(items).map_err(|_| serde::de::Error::custom("duplicate item"))
            }
        }

        deserializer.deserialize_seq(HexVecVisitor(std::marker::PhantomData))
    }
}
