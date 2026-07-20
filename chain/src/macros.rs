/// Chain aggregate transaction wrapper over modules' tx types.
///
/// This macro generates an enum wrapper, stable codec tags, forwarding
/// helpers, and [`nunchi_mempool::PoolTransaction`] implementation for
/// modules whose transaction type is a [`nunchi_common::Transaction`] alias.
#[macro_export]
macro_rules! transaction_wrapper {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $variant:ident {
                    tag: $tag:expr,
                    transaction: $transaction:ty,
                    operation: $operation:ty $(,)?
                }
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        $vis enum $name {
            $(
                $variant(::std::boxed::Box<$transaction>),
            )+
        }

        impl $name {
            /// Verify the wrapped transaction's stateless authorization.
            pub fn verify(&self) -> bool {
                match self {
                    $(
                        Self::$variant(tx) => tx.verify().is_ok(),
                    )+
                }
            }

            /// Return the wrapped transaction digest.
            pub fn digest(&self) -> ::commonware_cryptography::sha256::Digest {
                match self {
                    $(
                        Self::$variant(tx) => tx.digest(),
                    )+
                }
            }

            /// Return the account authorized by the wrapped transaction.
            pub fn account_id(&self) -> &::nunchi_common::Address {
                match self {
                    $(
                        Self::$variant(tx) => &tx.account_id,
                    )+
                }
            }

            /// Return a deterministic ordering key for proposer sorting.
            pub fn ordering_key(&self) -> ::std::vec::Vec<u8> {
                ::commonware_codec::Encode::encode(self.account_id())
                    .as_ref()
                    .to_vec()
            }

            /// Return the nonce in the wrapped transaction's module lane.
            pub fn nonce(&self) -> u64 {
                match self {
                    $(
                        Self::$variant(tx) => tx.payload.nonce,
                    )+
                }
            }

            /// Return the chain identifier bound into the wrapped transaction signature.
            pub fn chain_id(&self) -> ::nunchi_common::ChainId {
                match self {
                    $(
                        Self::$variant(tx) => tx.payload.chain_id,
                    )+
                }
            }
        }

        impl ::nunchi_mempool::PoolTransaction for $name {
            type NonceKey = ::nunchi_mempool::NonceKey;
            type VerifyError = ::nunchi_crypto::SignatureError;

            fn digest(&self) -> ::commonware_cryptography::sha256::Digest {
                Self::digest(self)
            }

            fn nonce_key(&self) -> Self::NonceKey {
                match self {
                    $(
                        Self::$variant(tx) => ::nunchi_mempool::NonceKey::new(
                            <$operation as ::nunchi_common::Operation>::NAMESPACE,
                            tx.account_id.clone(),
                        ),
                    )+
                }
            }

            fn nonce(&self) -> u64 {
                self.nonce()
            }

            fn encoded_size(&self) -> usize {
                ::commonware_codec::EncodeSize::encode_size(self)
            }

            fn verify(&self) -> ::std::result::Result<(), Self::VerifyError> {
                match self {
                    $(
                        Self::$variant(tx) => tx.verify(),
                    )+
                }
            }
        }

        $(
            impl ::std::convert::From<$transaction> for $name {
                fn from(tx: $transaction) -> Self {
                    Self::$variant(::std::boxed::Box::new(tx))
                }
            }
        )+

        impl ::commonware_codec::Write for $name {
            fn write(&self, buf: &mut impl ::bytes::BufMut) {
                match self {
                    $(
                        Self::$variant(tx) => {
                            <u8 as ::commonware_codec::Write>::write(&($tag as u8), buf);
                            <$transaction as ::commonware_codec::Write>::write(tx.as_ref(), buf);
                        }
                    )+
                }
            }
        }

        impl ::commonware_codec::Read for $name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl ::bytes::Buf,
                _: &Self::Cfg,
            ) -> ::std::result::Result<Self, ::commonware_codec::Error> {
                match <u8 as ::commonware_codec::Read>::read_cfg(buf, &())? {
                    $(
                        tag if tag == ($tag as u8) => Ok(Self::$variant(::std::boxed::Box::new(
                            <$transaction as ::commonware_codec::Read>::read_cfg(buf, &())?,
                        ))),
                    )+
                    tag => Err(::commonware_codec::Error::InvalidEnum(tag)),
                }
            }
        }

        impl ::commonware_codec::EncodeSize for $name {
            fn encode_size(&self) -> usize {
                1 + match self {
                    $(
                        Self::$variant(tx) => {
                            <$transaction as ::commonware_codec::EncodeSize>::encode_size(
                                tx.as_ref(),
                            )
                        }
                    )+
                }
            }
        }
    };
}
