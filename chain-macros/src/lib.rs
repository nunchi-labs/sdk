use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, spanned::Spanned, Attribute, Data,
    DeriveInput, Error, Expr, Fields, Ident, LitInt, Path, Result, Token, Type,
};

#[proc_macro_derive(TransactionWrapper, attributes(transaction))]
pub fn transaction_wrapper(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_transaction_wrapper(input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

fn expand_transaction_wrapper(input: DeriveInput) -> Result<TokenStream2> {
    let name = input.ident;
    let data = match input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(Error::new(
                name.span(),
                "TransactionWrapper can only be derived for enums",
            ))
        }
    };

    let mut variants = Vec::with_capacity(data.variants.len());
    for variant in data.variants {
        let ident = variant.ident;
        let transaction = boxed_transaction_type(&variant.fields)?;
        let operation = transaction_operation(&variant.attrs)?;
        let tag = match variant.discriminant {
            Some((_, tag)) => {
                validate_u8_tag(&tag)?;
                tag
            }
            None => {
                return Err(Error::new(
                    ident.span(),
                    "transaction wrapper variants must have an explicit u8 discriminant",
                ))
            }
        };
        variants.push(WrapperVariant {
            ident,
            transaction,
            operation,
            tag,
        });
    }

    let verify_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! { Self::#ident(tx) => tx.verify().is_ok(), }
    });
    let digest_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! { Self::#ident(tx) => tx.digest(), }
    });
    let account_id_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! { Self::#ident(tx) => &tx.account_id, }
    });
    let nonce_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! { Self::#ident(tx) => tx.payload.nonce, }
    });
    let nonce_key_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let operation = &v.operation;
        quote! {
            Self::#ident(tx) => ::nunchi_mempool::NonceKey::new(
                <#operation as ::nunchi_common::Operation>::NAMESPACE,
                tx.account_id.clone(),
            ),
        }
    });
    let pool_verify_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        quote! { Self::#ident(tx) => tx.verify(), }
    });
    let from_impls = variants.iter().map(|v| {
        let ident = &v.ident;
        let transaction = &v.transaction;
        quote! {
            impl ::std::convert::From<#transaction> for #name {
                fn from(tx: #transaction) -> Self {
                    Self::#ident(::std::boxed::Box::new(tx))
                }
            }
        }
    });
    let write_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let transaction = &v.transaction;
        let tag = &v.tag;
        quote! {
            Self::#ident(tx) => {
                <u8 as ::commonware_codec::Write>::write(&(#tag as u8), buf);
                <#transaction as ::commonware_codec::Write>::write(tx.as_ref(), buf);
            }
        }
    });
    let read_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let transaction = &v.transaction;
        let tag = &v.tag;
        quote! {
            tag if tag == (#tag as u8) => Ok(Self::#ident(::std::boxed::Box::new(
                <#transaction as ::commonware_codec::Read>::read_cfg(buf, &())?,
            ))),
        }
    });
    let encode_size_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let transaction = &v.transaction;
        quote! {
            Self::#ident(tx) => {
                <#transaction as ::commonware_codec::EncodeSize>::encode_size(tx.as_ref())
            }
        }
    });

    Ok(quote! {
        impl #name {
            /// Verify the wrapped transaction's stateless authorization.
            pub fn verify(&self) -> bool {
                match self {
                    #(#verify_arms)*
                }
            }

            /// Return the wrapped transaction digest.
            pub fn digest(&self) -> ::commonware_cryptography::sha256::Digest {
                match self {
                    #(#digest_arms)*
                }
            }

            /// Return the account authorized by the wrapped transaction.
            pub fn account_id(&self) -> &::nunchi_common::Address {
                match self {
                    #(#account_id_arms)*
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
                    #(#nonce_arms)*
                }
            }
        }

        impl ::nunchi_mempool::PoolTransaction for #name {
            type Digest = ::commonware_cryptography::sha256::Digest;
            type NonceKey = ::nunchi_mempool::NonceKey;
            type VerifyError = ::nunchi_crypto::SignatureError;

            fn digest(&self) -> Self::Digest {
                Self::digest(self)
            }

            fn nonce_key(&self) -> Self::NonceKey {
                match self {
                    #(#nonce_key_arms)*
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
                    #(#pool_verify_arms)*
                }
            }
        }

        #(#from_impls)*

        impl ::commonware_codec::Write for #name {
            fn write(&self, buf: &mut impl ::bytes::BufMut) {
                match self {
                    #(#write_arms)*
                }
            }
        }

        impl ::commonware_codec::Read for #name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl ::bytes::Buf,
                _: &Self::Cfg,
            ) -> ::std::result::Result<Self, ::commonware_codec::Error> {
                match <u8 as ::commonware_codec::Read>::read_cfg(buf, &())? {
                    #(#read_arms)*
                    tag => Err(::commonware_codec::Error::InvalidEnum(tag)),
                }
            }
        }

        impl ::commonware_codec::EncodeSize for #name {
            fn encode_size(&self) -> usize {
                1 + match self {
                    #(#encode_size_arms)*
                }
            }
        }
    })
}

struct WrapperVariant {
    ident: Ident,
    transaction: Type,
    operation: Path,
    tag: Expr,
}

fn boxed_transaction_type(fields: &Fields) -> Result<Type> {
    let unnamed = match fields {
        Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => unnamed,
        _ => {
            return Err(Error::new(
                fields.span(),
                "transaction wrapper variants must be tuple variants with one Box<T> field",
            ))
        }
    };
    let field = unnamed.unnamed.first().expect("field length checked above");
    match &field.ty {
        Type::Path(path) if is_box_type(path) => boxed_type_argument(path),
        _ => Err(Error::new(
            field.ty.span(),
            "transaction wrapper variant field must be Box<Transaction>",
        )),
    }
}

fn is_box_type(path: &syn::TypePath) -> bool {
    path.qself.is_none()
        && path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Box")
}

fn boxed_type_argument(path: &syn::TypePath) -> Result<Type> {
    let segment = path
        .path
        .segments
        .last()
        .expect("Box segment checked above");
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(Error::new(
            segment.span(),
            "Box must contain one transaction type",
        ));
    };
    if arguments.args.len() != 1 {
        return Err(Error::new(
            arguments.span(),
            "Box must contain one transaction type",
        ));
    }
    match arguments
        .args
        .first()
        .expect("argument length checked above")
    {
        syn::GenericArgument::Type(ty) => Ok(ty.clone()),
        argument => Err(Error::new(
            argument.span(),
            "Box argument must be a transaction type",
        )),
    }
}

fn transaction_operation(attrs: &[Attribute]) -> Result<Path> {
    let mut operation = None;
    for attr in attrs {
        if !attr.path().is_ident("transaction") {
            continue;
        }
        let meta = attr.parse_args::<TransactionMeta>()?;
        if operation.replace(meta.operation).is_some() {
            return Err(Error::new(
                attr.span(),
                "duplicate transaction operation attribute",
            ));
        }
    }
    operation.ok_or_else(|| {
        Error::new(
            proc_macro2::Span::call_site(),
            "transaction wrapper variants require #[transaction(operation = OperationType)]",
        )
    })
}

struct TransactionMeta {
    operation: Path,
}

impl Parse for TransactionMeta {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key: Ident = input.parse()?;
        if key != "operation" {
            return Err(Error::new(
                key.span(),
                "expected transaction(operation = OperationType)",
            ));
        }
        input.parse::<Token![=]>()?;
        let operation = input.parse::<Path>()?;
        if !input.is_empty() {
            input.parse::<Token![,]>()?;
            if !input.is_empty() {
                return Err(Error::new(
                    input.span(),
                    "expected only transaction(operation = OperationType)",
                ));
            }
        }
        if input.is_empty() {
            Ok(Self { operation })
        } else {
            Err(Error::new(
                input.span(),
                "expected transaction(operation = OperationType)",
            ))
        }
    }
}

fn validate_u8_tag(tag: &Expr) -> Result<()> {
    if let Expr::Lit(expr) = tag {
        if let syn::Lit::Int(value) = &expr.lit {
            validate_u8_literal(value)?;
        }
    }
    Ok(())
}

fn validate_u8_literal(value: &LitInt) -> Result<()> {
    let parsed = value.base10_parse::<u16>()?;
    if parsed <= u8::MAX as u16 {
        Ok(())
    } else {
        Err(Error::new(
            value.span(),
            "transaction discriminant must fit in u8",
        ))
    }
}
