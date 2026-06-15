use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, LitInt, Pat, Path, Result, Token, Visibility,
};

mod kw {
    syn::custom_keyword!(runtime);
    syn::custom_keyword!(transaction);
    syn::custom_keyword!(error);
    syn::custom_keyword!(modules);
    syn::custom_keyword!(storage);
}

struct RuntimeInput {
    visibility: Visibility,
    runtime: Ident,
    transaction: Ident,
    error: Ident,
    modules: Vec<ModuleInput>,
}

struct ModuleInput {
    variant: Ident,
    module: Path,
    transaction: Path,
    storage: Pat,
}

impl Parse for RuntimeInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let visibility = input.parse()?;
        input.parse::<kw::runtime>()?;
        let runtime = input.parse()?;

        let content;
        braced!(content in input);

        content.parse::<kw::transaction>()?;
        content.parse::<Token![:]>()?;
        let transaction = content.parse()?;
        content.parse::<Token![,]>()?;

        content.parse::<kw::error>()?;
        content.parse::<Token![:]>()?;
        let error = content.parse()?;
        content.parse::<Token![,]>()?;

        content.parse::<kw::modules>()?;
        content.parse::<Token![:]>()?;
        let modules_content;
        braced!(modules_content in content);
        let mut modules = Vec::new();
        while !modules_content.is_empty() {
            modules.push(modules_content.parse()?);
            if modules_content.is_empty() {
                break;
            }
            modules_content.parse::<Token![,]>()?;
        }
        if !content.is_empty() {
            content.parse::<Token![,]>()?;
        }

        Ok(Self {
            visibility,
            runtime,
            transaction,
            error,
            modules,
        })
    }
}

impl Parse for ModuleInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let variant = input.parse()?;
        input.parse::<Token![:]>()?;
        let module = input.parse()?;

        let content;
        braced!(content in input);
        content.parse::<kw::transaction>()?;
        content.parse::<Token![:]>()?;
        let transaction = content.parse()?;
        content.parse::<Token![,]>()?;

        content.parse::<kw::storage>()?;
        content.parse::<Token![:]>()?;
        let storage = content.call(Pat::parse_single)?;
        if !content.is_empty() {
            content.parse::<Token![,]>()?;
        }

        Ok(Self {
            variant,
            module,
            transaction,
            storage,
        })
    }
}

/// Generate a Nunchi runtime from selected modules.
///
/// Example:
///
/// ```ignore
/// nunchi_runtime! {
///     pub runtime CoinsRuntime {
///         transaction: RuntimeTransaction,
///         error: RuntimeError,
///         modules: {
///             Coins: nunchi_coins::Coins {
///                 transaction: nunchi_coins::Transaction,
///                 storage: nunchi_coins::LedgerError::Storage(_),
///             },
///         },
///     }
/// }
/// ```
#[proc_macro]
pub fn nunchi_runtime(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as RuntimeInput);
    let visibility = input.visibility;
    let runtime = input.runtime;
    let transaction = input.transaction;
    let error = input.error;

    let variants: Vec<_> = input.modules.iter().map(|module| &module.variant).collect();
    let module_paths: Vec<_> = input.modules.iter().map(|module| &module.module).collect();
    let transaction_paths: Vec<_> = input
        .modules
        .iter()
        .map(|module| &module.transaction)
        .collect();
    let storage_patterns: Vec<_> = input.modules.iter().map(|module| &module.storage).collect();
    let tags: Vec<_> = (0..input.modules.len())
        .map(|index| LitInt::new(&format!("{index}u8"), Span::call_site()))
        .collect();
    let messages: Vec<_> = input
        .modules
        .iter()
        .map(|module| {
            let name = module.variant.to_string().to_lowercase();
            format!("{name} module error: {{}}")
        })
        .collect();
    let display_arms: Vec<_> = variants
        .iter()
        .zip(messages.iter())
        .map(|(variant, message)| {
            quote! {
                Self::#variant(error) => write!(f, #message, error)
            }
        })
        .collect();
    let source_arms: Vec<_> = variants
        .iter()
        .map(|variant| {
            quote! {
                Self::#variant(error) => Some(error)
            }
        })
        .collect();
    let storage_arms: Vec<_> = variants
        .iter()
        .zip(storage_patterns.iter())
        .map(|(variant, pattern)| {
            quote! {
                Self::#variant(#pattern)
            }
        })
        .collect();
    let from_impls: Vec<_> = variants
        .iter()
        .zip(transaction_paths.iter())
        .map(|(variant, module_transaction)| {
            quote! {
                impl From<#module_transaction> for #transaction {
                    fn from(transaction: #module_transaction) -> Self {
                        Self::#variant(transaction)
                    }
                }
            }
        })
        .collect();

    let tag_consts: Vec<_> = variants
        .iter()
        .zip(tags.iter())
        .map(|(variant, tag)| {
            let const_name = format_ident!("TX_{}", variant.to_string().to_uppercase());
            quote! {
                const #const_name: u8 = #tag;
            }
        })
        .collect();
    let tag_const_idents: Vec<_> = variants
        .iter()
        .map(|variant| format_ident!("TX_{}", variant.to_string().to_uppercase()))
        .collect();

    let expanded = quote! {
        #(#tag_consts)*

        #[derive(Clone, Copy, Debug, Default)]
        #visibility struct #runtime;

        #[derive(Clone, Debug, Eq, PartialEq)]
        #visibility enum #transaction {
            #(
                #variants(#transaction_paths),
            )*
        }

        #[derive(Debug)]
        #visibility enum #error {
            #(
                #variants(<#module_paths as nunchi_common::ChainModule>::Error),
            )*
        }

        impl #error {
            pub fn is_storage(&self) -> bool {
                matches!(
                    self,
                    #(
                        #storage_arms
                    )|*
                )
            }
        }

        impl std::fmt::Display for #error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(
                        #display_arms,
                    )*
                }
            }
        }

        impl std::error::Error for #error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    #(
                        #source_arms,
                    )*
                }
            }
        }

        impl nunchi_common::Runtime for #runtime {
            type Transaction = #transaction;
            type Error = #error;

            async fn validate<S>(
                state: &mut S,
                transaction: &Self::Transaction,
            ) -> Result<(), Self::Error>
            where
                S: nunchi_common::StateStore + Send + Sync,
            {
                match transaction {
                    #(
                        #transaction::#variants(transaction) => {
                            <#module_paths as nunchi_common::ChainModule>::validate(state, transaction)
                                .await
                                .map_err(#error::#variants)?;
                        }
                    )*
                }
                Ok(())
            }

            async fn apply<S>(
                state: &mut S,
                transaction: &Self::Transaction,
            ) -> Result<(), Self::Error>
            where
                S: nunchi_common::StateStore + Send + Sync,
            {
                match transaction {
                    #(
                        #transaction::#variants(transaction) => {
                            <#module_paths as nunchi_common::ChainModule>::apply(
                                state,
                                transaction.clone(),
                            )
                            .await
                            .map_err(#error::#variants)?;
                        }
                    )*
                }
                Ok(())
            }

            fn is_storage_error(error: &Self::Error) -> bool {
                error.is_storage()
            }
        }

        #(#from_impls)*

        impl nunchi_common::PoolTransaction for #transaction {
            type VerificationError = String;

            fn digest(&self) -> commonware_cryptography::sha256::Digest {
                match self {
                    #(
                        Self::#variants(transaction) => {
                            nunchi_common::PoolTransaction::digest(transaction)
                        }
                    )*
                }
            }

            fn verify(&self) -> Result<(), Self::VerificationError> {
                match self {
                    #(
                        Self::#variants(transaction) => {
                            nunchi_common::PoolTransaction::verify(transaction)
                                .map_err(|error| error.to_string())
                        }
                    )*
                }
            }

            fn account_id(&self) -> &nunchi_common::Address {
                match self {
                    #(
                        Self::#variants(transaction) => {
                            nunchi_common::PoolTransaction::account_id(transaction)
                        }
                    )*
                }
            }

            fn nonce(&self) -> u64 {
                match self {
                    #(
                        Self::#variants(transaction) => {
                            nunchi_common::PoolTransaction::nonce(transaction)
                        }
                    )*
                }
            }
        }

        impl commonware_codec::Write for #transaction {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                match self {
                    #(
                        Self::#variants(transaction) => {
                            commonware_codec::Write::write(&#tag_const_idents, buf);
                            commonware_codec::Write::write(transaction, buf);
                        }
                    )*
                }
            }
        }

        impl commonware_codec::Read for #transaction {
            type Cfg = ();

            fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
                match <u8 as commonware_codec::Read>::read_cfg(buf, &())? {
                    #(
                        #tag_const_idents => {
                            Ok(Self::#variants(
                                <#transaction_paths as commonware_codec::Read>::read_cfg(buf, &())?,
                            ))
                        }
                    )*
                    tag => Err(commonware_codec::Error::InvalidEnum(tag)),
                }
            }
        }

        impl commonware_codec::EncodeSize for #transaction {
            fn encode_size(&self) -> usize {
                1 + match self {
                    #(
                        Self::#variants(transaction) => {
                            commonware_codec::EncodeSize::encode_size(transaction)
                        }
                    )*
                }
            }
        }
    };

    expanded.into()
}
