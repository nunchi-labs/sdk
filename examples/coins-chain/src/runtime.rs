//! Runtime generated from selected SDK modules.

nunchi_runtime_macros::nunchi_runtime! {
    pub runtime CoinsRuntime {
        transaction: RuntimeTransaction,
        error: RuntimeError,
        modules: {
            Coins: nunchi_coins::Coins {
                transaction: nunchi_coins::Transaction,
                storage: nunchi_coins::LedgerError::Storage(_),
            },
        },
    }
}
