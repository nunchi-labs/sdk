use nunchi_clob::ClobError;
use thiserror::Error;

/// Errors surfaced by the in-memory book actor.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MemClobError {
    #[error("memclob actor shut down")]
    Shutdown,
    #[error("duplicate gossiped order instruction")]
    DuplicateInstruction,
    #[error("clob error: {0}")]
    Clob(#[from] ClobError),
}
