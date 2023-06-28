use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
   

    #[error("From hex error: {msg} {source}")]
    FromHexError {
        msg: String,
        source: hex::FromHexError,
    },

    #[error("Signature error")]
    SignatureError {
        msg: String,
        source: ed25519_dalek_blake2b::SignatureError,
    },

    #[error("Try from slice error")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),


    #[error("Invalid Nano address")]
    InvalidAddress,

    #[error("Unknown character found while decoding: {0}")]
    DecodingError(char),

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Bad public key, can not verify")]
    BadPublicKey,

    #[error("Extended secret key error")]
    ExtendedSecretKeyError(#[from] ed25519_dalek_bip32::Error),

    #[error("Wrong length for {msg} (expected {expected:?}, found {found:?})")]
    WrongLength {
        msg: String,
        expected: usize,
        found: usize,
    },

    #[error("Parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Parse big decimal error")]
    ParseBigDecimalError(#[from] bigdecimal::ParseBigDecimalError),
    
}
