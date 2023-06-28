
use crate::hexify;
use crate::errors::Error;
use crate::{encoding, Address, Signature};
use bitvec::prelude::*;
use ed25519_dalek_blake2b::Verifier;
use serde::{Deserialize, Deserializer, Serializer};
use std::io::Read;
use std::iter::FromIterator;
use std::str::FromStr;

/// 256 bit public key which can be converted into an [Address](crate::Address) or verify a [Signature](crate::Signature).
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Public([u8; Public::LEN]);

hexify!(Public, "public key");

impl Public {
    pub const LEN: usize = 32;
    const ADDRESS_CHECKSUM_LEN: usize = 5;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn dalek_key(&self) -> Result<ed25519_dalek_blake2b::PublicKey, Error> {
        Ok(
            ed25519_dalek_blake2b::PublicKey::from_bytes(&self.0).map_err(|e| Error::SignatureError {
                msg: String::from("Converting to PublicKey"),
                source: e,
            })?,
        )
    }

    pub fn to_address(&self) -> Address {
        Address::from(self)
    }

    // Public key -> blake2(5) -> nano_base_32
    pub fn checksum(&self) -> String {
        let result = encoding::blake2b(Self::ADDRESS_CHECKSUM_LEN, &self.0);
        let bits = BitVec::from_iter(result.iter().rev());
        encoding::encode_nano_base_32(&bits)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let result = self.dalek_key();

        match result {
            Ok(key) => {
                key.verify(message, &signature.internal())
                    .map_err(|e| Error::SignatureError {
                        msg: format!(
                            "Public verification failed: sig: {:?} message: {:?} key: {:?}",
                            signature, String::from_utf8_lossy(message), &self
                        ),
                        source: e,
                    })
            }
            // We're returning false here because someone we can be given a bad public key,
            // but since we're not checking the key for how valid it is, only the signature,
            // we just say that it does not pass validation.
            _ => Err(Error::BadPublicKey),
        }
    }
}

impl From<ed25519_dalek_blake2b::PublicKey> for Public {
    fn from(v: ed25519_dalek_blake2b::PublicKey) -> Self {
        Self(*v.as_bytes())
    }
}

/// A serde serializer that converts to an address instead of public key hexes.
///
/// Use with #[serde(serialize_with = "to_address")] on the field that needs it.
pub fn to_address<S>(public: &Public, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(public.to_address().to_string().as_str())
}

pub fn from_address<'de, D>(deserializer: D) -> Result<Public, <D as Deserializer<'de>>::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Ok(Address::from_str(s)
        .map_err(serde::de::Error::custom)?
        .to_public())
}

