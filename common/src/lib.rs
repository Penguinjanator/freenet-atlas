//! Shared types for the Atlas discovery layer.
//!
//! This crate is used by both the index contract (compiled to
//! `wasm32-unknown-unknown`, verify-only) and the native curator tools. To keep
//! the contract WASM free of `getrandom`/wasm-bindgen placeholders, anything
//! that needs a CSPRNG (key generation, random subject ids) lives behind the
//! `rng` feature, which only the native crates enable.

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;

mod state;
mod types;

pub use state::{IndexDelta, IndexState, IndexSummary};
pub use types::{
    IndexEntry, IndexParams, KeyAuth, KeyAuthBody, Kind, Locator, RecordBody, SignedRecord,
    SubjectId, Tombstone,
};

/// Max records in a single index contract. Keeps the full state inside the
/// cold-fetch budget; the node also hard-caps contract state at 50 MiB. Beyond
/// this, the index shards (see the design doc, "Scaling beyond one contract").
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_TITLE: usize = 200;
pub const MAX_SNIPPET: usize = 500;
pub const MAX_TAGS: usize = 16;
pub const MAX_TAG_LEN: usize = 40;

/// Canonical CBOR bytes used as the signing payload for any signed struct.
/// Signing and verification must both go through this so the bytes match.
pub fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .expect("CBOR serialization of in-memory Atlas types is infallible");
    buf
}

/// Sign the canonical bytes of `value`. Deterministic (ed25519), no RNG needed.
pub fn sign<T: Serialize>(value: &T, key: &SigningKey) -> Signature {
    key.sign(&canonical(value))
}

/// Verify a signature over the canonical bytes of `value`.
pub fn verify<T: Serialize>(
    value: &T,
    sig: &Signature,
    vk: &VerifyingKey,
) -> Result<(), SignatureError> {
    vk.verify(&canonical(value), sig)
}

/// Generate a fresh signing key (native crates only).
#[cfg(feature = "rng")]
pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}
