use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{MAX_SNIPPET, MAX_TAGS, MAX_TAG_LEN, MAX_TITLE};

/// Number of random bytes behind a subject id (~72 bits, ~12 base58 chars).
const SUBJECT_ID_BYTES: usize = 9;

/// Opaque, stable handle for a subject. Base58 over [`SUBJECT_ID_BYTES`] random
/// bytes. Deliberately not derived from any attribute, so it survives WASM
/// upgrades, URL changes, and owner re-keying.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SubjectId(String);

impl SubjectId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse and validate a base58 subject id (must decode to the right length).
    pub fn parse(s: &str) -> Option<Self> {
        let decoded = bs58::decode(s).into_vec().ok()?;
        if decoded.len() != SUBJECT_ID_BYTES {
            return None;
        }
        Some(SubjectId(s.to_string()))
    }

    /// Mint a fresh random subject id (native crates only).
    #[cfg(feature = "rng")]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; SUBJECT_ID_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        SubjectId(bs58::encode(bytes).into_string())
    }

    fn is_well_formed(&self) -> bool {
        bs58::decode(&self.0)
            .into_vec()
            .map(|b| b.len() == SUBJECT_ID_BYTES)
            .unwrap_or(false)
    }
}

/// The 0.1 taxonomy. Constrained to things whose locator is directly openable;
/// richer kinds (Document, Media, Feed, Room) wait for per-kind Open semantics.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    App,
    Site,
    External,
}

/// Where "Open" navigates. An arbitrary URI; only the Freenet form has an
/// Atlas-defined shape. The path after the contract id is contract-defined and
/// opaque to Atlas.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Locator {
    /// `contract_id` is the full 43-44 char base58 instance id; `path` is the
    /// suffix after it (leading `/`, query, `#fragment`), possibly empty.
    Freenet { contract_id: String, path: String },
    /// External web resource. Must be https.
    External { url: String },
}

impl Locator {
    /// Structural validity. Mirrors the gateway's own retrieval facts: full id,
    /// no `..` path traversal, https-only externals.
    pub fn check(&self) -> Result<(), String> {
        match self {
            Locator::Freenet { contract_id, path } => {
                let n = contract_id.len();
                if n != 43 && n != 44 {
                    return Err(format!("contract id length {n} is not 43 or 44"));
                }
                if !contract_id.chars().all(is_base58_char) {
                    return Err("contract id has non-base58 chars".to_string());
                }
                if path.split(['?', '#']).next().unwrap_or(path).split('/').any(|seg| seg == "..") {
                    return Err("path contains a `..` segment".to_string());
                }
                Ok(())
            }
            Locator::External { url } => {
                if !url.starts_with("https://") {
                    return Err("external locator must be https".to_string());
                }
                Ok(())
            }
        }
    }

    /// Canonical string form (e.g. `freenet:<id><path>` or the external url).
    pub fn to_uri(&self) -> String {
        match self {
            Locator::Freenet { contract_id, path } => format!("freenet:{contract_id}{path}"),
            Locator::External { url } => url.clone(),
        }
    }
}

/// Bitcoin-style base58 alphabet (excludes `0 O I l`).
fn is_base58_char(c: char) -> bool {
    matches!(c,
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

/// A self-rendering entry: enough to draw a result card and detail view without
/// fetching anything else.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct IndexEntry {
    pub subject_id: SubjectId,
    pub version: u64,
    pub kind: Kind,
    pub title: String,
    pub snippet: String,
    pub tags: Vec<String>,
    pub locator: Locator,
    pub featured: bool,
    /// Unix seconds, set by the curator (contracts cannot read a clock).
    pub added_at: u64,
}

/// Removal marker. Wins over a live entry at the same subject once its version
/// is higher.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Tombstone {
    pub subject_id: SubjectId,
    pub version: u64,
}

/// The signable body of a per-subject record.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum RecordBody {
    Live(IndexEntry),
    Tomb(Tombstone),
}

impl RecordBody {
    pub fn subject_id(&self) -> &SubjectId {
        match self {
            RecordBody::Live(e) => &e.subject_id,
            RecordBody::Tomb(t) => &t.subject_id,
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            RecordBody::Live(e) => e.version,
            RecordBody::Tomb(t) => t.version,
        }
    }

    /// Structural checks independent of signatures.
    pub fn check_structure(&self) -> Result<(), String> {
        if self.version() == 0 {
            return Err("version must be >= 1".to_string());
        }
        if !self.subject_id().is_well_formed() {
            return Err("malformed subject id".to_string());
        }
        if let RecordBody::Live(e) = self {
            if e.title.is_empty() || e.title.len() > MAX_TITLE {
                return Err("title length out of range".to_string());
            }
            if e.snippet.len() > MAX_SNIPPET {
                return Err("snippet too long".to_string());
            }
            if e.tags.len() > MAX_TAGS || e.tags.iter().any(|t| t.len() > MAX_TAG_LEN) {
                return Err("too many tags or a tag is too long".to_string());
            }
            e.locator.check()?;
        }
        Ok(())
    }
}

/// A record signed by an online signing key (which must chain to the root key
/// via [`KeyAuth`]).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignedRecord {
    pub body: RecordBody,
    pub by: VerifyingKey,
    pub sig: Signature,
}

impl SignedRecord {
    /// Verify the signature over the body. Does not check authorization; the
    /// caller checks `by` against the current [`KeyAuth`].
    pub fn verify_sig(&self) -> Result<(), String> {
        crate::verify(&self.body, &self.sig, &self.by).map_err(|e| format!("bad record sig: {e}"))
    }
}

/// Root-signed authorization of the online signing keys. Merges last-write-wins
/// by `version`, so the root can rotate or revoke online keys without changing
/// the contract address.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyAuthBody {
    pub version: u64,
    pub authorized: Vec<VerifyingKey>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyAuth {
    pub body: KeyAuthBody,
    /// Signature by `root_vk` (from the contract parameters) over the body.
    pub sig: Signature,
}

impl KeyAuth {
    pub fn verify_sig(&self, root_vk: &VerifyingKey) -> Result<(), String> {
        crate::verify(&self.body, &self.sig, root_vk)
            .map_err(|e| format!("bad key_auth sig: {e}"))
    }

    pub fn authorizes(&self, key: &VerifyingKey) -> bool {
        self.body.authorized.iter().any(|k| k == key)
    }
}

/// Contract parameters: the index's identity. Fixed byte layout (not serde) so
/// a dependency bump can never silently re-key the live index.
/// Layout: `root_vk` (32 bytes) `||` `slug` (UTF-8).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IndexParams {
    pub root_vk: VerifyingKey,
    pub slug: String,
}

impl IndexParams {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.slug.len());
        out.extend_from_slice(self.root_vk.as_bytes());
        out.extend_from_slice(self.slug.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let vk_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let root_vk = VerifyingKey::from_bytes(&vk_bytes).ok()?;
        let slug = String::from_utf8(bytes[32..].to_vec()).ok()?;
        Some(IndexParams { root_vk, slug })
    }
}
