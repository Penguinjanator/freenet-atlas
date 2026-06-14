use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::{IndexEntry, IndexParams, KeyAuth, RecordBody, SignedRecord, SubjectId};
use crate::MAX_ENTRIES;

/// The full index state: a root-signed authorization of online keys, plus one
/// current record per subject. Records merge as a commutative monoid (per-subject
/// last-write-wins by `(version, signature)`), so peers converge regardless of
/// the order updates arrive in.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct IndexState {
    pub key_auth: Option<KeyAuth>,
    pub records: BTreeMap<SubjectId, SignedRecord>,
}

/// Compact "what I have" for delta computation: per-subject versions plus the
/// key_auth version.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct IndexSummary {
    pub key_auth_version: u64,
    pub versions: BTreeMap<SubjectId, u64>,
}

/// The diff a peer needs to catch up: records newer than its summary, and a
/// newer key_auth if any.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct IndexDelta {
    pub key_auth: Option<KeyAuth>,
    pub records: Vec<SignedRecord>,
}

/// Total order used to resolve which record wins for a subject. Higher version
/// wins; ties break deterministically on signature bytes so merge is commutative.
fn record_order(r: &SignedRecord) -> (u64, [u8; 64]) {
    (r.body.version(), r.sig.to_bytes())
}

fn key_auth_order(k: &KeyAuth) -> (u64, [u8; 64]) {
    (k.body.version, k.sig.to_bytes())
}

impl IndexState {
    pub fn initialized(key_auth: KeyAuth) -> Self {
        IndexState {
            key_auth: Some(key_auth),
            records: BTreeMap::new(),
        }
    }

    /// Full validity check (used by the contract's `validate_state`): key_auth is
    /// root-signed, the index is within bounds, and every record is correctly
    /// keyed, authorized, signed, and structurally valid.
    pub fn verify(&self, params: &IndexParams) -> Result<(), String> {
        let ka = self.key_auth.as_ref().ok_or("index has no key_auth")?;
        ka.verify_sig(&params.root_vk)?;
        if self.records.len() > MAX_ENTRIES {
            return Err(format!("too many records: {}", self.records.len()));
        }
        for (sid, rec) in &self.records {
            if rec.body.subject_id() != sid {
                return Err("record stored under the wrong subject id".to_string());
            }
            if !ka.authorizes(&rec.by) {
                return Err("record signed by an unauthorized key".to_string());
            }
            rec.verify_sig()?;
            rec.body.check_structure()?;
        }
        Ok(())
    }

    /// Merge another already-valid state into this one (both sides assumed
    /// verified). Commutative, associative, idempotent.
    pub fn merge(&mut self, other: &IndexState) {
        if let Some(oka) = &other.key_auth {
            let take = self
                .key_auth
                .as_ref()
                .map_or(true, |cur| key_auth_order(oka) > key_auth_order(cur));
            if take {
                self.key_auth = Some(oka.clone());
            }
        }
        for (sid, orec) in &other.records {
            let take = self
                .records
                .get(sid)
                .map_or(true, |cur| record_order(orec) > record_order(cur));
            if take {
                self.records.insert(sid.clone(), orec.clone());
            }
        }
    }

    /// Apply an untrusted delta (used by the contract's `update_state`): verify
    /// the key_auth and every record before merging it in.
    pub fn apply_delta(&mut self, delta: &IndexDelta, params: &IndexParams) -> Result<(), String> {
        if let Some(ka) = &delta.key_auth {
            ka.verify_sig(&params.root_vk)?;
            let take = self
                .key_auth
                .as_ref()
                .map_or(true, |cur| key_auth_order(ka) > key_auth_order(cur));
            if take {
                self.key_auth = Some(ka.clone());
            }
        }
        let ka = self
            .key_auth
            .clone()
            .ok_or("no key_auth available to authorize records")?;
        for rec in &delta.records {
            if !ka.authorizes(&rec.by) {
                return Err("record signed by an unauthorized key".to_string());
            }
            rec.verify_sig()?;
            rec.body.check_structure()?;
            let sid = rec.body.subject_id().clone();
            let take = self
                .records
                .get(&sid)
                .map_or(true, |cur| record_order(rec) > record_order(cur));
            if take {
                self.records.insert(sid, rec.clone());
            }
        }
        if self.records.len() > MAX_ENTRIES {
            return Err(format!("too many records: {}", self.records.len()));
        }
        Ok(())
    }

    pub fn summarize(&self) -> IndexSummary {
        IndexSummary {
            key_auth_version: self.key_auth.as_ref().map_or(0, |k| k.body.version),
            versions: self
                .records
                .iter()
                .map(|(sid, rec)| (sid.clone(), rec.body.version()))
                .collect(),
        }
    }

    pub fn delta(&self, summary: &IndexSummary) -> IndexDelta {
        let key_auth = match &self.key_auth {
            Some(ka) if ka.body.version > summary.key_auth_version => Some(ka.clone()),
            _ => None,
        };
        let records = self
            .records
            .iter()
            .filter(|(sid, rec)| {
                summary
                    .versions
                    .get(*sid)
                    .map_or(true, |v| rec.body.version() > *v)
            })
            .map(|(_, rec)| rec.clone())
            .collect();
        IndexDelta { key_auth, records }
    }

    /// Live (non-tombstoned) entries, for clients rendering Discover/search.
    pub fn live_entries(&self) -> impl Iterator<Item = &IndexEntry> {
        self.records.values().filter_map(|r| match &r.body {
            RecordBody::Live(e) => Some(e),
            RecordBody::Tomb(_) => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign;
    use crate::types::{IndexEntry, KeyAuth, KeyAuthBody, Kind, Locator, Tombstone};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sid(n: u8) -> SubjectId {
        SubjectId::parse(&bs58::encode([n; 9]).into_string()).unwrap()
    }

    fn entry(sid: &SubjectId, version: u64, title: &str) -> IndexEntry {
        IndexEntry {
            subject_id: sid.clone(),
            version,
            kind: Kind::App,
            title: title.to_string(),
            snippet: "snippet".into(),
            tags: vec!["tag".into()],
            locator: Locator::External {
                url: "https://example.com".into(),
            },
            featured: false,
            added_at: 1,
        }
    }

    fn signed(body: RecordBody, online: &SigningKey) -> SignedRecord {
        let sig = sign(&body, online);
        SignedRecord {
            body,
            by: online.verifying_key(),
            sig,
        }
    }

    fn key_auth(root: &SigningKey, online: &SigningKey, version: u64) -> KeyAuth {
        let body = KeyAuthBody {
            version,
            authorized: vec![online.verifying_key()],
        };
        let sig = sign(&body, root);
        KeyAuth { body, sig }
    }

    fn params(root: &SigningKey) -> IndexParams {
        IndexParams {
            root_vk: root.verifying_key(),
            slug: "default".into(),
        }
    }

    #[test]
    fn empty_initialized_state_verifies() {
        let (root, online) = (key(), key());
        let s = IndexState::initialized(key_auth(&root, &online, 1));
        assert!(s.verify(&params(&root)).is_ok());
    }

    #[test]
    fn delta_application_and_verify() {
        let (root, online) = (key(), key());
        let p = params(&root);
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        let id = sid(1);
        let rec = signed(RecordBody::Live(entry(&id, 1, "Hello")), &online);
        s.apply_delta(
            &IndexDelta {
                key_auth: None,
                records: vec![rec],
            },
            &p,
        )
        .unwrap();
        assert!(s.verify(&p).is_ok());
        assert_eq!(s.live_entries().count(), 1);
    }

    #[test]
    fn merge_is_commutative() {
        let (root, online) = (key(), key());
        let ka = key_auth(&root, &online, 1);
        let a = signed(RecordBody::Live(entry(&sid(1), 1, "A")), &online);
        let b = signed(RecordBody::Live(entry(&sid(2), 1, "B")), &online);
        let c = signed(RecordBody::Live(entry(&sid(1), 2, "A2")), &online); // newer for sid 1

        let build = |recs: &[&SignedRecord]| {
            let mut s = IndexState::initialized(ka.clone());
            for r in recs {
                s.records.insert(r.body.subject_id().clone(), (*r).clone());
            }
            s
        };

        let mut left = build(&[&a, &b]);
        left.merge(&build(&[&c]));
        let mut right = build(&[&c]);
        right.merge(&build(&[&a, &b]));
        assert_eq!(left, right);
        // sid 1 resolves to the higher version regardless of order.
        let winner = left.records.get(&sid(1)).unwrap();
        assert_eq!(winner.body.version(), 2);
    }

    #[test]
    fn higher_version_wins() {
        let (root, online) = (key(), key());
        let p = params(&root);
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        let id = sid(1);
        let v2 = signed(RecordBody::Live(entry(&id, 2, "v2")), &online);
        let v1 = signed(RecordBody::Live(entry(&id, 1, "v1")), &online);
        // apply newer then older; older must not win.
        s.apply_delta(&IndexDelta { key_auth: None, records: vec![v2] }, &p).unwrap();
        s.apply_delta(&IndexDelta { key_auth: None, records: vec![v1] }, &p).unwrap();
        assert_eq!(s.records.get(&id).unwrap().body.version(), 2);
    }

    #[test]
    fn tombstone_removes_from_live() {
        let (root, online) = (key(), key());
        let p = params(&root);
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        let id = sid(1);
        let live = signed(RecordBody::Live(entry(&id, 1, "x")), &online);
        let tomb = signed(
            RecordBody::Tomb(Tombstone {
                subject_id: id.clone(),
                version: 2,
            }),
            &online,
        );
        s.apply_delta(&IndexDelta { key_auth: None, records: vec![live] }, &p).unwrap();
        assert_eq!(s.live_entries().count(), 1);
        s.apply_delta(&IndexDelta { key_auth: None, records: vec![tomb] }, &p).unwrap();
        assert_eq!(s.live_entries().count(), 0);
    }

    #[test]
    fn tampered_entry_is_rejected() {
        let (root, online) = (key(), key());
        let p = params(&root);
        let id = sid(1);
        let mut rec = signed(RecordBody::Live(entry(&id, 1, "original")), &online);
        // Tamper after signing.
        if let RecordBody::Live(e) = &mut rec.body {
            e.title = "tampered".into();
        }
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        let err = s
            .apply_delta(&IndexDelta { key_auth: None, records: vec![rec] }, &p)
            .unwrap_err();
        assert!(err.contains("sig"), "expected sig error, got: {err}");
    }

    #[test]
    fn unauthorized_signer_is_rejected() {
        let (root, online, rogue) = (key(), key(), key());
        let p = params(&root);
        let id = sid(1);
        // rogue signs but is not in key_auth.authorized.
        let rec = signed(RecordBody::Live(entry(&id, 1, "x")), &rogue);
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        let err = s
            .apply_delta(&IndexDelta { key_auth: None, records: vec![rec] }, &p)
            .unwrap_err();
        assert!(err.contains("unauthorized"), "got: {err}");
    }

    #[test]
    fn forged_key_auth_is_rejected() {
        let (root, online, attacker) = (key(), key(), key());
        let p = params(&root);
        let mut s = IndexState::initialized(key_auth(&root, &online, 1));
        // attacker tries to authorize their own key with a key_auth they signed.
        let forged = key_auth(&attacker, &attacker, 2);
        let err = s
            .apply_delta(
                &IndexDelta {
                    key_auth: Some(forged),
                    records: vec![],
                },
                &p,
            )
            .unwrap_err();
        assert!(err.contains("key_auth sig"), "got: {err}");
    }

    #[test]
    fn params_roundtrip() {
        let root = key();
        let p = IndexParams {
            root_vk: root.verifying_key(),
            slug: "my-slug".into(),
        };
        let bytes = p.to_bytes();
        let back = IndexParams::from_bytes(&bytes).unwrap();
        assert_eq!(p, back);
    }
}
