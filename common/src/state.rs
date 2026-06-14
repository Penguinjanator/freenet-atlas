use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::{IndexEntry, IndexParams, KeyAuth, RecordBody, SignedRecord, SubjectId};
use crate::{MAX_AUTHORIZED, MAX_ENTRIES};

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
/// wins; at equal version a tombstone wins over a live entry (so a takedown is
/// never silently lost to a same-version entry); remaining ties break
/// deterministically on signature bytes so merge is commutative. Determinism of
/// the sig tie-break relies on signature non-malleability, which is why
/// verification uses `verify_strict` (see `crate::verify`).
fn record_order(r: &SignedRecord) -> (u64, bool, [u8; 64]) {
    let is_tomb = matches!(r.body, RecordBody::Tomb(_));
    (r.body.version(), is_tomb, r.sig.to_bytes())
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
        if ka.body.authorized.len() > MAX_AUTHORIZED {
            return Err(format!(
                "key_auth authorizes too many keys: {}",
                ka.body.authorized.len()
            ));
        }
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

    /// Merge another already-sig-verified state into this one. Commutative,
    /// associative, idempotent.
    ///
    /// Authorization is applied *against the final (merged) key_auth* and gates
    /// record selection, not just a post-filter. This is what makes revocation
    /// safe: when the winning key_auth de-authorizes a key, records signed by
    /// that key are never even considered, so they can neither resurrect (win on
    /// version then persist) nor grief (win on version then get filtered,
    /// erasing the legitimate record). Records by keys the final key_auth still
    /// authorizes are selected per-subject by `record_order`.
    pub fn merge(&mut self, other: &IndexState) {
        // 1. Resolve the final key_auth (higher version wins).
        if let Some(oka) = &other.key_auth {
            let take = self
                .key_auth
                .as_ref()
                .map_or(true, |cur| key_auth_order(oka) > key_auth_order(cur));
            if take {
                self.key_auth = Some(oka.clone());
            }
        }
        let ka = match self.key_auth.clone() {
            Some(ka) => ka,
            None => {
                // No authority yet: nothing can be authorized.
                self.records.clear();
                return;
            }
        };
        // 2. Drop any of our existing records the final key_auth no longer
        //    authorizes (handles revocation carried by `other`'s key_auth).
        self.records.retain(|_, rec| ka.authorizes(&rec.by));
        // 3. Consider the other side's records, but only authorized ones.
        for (sid, orec) in &other.records {
            if !ka.authorizes(&orec.by) {
                continue;
            }
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
            if ka.body.authorized.len() > MAX_AUTHORIZED {
                return Err(format!(
                    "key_auth authorizes too many keys: {}",
                    ka.body.authorized.len()
                ));
            }
            let take = self
                .key_auth
                .as_ref()
                .map_or(true, |cur| key_auth_order(ka) > key_auth_order(cur));
            if take {
                self.key_auth = Some(ka.clone());
                // Revocation: drop existing records the new key_auth no longer
                // authorizes, so a revoked key's content cannot linger.
                self.records.retain(|_, rec| ka.authorizes(&rec.by));
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

    #[test]
    fn revoked_key_cannot_resurrect_via_merge() {
        let (root, k1, k2) = (key(), key(), key());
        let p = params(&root);
        let id = sid(1);

        // Legitimate current state under key_auth v2 (only k2 authorized).
        let mut current = IndexState::initialized(key_auth(&root, &k2, 2));
        current
            .records
            .insert(id.clone(), signed(RecordBody::Live(entry(&id, 2, "legit")), &k2));
        assert!(current.verify(&p).is_ok());

        // Attacker holds an old state under key_auth v1 (k1) with a HIGHER-version
        // record signed by the now-revoked k1. It's valid under its own key_auth.
        let mut attacker = IndexState::initialized(key_auth(&root, &k1, 1));
        attacker
            .records
            .insert(id.clone(), signed(RecordBody::Live(entry(&id, 9, "evil")), &k1));
        assert!(attacker.verify(&p).is_ok());

        let mut a = current.clone();
        a.merge(&attacker);
        let mut b = attacker.clone();
        b.merge(&current);
        assert_eq!(a, b, "merge must converge regardless of order");
        assert!(a.verify(&p).is_ok(), "merged state must satisfy verify()");
        assert_eq!(
            a.records.get(&id).unwrap().body.version(),
            2,
            "legit v2 wins; the revoked key's higher-version record is excluded, not resurrected"
        );
    }

    #[test]
    fn revocation_via_delta_drops_old_records() {
        let (root, k1, k2) = (key(), key(), key());
        let p = params(&root);
        let id = sid(1);
        let mut s = IndexState::initialized(key_auth(&root, &k1, 1));
        s.apply_delta(
            &IndexDelta {
                key_auth: None,
                records: vec![signed(RecordBody::Live(entry(&id, 1, "x")), &k1)],
            },
            &p,
        )
        .unwrap();
        assert_eq!(s.live_entries().count(), 1);
        // A delta that revokes k1 (authorizes only k2) must drop k1's record.
        s.apply_delta(
            &IndexDelta {
                key_auth: Some(key_auth(&root, &k2, 2)),
                records: vec![],
            },
            &p,
        )
        .unwrap();
        assert_eq!(s.live_entries().count(), 0);
        assert!(s.verify(&p).is_ok());
    }

    #[test]
    fn tombstone_wins_at_equal_version() {
        let (root, online) = (key(), key());
        let p = params(&root);
        let id = sid(1);
        let live = signed(RecordBody::Live(entry(&id, 5, "x")), &online);
        let tomb = signed(
            RecordBody::Tomb(Tombstone {
                subject_id: id.clone(),
                version: 5,
            }),
            &online,
        );
        for order in [[live.clone(), tomb.clone()], [tomb.clone(), live.clone()]] {
            let mut s = IndexState::initialized(key_auth(&root, &online, 1));
            for rec in order {
                s.apply_delta(
                    &IndexDelta {
                        key_auth: None,
                        records: vec![rec],
                    },
                    &p,
                )
                .unwrap();
            }
            assert_eq!(
                s.live_entries().count(),
                0,
                "tombstone wins at equal version regardless of arrival order"
            );
        }
    }
}
