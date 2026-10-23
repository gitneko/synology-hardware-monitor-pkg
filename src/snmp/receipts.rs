//! Bounded diagnostics and explicit P4 ingestion, with atomic evidence/transition writes.
use super::records::Receipt;
use crate::{dsm::BoundaryError, store::Store};
use anyhow::{ensure, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
#[derive(Serialize)]
pub struct StoredReceipt {
    pub id: i64,
    pub device: String,
    pub revision: i64,
    pub received: i64,
    pub receipt: Receipt,
}
impl Store {
    pub fn save_snmp_receipt(
        &mut self,
        device: &str,
        revision: i64,
        epoch: i64,
        receipt: &Receipt,
        now: i64,
    ) -> Result<bool> {
        self.save_snmp_receipt_with_retention(device, revision, epoch, receipt, now)
            .map(|(stored, _)| stored)
    }
    pub fn save_snmp_receipt_with_retention(
        &mut self,
        device: &str,
        revision: i64,
        epoch: i64,
        receipt: &Receipt,
        now: i64,
    ) -> Result<(bool, usize)> {
        self.write_snmp_receipt(device, revision, epoch, receipt, now, false)
    }
    pub fn ingest_snmp_receipt(
        &mut self,
        device: &str,
        revision: i64,
        epoch: i64,
        receipt: &Receipt,
        now: i64,
    ) -> Result<(bool, usize)> {
        self.write_snmp_receipt(device, revision, epoch, receipt, now, true)
    }
    fn write_snmp_receipt(
        &mut self,
        device: &str,
        revision: i64,
        epoch: i64,
        receipt: &Receipt,
        now: i64,
        integrate: bool,
    ) -> Result<(bool, usize)> {
        let raw = serde_json::to_string(receipt)?;
        ensure!(raw.len() <= 4096, "SNMP receipt size");
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<(i64, String)> = tx
            .query_row(
                "SELECT revision,config FROM devices WHERE id=?1",
                [device],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let current = current
            .filter(|(rev, _)| *rev == revision)
            .and_then(|(_, config)| serde_json::from_str::<crate::model::Device>(&config).ok());
        let valid = current
            .as_ref()
            .is_some_and(|d| d.enabled && d.snmp_traps.as_ref().is_some_and(|t| t.enabled));
        if !valid
            || tx.query_row("SELECT epoch FROM snmp_runtime WHERE id=1", [], |r| {
                r.get::<_, i64>(0)
            })? != epoch
        {
            return Ok((false, 0));
        }
        tx.execute(
            "INSERT INTO snmp_receipts(device,revision,received,data) VALUES(?1,?2,?3,?4)",
            params![device, revision, now, raw],
        )?;
        if integrate {
            let id = tx.last_insert_rowid();
            let mut receipt = receipt.clone();
            super::integration::apply_receipt(
                &tx,
                &current.unwrap(),
                revision,
                &mut receipt,
                id,
                now,
            )?;
            let raw = serde_json::to_string(&receipt)?;
            ensure!(raw.len() <= 4096, "SNMP receipt size");
            tx.execute(
                "UPDATE snmp_receipts SET data=?2 WHERE id=?1",
                params![id, raw],
            )?;
        }
        let removed = prune(&tx, now)?;
        tx.commit()?;
        Ok((true, removed))
    }
    pub fn prune_snmp_receipts(&mut self, now: i64) -> Result<usize> {
        let tx = self.0.transaction()?;
        let removed = prune(&tx, now)?;
        tx.commit()?;
        Ok(removed)
    }
    pub fn snmp_receipts(&self, device: Option<&str>, limit: usize) -> Result<Vec<StoredReceipt>> {
        ensure!(
            (1..=100).contains(&limit),
            BoundaryError("snmp_receipt_limit")
        );
        let mut q=self.0.prepare("SELECT id,device,revision,received,data FROM snmp_receipts WHERE (?1 IS NULL OR device=?1) ORDER BY id DESC LIMIT ?2")?;
        let rows = q.query_map(params![device, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|r| {
            let (id, device, revision, received, raw) = r?;
            Ok(StoredReceipt {
                id,
                device,
                revision,
                received,
                receipt: serde_json::from_str(&raw)?,
            })
        })
        .collect()
    }
}
fn prune(tx: &rusqlite::Transaction<'_>, now: i64) -> Result<usize> {
    super::integration::prune_events(tx, now, 10000)?;
    // Compact evidence may survive its diagnostic receipt. Keep its nullable
    // reference valid before enforcing age/count retention, including P4 data.
    tx.execute("UPDATE observation_evidence SET receipt_id=NULL WHERE receipt_id IN (SELECT id FROM snmp_receipts WHERE received<?1 OR id IN (SELECT id FROM snmp_receipts ORDER BY id DESC LIMIT -1 OFFSET 10000))",[now-7*86400])?;
    Ok(tx.execute("DELETE FROM snmp_receipts WHERE received<?1 OR id IN (SELECT id FROM snmp_receipts ORDER BY id DESC LIMIT -1 OFFSET 10000)",[now-7*86400])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::Device,
        snmp::{
            persistence::prepare_secrets,
            secrets::{Credentials, SecretUpdate, SecretUpdates},
        },
        vault::Vault,
    };
    use serde_json::json;
    #[test]
    fn retention_is_independent_of_polls_and_detaches_old_receipt_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let vault = Vault::open(&dir.path().join("master.key")).unwrap();
        let device:Device=serde_json::from_value(json!({"id":"receipt","name":"Synthetic","endpoint":"https://example.invalid/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"snmp_traps":{"enabled":true,"allowed_sources":["127.0.0.1"],"security":{"version":"v2c"}}})).unwrap();
        let credentials = SecretUpdates {
            snmp_traps: SecretUpdate::Replace {
                credentials: Credentials::Community {
                    community: "synthetic-p3".into(),
                },
            },
            ..Default::default()
        };
        let updates = prepare_secrets(&store, &vault, &device, &credentials).unwrap();
        store
            .save_admin_with_snmp(
                &device,
                &vault.seal(&device.id, b"synthetic-rf").unwrap(),
                None,
                "synthetic",
                Some(&updates),
            )
            .unwrap();
        let receipt:Receipt=serde_json::from_value(json!({"fingerprint":"synthetic","trap_oid":"1.3.6.1.6.3.1.1.5.3","source":"127.0.0.1","verified":false,"component_key":null})).unwrap();
        let epoch = store.receiver_epoch().unwrap();
        let now = 1_000_000;
        assert!(!store
            .save_snmp_receipt(&device.id, 2, epoch, &receipt, now)
            .unwrap());
        assert!(!store
            .save_snmp_receipt(&device.id, 1, epoch + 1, &receipt, now)
            .unwrap());
        assert!(store
            .save_snmp_receipt(&device.id, 1, epoch, &receipt, now - 8 * 86400)
            .unwrap());
        let evidence=json!({"source":"snmp_trap","revision":1,"generation":1,"health":"critical","received":1,"active":false}).to_string();
        store.0.execute("INSERT INTO observation_evidence(device,key,receipt_id,data) VALUES(?1,'sensor',1,?2)",params![device.id,evidence]).unwrap();
        {
            let tx = store.0.transaction().unwrap();
            {
                let mut insert=tx.prepare("INSERT INTO snmp_receipts(device,revision,received,data) VALUES(?1,1,?2,?3)").unwrap();
                for _ in 0..10005 {
                    insert
                        .execute(params![
                            device.id,
                            now,
                            serde_json::to_string(&receipt).unwrap()
                        ])
                        .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        assert_eq!(store.prune_snmp_receipts(now).unwrap(), 6);
        let count: i64 = store
            .0
            .query_row("SELECT COUNT(*) FROM snmp_receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 10000);
        let linked: Option<i64> = store
            .0
            .query_row("SELECT receipt_id FROM observation_evidence", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(linked.is_none());
        let snapshot: Option<String> = store
            .0
            .query_row("SELECT snapshot FROM devices", [], |r| r.get(0))
            .unwrap();
        assert!(snapshot.is_none());
        assert!(store.snmp_receipts(None, 101).is_err());
        assert_eq!(store.snmp_receipts(Some("unknown"), 20).unwrap().len(), 0);
    }
}
