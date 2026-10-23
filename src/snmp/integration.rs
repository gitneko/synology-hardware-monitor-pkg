//! Trusted partial input and poll ordering. All writes join their caller's transaction.
use super::{
    records::{ComponentIdentity, Condition, EvidenceSource, ObservationEvidence, Receipt},
    traps::{Class, Identity},
};
use crate::{model::*, store::Store};
use anyhow::{ensure, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn snapshot(conn: &Connection, device: &str) -> Result<Option<Snapshot>> {
    let raw: Option<String> =
        conn.query_row("SELECT snapshot FROM devices WHERE id=?1", [device], |r| {
            r.get(0)
        })?;
    raw.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
}
pub(crate) fn alarm_evidence(
    conn: &Connection,
    device: &str,
    key: &str,
) -> Result<Option<ObservationEvidence>> {
    conn.query_row(
        "SELECT data FROM observation_evidence WHERE device=?1 AND key=?2",
        params![device, key],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| Ok(serde_json::from_str(&s)?))
    .transpose()
}
fn save_evidence(
    tx: &Transaction<'_>,
    device: &str,
    key: &str,
    id: Option<i64>,
    e: &ObservationEvidence,
) -> Result<()> {
    let raw = serde_json::to_string(e)?;
    ensure!(raw.len() <= 4096, "trap evidence limit");
    tx.execute("INSERT INTO observation_evidence(device,key,receipt_id,data) VALUES(?1,?2,?3,?4) ON CONFLICT(device,key) DO UPDATE SET receipt_id=excluded.receipt_id,data=excluded.data",params![device,key,id,raw])?;
    Ok(())
}
fn kind_matches(actual: &str, wanted: &str) -> bool {
    let actual = actual.rsplit('.').next().unwrap_or(actual);
    matches!(
        (wanted, actual),
        ("power_supply", "power_supply" | "PowerSupply")
            | ("fan", "fan" | "Fan")
            | ("temperature", "temperature" | "Temperature")
            | ("memory", "memory" | "Memory")
            | ("physical_disk", "physical_disk" | "Drive")
    )
}
/// Unique current inventory proof, never a label/MemberId guess. Index fallback
/// is restricted to SNMP-primary inventory in the authenticated agent generation.
#[allow(clippy::too_many_arguments)]
fn resolve(
    conn: &Connection,
    d: &Device,
    revision: i64,
    snapshot: &Snapshot,
    identity: &Identity,
    kind: &str,
    engine: Option<&str>,
    boots: Option<u32>,
    now: i64,
    fresh: bool,
) -> Result<Option<(String, i64)>> {
    let last: Option<i64> =
        conn.query_row("SELECT last_poll FROM devices WHERE id=?1", [&d.id], |r| {
            r.get(0)
        })?;
    if !fresh && last.is_none_or(|last| now < last || now - last > 900) {
        return Ok(None);
    }
    let mut q = conn.prepare("SELECT key,data FROM component_identity WHERE device=?1")?;
    let rows = q.query_map([&d.id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut found = BTreeMap::new();
    for row in rows {
        let (key, raw) = row?;
        let record: ComponentIdentity = serde_json::from_str(&raw)?;
        if record.revision != revision
            || !snapshot
                .resources
                .get(&key)
                .is_some_and(|r| kind_matches(&r.kind, kind))
        {
            continue;
        }
        if !snapshot.observations.iter().any(|o| o.key == key) {
            continue;
        }
        let matching = match identity {
            Identity::Fqdd { value } => record.aliases.contains(value),
            Identity::Serial {
                value,
                chassis,
                locator,
            } => {
                d.primary_protocol == PrimaryProtocol::Snmp
                    && record.aliases.contains(value)
                    && record.locator == *locator
                    && record
                        .locator
                        .rsplit('.')
                        .nth(1)
                        .and_then(|n| n.parse::<u32>().ok())
                        == Some(*chassis)
            }
            Identity::Index { locator } => {
                d.primary_protocol == PrimaryProtocol::Snmp
                    && record.locator == *locator
                    && snapshot.snmp.as_ref().is_some_and(|s| {
                        s.generation == record.generation
                            && s.engine_id.as_deref() == engine
                            && s.engine_boots == boots
                            && engine.is_some()
                    })
            }
        };
        if matching {
            found.insert(key, record.generation);
        }
    }
    Ok(if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    })
}
fn current_health(conn: &Connection, d: &str, key: &str) -> Result<Health> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT health FROM alarm_state WHERE device=?1 AND key=?2",
            params![d, key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or(Health::Unknown))
}
fn max(a: Health, b: Health) -> Health {
    if crate::identity::severity(a) >= crate::identity::severity(b) {
        a
    } else {
        b
    }
}
fn apply_conditions(snapshot: &mut Snapshot, key: &str, e: &ObservationEvidence) {
    let Some(resource) = snapshot.resources.get_mut(key) else {
        return;
    };
    let mut signature: Value = serde_json::from_str(&resource.condition_fingerprint)
        .ok()
        .filter(|v: &Value| v.as_array().is_some_and(|a| a.len() == 3))
        .unwrap_or_else(|| json!([null, null, []]));
    let mut conditions = signature[2].as_array().cloned().unwrap_or_default();
    for (name, c) in &e.conditions {
        conditions.push(
            json!([
                name,
                null,
                key,
                if c.health == Health::Critical {
                    "Critical"
                } else {
                    "Warning"
                }
            ])
            .to_string()
            .into(),
        );
    }
    conditions.sort_by_cached_key(Value::to_string);
    conditions.dedup();
    signature[2] = json!(conditions);
    resource.condition_fingerprint = signature.to_string();
}
pub(crate) fn annotate(
    tx: &Transaction<'_>,
    event: i64,
    source: &str,
    verified: bool,
    provisional: bool,
    receipt: Option<i64>,
    occurrence: Option<&Occurrence>,
) -> Result<()> {
    let raw: Option<String> = tx.query_row(
        "SELECT message_context FROM events WHERE id=?1",
        [event],
        |r| r.get(0),
    )?;
    let mut context = raw
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({"version":1}));
    context["source"] = json!(source);
    context["verified"] = json!(verified);
    context["provisional"] = json!(provisional);
    if let Some(id) = receipt {
        context["receipt_id"] = json!(id);
    }
    if let Some(id) = occurrence {
        context["occurrence"] = json!(id);
    }
    tx.execute(
        "UPDATE events SET message_context=?2 WHERE id=?1",
        params![event, context.to_string()],
    )?;
    if verified {
        if let Some(occurrence) = occurrence {
            link_occurrence(tx, event, occurrence)?;
        }
    }
    Ok(())
}
/// Only an exact, explicitly supplied occurrence identity can cancel a second
/// automatic submission. Native Dell MessageId is deliberately never promoted.
fn link_occurrence(tx: &Transaction<'_>, event: i64, occurrence: &Occurrence) -> Result<()> {
    if [
        &occurrence.vendor,
        &occurrence.record_id,
        &occurrence.component,
        &occurrence.generation,
    ]
    .iter()
    .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
    {
        return Ok(());
    }
    let (device, health, kind, key): (String, String, String, String) = tx.query_row(
        "SELECT device,health,kind,key FROM events WHERE id=?1",
        [event],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if !matches!(kind.as_str(), "alarm" | "hardware_log" | "snmp_trap")
        || kind == "alarm" && key != occurrence.component
    {
        return Ok(());
    }
    let mut q=tx.prepare("SELECT id,kind,key,message_context FROM events WHERE device=?1 AND health=?2 AND id<?3 AND kind IN ('alarm','hardware_log','snmp_trap') AND json_extract(message_context,'$.occurrence') IS NOT NULL ORDER BY id DESC LIMIT 10000")?;
    let rows = q.query_map(params![device, health, event], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (id, kind, key, raw) = row?;
        let context: Value = serde_json::from_str(&raw)?;
        if context["verified"] != true || kind == "alarm" && key != occurrence.component {
            continue;
        }
        if serde_json::from_value::<Occurrence>(context["occurrence"].clone())
            .ok()
            .as_ref()
            != Some(occurrence)
        {
            continue;
        }
        tx.execute(
            "UPDATE outbox SET cancelled=1 WHERE event_id=?1 AND delivered IS NULL",
            [event],
        )?;
        tx.execute(
            "UPDATE desktop_jobs SET cancelled=1 WHERE event_id=?1 AND delivered IS NULL",
            [event],
        )?;
        tx.execute("UPDATE events SET mail_reason='same_occurrence',desktop_reason='same_occurrence',message_context=json_set(message_context,'$.same_occurrence_as',?2) WHERE id=?1",params![event,id])?;
        break;
    }
    Ok(())
}
fn next_sequence(tx: &Transaction<'_>, device: &str) -> Result<i64> {
    tx.execute("INSERT INTO snmp_alarm_clock(device,sequence) VALUES(?1,1) ON CONFLICT(device) DO UPDATE SET sequence=sequence+1 WHERE sequence<9223372036854775806",[device])?;
    let sequence = sequence(tx, device)?;
    ensure!(sequence < i64::MAX - 1, "trap clock exhausted");
    Ok(sequence)
}
fn sequence(conn: &Connection, device: &str) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT sequence FROM snmp_alarm_clock WHERE device=?1",
            [device],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}
impl Store {
    pub fn trap_sequence(&self, device: &str) -> Result<i64> {
        sequence(&self.0, device)
    }
    /// A primary-confirmed recovery also ends a transport duplicate episode,
    /// even if the controller did not send a normal-state notification.
    pub(crate) fn recovered_since_receipt(
        &self,
        device: &str,
        revision: i64,
        fingerprint: &str,
    ) -> Result<bool> {
        Ok(self.0.query_row("SELECT EXISTS(SELECT 1 FROM snmp_receipts r JOIN alarm_state a ON a.device=r.device AND a.key=json_extract(r.data,'$.component_key') WHERE r.device=?1 AND r.revision=?2 AND json_extract(r.data,'$.fingerprint')=?3 AND json_extract(r.data,'$.verified')=1 AND json_extract(r.data,'$.restored')=0 AND a.health='\"ok\"')",params![device,revision,fingerprint],|r|r.get(0))?)
    }
}

pub(crate) fn apply_receipt(
    tx: &Transaction<'_>,
    d: &Device,
    revision: i64,
    receipt: &mut Receipt,
    id: i64,
    now: i64,
) -> Result<()> {
    let Some(event) = receipt.event.clone() else {
        return Ok(());
    };
    let trusted = receipt.verified && receipt.version.as_deref() == Some("v3");
    let saved = snapshot(tx, &d.id)?;
    let mut mapping = if trusted && matches!(event.class, Class::Fault | Class::Recovery) {
        if let (Some(saved), Some(identity)) = (&saved, &event.identity) {
            resolve(
                tx,
                d,
                revision,
                saved,
                identity,
                &event.component_kind,
                receipt.engine_id.as_deref(),
                receipt.engine_boots,
                now.max(crate::now()),
                false,
            )?
        } else {
            None
        }
    } else {
        None
    };
    if let Some((key, _)) = &mapping {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM observation_evidence WHERE device=?1 AND key=?2)",
            params![d.id, key],
            |r| r.get(0),
        )?;
        if !exists
            && tx.query_row(
                "SELECT COUNT(*) FROM observation_evidence WHERE device=?1",
                [&d.id],
                |r| r.get::<_, i64>(0),
            )? >= 4096
        {
            mapping = None;
        }
    }
    let linked = if let Some((key, generation)) = mapping {
        let clock = next_sequence(tx, &d.id)?;
        let health = current_health(tx, &d.id, &key)?;
        let mut e = alarm_evidence(tx, &d.id, &key)?.unwrap_or(ObservationEvidence {
            source: EvidenceSource::SnmpTrap,
            revision,
            generation,
            health,
            received: now,
            active: false,
            sequence: 0,
            provisional: false,
            confirmation: String::new(),
            conditions: BTreeMap::new(),
            identity: None,
        });
        e.revision = revision;
        e.generation = generation;
        e.sequence = clock;
        e.received = now;
        e.identity = event.identity.clone();
        e.confirmation = "pending".into();
        receipt.component_key = Some(key.clone());
        let boundary: i64 =
            tx.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |r| r.get(0))?;
        if event.class == Class::Fault {
            if !e.active || !crate::acknowledgement::fault(health) {
                e.conditions.clear();
            }
            let condition =
                if e.conditions.len() < 15 || e.conditions.contains_key(&event.condition) {
                    event.condition.clone()
                } else {
                    "additional_conditions".into()
                };
            let before = e
                .conditions
                .get(&condition)
                .map(|c| c.health)
                .unwrap_or(Health::Unknown);
            e.conditions.insert(
                condition,
                Condition {
                    health: max(before, event.health),
                    sequence: clock,
                    occurrence: None,
                },
            );
            e.health = max(health, event.health);
            e.active = true;
            e.provisional = true;
            e.source = EvidenceSource::SnmpTrap;
            let mut partial = saved.clone().unwrap_or_default();
            let label = partial
                .observations
                .iter()
                .find(|o| o.key == key)
                .map(|o| o.label.clone())
                .unwrap_or_else(|| event.message.clone());
            partial.observations = vec![Observation {
                key: key.clone(),
                label,
                health: e.health,
                reading: None,
                unit: None,
            }];
            apply_conditions(&mut partial, &key, &e);
            let mut device = d.clone();
            device.repeat_seconds = None;
            crate::alarm::reduce(tx, &device, &partial, now)?;
        } else {
            e.active = crate::acknowledgement::fault(health);
            e.health = health;
        }
        save_evidence(tx, &d.id, &key, Some(id), &e)?;
        receipt.handling = Some(
            if event.class == Class::Fault {
                "provisional_fault"
            } else {
                "recovery_pending"
            }
            .into(),
        );
        let created: Vec<i64> = {
            let mut q = tx.prepare("SELECT id FROM events WHERE id>?1 AND device=?2")?;
            let result = q
                .query_map(params![boundary, d.id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            result
        };
        for event_id in &created {
            annotate(
                tx,
                *event_id,
                "snmp_trap",
                true,
                event.class == Class::Fault,
                Some(id),
                event.occurrence.as_ref(),
            )?;
        }
        let latest: Option<i64> = if crate::acknowledgement::fault(health)
            || event.class == Class::Fault
        {
            tx.query_row("SELECT id FROM events WHERE device=?1 AND key=?2 AND kind='alarm' ORDER BY id DESC LIMIT 1",params![d.id,key],|r|r.get(0)).optional()?
        } else {
            None
        };
        created.last().copied().or(latest)
    } else {
        prune_events(tx, now, 9999)?;
        if tx.query_row(
            "SELECT COUNT(*) FROM events WHERE kind='snmp_trap'",
            [],
            |r| r.get::<_, i64>(0),
        )? >= 10000
        {
            receipt.handling = Some("event_history_full".into());
            return Ok(());
        }
        let health = if trusted && event.class == Class::Fault {
            event.health
        } else {
            Health::Unknown
        };
        let event_id = crate::store::event(
            tx,
            d,
            &format!("trap:{}", receipt.fingerprint),
            "snmp_trap",
            health,
            &event.message,
            now,
        )?;
        annotate(
            tx,
            event_id,
            "snmp_trap",
            trusted,
            false,
            Some(id),
            event.occurrence.as_ref(),
        )?;
        receipt.handling = Some(
            match event.class {
                Class::Fault if trusted => "event_only_pending",
                Class::Recovery => "recovery_hint",
                Class::Test => "test",
                Class::UnsupportedPet => "unsupported_pet",
                _ if !trusted => "unverified",
                _ => "unclassified",
            }
            .into(),
        );
        Some(event_id)
    };
    tx.execute(
        "UPDATE snmp_receipts SET event_id=?2 WHERE id=?1",
        params![id, linked],
    )?;
    Ok(())
}

pub(crate) fn persist_inventory(
    tx: &Transaction<'_>,
    d: &Device,
    snapshot: &Snapshot,
    revision: i64,
) -> Result<()> {
    // Legacy/manual snapshot application without SNMP metadata is not an
    // inventory refresh for an SNMP primary.
    if d.primary_protocol == PrimaryProtocol::Snmp && snapshot.snmp.is_none() {
        return Ok(());
    }
    tx.execute("DELETE FROM component_identity WHERE device=?1", [&d.id])?;
    let (source, generation, identities) = if let Some(s) = &snapshot.snmp {
        (
            EvidenceSource::SnmpPoll,
            s.generation,
            s.identities.as_slice(),
        )
    } else {
        (
            EvidenceSource::Redfish,
            revision,
            snapshot.component_identities.as_slice(),
        )
    };
    for c in identities.iter().take(4096) {
        let record = ComponentIdentity {
            source,
            locator: c.locator.clone(),
            aliases: c.aliases.clone(),
            generation,
            revision,
        };
        let raw = serde_json::to_string(&record)?;
        ensure!(raw.len() <= 4096, "inventory alias limit");
        tx.execute("INSERT INTO component_identity(device,key,data) VALUES(?1,?2,?3) ON CONFLICT(device,key) DO UPDATE SET data=excluded.data",params![d.id,c.key,raw])?;
    }
    tx.execute("DELETE FROM observation_evidence WHERE device=?1 AND json_extract(data,'$.active')=0 AND key NOT IN (SELECT key FROM component_identity WHERE device=?1)",[&d.id])?;
    Ok(())
}
/// Pending automatic or explicitly queued manual submissions are never evicted.
pub(crate) fn prune_events(tx: &Transaction<'_>, now: i64, keep: i64) -> Result<usize> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM events WHERE kind='snmp_trap'",
        [],
        |r| r.get(0),
    )?;
    let excess = (count - keep).max(0);
    let rows: Vec<(i64, i64)> = {
        let mut q=tx.prepare("SELECT e.id,e.created FROM events e WHERE e.kind='snmp_trap' AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.event_id=e.id AND o.delivered IS NULL AND o.cancelled=0) AND NOT EXISTS(SELECT 1 FROM desktop_jobs j WHERE j.event_id=e.id AND j.delivered IS NULL AND j.cancelled=0 AND j.attempts<8) AND NOT EXISTS(SELECT 1 FROM mail_replay r WHERE r.event_id=e.id AND r.state IN ('preview','queued')) ORDER BY e.id LIMIT 10000")?;
        let result = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        result
    };
    let mut removed = 0;
    for (id, created) in rows {
        if created >= now - 7 * 86400 && removed >= excess {
            continue;
        }
        tx.execute("DELETE FROM mail_recipient WHERE outbox_id IN (SELECT id FROM outbox WHERE event_id=?1)",[id])?;
        tx.execute("DELETE FROM outbox WHERE event_id=?1", [id])?;
        tx.execute("DELETE FROM desktop_jobs WHERE event_id=?1", [id])?;
        tx.execute("DELETE FROM events WHERE id=?1", [id])?;
        removed += 1;
    }
    Ok(removed as usize)
}
/// Called after current inventory is persisted and before shared alarm reduction.
/// A poll begun before a relevant trusted input cannot lower that component.
pub(crate) fn guard_poll(
    tx: &Transaction<'_>,
    d: &Device,
    snapshot: &mut Snapshot,
    revision: i64,
    started: Option<i64>,
    now: i64,
) -> Result<()> {
    let rows: Vec<(String, Option<i64>, String)> = {
        let mut q =
            tx.prepare("SELECT key,receipt_id,data FROM observation_evidence WHERE device=?1")?;
        let result = q
            .query_map([&d.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        result
    };
    for (key, receipt, raw) in rows {
        let mut e: ObservationEvidence = serde_json::from_str(&raw)?;
        if !e.active {
            continue;
        }
        let index = snapshot.observations.iter().position(|o| o.key == key);
        let h = index
            .map(|i| snapshot.observations[i].health)
            .unwrap_or(Health::Unknown);
        let complete = snapshot
            .capabilities
            .iter()
            .all(|c| c.outcome == "available")
            && snapshot.snmp.as_ref().is_none_or(|s| s.complete);
        let identity_valid = if let Some(identity) = &e.identity {
            let kind = snapshot
                .resources
                .get(&key)
                .map(|r| r.kind.as_str())
                .unwrap_or("");
            let canonical_kind = match kind.rsplit('.').next().unwrap_or(kind) {
                "PowerSupply" => "power_supply",
                "Fan" => "fan",
                "Temperature" => "temperature",
                "Memory" => "memory",
                "Drive" => "physical_disk",
                other => other,
            };
            resolve(
                tx,
                d,
                revision,
                snapshot,
                identity,
                canonical_kind,
                snapshot.snmp.as_ref().and_then(|s| s.engine_id.as_deref()),
                snapshot.snmp.as_ref().and_then(|s| s.engine_boots),
                now,
                true,
            )?
            .is_some_and(|(k, _)| k == key)
        } else {
            false
        };
        if e.sequence > started.unwrap_or(0) || !complete || !identity_valid || h == Health::Unknown
        {
            if let Some(i) = index {
                if crate::identity::severity(h) < crate::identity::severity(e.health) {
                    snapshot.observations[i].health = Health::Unknown;
                }
            }
            // An older rollup OK is not newer evidence about its trapped child.
            // Preserve independent siblings while guarding dependent summaries.
            let ancestors: Vec<_> = snapshot
                .resources
                .iter()
                .filter(|(_, r)| crate::correlation::summary(r))
                .filter(|(parent, _)| {
                    crate::correlation::descendants(parent, &snapshot.resources).contains(&key)
                })
                .map(|(key, _)| key.clone())
                .collect();
            for observation in &mut snapshot.observations {
                if ancestors.contains(&observation.key)
                    && crate::identity::severity(observation.health)
                        < crate::identity::severity(e.health)
                {
                    observation.health = Health::Unknown;
                }
            }
            if crate::acknowledgement::fault(h) {
                e.health = max(e.health, h);
            }
            e.confirmation = if e.sequence > started.unwrap_or(0) {
                "newer_trap"
            } else {
                "unavailable"
            }
            .into();
            if e.provisional {
                apply_conditions(snapshot, &key, &e);
            }
        } else {
            e.health = h;
            e.provisional = false;
            e.active = crate::acknowledgement::fault(h);
            e.confirmation = "confirmed".into();
            e.revision = revision;
            e.source = if d.primary_protocol == PrimaryProtocol::Snmp {
                EvidenceSource::SnmpPoll
            } else {
                EvidenceSource::Redfish
            };
            if h == Health::Ok {
                e.conditions.clear();
            }
        }
        save_evidence(tx, &d.id, &key, receipt, &e)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "integration_tests.rs"]
mod tests;
