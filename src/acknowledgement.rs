//! Local operator acknowledgement is independent of the reported hardware health.
use crate::{correlation, dsm::BoundaryError, model::*, store::Store};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn hardware(key: &str) -> bool {
    key != "collector" && !key.starts_with("coverage:") && !key.starts_with("log:")
}
pub(crate) fn fault(health: Health) -> bool {
    matches!(health, Health::Warning | Health::Critical)
}
fn token() -> String {
    format!("{:032x}", rand::random::<u128>())
}
pub(crate) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS alarm_control(
        device TEXT NOT NULL, key TEXT NOT NULL, token TEXT NOT NULL,
        acknowledged INTEGER NOT NULL DEFAULT 0, actor TEXT, acknowledged_at INTEGER,
        reason TEXT, signature TEXT NOT NULL DEFAULT '', reannounce INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(device,key), FOREIGN KEY(device,key) REFERENCES alarm_state(device,key) ON DELETE CASCADE);
        INSERT OR IGNORE INTO alarm_control(device,key,token)
        SELECT device,key,lower(hex(randomblob(16))) FROM alarm_state;")?;
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub status: String,
    pub acknowledged: bool,
    pub derived: bool,
    pub causes: Vec<String>,
    pub token: String,
    pub acknowledgement: Option<Value>,
}
pub(crate) struct Evaluation {
    pub statuses: BTreeMap<String, Status>,
}
impl Evaluation {
    pub fn acknowledged(&self) -> BTreeSet<String> {
        self.statuses
            .iter()
            .filter(|(_, s)| s.status == "acknowledged")
            .map(|(k, _)| k.clone())
            .collect()
    }
    pub fn overall(&self, snapshot: Option<&Snapshot>, stale: bool) -> &'static str {
        let Some(snapshot) = snapshot.filter(|_| !stale) else {
            return "unknown";
        };
        for (level, health) in [("critical", Health::Critical), ("warning", Health::Warning)] {
            if self.statuses.values().any(|s| s.status == level)
                || snapshot.observations.iter().any(|o| {
                    hardware(&o.key) && o.health == health && !self.statuses.contains_key(&o.key)
                })
            {
                // Reset removes the stored incident, not its last measurement.
                // A still-faulty current reading must not make the device green.
                return level;
            }
        }
        if snapshot
            .capabilities
            .iter()
            .any(|c| c.outcome != "available")
        {
            return "unknown";
        }
        let mut assessable = false;
        for o in snapshot.observations.iter().filter(|o| hardware(&o.key)) {
            if self
                .statuses
                .get(&o.key)
                .is_some_and(|s| s.status == "acknowledged")
            {
                assessable = true;
                continue;
            }
            if o.health == Health::Unknown && snapshot.assessment_exclusions.contains_key(&o.key) {
                continue;
            }
            assessable = true;
            if o.health == Health::Unknown {
                return "unknown";
            }
        }
        if !assessable {
            "unknown"
        } else if self.statuses.values().any(|s| s.status == "acknowledged") {
            "acknowledged"
        } else {
            "ok"
        }
    }
}

pub(crate) fn evaluate(
    conn: &Connection,
    device: &str,
    snapshot: Option<&Snapshot>,
) -> Result<Evaluation> {
    let mut q = conn.prepare("SELECT a.key,a.health,c.token,c.acknowledged,c.actor,c.acknowledged_at,c.reason FROM alarm_state a LEFT JOIN alarm_control c ON c.device=a.device AND c.key=a.key WHERE a.device=?1 AND a.health!='\"ok\"'")?;
    let rows = q
        .query_map([device], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<bool>>(3)?.unwrap_or(false),
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut states = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for (key, raw, token, acknowledged, actor, at, reason) in rows {
        let health: Health = serde_json::from_str(&raw)?;
        if !fault(health) {
            continue;
        }
        states.insert(key.clone(), health);
        statuses.insert(key.clone(), Status {
            status: if acknowledged && hardware(&key) { "acknowledged".into() } else { code(health).into() },
            acknowledged: acknowledged && hardware(&key),
            derived: false, causes: vec![], token,
            acknowledgement: at.map(|at| json!({"actor":actor,"created":at,"reason":reason,"needs_review":!acknowledged})),
        });
    }
    if let Some(snapshot) = snapshot {
        let groups = correlation::groups(&snapshot.resources, &states);
        let originals = statuses.clone();
        for key in states.keys() {
            derive(
                key,
                snapshot,
                &states,
                &groups,
                &originals,
                &mut statuses,
                &mut BTreeSet::new(),
            );
        }
    }
    Ok(Evaluation { statuses })
}
fn code(h: Health) -> &'static str {
    match h {
        Health::Critical => "critical",
        Health::Warning => "warning",
        Health::Ok => "ok",
        Health::Unknown => "unknown",
    }
}
fn derive(
    key: &str,
    snapshot: &Snapshot,
    states: &BTreeMap<String, Health>,
    groups: &BTreeMap<String, Vec<String>>,
    original: &BTreeMap<String, Status>,
    result: &mut BTreeMap<String, Status>,
    visiting: &mut BTreeSet<String>,
) -> u8 {
    // Cache completed summaries: walking every descendant recursively without
    // memoization would grow exponentially on a long dependency chain.
    if let Some(status) = result.get(key).filter(|s| !s.causes.is_empty()) {
        return match status.status.as_str() {
            "acknowledged" => 0,
            "warning" => 2,
            _ => 3,
        };
    }
    let Some(current) = original.get(key) else {
        return 0;
    };
    let manual_summary = current.acknowledged
        && snapshot
            .resources
            .get(key)
            .is_some_and(correlation::summary);
    if current.acknowledged && !manual_summary {
        return 0;
    }
    let raw = crate::identity::severity(states[key]);
    if (!groups.contains_key(key) && !manual_summary) || !visiting.insert(key.into()) {
        return raw;
    }
    let below = correlation::descendants(key, &snapshot.resources);
    // Conditions with no known faulty origin cannot be explained by a different fault.
    if !manual_summary
        && snapshot.resources[key]
            .condition_origins
            .iter()
            .any(|origin| {
                !states.get(origin).is_some_and(|h| fault(*h))
                    && !correlation::descendants(origin, &snapshot.resources)
                        .iter()
                        .any(|k| states.get(k).is_some_and(|h| fault(*h)))
            })
    {
        visiting.remove(key);
        return raw;
    }
    let mut level = 0;
    let mut causes = Vec::new();
    for child in below.iter().filter(|child| states.contains_key(*child)) {
        level = level.max(derive(
            child, snapshot, states, groups, original, result, visiting,
        ));
        causes.push(child.clone());
    }
    visiting.remove(key);
    if !causes.is_empty() {
        let status = result.get_mut(key).unwrap();
        status.derived = !current.acknowledged;
        status.causes = causes;
        status.status = match level {
            0 => "acknowledged",
            2 => "warning",
            _ => "critical",
        }
        .into();
    }
    if manual_summary && result[key].causes.is_empty() {
        0
    } else {
        level
    }
}

fn reported_identity(value: &Value, uuid: bool) -> Option<String> {
    let value = value.as_str()?.trim();
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || [
            "n/a",
            "na",
            "none",
            "unknown",
            "not available",
            "not specified",
            "unspecified",
        ]
        .contains(&lower.as_str())
        || !value
            .chars()
            .any(|c| c != '0' && c != '-' && c != ':' && !c.is_whitespace())
    {
        return None;
    }
    Some(if uuid { lower } else { value.to_owned() })
}

// BMCs expose less metadata while off or starting. Missing/placeholder identities
// and absent condition details do not erase the last usable comparison baseline.
// Confirmed OK, in contrast, ends the episode and may clear its condition details.
fn comparison_baseline(previous: &str, current: &str, ongoing_fault: bool) -> String {
    let old = serde_json::from_str::<Value>(previous).unwrap_or(Value::Null);
    let Ok(mut new) = serde_json::from_str::<Value>(current) else {
        return current.into();
    };
    if new.as_array().is_none_or(|a| a.len() != 3) {
        return current.into();
    }
    for i in 0..2 {
        new[i] = reported_identity(&new[i], i == 0)
            .or_else(|| reported_identity(&old[i], i == 0))
            .map(Value::String)
            .unwrap_or(Value::Null);
    }
    if ongoing_fault
        && new[2].as_array().is_some_and(Vec::is_empty)
        && old[2].as_array().is_some_and(|a| !a.is_empty())
    {
        new[2] = old[2].clone();
    }
    new.to_string()
}

// Only a contradiction of previously known identity/condition data establishes
// a new cause. First available details are learned, including after migration or
// off -> on. Message arguments can contain fluctuating readings.
fn new_cause(previous: &str, current: &str) -> bool {
    if previous.is_empty() {
        return false;
    }
    let parse = |raw: &str| serde_json::from_str::<Value>(raw).ok();
    let old = parse(previous).unwrap_or_else(|| json!([null, null, []]));
    let Some(new) = parse(current) else {
        return true;
    };
    if old.as_array().is_none_or(|v| v.len() != 3) || new.as_array().is_none_or(|v| v.len() != 3) {
        return previous != current;
    }
    if (0..2).any(|i| {
        match (
            reported_identity(&old[i], i == 0),
            reported_identity(&new[i], i == 0),
        ) {
            (Some(before), Some(after)) => before != after,
            _ => false,
        }
    }) {
        return true;
    }
    let conditions = |value: &Value| -> BTreeMap<String, u8> {
        let mut found = BTreeMap::new();
        for raw in value[2].as_array().into_iter().flatten() {
            let Some(c) = raw
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
            else {
                continue;
            };
            let key = json!([c[0], c[2]]).to_string();
            let severity = match c[3].as_str() {
                Some("OK") => 0,
                Some("Warning") => 2,
                _ => 3,
            };
            found
                .entry(key)
                .and_modify(|h: &mut u8| *h = (*h).max(severity))
                .or_insert(severity);
        }
        found
    };
    let before = conditions(&old);
    !before.is_empty()
        && conditions(&new)
            .iter()
            .any(|(id, level)| before.get(id).is_none_or(|old| level > old))
}

pub(crate) fn signatures(
    tx: &Transaction<'_>,
    device: &str,
    snapshot: &Snapshot,
    now: i64,
) -> Result<()> {
    for o in snapshot
        .observations
        .iter()
        .filter(|o| hardware(&o.key) && o.health != Health::Unknown)
    {
        let Some(resource) = snapshot.resources.get(&o.key) else {
            continue;
        };
        let previous: Option<(String, bool)> = tx
            .query_row(
                "SELECT signature,acknowledged FROM alarm_control WHERE device=?1 AND key=?2",
                params![device, o.key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((signature, acknowledged)) = previous {
            let baseline =
                comparison_baseline(&signature, &resource.condition_fingerprint, fault(o.health));
            if signature != baseline && !baseline.is_empty() {
                let invalidate = new_cause(&signature, &baseline);
                tx.execute("UPDATE alarm_control SET signature=?3,token=CASE WHEN ?5 THEN ?4 ELSE token END,acknowledged=CASE WHEN ?5 THEN 0 ELSE acknowledged END,actor=CASE WHEN ?5 THEN NULL ELSE actor END,acknowledged_at=CASE WHEN ?5 THEN NULL ELSE acknowledged_at END,reason=CASE WHEN ?5 THEN NULL ELSE reason END,reannounce=CASE WHEN acknowledged=1 AND ?5 THEN 1 ELSE reannounce END WHERE device=?1 AND key=?2",params![device,o.key,baseline,token(),invalidate])?;
                if acknowledged && invalidate {
                    audit(
                        tx,
                        "system",
                        "alarm.invalidate",
                        device,
                        &format!("{}: Fehlermerkmale geändert", o.key),
                        now,
                    )?;
                }
            }
        }
    }
    Ok(())
}

// Called before event creation; the state row already exists at this point.
pub(crate) fn transition(
    tx: &Transaction<'_>,
    d: &Device,
    o: &Observation,
    before: Option<Health>,
    now: i64,
) -> Result<bool> {
    tx.execute(
        "INSERT OR IGNORE INTO alarm_control(device,key,token) VALUES(?1,?2,?3)",
        params![d.id, o.key, token()],
    )?;
    let (acknowledged, force): (bool, bool) = tx.query_row(
        "SELECT acknowledged,reannounce FROM alarm_control WHERE device=?1 AND key=?2",
        params![d.id, o.key],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let invalidated = o.health == Health::Ok
        || before
            .is_some_and(|h| crate::identity::severity(o.health) > crate::identity::severity(h));
    if before != Some(o.health) || force {
        tx.execute("UPDATE alarm_control SET token=?3,reannounce=0,acknowledged=CASE WHEN ?4 THEN 0 ELSE acknowledged END,actor=CASE WHEN ?4 THEN NULL ELSE actor END,acknowledged_at=CASE WHEN ?4 THEN NULL ELSE acknowledged_at END,reason=CASE WHEN ?4 THEN NULL ELSE reason END WHERE device=?1 AND key=?2",params![d.id,o.key,token(),invalidated])?;
    }
    if acknowledged && invalidated {
        audit(
            tx,
            "system",
            "alarm.invalidate",
            &d.id,
            &format!("{}: Zustand {}", o.key, code(o.health)),
            now,
        )?;
    }
    Ok(force && fault(o.health))
}
fn audit(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    device: &str,
    outcome: &str,
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,?2,?3,?4,?5)",
        params![actor, action, device, outcome, now],
    )?;
    Ok(())
}

pub(crate) fn suppress(
    tx: &Transaction<'_>,
    device: &str,
    snapshot: &Snapshot,
    boundary: i64,
    previous: &BTreeSet<String>,
) -> Result<()> {
    let evaluation = evaluate(tx, device, Some(snapshot))?;
    let current = evaluation.acknowledged();
    for key in current.union(previous) {
        // Only new recovery events inherit the preceding acknowledgement.
        let active = current.contains(key);
        for (column, queue) in [
            ("mail_reason", "outbox"),
            ("desktop_reason", "desktop_jobs"),
        ] {
            tx.execute(&format!("UPDATE events SET {column}='acknowledged' WHERE device=?1 AND key=?2 AND kind!='hardware_log' AND ((id>?3 AND (?4 OR kind='recovery')) OR (?4 AND id IN (SELECT event_id FROM {queue} WHERE delivered IS NULL AND cancelled=0)))"),params![device,key,boundary,active])?;
        }
        tx.execute("UPDATE outbox SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key=?2 AND mail_reason='acknowledged')",params![device,key])?;
        tx.execute("UPDATE desktop_jobs SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND key=?2 AND desktop_reason='acknowledged')",params![device,key])?;
    }
    Ok(())
}

impl Store {
    /// Remove one stored incident, without inventing a healthy measurement.
    /// A later confirmed fault creates a new incident through normal polling.
    pub fn reset_alarm(
        &mut self,
        id: &str,
        revision: i64,
        key: &str,
        expected_token: &str,
        actor: &str,
        now: i64,
    ) -> Result<()> {
        anyhow::ensure!(
            hardware(key) && !key.is_empty() && key.len() <= 4096,
            BoundaryError("alarm_not_acknowledgeable")
        );
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let row: Option<(i64, Option<String>)> = tx
            .query_row(
                "SELECT revision,snapshot FROM devices WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (current_revision, raw) = row.ok_or(BoundaryError("device_conflict"))?;
        anyhow::ensure!(
            current_revision == revision,
            BoundaryError("device_conflict")
        );
        let snapshot: Option<Snapshot> = raw.map(|raw| serde_json::from_str(&raw)).transpose()?;
        let evaluation = evaluate(&tx, id, snapshot.as_ref())?;
        let status = evaluation
            .statuses
            .get(key)
            .ok_or(BoundaryError("alarm_conflict"))?;
        anyhow::ensure!(
            status.token == expected_token,
            BoundaryError("alarm_conflict")
        );
        anyhow::ensure!(!status.derived, BoundaryError("alarm_not_acknowledgeable"));

        // Cancel only automatic jobs for this canonical resource. Historical
        // events and explicitly requested manual replays remain independent.
        for (column, queue) in [
            ("mail_reason", "outbox"),
            ("desktop_reason", "desktop_jobs"),
        ] {
            tx.execute(
                &format!("UPDATE events SET {column}='reset' WHERE device=?1 AND (key=?2 OR canonical_key=?2) AND kind!='hardware_log' AND id IN (SELECT event_id FROM {queue} WHERE delivered IS NULL AND cancelled=0)"),
                params![id, key],
            )?;
            tx.execute(
                &format!("UPDATE {queue} SET cancelled=1 WHERE delivered IS NULL AND event_id IN (SELECT id FROM events WHERE device=?1 AND (key=?2 OR canonical_key=?2) AND kind!='hardware_log')"),
                params![id, key],
            )?;
        }
        // alarm_control is removed by its existing ON DELETE CASCADE.
        tx.execute(
            "DELETE FROM alarm_state WHERE device=?1 AND key=?2",
            params![id, key],
        )?;
        audit(&tx, actor, "alarm.reset", id, key, now)?;
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn acknowledge_alarm(
        &mut self,
        id: &str,
        revision: i64,
        key: &str,
        expected_token: &str,
        acknowledged: bool,
        reason: &str,
        actor: &str,
        now: i64,
    ) -> Result<()> {
        anyhow::ensure!(
            hardware(key) && key.len() <= 4096,
            BoundaryError("alarm_not_acknowledgeable")
        );
        let reason = reason.trim();
        anyhow::ensure!(
            reason.len() <= 1000
                && !reason.chars().any(char::is_control)
                && (!acknowledged || !reason.is_empty()),
            BoundaryError("alarm_reason_invalid")
        );
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let row: Option<(String, i64, Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT config,revision,snapshot,last_poll FROM devices WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (config, current_revision, raw, last_poll) =
            row.ok_or(BoundaryError("device_conflict"))?;
        anyhow::ensure!(
            revision == current_revision,
            BoundaryError("device_conflict")
        );
        let device: Device = serde_json::from_str(&config)?;
        let snapshot: Snapshot = raw
            .map(|r| serde_json::from_str(&r))
            .transpose()?
            .unwrap_or_default();
        let evaluation = evaluate(&tx, id, Some(&snapshot))?;
        let status = evaluation
            .statuses
            .get(key)
            .ok_or(BoundaryError("alarm_conflict"))?;
        anyhow::ensure!(
            status.token == expected_token,
            BoundaryError("alarm_conflict")
        );
        // Summaries are confirmed through their concrete causes whenever possible.
        anyhow::ensure!(!status.derived, BoundaryError("alarm_not_acknowledgeable"));
        let previous = evaluation.acknowledged();
        let was_acknowledged = status.acknowledged;
        if was_acknowledged == acknowledged {
            return Ok(());
        }
        let boundary: i64 =
            tx.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |r| r.get(0))?;
        let fresh = device.enabled
            && last_poll.is_some_and(|at| now - at <= device.stale_after_seconds() as i64)
            && snapshot
                .observations
                .iter()
                .any(|o| o.key == key && fault(o.health));
        tx.execute("UPDATE alarm_control SET token=?3,acknowledged=?4,actor=CASE WHEN ?4 THEN ?5 ELSE NULL END,acknowledged_at=CASE WHEN ?4 THEN ?6 ELSE NULL END,reason=CASE WHEN ?4 THEN ?7 ELSE NULL END,reannounce=?8 WHERE device=?1 AND key=?2",params![id,key,token(),acknowledged,actor,now,reason,!acknowledged && !fresh])?;
        audit(
            &tx,
            actor,
            if acknowledged {
                "alarm.acknowledge"
            } else {
                "alarm.reopen"
            },
            id,
            &format!("{key}: {reason}"),
            now,
        )?;
        // Removing an old manual summary acknowledgement must not bypass the
        // ordinary grouping policy when concrete causes have since appeared.
        let grouped = evaluate(&tx, id, Some(&snapshot))?
            .statuses
            .get(key)
            .is_some_and(|s| s.derived);
        if !acknowledged && fresh && !grouped {
            let o = snapshot.observations.iter().find(|o| o.key == key).unwrap();
            crate::store::event(&tx, &device, key, "alarm", o.health, &o.label, now)?;
            tx.execute(
                "UPDATE alarm_state SET emitted=?3 WHERE device=?1 AND key=?2",
                params![id, key, now],
            )?;
        }
        suppress(&tx, id, &snapshot, boundary, &previous)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset(s: &mut Store, d: &Device, key: &str, now: i64) {
        let version = assessment(s, d, key).token;
        let revision = s.get(&d.id).unwrap().unwrap().2;
        s.reset_alarm(&d.id, revision, key, &version, "reset-admin", now)
            .unwrap();
    }

    #[test]
    fn powered_off_hpe_inventory_preserves_old_incident_until_reset_and_real_fault_rearms() {
        let (_dir, mut s, d) = setup();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/hpe-ilo6-179-power-off.json"
        ))
        .unwrap();
        let mut observations = BTreeMap::new();
        let mut applicability = crate::assessment::Applicability::default();
        for resource in fixture["resources"].as_array().unwrap() {
            let uri = resource["uri"].as_str().unwrap();
            let body = &resource["body"];
            applicability.observe(uri, body);
            crate::collector::normalize(uri, body, &mut observations, &mut Vec::new());
        }
        let key = "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/0/";
        let current = Snapshot {
            assessment_exclusions: applicability.exclusions(&observations),
            observations: observations.into_values().collect(),
            ..Default::default()
        };
        assert_eq!(
            current.assessment_exclusions[key],
            AssessmentExclusion::Absent
        );
        let mut previous = current.clone();
        previous.assessment_exclusions.remove(key);
        previous
            .observations
            .iter_mut()
            .find(|o| o.key == key)
            .unwrap()
            .health = Health::Warning;
        let now = crate::now();
        s.apply(&d, &previous, now - 60).unwrap();
        let count = s.event_entries(-1).unwrap().len();
        s.apply(&d, &current, now).unwrap();
        assert_eq!(assessment(&s, &d, key).status, "warning");
        assert_eq!(s.event_entries(-1).unwrap().len(), count);
        reset(&mut s, &d, key, now + 1);
        s.apply(&d, &current, now + 2).unwrap();
        s.apply(&d, &current, now + 3).unwrap();
        assert!(s.dashboard().unwrap()["devices"][0]["alarms"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(s.event_entries(-1).unwrap().len(), count);
        let mut failed = current;
        failed.assessment_exclusions.remove(key);
        failed
            .observations
            .iter_mut()
            .find(|o| o.key == key)
            .unwrap()
            .health = Health::Critical;
        s.apply(&d, &failed, now + 4).unwrap();
        let alarm = assessment(&s, &d, key);
        assert_eq!(alarm.status, "critical");
        assert!(!alarm.acknowledged);
        assert_eq!(s.event_entries(-1).unwrap().len(), count + 1);
    }

    #[test]
    fn resetting_absent_retained_alarm_preserves_history_measurements_and_other_incidents() {
        let (dir, mut s, d) = setup();
        let now = crate::now();
        let old = Snapshot {
            observations: vec![
                Observation {
                    key: "psu".into(),
                    label: "Empty bay".into(),
                    health: Health::Warning,
                    reading: None,
                    unit: None,
                },
                Observation {
                    key: "drive".into(),
                    label: "Drive".into(),
                    health: Health::Critical,
                    reading: None,
                    unit: None,
                },
            ],
            ..Default::default()
        };
        s.apply(&d, &old, now).unwrap();
        let mut current = old;
        current.observations[0].health = Health::Unknown;
        current
            .assessment_exclusions
            .insert("psu".into(), AssessmentExclusion::Absent);
        s.apply(&d, &current, now + 1).unwrap();
        let before = s.event_entries(-1).unwrap();
        let raw: String =
            s.0.query_row("SELECT snapshot FROM devices WHERE id=?1", [&d.id], |r| {
                r.get(0)
            })
            .unwrap();
        reset(&mut s, &d, "psu", now + 2);
        let after = s.event_entries(-1).unwrap();
        assert_eq!(before.len(), after.len());
        for (a, b) in before.iter().zip(&after) {
            for field in [
                "id", "device", "key", "kind", "health", "message", "created",
            ] {
                assert_eq!(a[field], b[field], "{field}");
            }
        }
        assert_eq!(
            raw,
            s.0.query_row::<String, _, _>(
                "SELECT snapshot FROM devices WHERE id=?1",
                [&d.id],
                |r| r.get(0)
            )
            .unwrap()
        );
        assert_eq!(
            s.0.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM alarm_control WHERE device=?1 AND key='psu'",
                [&d.id],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        let data = s.dashboard().unwrap();
        assert!(data["devices"][0]["alarm_statuses"].get("psu").is_none());
        assert_eq!(
            data["devices"][0]["alarm_statuses"]["drive"]["status"],
            "critical"
        );
        assert_eq!(
            s.pending_mail(now + 2).unwrap().unwrap().event.resource,
            "drive"
        );
        let desktop = s.pending_desktop(now + 2).unwrap().unwrap();
        assert_eq!(
            s.0.query_row::<String, _, _>(
                "SELECT key FROM events WHERE id=?1",
                [desktop.event_id],
                |r| r.get(0)
            )
            .unwrap(),
            "drive"
        );
        let reset_event = after.iter().find(|e| e["key"] == "psu").unwrap();
        assert_eq!(reset_event["mail_reason"], "reset");
        assert_eq!(reset_event["desktop_reason"], "reset");
        s.apply(&d, &current, now + 3).unwrap();
        drop(s);
        let s = Store::open(dir.path()).unwrap();
        assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
            .get("psu")
            .is_none());
        assert_eq!(s.event_entries(-1).unwrap().len(), before.len());
        assert!(s
            .audit_entries()
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "alarm.reset" && e["actor"] == "reset-admin"));
    }

    #[test]
    fn resetting_a_current_or_acknowledged_fault_rearms_it_only_on_the_next_poll() {
        for acknowledged in [false, true] {
            let (_dir, mut s, d) = setup();
            let now = crate::now();
            let snap = Snapshot {
                observations: vec![Observation {
                    key: "fan".into(),
                    label: "Fan".into(),
                    health: Health::Critical,
                    reading: None,
                    unit: None,
                }],
                ..Default::default()
            };
            s.apply(&d, &snap, now).unwrap();
            if acknowledged {
                ack(&mut s, &d, "fan", true, now);
            }
            let old_token = assessment(&s, &d, "fan").token;
            let count = s.event_entries(-1).unwrap().len();
            reset(&mut s, &d, "fan", now + 1);
            assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
                .get("fan")
                .is_none());
            assert_eq!(
                s.dashboard().unwrap()["devices"][0]["overall_status"],
                "critical"
            );
            assert_eq!(s.event_entries(-1).unwrap().len(), count);
            s.apply(&d, &snap, now + 2).unwrap();
            let status = assessment(&s, &d, "fan");
            assert_eq!(status.status, "critical");
            assert!(!status.acknowledged);
            assert_ne!(status.token, old_token);
            assert!(s
                .reset_alarm(&d.id, 1, "fan", &old_token, "admin", now + 3)
                .is_err());
            assert_eq!(
                s.event_entries(-1)
                    .unwrap()
                    .iter()
                    .filter(|e| e["key"] == "fan" && e["kind"] == "alarm")
                    .count(),
                2
            );
        }
    }

    #[test]
    fn reset_rejects_changed_versions_derived_summaries_and_non_hardware_scopes() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now)
            .unwrap();
        let version = assessment(&s, &d, "fan").token;
        for (id, revision, key, token) in [
            (d.id.as_str(), 2, "fan", version.as_str()),
            (d.id.as_str(), 1, "fan", "stale-token"),
            ("missing", 1, "fan", version.as_str()),
            (d.id.as_str(), 1, "missing", version.as_str()),
            (d.id.as_str(), 1, "collector", version.as_str()),
            (d.id.as_str(), 1, "coverage:/redfish/v1/", version.as_str()),
            (d.id.as_str(), 1, "log:fan", version.as_str()),
            (d.id.as_str(), 1, "", version.as_str()),
        ] {
            assert!(
                s.reset_alarm(id, revision, key, token, "admin", now)
                    .is_err(),
                "{key}"
            );
        }
        let parent = assessment(&s, &d, "system");
        assert!(parent.derived);
        assert!(s
            .reset_alarm(&d.id, 1, "system", &parent.token, "admin", now)
            .is_err());
        reset(&mut s, &d, "fan", now + 1);
        assert!(s
            .reset_alarm(&d.id, 1, "fan", &version, "admin", now + 2)
            .is_err());
        assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
            .get("system")
            .is_some());
    }

    #[test]
    fn resetting_canonical_alias_cancels_unsent_automatic_jobs_but_preserves_accepted_and_manual_delivery(
    ) {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = Snapshot {
            observations: vec![Observation {
                key: "legacy".into(),
                label: "PSU".into(),
                health: Health::Warning,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        };
        s.apply(&d, &snap, now).unwrap();
        let first = s.pending_mail(now).unwrap().unwrap();
        s.finish_mail(&first, None, now).unwrap();
        let id = s.event_entries(-1).unwrap()[0]["id"].as_i64().unwrap();
        let preview = s
            .preview_mail_replay(id, "first@example.invalid", "admin", now)
            .unwrap();
        s.enqueue_mail_replay(preview["id"].as_str().unwrap(), "admin", now)
            .unwrap();
        snap.observations[0].key = "modern".into();
        snap.resource_aliases
            .insert("legacy".into(), "modern".into());
        s.apply(&d, &snap, now + 1).unwrap();
        reset(&mut s, &d, "modern", now + 2);
        quiet(&s, now + 2);
        assert!(s.pending_mail_replay(now + 2).unwrap().is_some());
        let event = s
            .event_entries(-1)
            .unwrap()
            .into_iter()
            .find(|e| e["id"] == id)
            .unwrap();
        assert_eq!(event["submitted_recipients"], 1);
        assert_eq!(event["mail_reason"], "reset");
        assert_eq!(event["desktop_reason"], "reset");
    }

    #[test]
    fn resetting_a_retained_cause_does_not_hide_or_dangle_a_still_faulty_summary() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        snap.observations
            .iter_mut()
            .find(|o| o.key == "fan")
            .unwrap()
            .health = Health::Unknown;
        snap.assessment_exclusions
            .insert("fan".into(), AssessmentExclusion::Absent);
        s.apply(&d, &snap, now + 1).unwrap();
        reset(&mut s, &d, "fan", now + 2);
        let data = s.dashboard().unwrap();
        let parent = data["devices"][0]["alarms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == "system")
            .unwrap();
        assert_eq!(parent["covered_by"], json!([]));
        assert_eq!(data["devices"][0]["overall_status"], "critical");
        let count = s.event_entries(-1).unwrap().len();
        s.apply(&d, &snap, now + 3).unwrap();
        assert!(s.event_entries(-1).unwrap().len() > count);
        assert!(s.dashboard().unwrap()["devices"][0]["alarm_statuses"]
            .get("fan")
            .is_none());
        assert_eq!(assessment(&s, &d, "system").status, "critical");
    }

    #[test]
    fn absent_sensor_exclusion_never_clears_a_retained_fault_or_its_acknowledgement() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        let event_count = s.event_entries(-1).unwrap().len();
        snap.observations
            .iter_mut()
            .find(|o| o.key == "fan")
            .unwrap()
            .health = Health::Unknown;
        snap.assessment_exclusions
            .insert("fan".into(), AssessmentExclusion::Absent);
        s.apply(&d, &snap, now + 1).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        assert_eq!(s.event_entries(-1).unwrap().len(), event_count);
        ack(&mut s, &d, "fan", true, now + 1);
        s.apply(&d, &snap, now + 2).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
        quiet(&s, now + 2);
    }
    #[test]
    fn replaying_an_acknowledged_event_does_not_change_alarm_acknowledgement_or_original_delivery()
    {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now)
            .unwrap();
        ack(&mut s, &d, "fan", true, now);
        let events = s.event_entries(-1).unwrap();
        let id = events.iter().find(|e| e["key"] == "fan").unwrap()["id"]
            .as_i64()
            .unwrap();
        let before = s.dashboard().unwrap()["devices"].clone();
        let p = s
            .preview_mail_replay(id, "first@example.invalid", "admin", now + 1)
            .unwrap();
        s.enqueue_mail_replay(p["id"].as_str().unwrap(), "admin", now + 1)
            .unwrap();
        let job = s.pending_mail_replay(now + 1).unwrap().unwrap();
        s.finish_mail_replay(&job, None, now + 2).unwrap();
        assert_eq!(s.dashboard().unwrap()["devices"], before);
        assert_eq!(s.event_entries(-1).unwrap(), events);
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
        quiet(&s, now + 2);
    }
    #[test]
    fn hpe_drive_acknowledgement_groups_summaries_but_not_new_drives_or_controller_faults() {
        use crate::correlation::tests::{hpe_fixture, HPE_FAILED, HPE_OK, HPE_SUMMARIES};
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = hpe_fixture();
        s.apply(&d, &snap, now).unwrap();
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["overall_status"],
            "critical"
        );
        assert_eq!(
            s.pending_mail(now).unwrap().unwrap().event.resource,
            HPE_FAILED
        );
        for parent in HPE_SUMMARIES {
            assert!(assessment(&s, &d, parent).derived);
        }
        ack(&mut s, &d, HPE_FAILED, true, now);
        quiet(&s, now);
        for parent in HPE_SUMMARIES {
            assert_eq!(assessment(&s, &d, parent).status, "acknowledged");
        }
        snap.observations
            .iter_mut()
            .find(|o| o.key == HPE_OK)
            .unwrap()
            .health = Health::Critical;
        snap.resources.get_mut(HPE_OK).unwrap().own_health = Some(Health::Critical);
        s.apply(&d, &snap, now + 1).unwrap();
        assert_eq!(assessment(&s, &d, HPE_FAILED).status, "acknowledged");
        assert_eq!(assessment(&s, &d, HPE_OK).status, "critical");
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.resource,
            HPE_OK
        );
        for parent in HPE_SUMMARIES {
            assert_eq!(assessment(&s, &d, parent).status, "critical");
        }
        ack(&mut s, &d, HPE_OK, true, now + 1);
        quiet(&s, now + 1);
        let controller = HPE_SUMMARIES[3];
        snap.resources
            .get_mut(controller)
            .unwrap()
            .independent_condition = true;
        s.apply(&d, &snap, now + 2).unwrap();
        assert_eq!(assessment(&s, &d, controller).status, "warning");
        assert!(!assessment(&s, &d, controller).derived);
        assert_eq!(
            s.pending_mail(now + 2).unwrap().unwrap().event.resource,
            controller
        );
    }
    #[test]
    fn migrated_psu_acknowledged_while_off_stays_acknowledged_when_powered_on() {
        use crate::correlation::tests::{PSU, SUBSYSTEM, SYSTEM};
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        // An existing retained fault from before acknowledgement support was
        // installed has no comparison baseline. The off BMC reports null health.
        s.0.execute("INSERT INTO alarm_state(device,key,health,label,observed,emitted) VALUES(?1,?2,'\"critical\"','PS1 Status',?3,?3)",params![d.id,PSU,now-60]).unwrap();
        initialize(&s.0).unwrap();
        let off = crate::correlation::tests::fixture();
        s.apply(&d, &off, now).unwrap();
        ack(&mut s, &d, PSU, true, now);
        let before = assessment(&s, &d, PSU);
        assert_eq!(before.status, "acknowledged");
        assert_eq!(
            s.0.query_row(
                "SELECT signature FROM alarm_control WHERE device=?1 AND key=?2",
                params![d.id, PSU],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            ""
        );
        let mut on = off.clone();
        for o in &mut on.observations {
            if o.key == PSU || o.key == SUBSYSTEM {
                o.health = Health::Critical;
            }
        }
        on.resources.get_mut(PSU).unwrap().own_health = Some(Health::Critical);
        on.resources.get_mut(SUBSYSTEM).unwrap().own_health = Some(Health::Critical);
        s.apply(&d, &on, now + 1).unwrap();
        let after = assessment(&s, &d, PSU);
        assert_eq!(after.status, "acknowledged");
        assert_eq!(after.token, before.token);
        assert_eq!(after.acknowledgement, before.acknowledgement);
        assert_eq!(assessment(&s, &d, SYSTEM).status, "acknowledged");
        quiet(&s, now + 1);
        s.apply(&d, &off, now + 2).unwrap();
        s.apply(&d, &on, now + 3).unwrap();
        let after_cycle = assessment(&s, &d, PSU);
        assert_eq!(after_cycle.token, before.token);
        assert_eq!(after_cycle.status, "acknowledged");
        assert_eq!(after_cycle.acknowledgement, before.acknowledgement);
        quiet(&s, now + 3);
    }
    #[test]
    fn first_available_identity_is_learned_and_a_later_replacement_is_still_detected() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        snap.resources.get_mut("fan").unwrap().condition_fingerprint =
            json!([null, "", []]).to_string();
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        let acknowledged = assessment(&s, &d, "fan");
        for (i, serial) in [
            json!("SYNTHETIC-PS1"),
            Value::Null,
            json!(""),
            json!("Unknown"),
            json!("00000000"),
            json!("SYNTHETIC-PS1"),
        ]
        .into_iter()
        .enumerate()
        {
            snap.resources.get_mut("fan").unwrap().condition_fingerprint =
                json!([null, serial, []]).to_string();
            s.apply(&d, &snap, now + i as i64 + 1).unwrap();
            assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
            assert_eq!(assessment(&s, &d, "fan").token, acknowledged.token);
            quiet(&s, now + i as i64 + 1);
        }
        snap.resources.get_mut("fan").unwrap().condition_fingerprint =
            json!([null, "SYNTHETIC-REPLACEMENT", []]).to_string();
        s.apply(&d, &snap, now + 10).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        assert!(s.pending_mail(now + 10).unwrap().is_some());
    }
    #[test]
    fn unavailable_condition_details_do_not_turn_the_same_returning_condition_into_a_new_fault() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        let signature = |id: &str| {
            json!([null, null, [json!([id, [], null, "Critical"]).to_string()]]).to_string()
        };
        snap.resources.get_mut("fan").unwrap().condition_fingerprint =
            json!([null, null, []]).to_string();
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        let acknowledged = assessment(&s, &d, "fan");
        for (i, detail) in [
            signature("PSU.Failed"),
            json!([null, null, []]).to_string(),
            signature("PSU.Failed"),
        ]
        .into_iter()
        .enumerate()
        {
            snap.resources.get_mut("fan").unwrap().condition_fingerprint = detail;
            s.apply(&d, &snap, now + i as i64 + 1).unwrap();
            assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
            assert_eq!(assessment(&s, &d, "fan").token, acknowledged.token);
            quiet(&s, now + i as i64 + 1);
        }
        snap.resources.get_mut("fan").unwrap().condition_fingerprint =
            signature("PSU.DifferentFailure");
        s.apply(&d, &snap, now + 4).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        assert!(s.pending_mail(now + 4).unwrap().is_some());
    }
    #[test]
    fn reopening_an_old_manual_summary_does_not_duplicate_a_now_known_component_alarm() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Ok, Health::Ok);
        snap.observations
            .retain(|o| matches!(o.key.as_str(), "system" | "drive"));
        snap.resources.get_mut("system").unwrap().children = BTreeSet::from(["drive".into()]);
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "system", true, now);
        snap.observations
            .iter_mut()
            .find(|o| o.key == "drive")
            .unwrap()
            .health = Health::Critical;
        s.apply(&d, &snap, now + 1).unwrap();
        ack(&mut s, &d, "system", false, now + 1);
        assert!(!assessment(&s, &d, "system").acknowledged);
        assert!(assessment(&s, &d, "system").derived);
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.resource,
            "drive"
        );
        let pending: i64 =
            s.0.query_row(
                "SELECT COUNT(*) FROM outbox WHERE cancelled=0 AND delivered IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
    }
    #[test]
    fn a_manually_acknowledged_summary_still_shows_a_new_lower_severity_child_fault() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Ok, Health::Ok);
        snap.observations
            .retain(|o| matches!(o.key.as_str(), "system" | "drive"));
        snap.resources.get_mut("system").unwrap().children = BTreeSet::from(["drive".into()]);
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "system", true, now);
        quiet(&s, now);
        snap.observations
            .iter_mut()
            .find(|o| o.key == "drive")
            .unwrap()
            .health = Health::Warning;
        s.apply(&d, &snap, now + 1).unwrap();
        let status = assessment(&s, &d, "system");
        assert_eq!(status.status, "warning");
        assert!(status.acknowledged);
        assert!(!status.derived);
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["acknowledged_count"],
            1
        );
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.resource,
            "drive"
        );
        ack(&mut s, &d, "drive", true, now + 1);
        quiet(&s, now + 1);
        assert_eq!(assessment(&s, &d, "system").status, "acknowledged");
        ack(&mut s, &d, "system", false, now + 2);
        assert_eq!(assessment(&s, &d, "system").status, "critical");
        assert_eq!(
            s.pending_mail(now + 2).unwrap().unwrap().event.resource,
            "system"
        );
    }
    #[test]
    fn condition_improvements_and_fluctuating_arguments_do_not_revoke_acknowledgement() {
        let fingerprint = |severity: &str, args: Value, id: &str| {
            json!([null, null, [json!([id, args, "fan", severity]).to_string()]]).to_string()
        };
        let original = fingerprint("Critical", json!([0]), "Fan.Failed");
        assert!(!new_cause(
            &original,
            &fingerprint("Warning", json!([100]), "Fan.Failed")
        ));
        assert!(!new_cause(&original, &json!([null, null, []]).to_string()));
        assert!(new_cause(
            &fingerprint("Warning", json!([1]), "Fan.Failed"),
            &original
        ));
        assert!(new_cause(
            &original,
            &fingerprint("Critical", json!([0]), "Fan.OtherFault")
        ));
        let mut nodes = BTreeMap::new();
        correlation::observe(
            "/redfish/v1/Chassis/Test/Fans/1",
            &json!({"@odata.type":"#Fan.v1_0_0.Fan","SerialNumber":"different-hardware","Status":{"Health":"Critical"}}),
            &mut nodes,
        );
        assert!(new_cause(
            &json!([null, "original-hardware", []]).to_string(),
            &nodes.values().next().unwrap().condition_fingerprint
        ));
    }
    #[test]
    fn long_dependency_chains_are_evaluated_with_completed_summaries_cached() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        for i in 0..35 {
            let key = format!("level-{i:02}");
            let child = if i == 34 {
                "system".into()
            } else {
                format!("level-{:02}", i + 1)
            };
            snap.observations.push(Observation {
                key: key.clone(),
                label: key.clone(),
                health: Health::Critical,
                reading: None,
                unit: None,
            });
            snap.resources.insert(
                key,
                correlation::Resource {
                    kind: "#Chassis.v1_0_0.Chassis".into(),
                    own_health: Some(Health::Critical),
                    rollup: Some(Health::Critical),
                    children: BTreeSet::from([child]),
                    ..Default::default()
                },
            );
        }
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        assert_eq!(assessment(&s, &d, "level-00").status, "acknowledged");
        quiet(&s, now);
    }
    #[test]
    fn proven_aliases_transfer_acknowledgement_but_an_unacknowledged_peer_stays_open() {
        for peer in [false, true] {
            let (_dir, mut s, d) = setup();
            let now = crate::now();
            let mut snap = Snapshot {
                observations: vec![Observation {
                    key: "old-fan".into(),
                    label: "Fan".into(),
                    health: Health::Critical,
                    reading: None,
                    unit: None,
                }],
                ..Default::default()
            };
            if peer {
                let mut o = snap.observations[0].clone();
                o.key = "new-fan".into();
                snap.observations.push(o);
            }
            s.apply(&d, &snap, now).unwrap();
            ack(&mut s, &d, "old-fan", true, now);
            snap.observations.truncate(1);
            snap.observations[0].key = "new-fan".into();
            snap.resource_aliases
                .insert("old-fan".into(), "new-fan".into());
            s.apply(&d, &snap, now + 1).unwrap();
            assert_eq!(
                assessment(&s, &d, "new-fan").status,
                if peer { "critical" } else { "acknowledged" }
            );
            assert!(!s
                .0
                .prepare("PRAGMA foreign_key_check")
                .unwrap()
                .exists([])
                .unwrap());
        }
    }
    fn setup() -> (tempfile::TempDir, Store, Device) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let d = Device {
            id: "ack-test".into(),
            name: "Test".into(),
            endpoint: "https://bmc.example/".into(),
            username: "monitor".into(),
            interval_seconds: 60,
            repeat_seconds: Some(300),
            alerts_enabled: true,
            ca_file: None,
            ca_pem: None,
            tls_profile: Default::default(),
            pinned_certificate_pem: None,
            enabled: true,
        };
        s.put(&d, b"synthetic-sealed-secret").unwrap();
        s.save_mail(
            &crate::mail::Settings {
                enabled: true,
                host: "smtp.example.invalid".into(),
                from_address: "sender@example.invalid".into(),
                recipients: vec![
                    "first@example.invalid".into(),
                    "second@example.invalid".into(),
                ],
                ..Default::default()
            },
            b"",
            0,
            "admin",
        )
        .unwrap();
        s.save_notifications(
            &crate::notification::Input {
                language: Default::default(),
                revision: 0,
                desktop_enabled: true,
                selection: Default::default(),
            },
            "admin",
        )
        .unwrap();
        (dir, s, d)
    }
    fn snapshot(fan: Health, drive: Health) -> Snapshot {
        let mut s = Snapshot::default();
        for (key, kind, health, children) in [
            (
                "system",
                "#ComputerSystem.v1_0_0.ComputerSystem",
                Health::Critical,
                vec!["thermal", "drive"],
            ),
            (
                "thermal",
                "#ThermalSubsystem.v1_0_0.ThermalSubsystem",
                Health::Critical,
                vec!["fan"],
            ),
            ("fan", "#Fan.v1_0_0.Fan", fan, vec![]),
            ("drive", "#Drive.v1_0_0.Drive", drive, vec![]),
        ] {
            s.observations.push(Observation {
                key: key.into(),
                label: key.into(),
                health,
                reading: None,
                unit: None,
            });
            s.resources.insert(
                key.into(),
                correlation::Resource {
                    kind: kind.into(),
                    own_health: Some(health),
                    rollup: Some(health),
                    children: children.into_iter().map(str::to_owned).collect(),
                    ..Default::default()
                },
            );
        }
        s
    }
    fn assessment(s: &Store, d: &Device, key: &str) -> Status {
        let raw: String =
            s.0.query_row("SELECT snapshot FROM devices WHERE id=?1", [&d.id], |r| {
                r.get(0)
            })
            .unwrap();
        evaluate(&s.0, &d.id, Some(&serde_json::from_str(&raw).unwrap()))
            .unwrap()
            .statuses
            .remove(key)
            .unwrap()
    }
    fn ack(s: &mut Store, d: &Device, key: &str, enabled: bool, now: i64) {
        let token = assessment(s, d, key).token;
        let revision = s.get(&d.id).unwrap().unwrap().2;
        s.acknowledge_alarm(
            &d.id,
            revision,
            key,
            &token,
            enabled,
            "Sensor input externally checked",
            "admin",
            now,
        )
        .unwrap();
    }
    fn quiet(s: &Store, now: i64) {
        assert!(s.pending_mail(now).unwrap().is_none());
        assert!(s.pending_desktop(now).unwrap().is_none());
    }
    #[test]
    fn acknowledgement_cancels_both_channels_survives_restart_and_never_changes_raw_health() {
        let (dir, mut s, d) = setup();
        let now = crate::now();
        let snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        assert!(s.pending_mail(now).unwrap().is_some());
        ack(&mut s, &d, "fan", true, now);
        quiet(&s, now);
        for key in ["fan", "thermal", "system"] {
            assert_eq!(assessment(&s, &d, key).status, "acknowledged");
        }
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["overall_status"],
            "acknowledged"
        );
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["alarms"][0]["health"],
            "critical"
        );
        drop(s);
        let mut s = Store::open(dir.path()).unwrap();
        s.apply(&d, &snap, now + 300).unwrap();
        quiet(&s, now + 300);
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
        let mut offline = snap.clone();
        offline
            .observations
            .iter_mut()
            .find(|o| o.key == "fan")
            .unwrap()
            .health = Health::Unknown;
        s.apply(&d, &offline, now + 600).unwrap();
        quiet(&s, now + 600);
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
        s.clear_events("admin").unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
    }
    #[test]
    fn mixed_severity_parents_follow_every_open_fault_including_lower_severity() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now)
            .unwrap();
        ack(&mut s, &d, "fan", true, now);
        let mixed = snapshot(Health::Critical, Health::Warning);
        s.apply(&d, &mixed, now + 1).unwrap();
        assert_eq!(assessment(&s, &d, "system").status, "warning");
        assert_eq!(assessment(&s, &d, "thermal").status, "acknowledged");
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["overall_status"],
            "warning"
        );
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.resource,
            "drive"
        );
        ack(&mut s, &d, "drive", true, now + 1);
        quiet(&s, now + 1);
        assert_eq!(assessment(&s, &d, "system").status, "acknowledged");
        let mut independent = mixed.clone();
        independent
            .resources
            .get_mut("system")
            .unwrap()
            .independent_condition = true;
        s.apply(&d, &independent, now + 2).unwrap();
        assert_eq!(assessment(&s, &d, "system").status, "critical");
        assert_eq!(
            s.pending_mail(now + 2).unwrap().unwrap().event.resource,
            "system"
        );
    }
    #[test]
    fn recovery_is_local_and_a_later_fault_or_any_worsening_requires_new_acknowledgement() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        snap.observations
            .iter_mut()
            .for_each(|o| o.health = Health::Ok);
        s.apply(&d, &snap, now + 1).unwrap();
        quiet(&s, now + 1);
        assert_eq!(s.dashboard().unwrap()["devices"][0]["overall_status"], "ok");
        snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now + 2).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        ack(&mut s, &d, "fan", true, now + 2);
        snap.observations
            .iter_mut()
            .find(|o| o.key == "fan")
            .unwrap()
            .health = Health::Warning;
        s.apply(&d, &snap, now + 3).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
        snap.observations
            .iter_mut()
            .find(|o| o.key == "fan")
            .unwrap()
            .health = Health::Critical;
        s.apply(&d, &snap, now + 4).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        assert_eq!(
            s.pending_mail(now + 4).unwrap().unwrap().event.resource,
            "fan"
        );
    }
    #[test]
    fn a_new_identifiable_condition_reannounces_even_without_a_severity_change() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        snap.resources.get_mut("fan").unwrap().condition_fingerprint = "[\"initial\"]".into();
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        snap.resources.get_mut("fan").unwrap().condition_fingerprint = "[\"different\"]".into();
        s.apply(&d, &snap, now + 1).unwrap();
        assert_eq!(assessment(&s, &d, "fan").status, "critical");
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.resource,
            "fan"
        );
    }
    #[test]
    fn stale_tokens_and_invalid_scope_do_not_acknowledge_another_incident() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        let token = assessment(&s, &d, "fan").token;
        ack(&mut s, &d, "fan", true, now);
        assert!(s
            .acknowledge_alarm(&d.id, 1, "fan", &token, false, "", "admin", now)
            .is_err());
        let current = assessment(&s, &d, "fan").token;
        assert!(s
            .acknowledge_alarm(
                &d.id,
                1,
                "fan",
                &current,
                false,
                &"x".repeat(1001),
                "admin",
                now
            )
            .is_err());
        assert!(s
            .acknowledge_alarm(
                &d.id,
                1,
                "fan",
                &current,
                false,
                "invalid\nreason",
                "admin",
                now
            )
            .is_err());
        assert!(s
            .acknowledge_alarm(&d.id, 1, "fan", &current, true, " ", "admin", now)
            .is_err());
        assert!(s
            .acknowledge_alarm(&d.id, 2, "fan", &current, true, "reason", "admin", now)
            .is_err());
        assert!(s
            .acknowledge_alarm(
                &d.id,
                1,
                "collector",
                &current,
                true,
                "reason",
                "admin",
                now
            )
            .is_err());
        let parent = assessment(&s, &d, "system").token;
        assert!(s
            .acknowledge_alarm(&d.id, 1, "system", &parent, true, "reason", "admin", now)
            .is_err());
        let mut healthy = snap.clone();
        healthy
            .observations
            .iter_mut()
            .for_each(|o| o.health = Health::Ok);
        s.apply(&d, &healthy, now + 1).unwrap();
        s.apply(&d, &snap, now + 2).unwrap();
        assert!(s
            .acknowledge_alarm(&d.id, 1, "fan", &current, true, "reason", "admin", now + 2)
            .is_err());
    }
    #[test]
    fn reopening_old_data_waits_for_a_fresh_poll_even_when_reminders_are_disabled() {
        let (_dir, mut s, mut d) = setup();
        let now = crate::now();
        d.repeat_seconds = None;
        s.put(&d, b"synthetic-sealed-secret").unwrap();
        let snap = snapshot(Health::Critical, Health::Ok);
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        ack(&mut s, &d, "fan", false, now + 1000);
        quiet(&s, now + 1000);
        s.apply(&d, &snap, now + 1001).unwrap();
        assert_eq!(
            s.pending_mail(now + 1001).unwrap().unwrap().event.resource,
            "fan"
        );
    }
    #[test]
    fn hardware_logs_and_query_failures_are_independent_of_an_acknowledged_sensor() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        let mut snap = snapshot(Health::Critical, Health::Ok);
        snap.logs_complete = true;
        s.apply(&d, &snap, now).unwrap();
        ack(&mut s, &d, "fan", true, now);
        snap.logs.push(HardwareLog {
            fingerprint: "new-log".into(),
            message: "New fan log".into(),
            severity: Health::Warning,
            created: None,
        });
        s.apply(&d, &snap, now + 1).unwrap();
        assert_eq!(
            s.pending_mail(now + 1).unwrap().unwrap().event.kind,
            "hardware_log"
        );
        s.poll_error(&d, now + 2).unwrap();
        assert_eq!(
            s.dashboard().unwrap()["devices"][0]["overall_status"],
            "critical"
        );
        assert_eq!(assessment(&s, &d, "fan").status, "acknowledged");
    }
    #[test]
    fn submitted_email_is_not_relabelled_when_only_desktop_remains_pending() {
        let (_dir, mut s, d) = setup();
        let now = crate::now();
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now)
            .unwrap();
        while let Some(job) = s.pending_mail(now).unwrap() {
            s.finish_mail(&job, None, now).unwrap();
        }
        ack(&mut s, &d, "fan", true, now);
        let event = s
            .event_entries(-1)
            .unwrap()
            .into_iter()
            .find(|e| e["key"] == "fan")
            .unwrap();
        assert_eq!(event["mail_reason"], "queued");
        assert!(event["delivered"].is_number());
        assert_eq!(event["desktop_reason"], "acknowledged");
        quiet(&s, now);
    }
    #[test]
    fn endpoint_retarget_and_delete_remove_active_acknowledgements() {
        let (_dir, mut s, mut d) = setup();
        let now = crate::now();
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now)
            .unwrap();
        ack(&mut s, &d, "fan", true, now);
        d.endpoint = "https://different.example/".into();
        s.put(&d, b"synthetic-sealed-secret").unwrap();
        let count: i64 =
            s.0.query_row("SELECT COUNT(*) FROM alarm_control", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 0);
        s.apply(&d, &snapshot(Health::Critical, Health::Ok), now + 1)
            .unwrap();
        ack(&mut s, &d, "fan", true, now + 1);
        s.delete_admin(&d.id, 2, "admin").unwrap();
        let count: i64 =
            s.0.query_row("SELECT COUNT(*) FROM alarm_control", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 0);
    }
}
