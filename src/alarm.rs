//! Shared transactional alarm reduction for full polls and partial trusted input.
use crate::model::*;
use anyhow::Result;
use rusqlite::{params, OptionalExtension, Transaction};
use serde_json::json;

pub(crate) fn reduce(
    tx: &Transaction<'_>,
    d: &Device,
    snapshot: &Snapshot,
    now: i64,
) -> Result<std::collections::BTreeMap<String, Vec<String>>> {
    let boundary: i64 = tx.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |r| r.get(0))?;
    let previous_raw: Option<String> =
        tx.query_row("SELECT snapshot FROM devices WHERE id=?1", [&d.id], |r| {
            r.get(0)
        })?;
    let previous_snapshot: Option<Snapshot> = previous_raw
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?;
    let acknowledged_before =
        crate::acknowledgement::evaluate(tx, &d.id, previous_snapshot.as_ref())?.acknowledged();
    crate::acknowledgement::signatures(tx, &d.id, snapshot, now)?;
    let mut q = tx.prepare("SELECT key,health FROM alarm_state WHERE device=?1")?;
    let previous = q
        .query_map([&d.id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (key, raw) = row?;
            Ok((key, serde_json::from_str::<Health>(&raw)?))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    drop(q);
    let mut states = previous.clone();
    for o in &snapshot.observations {
        if o.health != Health::Unknown {
            states.insert(o.key.clone(), o.health);
        }
    }
    let groups = crate::correlation::groups(&snapshot.resources, &states);
    let old_groups = previous_snapshot
        .as_ref()
        .map(|s| s.notification_groups.clone())
        .unwrap_or_default();
    for observation in &snapshot.observations {
        crate::store::apply_observation(tx, d, observation, now)?;
    }
    // If a formerly grouped summary remains faulty after its component clears,
    // announce it immediately, even if its raw severity has not changed.
    for parent in old_groups.keys().filter(|key| !groups.contains_key(*key)) {
        if let Some(o) = snapshot
            .observations
            .iter()
            .find(|o| &o.key == parent && matches!(o.health, Health::Warning | Health::Critical))
        {
            let emitted: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE device=?1 AND key=?2 AND id>?3)",
                params![d.id, parent, boundary],
                |r| r.get(0),
            )?;
            if !emitted {
                crate::store::event(
                    tx,
                    d,
                    parent,
                    "alarm",
                    o.health,
                    &format!(
                        "{} (kein zugeordneter Komponentenfehler mehr bekannt)",
                        o.label
                    ),
                    now,
                )?;
                tx.execute(
                    "UPDATE alarm_state SET emitted=?3 WHERE device=?1 AND key=?2",
                    params![d.id, parent, now],
                )?;
            }
        }
    }
    // A fresh faulty summary may corroborate a retained component alarm when
    // the powered-off BMC cannot assess that component. Remind only when due,
    // without refreshing its last-confirmed timestamp or claiming a new reading.
    if let Some(interval) = d.repeat_seconds {
        let anchors: std::collections::BTreeSet<_> = groups
            .iter()
            .filter(|(parent, _)| {
                snapshot.observations.iter().any(|o| {
                    &o.key == *parent && matches!(o.health, Health::Critical | Health::Warning)
                })
            })
            .flat_map(|(_, keys)| keys.iter().cloned())
            .collect();
        for anchor in anchors {
            let current = snapshot
                .observations
                .iter()
                .find(|o| o.key == anchor)
                .map(|o| o.health)
                .unwrap_or(Health::Unknown);
            if current != Health::Unknown || groups.contains_key(&anchor) {
                continue;
            }
            let state: Option<(String, String, Option<i64>)> = tx
                .query_row(
                    "SELECT health,label,emitted FROM alarm_state WHERE device=?1 AND key=?2",
                    params![d.id, anchor],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((raw, label, last)) = state {
                let health: Health = serde_json::from_str(&raw)?;
                if matches!(health, Health::Warning | Health::Critical)
                    && last.is_some_and(|last| now - last >= interval)
                {
                    let id = crate::store::event(tx, d, &anchor, "repeat", health, &label, now)?;
                    let description = if health == Health::Critical {
                        "kritisch"
                    } else {
                        "Warnung"
                    };
                    tx.execute("UPDATE events SET message=?2 WHERE id=?1",params![id,format!("{}: Gespeicherter Hardwarefehler (zuletzt {description}, aktuell nicht bewertbar): {}. Zugeordneter Sammelzustand weiterhin gestört.",d.name,label)])?;
                    tx.execute(
                        "UPDATE events SET message_context=?2 WHERE id=?1",
                        params![
                            id,
                            serde_json::to_string(
                                &json!({"version":1,"label":label,"retained":true})
                            )?
                        ],
                    )?;
                    tx.execute(
                        "UPDATE alarm_state SET emitted=?3 WHERE device=?1 AND key=?2",
                        params![d.id, anchor, now],
                    )?;
                }
            }
        }
    }
    for (parent, anchors) in &groups {
        crate::store::group_notifications(tx, &d.id, parent, anchors, boundary)?;
    }
    // Recovery summaries are bundled only when all previously associated
    // component faults have a confirmed recovery in this same poll.
    for (parent, anchors) in &old_groups {
        if snapshot
            .observations
            .iter()
            .any(|o| &o.key == parent && o.health == Health::Ok)
            && anchors.iter().all(|key| {
                previous
                    .get(key)
                    .is_some_and(|h| matches!(h, Health::Warning | Health::Critical))
                    && snapshot
                        .observations
                        .iter()
                        .any(|o| &o.key == key && o.health == Health::Ok)
            })
        {
            crate::store::group_notifications(tx, &d.id, parent, anchors, boundary)?;
        }
    }
    crate::acknowledgement::signatures(tx, &d.id, snapshot, now)?;
    crate::acknowledgement::suppress(tx, &d.id, snapshot, boundary, &acknowledged_before)?;
    Ok(groups)
}
