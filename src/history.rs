//! Human-readable, spreadsheet-safe history export; clearing never resets alarms.
use crate::{dsm::BoundaryError, store::Store};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filter {
    pub category: String,
    pub health: String,
    pub device: String,
}
fn cell(value: &str) -> String {
    let trimmed = value.trim_start_matches(char::is_whitespace);
    let guard = trimmed.starts_with(['=', '+', '-', '@']) || value.starts_with(['\t', '\r', '\n']);
    format!(
        "\"{}{}\"",
        if guard { "'" } else { "" },
        value.replace('"', "\"\"")
    )
}
impl Store {
    pub fn events_csv(&self, filter: &Filter) -> Result<(String, usize)> {
        self.events_csv_localized(filter, Default::default())
    }
    pub fn events_csv_localized(
        &self,
        filter: &Filter,
        language: crate::i18n::Language,
    ) -> Result<(String, usize)> {
        anyhow::ensure!(
            matches!(
                filter.category.as_str(),
                "" | "all" | "hardware" | "monitoring" | "log" | "trap"
            ) && matches!(
                filter.health.as_str(),
                "" | "all" | "critical" | "warning" | "ok" | "unknown"
            ) && filter.device.len() <= 80,
            BoundaryError("history_filter_invalid")
        );
        let total: i64 = self
            .0
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        anyhow::ensure!(total <= 50000, BoundaryError("history_too_large"));
        let mut events = self.event_entries(-1)?;
        crate::i18n::localize_events(&mut events, language);
        let settings = self
            .mail_settings()?
            .map(|v| v.0)
            .unwrap_or_else(|| crate::mail::Settings::default_for(language));
        let zone: chrono_tz::Tz = settings.timezone.parse()?;
        let mut csv = String::new();
        let headers = [
            "Ereignis-ID",
            "Erfasst (UTC)",
            "Erfasst (Lokalzeit)",
            "Zeitzone",
            "Gerät",
            "Geräte-ID",
            "Art",
            "Zustand",
            "Meldung",
            "Komponente",
            "Hardwarelog-Zeit",
            "E-Mail-Status",
            "SMTP angenommen",
            "SMTP Empfänger",
            "DSM-Desktop-Status",
            "Gebündelte Komponenten",
            "Quelle",
            "Verifiziert",
            "Vorläufig",
            "Empfangsbeleg",
            "Webhook-Versand",
        ];
        csv.push_str(
            &headers
                .map(|v| cell(&crate::i18n::text(v, language)))
                .join(";"),
        );
        csv.push_str("\r\n");
        let mut count = 0;
        for e in events {
            let text = |key: &str| e[key].as_str().unwrap_or("");
            let category = if text("kind") == "snmp_trap" {
                "trap"
            } else if text("kind") == "hardware_log" {
                "log"
            } else if text("key") == "collector" || text("key").starts_with("coverage:") {
                "monitoring"
            } else {
                "hardware"
            };
            if (!matches!(filter.category.as_str(), "" | "all") && filter.category != category)
                || (!matches!(filter.health.as_str(), "" | "all")
                    && filter.health != text("health"))
                || (!matches!(filter.device.as_str(), "" | "all")
                    && filter.device != text("device"))
            {
                continue;
            }
            let date = chrono::DateTime::from_timestamp(e["created"].as_i64().unwrap_or(0), 0)
                .context("event timestamp")?;
            let local = date
                .with_timezone(&zone)
                .format(&settings.date_format)
                .to_string();
            let mail = if text("mail_reason") == "acknowledged" {
                "acknowledged"
            } else if e["delivered"].is_number() {
                "smtp_accepted"
            } else if e["cancelled"] == true {
                "cancelled"
            } else if e["queued"] == true {
                "queued"
            } else {
                text("mail_reason")
            };
            let desktop = &e["desktop"];
            let desktop_status = if text("desktop_reason") == "acknowledged" {
                "acknowledged"
            } else if desktop["delivered"].is_number() {
                "submitted"
            } else if desktop["cancelled"] == true {
                "cancelled"
            } else if desktop["attempts"].as_i64().unwrap_or(0) >= 8 {
                "failed"
            } else if desktop.is_object() {
                "queued"
            } else {
                text("desktop_reason")
            };
            let related = e["correlated_keys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .unwrap_or_default();
            let values = vec![
                e["id"].to_string(),
                date.to_rfc3339(),
                local,
                settings.timezone.clone(),
                text("device_name").into(),
                text("device").into(),
                text("kind").into(),
                text("health").into(),
                text("message").into(),
                text("key").into(),
                text("source_created").into(),
                mail.into(),
                e["submitted_recipients"].to_string(),
                e["total_recipients"].to_string(),
                desktop_status.into(),
                related,
                e["message_context"]["source"].as_str().unwrap_or("").into(),
                e["message_context"]["verified"]
                    .as_bool()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                e["message_context"]["provisional"]
                    .as_bool()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                e["message_context"]["receipt_id"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
            ];
            let mut values = values;
            values.push(serde_json::to_string(&e["webhooks"])?);
            csv.push_str(&values.iter().map(|v| cell(v)).collect::<Vec<_>>().join(";"));
            csv.push_str("\r\n");
            count += 1;
            anyhow::ensure!(
                csv.len() <= 16 * 1024 * 1024,
                BoundaryError("history_too_large")
            );
        }
        Ok((csv, count))
    }
    pub fn clear_events(&mut self, actor: &str) -> Result<usize> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO counters(name,value) SELECT 'events',MAX(COALESCE(MAX(id),0),COALESCE((SELECT value FROM counters WHERE name='events'),0)) FROM events WHERE true ON CONFLICT(name) DO UPDATE SET value=excluded.value",[])?;
        tx.execute("DELETE FROM mail_recipient", [])?;
        tx.execute("DELETE FROM outbox", [])?;
        tx.execute("DELETE FROM desktop_jobs", [])?;
        let count = tx.execute("DELETE FROM events", [])?;
        // Prevent an old reminder from being re-created immediately after clearing.
        tx.execute(
            "UPDATE alarm_state SET emitted=?1 WHERE health!='\"ok\"'",
            [crate::now()],
        )?;
        tx.execute("INSERT INTO audit_log(actor,action,device,outcome,created) VALUES(?1,'events.clear','events',?2,?3)",rusqlite::params![actor,format!("{count} Ereignisse gelöscht; ausstehende Sendungen verworfen"),crate::now()])?;
        tx.commit()?;
        Ok(count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_starts_with_localized_header_without_bom_for_empty_and_populated_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for expected_count in 0..=1 {
            if expected_count == 1 {
                store.0.execute("INSERT INTO events(device,key,kind,health,message,created) VALUES('removed','ps1','alarm','\"warning\"','Überprüfung nötig',1)",[]).unwrap();
            }
            for (language, header) in [
                (crate::i18n::Language::De, "\"Ereignis-ID\";"),
                (crate::i18n::Language::En, "\"Event ID\";"),
            ] {
                let (csv, count) = store
                    .events_csv_localized(&Filter::default(), language)
                    .unwrap();
                assert_eq!(count, expected_count);
                assert!(!csv.as_bytes().starts_with(&[0xef, 0xbb, 0xbf]));
                assert!(csv.starts_with(header));
                if count == 1 {
                    assert!(csv.contains("Überprüfung nötig"));
                }
            }
        }
    }
    #[test]
    fn unconfigured_csv_uses_language_defaults_and_localizes_missing_device_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.0.execute("INSERT INTO events(device,key,kind,health,message,created) VALUES('removed','ps1','alarm','\"warning\"','Historischer Text',1)",[]).unwrap();
        let (csv, _) = store
            .events_csv_localized(&Filter::default(), crate::i18n::Language::En)
            .unwrap();
        assert!(
            csv.contains("1970-01-01 00:00:01 +00:00")
                && csv.contains("Removed device")
                && csv.contains("Historischer Text")
        );
        let (german, _) = store.events_csv(&Filter::default()).unwrap();
        assert!(german.contains("01.01.1970 00:00:01") && german.contains("Entferntes Gerät"));
    }
    #[test]
    fn spreadsheet_cells_are_quoted_and_formulas_neutralized() {
        for v in ["=SUM(A1)", " +cmd", "\t@cmd", "-4", "@A1", "\ntext"] {
            assert!(cell(v).starts_with("\"'"));
        }
        assert_eq!(cell("text;\"x\"\nline"), "\"text;\"\"x\"\"\nline\"");
    }
}
