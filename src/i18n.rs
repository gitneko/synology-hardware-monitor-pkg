//! Presentation language is never an authorization input. Historical free text stays intact.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::OnceLock};
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    De,
    En,
}
impl Language {
    pub fn tag(self) -> &'static str {
        match self {
            Self::De => "de",
            Self::En => "en",
        }
    }
    pub fn header(value: &str) -> Self {
        if value == "de" {
            Self::De
        } else {
            Self::En
        }
    }
}
fn catalog() -> &'static BTreeMap<String, String> {
    static CATALOG: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../web/src/en.json"))
            .expect("checked translation catalog")
    })
}
pub fn text(value: &str, language: Language) -> String {
    if language == Language::En {
        catalog()
            .get(value)
            .cloned()
            .unwrap_or_else(|| value.into())
    } else {
        value.into()
    }
}
pub fn label(value: &str, language: Language) -> String {
    if language == Language::De {
        return value.into();
    }
    if value.starts_with("USV · ") {
        return value
            .split(" · ")
            .map(|part| text(part, language))
            .collect::<Vec<_>>()
            .join(" · ");
    }
    if value.starts_with("DSM · ") {
        return text(value, language);
    }
    if value.starts_with("SNMP · ") {
        let translated = text(value, language);
        if translated != value {
            return translated;
        }
        if let Some((prefix, suffix)) = value.rsplit_once(" · ") {
            return format!("{prefix} · {}", text(suffix, language));
        }
    }
    if value == "Management-Abfrage erfolgreich" {
        return "Management query successful".into();
    }
    if value == "Management-Abfrage unvollständig" {
        return "Management query incomplete".into();
    }
    if let Some(detail) = value.strip_prefix("Management-Abfrage fehlgeschlagen · ") {
        return format!("Management query failed · {}", label(detail, language));
    }
    if value.starts_with("/redfish/") || value.starts_with("Redfish-Verweis:") {
        if let Some((uri, detail)) = value.rsplit_once(": ") {
            return format!("{uri}: {}", text(detail, language));
        }
    }
    if value == "Management-Abfrage fehlgeschlagen (Netzwerk, TLS, Anmeldung oder Zeitlimit)" {
        return "Management query failed (network, TLS, sign-in or timeout)".into();
    }
    let mut result = value.to_owned();
    for (de, en) in [
        (
            "Netzteile (HPE-Gesamtzustand)",
            "Power supplies (HPE aggregate health)",
        ),
        ("Netzteilredundanz (HPE)", "Power supply redundancy (HPE)"),
        ("Stromversorgungsdomäne (HPE)", "Power domain (HPE)"),
    ] {
        if let Some(suffix) = value
            .strip_prefix(de)
            .filter(|s| s.is_empty() || s.starts_with(" ["))
        {
            result = format!("{en}{suffix}");
            break;
        }
    }
    for (de, en) in [
        (" (Betrieb: ausgeschaltet)", " (power: off)"),
        (" (Betrieb: eingeschaltet)", " (power: on)"),
        (" (Betrieb: wird eingeschaltet)", " (power: powering on)"),
        (" (Betrieb: wird ausgeschaltet)", " (power: powering off)"),
    ] {
        if result.ends_with(de) {
            result.truncate(result.len() - de.len());
            result.push_str(en);
            break;
        }
    }
    if let Some(index) = result.rfind(" – Gesamtgesundheit") {
        let end = index + " – Gesamtgesundheit".len();
        if end == result.len() || result[end..].starts_with(" (power:") {
            result.replace_range(index..end, " – Overall health");
        }
    }
    result
}
pub fn event_message(
    device: &str,
    key: &str,
    kind: &str,
    health: &str,
    original: &str,
    context: Option<&Value>,
    language: Language,
) -> String {
    let Some(context) = context.filter(|c| c["version"] == 1) else {
        return original.into();
    };
    let raw = context["label"].as_str().unwrap_or("");
    // Hardware logs and component names are vendor data, never machine translated.
    let detail = if kind == "snmp_trap" {
        format!(
            "{}: {raw}",
            if language == Language::En {
                "SNMP event"
            } else {
                "SNMP-Ereignis"
            }
        )
    } else if kind == "hardware_log" {
        raw.into()
    } else if context["retained"] == true {
        let health = if language == Language::En {
            if health == "critical" {
                "critical"
            } else {
                "warning"
            }
        } else if health == "critical" {
            "kritisch"
        } else {
            "Warnung"
        };
        let label = label(raw, language);
        if language == Language::En {
            format!("Retained hardware fault (last {health}, currently unavailable for assessment): {label}. Associated summary state is still faulty.")
        } else {
            format!("Gespeicherter Hardwarefehler (zuletzt {health}, aktuell nicht bewertbar): {label}. Zugeordneter Sammelzustand weiterhin gestört.")
        }
    } else if key.starts_with("coverage:") {
        let body = if language == Language::En {
            label(raw, language)
                .replace("erfolgreich nach Wiederholung", "successful after retry")
                .replace("erfolgreich", "successful")
                .replace(" nach Wiederholung", " after retry")
                .replace("Netzwerk- oder TLS-Fehler", "Network or TLS error")
        } else {
            raw.into()
        };
        let title = if language == Language::En {
            if kind == "recovery" {
                "Redfish query recovered"
            } else {
                "Redfish query incomplete"
            }
        } else if kind == "recovery" {
            "Redfish-Abfrage wieder erfolgreich"
        } else {
            "Redfish-Abfrage eingeschränkt"
        };
        format!("{title}: {body}")
    } else if key == "collector" {
        let title = if language == Language::En {
            if kind == "recovery" {
                "Device query recovered"
            } else {
                "Device query failed"
            }
        } else if kind == "recovery" {
            "Geräteabfrage wieder erfolgreich"
        } else {
            "Geräteabfrage fehlgeschlagen"
        };
        format!("{title}: {}", label(raw, language))
    } else {
        let state = match (language, health) {
            (Language::En, "critical") => "critical",
            (Language::En, "warning") => "warning",
            (Language::En, "ok") => "healthy",
            (Language::En, _) => "unknown",
            (_, "critical") => "kritisch",
            (_, "warning") => "Warnung",
            (_, "ok") => "in Ordnung",
            _ => "unbekannt",
        };
        let phase = match (language, kind) {
            (Language::En, "repeat") => "still ",
            (Language::En, "recovery") => "recovered to ",
            (_, "repeat") => "weiterhin ",
            (_, "recovery") => "wieder ",
            _ => "",
        };
        format!(
            "{} {phase}{state}: {}",
            if language == Language::En {
                "Hardware state"
            } else {
                "Hardwarezustand"
            },
            label(raw, language)
        )
    };
    let suffix = if context["source"] == "snmp_trap" && context["provisional"] == true {
        if language == Language::En {
            " · SNMP trap, confirmation pending"
        } else {
            " · SNMP-Trap, Bestätigung ausstehend"
        }
    } else {
        ""
    };
    format!(
        "{device}: {}{suffix}",
        detail.chars().take(1600).collect::<String>()
    )
}
pub fn localize_events(events: &mut [Value], language: Language) {
    for e in events {
        if e["device_name_missing"] == true {
            e["device_name"] = json!(text("Entferntes Gerät", language));
        }
        e["message"] = json!(event_message(
            e["device_name"].as_str().unwrap_or(""),
            e["key"].as_str().unwrap_or(""),
            e["kind"].as_str().unwrap_or(""),
            e["health"].as_str().unwrap_or(""),
            e["message"].as_str().unwrap_or(""),
            e.get("message_context"),
            language
        ));
    }
}
pub fn dashboard(data: &mut Value, language: Language) {
    if let Some(events) = data["events"].as_array_mut() {
        localize_events(events, language);
        for event in events {
            event.as_object_mut().unwrap().remove("message_context");
            event.as_object_mut().unwrap().remove("device_name_missing");
        }
    }
    if let Some(devices) = data["devices"].as_array_mut() {
        for device in devices {
            for field in ["alarms"] {
                if let Some(rows) = device[field].as_array_mut() {
                    for row in rows {
                        row["label"] = json!(label(row["label"].as_str().unwrap_or(""), language));
                    }
                }
            }
            // Mutable indexing would turn a null snapshot into an object.
            if let Some(rows) = device
                .get_mut("snapshot")
                .and_then(|snapshot| snapshot.get_mut("observations"))
                .and_then(Value::as_array_mut)
            {
                for row in rows {
                    row["label"] = json!(label(row["label"].as_str().unwrap_or(""), language));
                }
            }
        }
    }
}
pub fn outcome(value: &str, language: Language) -> String {
    if language == Language::En {
        for (suffix, en) in [
            (" Ereignisse exportiert", " events exported"),
            (
                " Ereignisse gelöscht; ausstehende Sendungen verworfen",
                " events deleted; pending deliveries discarded",
            ),
        ] {
            if let Some(count) = value
                .strip_suffix(suffix)
                .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
            {
                return format!("{count}{en}");
            }
        }
    }
    text(value, language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpe_power_assessment_labels_translate_without_changing_reported_values() {
        for (de, en) in [
            (
                "Netzteile (HPE-Gesamtzustand)",
                "Power supplies (HPE aggregate health)",
            ),
            (
                "Netzteilredundanz (HPE) [FailedRedundant]",
                "Power supply redundancy (HPE) [FailedRedundant]",
            ),
            (
                "Netzteilredundanz (HPE) [2] [NonRedundant]",
                "Power supply redundancy (HPE) [2] [NonRedundant]",
            ),
            ("Stromversorgungsdomäne (HPE) [2]", "Power domain (HPE) [2]"),
        ] {
            assert_eq!(label(de, Language::En), en);
            assert_eq!(label(de, Language::De), de);
        }
        assert_eq!(
            label("HpeServerPowerSupply", Language::En),
            "HpeServerPowerSupply"
        );
    }

    #[test]
    fn dashboard_preserves_missing_measurements_in_both_languages() {
        for language in [Language::De, Language::En] {
            let mut data = json!({
                "events": [],
                "devices": [
                    {"alarms": [], "snapshot": null},
                    {"alarms": []},
                    {"alarms": [], "snapshot": {"capabilities": []}}
                ]
            });
            let original = data.clone();
            dashboard(&mut data, language);
            assert_eq!(data, original);
        }
    }

    #[test]
    fn dashboard_localizes_existing_measurements_alongside_a_new_device() {
        let mut data = json!({
            "events": [],
            "devices": [
                {"alarms": [], "snapshot": null},
                {
                    "alarms": [{"label": "System – Gesamtgesundheit", "health": "critical"}],
                    "snapshot": {
                        "observations": [{"key": "system", "label": "System – Gesamtgesundheit", "health": "ok"}],
                        "capabilities": []
                    }
                }
            ]
        });
        dashboard(&mut data, Language::En);
        assert!(data["devices"][0]["snapshot"].is_null());
        assert_eq!(
            data["devices"][1]["alarms"][0]["label"],
            "System – Overall health"
        );
        assert_eq!(
            data["devices"][1]["snapshot"]["observations"][0]["label"],
            "System – Overall health"
        );
        assert_eq!(
            data["devices"][1]["snapshot"]["observations"][0]["health"],
            "ok"
        );
    }

    #[test]
    fn application_text_is_localized_but_legacy_and_vendor_messages_survive() {
        let context = json!({"version":1,"label":"System – Gesamtgesundheit (Betrieb: ausgeschaltet)","retained":false});
        let rendered = event_message(
            "Server",
            "system",
            "alarm",
            "critical",
            "original",
            Some(&context),
            Language::En,
        );
        assert_eq!(
            rendered,
            "Server: Hardware state critical: System – Overall health (power: off)"
        );
        assert_eq!(
            event_message(
                "Server",
                "system",
                "alarm",
                "critical",
                "Gespeicherter alter Text",
                None,
                Language::En
            ),
            "Gespeicherter alter Text"
        );
        let vendor =
            json!({"version":1,"label":"Herstellerwarnung = literal {0}","retained":false});
        assert_eq!(
            event_message(
                "Server",
                "log:id",
                "hardware_log",
                "warning",
                "",
                Some(&vendor),
                Language::En
            ),
            "Server: Herstellerwarnung = literal {0}"
        );
        let retained = json!({"version":1,"label":"PS1 Status","retained":true});
        assert!(event_message(
            "Server",
            "ps1",
            "repeat",
            "critical",
            "",
            Some(&retained),
            Language::En
        )
        .contains("last critical, currently unavailable"));
        assert_eq!(
            text(crate::api::message("write_csrf_invalid"), Language::En),
            "The editing session has expired. Refresh and try again."
        );
        assert_eq!(
            text("Arbitrary vendor text", Language::En),
            "Arbitrary vendor text"
        );
    }
    #[test]
    fn english_mail_defaults_and_tokens_do_not_overwrite_custom_templates() {
        let mut settings = crate::mail::Settings::default_for(Language::En);
        settings.host = "smtp.example".into();
        settings.from_address = "sender@example.org".into();
        settings.recipients = vec!["ops@example.org".into()];
        let (subject, body) = settings.preview(&crate::mail::Event::sample()).unwrap();
        assert!(subject.contains("Warning") && subject.contains("Test device"));
        assert!(
            body.contains("Device:")
                && body.contains("explicitly requested")
                && body.contains("Type: Test email")
        );
        settings.body_template = "My custom template: {{message}}".into();
        assert!(settings
            .preview(&crate::mail::Event::sample())
            .unwrap()
            .1
            .starts_with("My custom template:"));
        let old = serde_json::json!({"desktop_enabled":false,"desktop_recipient":null,"selection":{"critical":true,"warning":true,"recovery":true,"repeat":true,"hardware_log":true}});
        let parsed: crate::notification::Settings = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.language, Language::De);
    }
}
