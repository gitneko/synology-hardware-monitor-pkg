//! Independent desktop channel and shared event selection. No native system event registration.
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Selection {
    pub critical: bool,
    pub warning: bool,
    pub recovery: bool,
    pub repeat: bool,
    pub hardware_log: bool,
    /// None preserves the severity-based selection of existing installations.
    /// An explicit choice controls query events independently of hardware severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<bool>,
}
impl Default for Selection {
    fn default() -> Self {
        Self {
            critical: true,
            warning: true,
            recovery: true,
            repeat: true,
            hardware_log: true,
            monitoring: None,
        }
    }
}
impl Selection {
    pub fn accepts(&self, key: &str, kind: &str, health: crate::model::Health) -> bool {
        // Match the event log's category, including incomplete coverage and fatal
        // collection errors. A vendor log cannot become a monitoring event by key.
        let monitoring =
            kind != "hardware_log" && (key == "collector" || key.starts_with("coverage:"));
        if monitoring && self.monitoring == Some(false) {
            return false;
        }
        if kind == "recovery" {
            return self.recovery;
        }
        if kind == "repeat" && !self.repeat {
            return false;
        }
        if kind == "hardware_log" && !self.hardware_log {
            return false;
        }
        if monitoring && self.monitoring == Some(true) {
            return matches!(
                health,
                crate::model::Health::Warning | crate::model::Health::Critical
            );
        }
        match health {
            crate::model::Health::Critical => self.critical,
            crate::model::Health::Warning => self.warning,
            _ => false,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub language: crate::i18n::Language,
    pub desktop_enabled: bool,
    pub desktop_recipient: Option<String>,
    pub selection: Selection,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(default)]
    pub language: crate::i18n::Language,
    pub revision: i64,
    pub desktop_enabled: bool,
    pub selection: Selection,
}
pub struct DesktopJob {
    pub language: crate::i18n::Language,
    pub event_id: i64,
    pub recipient: String,
    pub kind: String,
    pub health: String,
    pub device: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DesktopLevel {
    #[default]
    Info,
    Warn,
    Error,
}
impl DesktopLevel {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
    pub fn for_event(kind: &str, health: &str) -> Self {
        if kind == "recovery" {
            Self::Info
        } else {
            match health {
                "critical" => Self::Error,
                "warning" => Self::Warn,
                _ => Self::Info,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Health;

    #[test]
    fn query_selection_is_independent_of_hardware_severity_but_respects_event_phase() {
        let mut selection = Selection {
            critical: false,
            warning: false,
            monitoring: Some(true),
            ..Default::default()
        };
        for key in ["collector", "coverage:/redfish/v1/Systems"] {
            assert!(selection.accepts(key, "alarm", Health::Warning));
            assert!(selection.accepts(key, "alarm", Health::Critical));
            assert!(selection.accepts(key, "repeat", Health::Warning));
            assert!(selection.accepts(key, "recovery", Health::Ok));
            assert!(!selection.accepts(key, "alarm", Health::Unknown));
            selection.repeat = false;
            selection.recovery = false;
            assert!(!selection.accepts(key, "repeat", Health::Warning));
            assert!(!selection.accepts(key, "recovery", Health::Ok));
            selection.repeat = true;
            selection.recovery = true;
        }
        assert!(!selection.accepts("fan", "alarm", Health::Warning));
        assert!(!selection.accepts("fan", "alarm", Health::Critical));
        assert!(!selection.accepts("collector", "hardware_log", Health::Critical));
        selection.critical = true;
        selection.warning = true;
        selection.monitoring = Some(false);
        assert!(selection.accepts("fan", "alarm", Health::Warning));
        for kind in ["alarm", "repeat", "recovery"] {
            assert!(!selection.accepts("collector", kind, Health::Critical));
            assert!(!selection.accepts("coverage:/redfish/v1/Chassis", kind, Health::Warning));
        }
    }

    #[test]
    fn old_settings_keep_exact_severity_selection_until_an_explicit_choice_is_saved() {
        let selection: Selection =
            serde_json::from_value(serde_json::json!({"critical":true,"warning":false})).unwrap();
        assert_eq!(selection.monitoring, None);
        assert!(!selection.accepts("collector", "alarm", Health::Warning));
        assert!(selection.accepts("collector", "alarm", Health::Critical));
        assert!(selection.accepts("collector", "recovery", Health::Ok));
        assert!(serde_json::to_value(&selection)
            .unwrap()
            .get("monitoring")
            .is_none());
        for enabled in [false, true] {
            let selection = Selection {
                monitoring: Some(enabled),
                ..selection.clone()
            };
            let saved = serde_json::to_value(&selection).unwrap();
            let restored: Selection = serde_json::from_value(saved).unwrap();
            assert_eq!(restored, selection);
        }
    }
}
