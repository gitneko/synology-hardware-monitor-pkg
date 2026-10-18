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
}
impl Default for Selection {
    fn default() -> Self {
        Self {
            critical: true,
            warning: true,
            recovery: true,
            repeat: true,
            hardware_log: true,
        }
    }
}
impl Selection {
    pub fn accepts(&self, kind: &str, health: crate::model::Health) -> bool {
        if kind == "recovery" {
            return self.recovery;
        }
        if kind == "repeat" && !self.repeat {
            return false;
        }
        if kind == "hardware_log" && !self.hardware_log {
            return false;
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
