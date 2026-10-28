//! Outgoing HTTP notifications. Secrets never occur in dashboard views or transport errors.
mod chat;
mod delivery;
mod persistence;
mod template;
use crate::{dsm::BoundaryError, i18n::Language, notification::Selection};
use anyhow::{Context, Result};
pub use delivery::{submit, Outcome};
pub use persistence::{enqueue, initialize, restore, Endpoint, Job, TABLES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub use template::{render, Event, Rendered};
use zeroize::Zeroize;

pub const MAX_BODY: usize = 65536;
pub const MAX_TARGETS: usize = 16;
pub const MAX_PENDING: i64 = 10000;
pub const MAX_AGE: i64 = 86400;
pub fn aad(id: &str) -> String {
    format!("webhook:{id}")
}
pub fn new_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Generic,
    Text,
    Json,
    Form,
    Multipart,
    Discord,
    Slack,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    #[default]
    None,
    Bearer,
    Basic,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub id: String,
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub content_type: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub name: String,
    pub enabled: bool,
    pub language: Language,
    pub format: Format,
    pub template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeds_template: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub discord_username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub discord_avatar_url: String,
    pub fields: Vec<Field>,
    pub headers: Vec<Field>,
    pub auth: Auth,
    pub username: String,
    pub allow_private: bool,
    pub ca_pem: String,
    pub content_type: String,
    pub devices: Vec<String>,
    pub selection: Selection,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: false,
            language: Language::De,
            format: Format::Generic,
            template: "{{message}}".into(),
            chat_template: None,
            embeds_template: None,
            discord_username: String::new(),
            discord_avatar_url: String::new(),
            fields: vec![],
            headers: vec![],
            auth: Auth::None,
            username: String::new(),
            allow_private: false,
            ca_pem: String::new(),
            content_type: String::new(),
            devices: vec![],
            selection: Selection::default(),
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub url: String,
    pub credential: String,
    pub values: BTreeMap<String, String>,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.url.zeroize();
        self.credential.zeroize();
        for value in self.values.values_mut() {
            value.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub id: Option<String>,
    pub revision: i64,
    pub settings: Settings,
    /// Omitted/empty URL or credential preserves the saved value, subject to identity checks.
    pub url: Option<String>,
    pub credential: Option<String>,
}
impl Drop for Input {
    fn drop(&mut self) {
        if let Some(url) = &mut self.url {
            url.zeroize();
        }
        if let Some(value) = &mut self.credential {
            value.zeroize();
        }
        for field in self
            .settings
            .fields
            .iter_mut()
            .chain(self.settings.headers.iter_mut())
        {
            if field.secret {
                field.value.zeroize();
            }
        }
    }
}

pub fn url(value: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(value).context(BoundaryError("webhook_config_invalid"))?;
    anyhow::ensure!(
        value.len() <= 8192
            && matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.fragment().is_none(),
        BoundaryError("webhook_config_invalid")
    );
    Ok(parsed)
}
fn mime(value: &str) -> bool {
    let base = value.split(';').next().unwrap_or_default();
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&c))
    };
    value.len() <= 200
        && !value.bytes().any(|b| b < 32 || b == 127)
        && base
            .split_once('/')
            .is_some_and(|(a, b)| token(a) && token(b))
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        let invalid = || BoundaryError("webhook_config_invalid");
        anyhow::ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 120
                && self.template.len() <= MAX_BODY
                && self
                    .chat_template
                    .as_ref()
                    .is_none_or(|s| s.len() <= MAX_BODY)
                && self
                    .embeds_template
                    .as_ref()
                    .is_none_or(|s| s.len() <= MAX_BODY)
                && self.username.len() <= 256
                && self.discord_username.encode_utf16().count() <= 80
                && !self.discord_username.chars().any(char::is_control)
                && self.discord_avatar_url.len() <= 2048
                && self.fields.len() <= 64
                && self.headers.len() <= 32
                && self.devices.len() <= 256
                && self
                    .devices
                    .iter()
                    .all(|id| !id.is_empty() && id.len() <= 80)
                && self.ca_pem.len() <= 65536,
            invalid()
        );
        if !self.ca_pem.is_empty() {
            crate::model::validate_certificates(&self.ca_pem).context(invalid())?;
        }
        anyhow::ensure!(
            self.content_type.is_empty()
                || matches!(self.format, Format::Text | Format::Json) && mime(&self.content_type),
            invalid()
        );
        let mut identifiers = BTreeSet::new();
        let mut header_names = BTreeSet::new();
        for (header, fields) in [(true, &self.headers), (false, &self.fields)] {
            for field in fields {
                anyhow::ensure!(
                    valid_id(&field.id)
                        && identifiers.insert(&field.id)
                        && !field.name.is_empty()
                        && field.name.len() <= 200
                        && !field.name.chars().any(char::is_control)
                        && field.value.len() <= 8192
                        && (field.content_type.is_empty() || !header && mime(&field.content_type)),
                    invalid()
                );
                if header {
                    let name = reqwest::header::HeaderName::from_bytes(field.name.as_bytes())
                        .context(invalid())?;
                    anyhow::ensure!(
                        header_names.insert(name.as_str().to_owned())
                            && (name.as_str() != "authorization" || self.auth == Auth::None)
                            && !matches!(
                                name.as_str(),
                                "host"
                                    | "content-length"
                                    | "transfer-encoding"
                                    | "connection"
                                    | "content-type"
                                    | "proxy-authorization"
                                    | "proxy-connection"
                                    | "trailer"
                                    | "te"
                                    | "upgrade"
                                    | "x-hardware-monitor-delivery"
                            ),
                        invalid()
                    );
                    // Headers are literal configuration; event strings cannot create request headers.
                    reqwest::header::HeaderValue::from_str(&field.value).context(invalid())?;
                } else if !field.secret {
                    template::text(
                        &field.value,
                        &Event::sample_for(self.language).values("sample"),
                    )?;
                }
                anyhow::ensure!(field.secret || field.value.len() <= 8192, invalid());
            }
        }
        if matches!(self.format, Format::Discord | Format::Slack) {
            chat::payload(self, &Event::sample_for(self.language).values("sample"))?;
        }
        if self.format == Format::Json {
            template::json(
                &self.template,
                &Event::sample_for(self.language).values("sample"),
            )?;
        } else if self.format == Format::Text {
            template::text(
                &self.template,
                &Event::sample_for(self.language).values("sample"),
            )?;
        }
        Ok(())
    }
    pub fn hydrate(&self, secrets: &Secrets) -> Result<Self> {
        let mut settings = self.clone();
        for field in settings
            .fields
            .iter_mut()
            .chain(settings.headers.iter_mut())
        {
            if field.secret {
                field.value = secrets
                    .values
                    .get(&field.id)
                    .context(BoundaryError("webhook_secret_required"))?
                    .clone();
            }
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests;
