//! Bounded SMTP submission; no shell, DSM credentials or implicit TLS downgrade.
use crate::dsm::BoundaryError;
use anyhow::{Context, Result};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    Starttls,
    Tls,
    Plain,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub language: crate::i18n::Language,
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
    pub from_address: String,
    pub from_name: String,
    pub recipients: Vec<String>,
    pub subject_template: String,
    pub body_template: String,
    pub ca_pem: Option<String>,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default = "default_date_format")]
    pub date_format: String,
}
fn default_timezone() -> String {
    "UTC".into()
}
fn default_date_format() -> String {
    "%d.%m.%Y %H:%M:%S".into()
}
impl Default for Settings {
    fn default() -> Self {
        Self { language:Default::default(), enabled:false, host:String::new(), port:587, security:Security::Starttls,
            username:String::new(), from_address:String::new(), from_name:"Hardware Monitor".into(), recipients:vec![],
            subject_template:"[Hardware Monitor] {{health}} – {{device}}".into(),
            body_template:"{{message}}\n\nGerät: {{device}}\nZustand: {{health}}\nArt: {{kind}}\nZeit: {{time}}\nEreignis: {{event_id}}\nKomponente: {{resource}}\n".into(), ca_pem:None, timezone:default_timezone(), date_format:default_date_format() }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub revision: i64,
    pub settings: Settings,
    pub password: Option<String>,
}
impl Drop for Input {
    fn drop(&mut self) {
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct Event {
    pub context: Option<serde_json::Value>,
    pub id: i64,
    pub device: String,
    pub health: String,
    pub kind: String,
    pub message: String,
    pub time: i64,
    pub resource: String,
}
impl Event {
    pub fn sample() -> Self {
        Self {
            context: None,
            id: 0,
            device: "Testgerät".into(),
            health: "warning".into(),
            kind: "test".into(),
            message: "Dies ist eine bewusst ausgelöste Testmail von Hardware Monitor.".into(),
            time: crate::now(),
            resource: "test".into(),
        }
    }
    fn values(&self, language: crate::i18n::Language) -> Vec<(&'static str, String)> {
        let health = match self.health.as_str() {
            "critical" => "Kritisch",
            "warning" => "Warnung",
            "ok" => "Entwarnung / OK",
            _ => "Unbekannt",
        };
        let kind = match self.kind.as_str() {
            "alarm" => "Alarm",
            "recovery" => "Entwarnung",
            "repeat" => "Wiederholung",
            "hardware_log" => "Hardwarelog",
            "test" => "Testmail",
            _ => "Ereignis",
        };
        let time = chrono::DateTime::from_timestamp(self.time, 0)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| self.time.to_string());
        vec![
            (
                "device",
                if self.id == 0 {
                    crate::i18n::text(&self.device, language)
                } else {
                    self.device.clone()
                },
            ),
            ("health", crate::i18n::text(health, language)),
            ("kind", crate::i18n::text(kind, language)),
            (
                "message",
                if self.id == 0 {
                    crate::i18n::text(&self.message, language)
                } else {
                    crate::i18n::event_message(
                        &self.device,
                        &self.resource,
                        &self.kind,
                        &self.health,
                        &self.message,
                        self.context.as_ref(),
                        language,
                    )
                },
            ),
            ("event_id", self.id.to_string()),
            ("time", time),
            ("resource", self.resource.clone()),
        ]
    }
}
pub fn render(template: &str, event: &Event) -> Result<String> {
    render_with(
        template,
        event,
        &default_timezone(),
        &default_date_format(),
        Default::default(),
    )
}
fn render_with(
    template: &str,
    event: &Event,
    timezone: &str,
    format: &str,
    language: crate::i18n::Language,
) -> Result<String> {
    let mut values = event.values(language);
    let zone: chrono_tz::Tz = timezone
        .parse()
        .context(BoundaryError("mail_time_invalid"))?;
    let instant = chrono::DateTime::from_timestamp(event.time, 0)
        .context(BoundaryError("mail_time_invalid"))?;
    let mut local = String::new();
    instant
        .with_timezone(&zone)
        .format(format)
        .write_to(&mut local)
        .map_err(|_| anyhow::anyhow!(BoundaryError("mail_time_invalid")))?;
    let utc = values.iter().find(|(k, _)| *k == "time").unwrap().1.clone();
    values.retain(|(k, _)| *k != "time");
    values.extend([
        ("time", local.clone()),
        ("time_local", local),
        ("time_utc", utc),
        ("timezone", timezone.to_owned()),
    ]);
    let mut rest = template;
    let mut result = String::new();
    while let Some(start) = rest.find("{{") {
        anyhow::ensure!(
            !rest[..start].contains("}}"),
            BoundaryError("mail_template_invalid")
        );
        result.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail
            .find("}}")
            .context(BoundaryError("mail_template_invalid"))?;
        let key = &tail[..end];
        let (_, value) = values
            .iter()
            .find(|(name, _)| *name == key)
            .context(BoundaryError("mail_template_invalid"))?;
        result.push_str(value);
        rest = &tail[end + 2..];
    }
    anyhow::ensure!(!rest.contains("}}"), BoundaryError("mail_template_invalid"));
    result.push_str(rest);
    Ok(result)
}
impl Settings {
    pub fn default_for(language: crate::i18n::Language) -> Self {
        let mut settings = Self {
            language,
            ..Self::default()
        };
        if language == crate::i18n::Language::En {
            settings.body_template="{{message}}\n\nDevice: {{device}}\nState: {{health}}\nType: {{kind}}\nTime: {{time}}\nEvent: {{event_id}}\nComponent: {{resource}}\n".into();
            settings.date_format = "%Y-%m-%d %H:%M:%S %:z".into();
        }
        settings
    }

    pub fn validate(&self) -> Result<()> {
        let valid = || -> Result<()> {
            anyhow::ensure!(
                !self.host.is_empty() && self.host.len() <= 253 && self.host == self.host.trim()
            );
            anyhow::ensure!(
                !self
                    .host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
                    && !self.host.contains(['/', '@', '?', '#'])
            );
            if self.host.parse::<std::net::IpAddr>().is_err() {
                let _ = url::Host::parse(&self.host)?;
            }
            anyhow::ensure!(
                self.port > 0
                    && self.username.len() <= 256
                    && !self.username.chars().any(char::is_control)
            );
            anyhow::ensure!(
                self.from_name.len() <= 128 && !self.from_name.chars().any(char::is_control)
            );
            let _ = address(&self.from_address)?;
            anyhow::ensure!(!self.recipients.is_empty() && self.recipients.len() <= 20);
            let mut unique = std::collections::BTreeSet::new();
            for r in &self.recipients {
                let _ = address(r)?;
                anyhow::ensure!(unique.insert(r.to_ascii_lowercase()));
            }
            anyhow::ensure!(
                !self.subject_template.trim().is_empty()
                    && self.subject_template.len() <= 500
                    && !self.subject_template.chars().any(char::is_control)
            );
            anyhow::ensure!(
                !self.body_template.trim().is_empty()
                    && self.body_template.len() <= 16384
                    && !self.body_template.contains('\0')
            );
            anyhow::ensure!(
                self.timezone.len() <= 64 && self.timezone.parse::<chrono_tz::Tz>().is_ok(),
                BoundaryError("mail_time_invalid")
            );
            anyhow::ensure!(
                !self.date_format.is_empty()
                    && self.date_format.len() <= 120
                    && !self.date_format.chars().any(char::is_control),
                BoundaryError("mail_time_invalid")
            );
            anyhow::ensure!(
                !chrono::format::StrftimeItems::new(&self.date_format)
                    .any(|v| matches!(v, chrono::format::Item::Error)),
                BoundaryError("mail_time_invalid")
            );
            self.preview(&Event::sample())?;
            if let Some(pem) = &self.ca_pem {
                crate::model::validate_certificates(pem)?;
            }
            let _ = self.transport(None)?;
            Ok(())
        };
        valid().context(BoundaryError("mail_config_invalid"))
    }
    pub fn same_auth_target(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.security == other.security
            && self.username == other.username
    }
    pub fn transport(&self, password: Option<&str>) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let mode = if self.security == Security::Plain {
            Tls::None
        } else {
            let mut tls = TlsParameters::builder(self.host.clone());
            if let Some(pem) = &self.ca_pem {
                tls = tls.add_root_certificate(Certificate::from_pem(pem.as_bytes())?);
            }
            let tls = tls.build()?;
            match self.security {
                Security::Starttls => Tls::Required(tls),
                Security::Tls => Tls::Wrapper(tls),
                Security::Plain => unreachable!(),
            }
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host)
            .port(self.port)
            .tls(mode)
            .timeout(Some(Duration::from_secs(8)));
        if !self.username.is_empty() {
            if let Some(p) = password {
                builder = builder.credentials(Credentials::new(self.username.clone(), p.into()));
            }
        }
        Ok(builder.build())
    }
    pub fn preview(&self, event: &Event) -> Result<(String, String)> {
        let subject = render_with(
            &self.subject_template,
            event,
            &self.timezone,
            &self.date_format,
            self.language,
        )?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect();
        Ok((
            subject,
            render_with(
                &self.body_template,
                event,
                &self.timezone,
                &self.date_format,
                self.language,
            )?,
        ))
    }
    pub fn message(&self, event: &Event, recipient: &str, message_id: &str) -> Result<Message> {
        let (subject, body) = self.preview(event)?;
        Ok(Message::builder()
            .from(Mailbox::new(
                Some(self.from_name.clone()),
                address(&self.from_address)?,
            ))
            .to(Mailbox::new(None, address(recipient)?))
            .subject(subject)
            .message_id(Some(message_id.into()))
            .header(ContentType::TEXT_PLAIN)
            .body(body)?)
    }
}
fn address(value: &str) -> Result<lettre::Address> {
    anyhow::ensure!(
        value.len() <= 254 && value == value.trim() && !value.chars().any(char::is_control)
    );
    Ok(value.parse()?)
}
// Safe fixed error labels only; never return an SMTP response containing tokens/content.
pub async fn submit(
    settings: &Settings,
    password: Option<&str>,
    event: &Event,
    recipient: &str,
    id: &str,
) -> Result<(), &'static str> {
    let transport = settings
        .transport(password)
        .map_err(|_| "mail_config_invalid")?;
    let message = settings
        .message(event, recipient, id)
        .map_err(|_| "mail_template_invalid")?;
    match tokio::time::timeout(Duration::from_secs(12), transport.send(message)).await {
        Err(_) => Err("mail_timeout"),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) if e.is_permanent() => Err("mail_rejected"),
        Ok(Err(_)) => Err("mail_connection_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn settings() -> Settings {
        Settings {
            host: "localhost".into(),
            from_address: "monitor@example.invalid".into(),
            recipients: vec!["receiver@example.invalid".into()],
            ..Settings::default()
        }
    }
    #[test]
    fn local_times_include_dst_and_utc_and_reject_bad_formats() {
        let mut s = settings();
        s.timezone = "Europe/Zurich".into();
        s.body_template = "{{time}} | {{time_local}} | {{time_utc}} | {{timezone}}".into();
        let mut e = Event::sample();
        e.time = 1767225600;
        assert_eq!(
            s.preview(&e).unwrap().1,
            "01.01.2026 01:00:00 | 01.01.2026 01:00:00 | 2026-01-01T00:00:00Z | Europe/Zurich"
        );
        e.time = 1782864000;
        assert!(s.preview(&e).unwrap().1.starts_with("01.07.2026 02:00:00"));
        for format in ["%Q", "%", "%#z", "bad\n"] {
            s.date_format = format.into();
            assert!(s.validate().is_err());
        }
        s.date_format = "%Y-%m-%d %H:%M:%S %:z".into();
        s.validate().unwrap();
        s.timezone = "Bad/Zone".into();
        assert!(s.validate().is_err());
    }
    #[test]
    fn templates_are_one_pass_and_headers_cannot_be_injected() {
        let mut s = settings();
        s.validate().unwrap();
        let mut event = Event::sample();
        event.device = "Device\r\nBcc: attacker@example.invalid".into();
        event.message = "{{device}}".into();
        assert_eq!(render("{{message}}", &event).unwrap(), "{{device}}");
        let message = s
            .message(
                &event,
                &s.recipients[0],
                "<synthetic@hardwaremonitor.invalid>",
            )
            .unwrap()
            .formatted();
        assert!(!String::from_utf8(message)
            .unwrap()
            .split("\r\n\r\n")
            .next()
            .unwrap()
            .contains("\r\nBcc:"));
        for template in ["{{unknown}}", "{{device", "oops }}"] {
            assert!(render(template, &event).is_err());
        }
        s.from_address = "a@example.invalid\r\nBcc: b@example.invalid".into();
        assert!(s.validate().is_err());
        s = settings();
        s.subject_template = "subject\nBcc: bad".into();
        assert!(s.validate().is_err());
        s = settings();
        s.recipients.push(s.recipients[0].clone());
        assert!(s.validate().is_err());
        assert!(serde_json::from_value::<Security>(serde_json::json!("none")).is_err());
    }
}
