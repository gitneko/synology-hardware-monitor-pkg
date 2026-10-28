use super::*;
use serde_json::{json, Value};
#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub device_id: String,
    pub device: String,
    pub resource: String,
    pub kind: String,
    pub health: String,
    pub message: String,
    pub created: i64,
    pub context: Option<Value>,
}
impl Event {
    pub fn sample() -> Self {
        Self::sample_for(Language::De)
    }
    /// Synthetic names and message text follow the destination language, not the UI language.
    pub fn sample_for(language: Language) -> Self {
        let device = match language {
            Language::De => "Beispielserver",
            Language::En => "Sample server",
        };
        Self {
            id: 123,
            device_id: "sample-device".into(),
            device: device.into(),
            resource: "fan:1".into(),
            kind: "alarm".into(),
            health: "critical".into(),
            message: format!(
                "{device}: {}",
                crate::i18n::text("Lüfter ausgefallen", language)
            ),
            created: 1793188800,
            context: Some(json!({"source":"redfish","verified":true,"provisional":false})),
        }
    }
    pub fn values(&self, delivery: &str) -> Value {
        json!({"schema_version":1,"event_id":self.id,"delivery_id":delivery,"device_id":self.device_id,"device":self.device,"resource":self.resource,
            "kind":self.kind,"health":self.health,"message":self.message,"created":self.created,
            "time":chrono::DateTime::from_timestamp(self.created,0).map(|v|v.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default(),
            "source":self.context.as_ref().and_then(|c|c.get("source")).cloned().unwrap_or(Value::Null),
            "verified":self.context.as_ref().and_then(|c|c.get("verified")).cloned().unwrap_or(Value::Null),
            "provisional":self.context.as_ref().and_then(|c|c.get("provisional")).cloned().unwrap_or(Value::Bool(false))})
    }
}
fn string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
/// One pass: event text containing braces is never interpreted as a second template.
pub(super) fn text(template: &str, values: &Value) -> Result<String> {
    let mut rest = template;
    let mut output = String::new();
    while let Some(start) = rest.find("{{") {
        anyhow::ensure!(
            !rest[..start].contains("}}"),
            BoundaryError("webhook_template_invalid")
        );
        output.push_str(&rest[..start]);
        let end = rest[start + 2..]
            .find("}}")
            .context(BoundaryError("webhook_template_invalid"))?
            + start
            + 2;
        let key = rest[start + 2..end].trim();
        let value = values
            .get(key)
            .context(BoundaryError("webhook_template_invalid"))?;
        output.push_str(&string(value));
        rest = &rest[end + 2..];
        anyhow::ensure!(
            output.len() <= MAX_BODY,
            BoundaryError("webhook_body_large")
        );
    }
    anyhow::ensure!(
        !rest.contains("}}"),
        BoundaryError("webhook_template_invalid")
    );
    output.push_str(rest);
    anyhow::ensure!(
        output.len() <= MAX_BODY,
        BoundaryError("webhook_body_large")
    );
    Ok(output)
}
pub(super) fn json(template: &str, values: &Value) -> Result<Value> {
    fn visit(value: &mut Value, values: &Value, depth: usize) -> Result<()> {
        anyhow::ensure!(depth < 32, BoundaryError("webhook_template_invalid"));
        match value {
            Value::String(s) => {
                if let Some(key) = s.strip_prefix("{{").and_then(|s| s.strip_suffix("}}")) {
                    if let Some(v) = values.get(key.trim()) {
                        *value = v.clone();
                        return Ok(());
                    }
                }
                *s = text(s, values)?;
            }
            Value::Array(items) => {
                for item in items {
                    visit(item, values, depth + 1)?;
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    anyhow::ensure!(
                        !key.contains("{{") && !key.contains("}}"),
                        BoundaryError("webhook_template_invalid")
                    );
                    visit(value, values, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut value: Value =
        serde_json::from_str(template).context(BoundaryError("webhook_template_invalid"))?;
    visit(&mut value, values, 0)?;
    Ok(value)
}
pub struct Rendered {
    pub body: Vec<u8>,
    pub content_type: String,
    pub fields: Vec<(String, String)>,
}
pub fn render(
    settings: &Settings,
    event: &Event,
    delivery: &str,
    redact: bool,
) -> Result<Rendered> {
    let values = event.values(delivery);
    let mut fields = vec![];
    for field in &settings.fields {
        // Secret fields are literal; their contents must never be interpreted as templates.
        fields.push((
            field.name.clone(),
            if field.secret {
                if redact {
                    "[REDACTED]".into()
                } else {
                    field.value.clone()
                }
            } else {
                text(&field.value, &values)?
            },
        ));
    }
    let (body, kind) = match settings.format {
        Format::Generic => (serde_json::to_vec(&values)?, "application/json".into()),
        Format::Json => (
            serde_json::to_vec(&json(&settings.template, &values)?)?,
            "application/json".into(),
        ),
        Format::Text => (
            text(&settings.template, &values)?.into_bytes(),
            "text/plain; charset=utf-8".into(),
        ),
        Format::Form => (
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&fields)
                .finish()
                .into_bytes(),
            "application/x-www-form-urlencoded".into(),
        ),
        Format::Multipart => {
            let mut boundary = format!("hm-{}", new_id());
            while fields.iter().any(|(_, value)| value.contains(&boundary)) {
                boundary = format!("hm-{}", new_id());
            }
            let mut body = Vec::new();
            for ((name, value), field) in fields.iter().zip(&settings.fields) {
                let name = name.replace('\\', "\\\\").replace('"', "\\\"");
                body.extend_from_slice(
                    format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n")
                        .as_bytes(),
                );
                if !field.content_type.is_empty() {
                    body.extend_from_slice(
                        format!("Content-Type: {}\r\n", field.content_type).as_bytes(),
                    );
                }
                body.extend_from_slice(b"\r\n");
                body.extend_from_slice(value.as_bytes());
                body.extend_from_slice(b"\r\n");
                anyhow::ensure!(body.len() <= MAX_BODY, BoundaryError("webhook_body_large"));
            }
            body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            (body, format!("multipart/form-data; boundary={boundary}"))
        }
        Format::Discord | Format::Slack => (
            serde_json::to_vec(&super::chat::payload(settings, &values)?)?,
            "application/json".into(),
        ),
    };
    anyhow::ensure!(body.len() <= MAX_BODY, BoundaryError("webhook_body_large"));
    Ok(Rendered {
        body,
        content_type: if settings.content_type.is_empty() {
            kind
        } else {
            settings.content_type.clone()
        },
        fields,
    })
}
