//! Native chat payloads with configurable text and bounded Discord rich embeds.
use super::*;
use serde_json::{json, Map, Value};
pub const DEFAULT_TEXT: &str = "[{{health}}] {{message}}";
fn invalid() -> BoundaryError {
    BoundaryError("webhook_discord_invalid")
}
fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().context(invalid())?;
    anyhow::ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        invalid()
    );
    Ok(object)
}
fn bounded_text(
    map: &Map<String, Value>,
    key: &str,
    max: usize,
    total: &mut usize,
    required: bool,
) -> Result<bool> {
    let Some(value) = map.get(key) else {
        anyhow::ensure!(!required, invalid());
        return Ok(false);
    };
    let value = value.as_str().context(invalid())?;
    let count = value.trim().encode_utf16().count();
    anyhow::ensure!(count <= max && (!required || count > 0), invalid());
    *total += count;
    Ok(count > 0)
}
fn link(map: &Map<String, Value>, key: &str, required: bool) -> Result<()> {
    if let Some(value) = map.get(key) {
        let value = value.as_str().context(invalid())?;
        let u = url::Url::parse(value).context(invalid())?;
        anyhow::ensure!(
            value.len() <= 2048
                && matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none(),
            invalid()
        );
    } else {
        anyhow::ensure!(!required, invalid());
    }
    Ok(())
}
fn embeds(template: &str, values: &Value) -> Result<Value> {
    let value = super::template::json(template, values).context(invalid())?;
    let entries = value.as_array().context(invalid())?;
    anyhow::ensure!(entries.len() <= 10, invalid());
    let mut total = 0;
    for entry in entries {
        let map = object(
            entry,
            &[
                "title",
                "description",
                "url",
                "timestamp",
                "color",
                "footer",
                "image",
                "thumbnail",
                "author",
                "fields",
            ],
        )?;
        let mut visible = bounded_text(map, "title", 256, &mut total, false)?;
        visible |= bounded_text(map, "description", 4096, &mut total, false)?;
        link(map, "url", false)?;
        if let Some(v) = map.get("timestamp") {
            chrono::DateTime::parse_from_rfc3339(v.as_str().context(invalid())?)
                .context(invalid())?;
        }
        if let Some(v) = map.get("color") {
            anyhow::ensure!(v.as_u64().is_some_and(|c| c <= 0xffffff), invalid());
        }
        if let Some(v) = map.get("footer") {
            let footer = object(v, &["text", "icon_url"])?;
            visible |= bounded_text(footer, "text", 2048, &mut total, true)?;
            link(footer, "icon_url", false)?;
        }
        if let Some(v) = map.get("author") {
            let author = object(v, &["name", "url", "icon_url"])?;
            visible |= bounded_text(author, "name", 256, &mut total, true)?;
            link(author, "url", false)?;
            link(author, "icon_url", false)?;
        }
        for name in ["image", "thumbnail"] {
            if let Some(v) = map.get(name) {
                let image = object(v, &["url"])?;
                link(image, "url", true)?;
                visible = true;
            }
        }
        if let Some(v) = map.get("fields") {
            let fields = v.as_array().context(invalid())?;
            anyhow::ensure!(fields.len() <= 25, invalid());
            for field in fields {
                let field = object(field, &["name", "value", "inline"])?;
                bounded_text(field, "name", 256, &mut total, true)?;
                bounded_text(field, "value", 1024, &mut total, true)?;
                anyhow::ensure!(field.get("inline").is_none_or(Value::is_boolean), invalid());
                visible = true;
            }
        }
        anyhow::ensure!(visible && total <= 6000, invalid());
    }
    Ok(value)
}
fn truncate(value: &str, limit: usize) -> String {
    let mut size = 0;
    value
        .chars()
        .take_while(|c| {
            size += c.len_utf16();
            size <= limit
        })
        .collect()
}
pub fn payload(settings: &Settings, values: &Value) -> Result<Value> {
    let content = super::template::text(
        settings.chat_template.as_deref().unwrap_or(DEFAULT_TEXT),
        values,
    )?;
    match settings.format {
        Format::Discord => {
            let embeds = if let Some(template) = settings
                .embeds_template
                .as_deref()
                .filter(|t| !t.trim().is_empty())
            {
                embeds(template, values)?
            } else {
                json!([])
            };
            let limit = if settings.chat_template.is_some() {
                2000
            } else {
                1900
            };
            let content = truncate(&content, limit);
            anyhow::ensure!(
                !content.trim().is_empty() || !embeds.as_array().unwrap().is_empty(),
                invalid()
            );
            let mut payload = json!({"content":content,"allowed_mentions":{"parse":[]}});
            if !settings.discord_username.trim().is_empty() {
                payload["username"] = json!(settings.discord_username.trim());
            }
            if !settings.discord_avatar_url.trim().is_empty() {
                let avatar = settings.discord_avatar_url.trim();
                let configured = json!({"avatar_url":avatar});
                link(configured.as_object().unwrap(), "avatar_url", true)?;
                payload["avatar_url"] = json!(avatar);
            }
            if !embeds.as_array().unwrap().is_empty() {
                payload["embeds"] = embeds;
            }
            Ok(payload)
        }
        Format::Slack => {
            anyhow::ensure!(
                !content.trim().is_empty(),
                BoundaryError("webhook_template_invalid")
            );
            let text = truncate(
                &content,
                if settings.chat_template.is_some() {
                    3000
                } else {
                    2900
                },
            );
            let fallback = truncate(
                &content,
                if settings.chat_template.is_some() {
                    3000
                } else {
                    3500
                },
            );
            Ok(
                json!({"text":fallback,"blocks":[{"type":"section","text":{"type":"plain_text","text":text,"emoji":false}}],"unfurl_links":false,"unfurl_media":false}),
            )
        }
        _ => unreachable!("chat payload is only used for chat formats"),
    }
}
