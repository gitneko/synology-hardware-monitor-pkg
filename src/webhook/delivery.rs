use super::*;
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub code: Option<&'static str>,
    pub status: Option<u16>,
    pub retry_after: Option<i64>,
    pub permanent: bool,
}
impl Outcome {
    fn failure(code: &'static str, permanent: bool) -> Self {
        Self {
            code: Some(code),
            status: None,
            retry_after: None,
            permanent,
        }
    }
}
/// Network policy applies to actual connection addresses, including mapped IPv4.
pub fn allowed(address: IpAddr, private: bool) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            if ip.is_unspecified()
                || ip.octets() == [100, 100, 100, 200]
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_link_local()
                || a == 0
                || a >= 240
            {
                return false;
            }
            if ip.is_private() || ip.is_loopback() || a == 100 && (64..=127).contains(&b) {
                return private;
            }
            // Special-use and documentation destinations are not Internet receivers.
            !(a == 192 && b == 0 && (c == 0 || c == 2)
                || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
                || a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return allowed(IpAddr::V4(v4), private);
            }
            if ip.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
            {
                return false;
            }
            if ip.is_loopback() || ip.is_unique_local() {
                return private;
            }
            // Restrict to global unicast; exclude documentation and IPv4 translation ranges.
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && s[0] != 0x2002
        }
    }
}
pub async fn submit(endpoint: &Endpoint, event: &Event, delivery: &str) -> Outcome {
    match tokio::time::timeout(Duration::from_secs(15), send(endpoint, event, delivery)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            let code = crate::dsm::error_code(&error);
            match code {
                "webhook_network_blocked" => Outcome::failure("webhook_network_blocked", true),
                "webhook_discord_invalid" => Outcome::failure("webhook_discord_invalid", true),
                "webhook_config_invalid"
                | "webhook_template_invalid"
                | "webhook_body_large"
                | "webhook_secret_required" => Outcome::failure("webhook_config_invalid", true),
                _ => Outcome::failure("webhook_connection_failed", false),
            }
        }
        Err(_) => Outcome::failure("webhook_timeout", false),
    }
}
async fn send(endpoint: &Endpoint, event: &Event, delivery: &str) -> Result<Outcome> {
    let mut target = url(&endpoint.secrets.url)?;
    if endpoint.settings.format == Format::Discord {
        let pairs = target
            .query_pairs()
            .filter(|(key, _)| key != "wait")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        target
            .query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair("wait", "true");
    }
    let host = target
        .host_str()
        .context(BoundaryError("webhook_config_invalid"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = target
        .port_or_known_default()
        .context(BoundaryError("webhook_config_invalid"))?;
    let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await?
            .take(33)
            .collect()
    };
    anyhow::ensure!(
        !addresses.is_empty()
            && addresses.len() <= 32
            && addresses
                .iter()
                .all(|a| allowed(a.ip(), endpoint.settings.allow_private)),
        BoundaryError("webhook_network_blocked")
    );
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(&host, &addresses);
    if !endpoint.settings.ca_pem.is_empty() {
        for cert in reqwest::Certificate::from_pem_bundle(endpoint.settings.ca_pem.as_bytes())
            .context(BoundaryError("webhook_config_invalid"))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build()?;
    let settings = endpoint.settings.hydrate(&endpoint.secrets)?;
    let rendered = render(&settings, event, delivery, false)?;
    let mut request = client
        .post(target)
        .header(reqwest::header::CONTENT_TYPE, rendered.content_type)
        .header("X-Hardware-Monitor-Delivery", delivery);
    for field in &settings.headers {
        request = request.header(&field.name, &field.value);
    }
    request = match settings.auth {
        Auth::None => request,
        Auth::Bearer => request.bearer_auth(&endpoint.secrets.credential),
        Auth::Basic => request.basic_auth(&settings.username, Some(&endpoint.secrets.credential)),
    };
    let mut response = request.body(rendered.body).send().await?;
    let status = response.status();
    let mut retry = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| retry_after(v, crate::now()));
    // Bounded response handling: responses and request URLs never enter errors or logs.
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > 65536 {
            return Ok(Outcome {
                code: if status.is_success() {
                    None
                } else {
                    Some("webhook_response_large")
                },
                status: Some(status.as_u16()),
                retry_after: None,
                permanent: !status.is_success(),
            });
        }
        body.extend_from_slice(&chunk);
    }
    if status.as_u16() == 429 && settings.format == Format::Discord {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
            if let Some(seconds) = value["retry_after"]
                .as_f64()
                .filter(|v| v.is_finite() && *v >= 0.0)
            {
                retry = Some(
                    retry
                        .unwrap_or(0)
                        .max(seconds.ceil().min(MAX_AGE as f64) as i64),
                );
            }
        }
    }
    Ok(Outcome {
        code: if status.is_success() {
            None
        } else {
            Some("webhook_http_error")
        },
        status: Some(status.as_u16()),
        retry_after: retry,
        permanent: !status.is_success()
            && !status.is_server_error()
            && !matches!(status.as_u16(), 408 | 429),
    })
}
fn retry_after(value: &str, now: i64) -> Option<i64> {
    if let Ok(seconds) = value.parse::<i64>() {
        return Some(seconds.clamp(1, MAX_AGE));
    }
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|date| (date.timestamp() - now).clamp(1, MAX_AGE))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_policy_covers_private_mapped_and_metadata_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.0.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            let ip = ip.parse().unwrap();
            assert!(!allowed(ip, false));
            assert!(allowed(ip, true));
        }
        for ip in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!allowed(ip.parse().unwrap(), true));
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(allowed(ip.parse().unwrap(), false));
        }
        assert_eq!(retry_after("5", 0), Some(5));
        assert_eq!(
            retry_after("Wed, 28 Oct 2026 12:00:00 GMT", 1793188790),
            Some(10)
        );
    }
}
