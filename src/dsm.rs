//! DSM boundary: fixed native commands, no shell and no client-supplied identity.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::CString, process::Stdio, time::Duration};

// Only fixed codes cross the HTTP boundary. Native error messages, environment
// contents, usernames and helper output must never enter diagnostics.
#[derive(Debug)]
pub struct BoundaryError(pub &'static str);
impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for BoundaryError {}
pub fn error_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<BoundaryError>()
        .map_or("internal_error", |e| e.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Administrator,
    Viewer,
}

pub fn role_for_groups(groups: &[String]) -> Option<Role> {
    if groups.iter().any(|g| g == "administrators") {
        Some(Role::Administrator)
    } else if groups.iter().any(|g| g == "hardware-monitor-viewers") {
        Some(Role::Viewer)
    } else {
        None
    }
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub diagnostic: bool,
}

impl AuthContext {
    pub fn from_cgi() -> Self {
        Self {
            environment: AUTH_KEYS
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).into(), v)))
                .collect(),
            diagnostic: false,
        }
    }
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.environment
                .keys()
                .all(|k| AUTH_KEYS.contains(&k.as_str())),
            BoundaryError("cgi_context_invalid")
        );
        anyhow::ensure!(
            self.environment
                .get("HTTP_COOKIE")
                .is_some_and(|v| !v.is_empty()
                    && v.len() <= 8192
                    && !v.contains(['\r', '\n', '\0'])),
            BoundaryError("cgi_cookie_missing_or_invalid")
        );
        for key in ["REMOTE_ADDR", "SERVER_ADDR"] {
            anyhow::ensure!(
                self.environment
                    .get(key)
                    .is_some_and(|v| v.parse::<std::net::IpAddr>().is_ok()),
                BoundaryError(if key == "REMOTE_ADDR" {
                    "cgi_client_address_missing_or_invalid"
                } else {
                    "cgi_server_address_missing_or_invalid"
                })
            );
        }
        Ok(())
    }
}
const AUTH_KEYS: &[&str] = &[
    "HTTP_COOKIE",
    "REMOTE_ADDR",
    "SERVER_ADDR",
    "SERVER_PORT",
    "HTTPS",
    "HTTP_X_SYNO_TOKEN",
    "REQUEST_METHOD",
    "HTTP_HOST",
    "HTTP_ORIGIN",
    "REQUEST_SCHEME",
    "HTTP_SEC_FETCH_SITE",
];

pub fn validate_write_context(context: &AuthContext) -> Result<()> {
    let get = |key: &str| {
        context
            .environment
            .get(key)
            .map(String::as_str)
            .unwrap_or("")
    };
    anyhow::ensure!(
        get("REQUEST_METHOD") == "POST",
        BoundaryError("write_method_invalid")
    );
    anyhow::ensure!(
        get("HTTPS") == "on" || get("HTTPS") == "1" || get("REQUEST_SCHEME") == "https",
        BoundaryError("write_https_required")
    );
    let token = get("HTTP_X_SYNO_TOKEN");
    anyhow::ensure!(
        !token.is_empty() && token.len() <= 4096 && !token.chars().any(char::is_control),
        BoundaryError("write_dsm_token_required")
    );
    anyhow::ensure!(
        matches!(get("HTTP_SEC_FETCH_SITE"), "" | "same-origin"),
        BoundaryError("write_origin_invalid")
    );
    let expected = url::Url::parse(&format!("https://{}", get("HTTP_HOST")))
        .map_err(|_| anyhow::anyhow!(BoundaryError("write_origin_invalid")))?;
    let supplied = url::Url::parse(get("HTTP_ORIGIN"))
        .map_err(|_| anyhow::anyhow!(BoundaryError("write_origin_invalid")))?;
    for origin in [&expected, &supplied] {
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            BoundaryError("write_origin_invalid")
        );
    }
    anyhow::ensure!(
        expected.origin() == supplied.origin(),
        BoundaryError("write_origin_invalid")
    );
    Ok(())
}

pub async fn authenticate(context: &AuthContext) -> Result<(String, Role)> {
    context.validate()?;
    let mut command =
        tokio::process::Command::new("/usr/syno/synoman/webman/modules/authenticate.cgi");
    command
        .env_clear()
        .envs(&context.environment)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(3), command.output())
        .await
        .context(BoundaryError("dsm_helper_timeout"))?
        .context(BoundaryError("dsm_helper_unavailable"))?;
    anyhow::ensure!(
        output.status.success() && output.stdout.len() <= 256,
        BoundaryError("dsm_helper_failed")
    );
    let username = String::from_utf8(output.stdout)
        .context(BoundaryError("dsm_identity_invalid"))?
        .trim()
        .to_owned();
    anyhow::ensure!(!username.is_empty(), BoundaryError("dsm_session_rejected"));
    anyhow::ensure!(
        username.len() <= 128 && !username.chars().any(char::is_control),
        BoundaryError("dsm_identity_invalid")
    );
    let groups = groups_for_user(&username).context(BoundaryError("dsm_group_lookup_failed"))?;
    let role = role_for_groups(&groups)
        .ok_or_else(|| anyhow::anyhow!(BoundaryError("application_role_denied")))?;
    Ok((username, role))
}

fn groups_for_user(username: &str) -> Result<Vec<String>> {
    let username = CString::new(username)?;
    let mut buffer = vec![0u8; 65536];
    // Reentrant NSS calls also resolve DSM domain users when configured by DSM.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut found = std::ptr::null_mut();
        let rc = libc::getpwnam_r(
            username.as_ptr(),
            &mut pwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        );
        anyhow::ensure!(rc == 0 && !found.is_null(), "DSM user lookup failed");
        let mut count = 256;
        let mut ids = vec![0 as libc::gid_t; count as usize];
        anyhow::ensure!(
            libc::getgrouplist(username.as_ptr(), pwd.pw_gid, ids.as_mut_ptr(), &mut count) >= 0
                && count <= 256,
            "DSM group lookup failed"
        );
        let mut names = Vec::new();
        for id in ids.into_iter().take(count as usize) {
            let mut group: libc::group = std::mem::zeroed();
            let mut found = std::ptr::null_mut();
            let rc = libc::getgrgid_r(
                id,
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            );
            anyhow::ensure!(rc == 0 && !found.is_null(), "DSM group name lookup failed");
            names.push(std::ffi::CStr::from_ptr(group.gr_name).to_str()?.to_owned());
        }
        Ok(names)
    }
}

// Recipients are captured from verified native DSM identities, never arbitrary request text.
pub fn desktop_test_available() -> bool {
    std::fs::metadata("/usr/syno/bin/synodsmnotify").is_ok_and(|m| m.is_file())
}
use crate::notification::DesktopLevel;
#[derive(Clone, Copy, Debug)]
struct DesktopFeatures {
    levels: bool,
}
static DESKTOP_FEATURES: tokio::sync::OnceCell<DesktopFeatures> =
    tokio::sync::OnceCell::const_new();
fn desktop_features_from_usage(usage: &str) -> DesktopFeatures {
    DesktopFeatures {
        levels: usage.contains("-l info/warn/error"),
    }
}
// Read usage once, with no recipient/title/message: this sends no notification.
// Older DSM versions may not support -l. Do not break their existing desktop channel.
async fn desktop_features() -> Result<DesktopFeatures> {
    let features = DESKTOP_FEATURES
        .get_or_try_init(|| async {
            let usage = tokio::time::timeout(Duration::from_secs(2), async {
                use tokio::io::AsyncReadExt;
                let mut child = tokio::process::Command::new("/usr/syno/bin/synodsmnotify")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .context(BoundaryError("desktop_test_unavailable"))?;
                let mut stdout = child.stdout.take().unwrap().take(8192);
                let mut stderr = child.stderr.take().unwrap().take(8192);
                let (mut out, mut err) = (Vec::new(), Vec::new());
                tokio::try_join!(
                    stdout.read_to_end(&mut out),
                    stderr.read_to_end(&mut err),
                    child.wait()
                )
                .context(BoundaryError("desktop_test_unavailable"))?;
                out.extend_from_slice(&err);
                Ok::<_, anyhow::Error>(String::from_utf8_lossy(&out).into_owned())
            })
            .await
            .context(BoundaryError("desktop_test_timeout"))??;
            Ok::<_, anyhow::Error>(desktop_features_from_usage(&usage))
        })
        .await?;
    Ok(*features)
}
fn desktop_text(value: &str, max: usize) -> String {
    let mut text: String = value
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .take(max)
        .collect();
    // Some getopt implementations parse options after positionals. Keep data that
    // starts with '-' a literal value without relying on an undocumented '--'.
    if text.starts_with('-') {
        text.insert(0, ' ');
    }
    text
}
#[cfg(test)]
fn desktop_test_command(
    actor: &str,
    level: DesktopLevel,
    features: DesktopFeatures,
) -> Result<tokio::process::Command> {
    desktop_test_command_localized(actor, level, features, Default::default())
}
fn desktop_test_command_localized(
    actor: &str,
    level: DesktopLevel,
    features: DesktopFeatures,
    language: crate::i18n::Language,
) -> Result<tokio::process::Command> {
    desktop_command(actor,"test",level,features,[desktop_text(actor,128),crate::i18n::text("Diese Testmeldung wurde bewusst ausgelöst. Platzhalterprüfung mit Gerät, Meldung und Kennung.",language),"Test-0017".into()], language)
}
fn desktop_command(
    actor: &str,
    category: &str,
    level: DesktopLevel,
    features: DesktopFeatures,
    values: [String; 3],
    language: crate::i18n::Language,
) -> Result<tokio::process::Command> {
    anyhow::ensure!(
        [
            "test",
            "critical",
            "warning",
            "recovery",
            "repeat",
            "hardware_log"
        ]
        .contains(&category),
        BoundaryError("desktop_test_rejected")
    );
    anyhow::ensure!(
        !actor.is_empty()
            && actor.len() <= 128
            && !actor.starts_with(['-', '@'])
            && !actor.chars().any(|c| c.is_control() || c == ','),
        BoundaryError("desktop_recipient_invalid")
    );
    let mut command = tokio::process::Command::new("/usr/syno/bin/synodsmnotify");
    command.env_clear().env("PATH", "/usr/bin:/bin");
    if features.levels {
        command.args(["-l", level.argument()]);
    }
    command
        .args([
            "-p",
            "plain",
            "-c",
            "SYNO.SDS.App.HardwareMonitor.Instance",
            actor,
            &format!(
                "HardwareMonitor:notification_details_{}:{category}_title",
                language.tag()
            ),
            &format!(
                "HardwareMonitor:notification_details_{}:{category}_body",
                language.tag()
            ),
        ])
        .args(values)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    Ok(command)
}
pub async fn desktop_test(actor: &str, level: DesktopLevel) -> Result<DesktopLevel> {
    desktop_test_localized(actor, level, Default::default()).await
}
pub async fn desktop_test_localized(
    actor: &str,
    level: DesktopLevel,
    language: crate::i18n::Language,
) -> Result<DesktopLevel> {
    let features = desktop_features().await?;
    run_desktop(desktop_test_command_localized(
        actor, level, features, language,
    )?)
    .await?;
    Ok(if features.levels {
        level
    } else {
        DesktopLevel::Info
    })
}
fn desktop_event_command(
    job: &crate::notification::DesktopJob,
    features: DesktopFeatures,
) -> Result<tokio::process::Command> {
    let category = match job.kind.as_str() {
        "recovery" => "recovery",
        "repeat" => "repeat",
        "hardware_log" => "hardware_log",
        _ => {
            if job.health == "critical" {
                "critical"
            } else {
                "warning"
            }
        }
    };
    desktop_command(
        &job.recipient,
        category,
        DesktopLevel::for_event(&job.kind, &job.health),
        features,
        [
            desktop_text(&job.device, 160),
            desktop_text(
                job.message
                    .strip_prefix(&format!("{}: ", job.device))
                    .unwrap_or(&job.message),
                1600,
            ),
            desktop_text(&job.event_id.to_string(), 24),
        ],
        job.language,
    )
}
pub async fn desktop_event(job: &crate::notification::DesktopJob) -> Result<()> {
    run_desktop(desktop_event_command(job, desktop_features().await?)?).await
}
async fn run_desktop(mut command: tokio::process::Command) -> Result<()> {
    let status = tokio::time::timeout(Duration::from_secs(5), command.status())
        .await
        .context(BoundaryError("desktop_test_timeout"))?
        .context(BoundaryError("desktop_test_unavailable"))?;
    anyhow::ensure!(status.success(), BoundaryError("desktop_test_rejected"));
    Ok(())
}

pub async fn notify(kind: &str, health: &str, message: &str) -> Result<()> {
    let key = if kind == "recovery" {
        "HardwareMonitorRecovered"
    } else if health == "\"critical\"" {
        "HardwareMonitorCritical"
    } else {
        "HardwareMonitorWarning"
    };
    let variables = serde_json::json!({"%DETAIL%":message}).to_string();
    let mut command = tokio::process::Command::new("/usr/syno/bin/synonotify");
    command
        .arg(key)
        .arg(variables)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(5), command.status()).await??;
    anyhow::ensure!(status.success(), "DSM notification command failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desktop_uses_fixed_identity_keys_plain_text_and_three_distinct_values() {
        let command = desktop_test_command(
            "test-admin",
            DesktopLevel::Warn,
            DesktopFeatures { levels: true },
        )
        .unwrap();
        let native = command.as_std();
        assert_eq!(native.get_program(), "/usr/syno/bin/synodsmnotify");
        let args: Vec<_> = native.get_args().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(
            &args[..9],
            &[
                "-l",
                "warn",
                "-p",
                "plain",
                "-c",
                "SYNO.SDS.App.HardwareMonitor.Instance",
                "test-admin",
                "HardwareMonitor:notification_details_de:test_title",
                "HardwareMonitor:notification_details_de:test_body"
            ]
        );
        assert_eq!(&args[9..],&["test-admin","Diese Testmeldung wurde bewusst ausgelöst. Platzhalterprüfung mit Gerät, Meldung und Kennung.","Test-0017"]);
        assert!(!native.get_envs().any(|(key, _)| key == "HTTP_COOKIE"));
        let english = desktop_test_command_localized(
            "test-admin",
            DesktopLevel::Error,
            DesktopFeatures { levels: true },
            crate::i18n::Language::En,
        )
        .unwrap();
        let english_args: Vec<_> = english
            .as_std()
            .get_args()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            english_args[7],
            "HardwareMonitor:notification_details_en:test_title"
        );
        assert!(english_args[10].starts_with("This test was explicitly requested."));

        for invalid in ["", "@administrators", "-c", "one,two", "one\nother"] {
            assert!(desktop_test_command(
                invalid,
                DesktopLevel::Info,
                DesktopFeatures { levels: true }
            )
            .is_err());
        }
    }
    #[test]
    fn levels_follow_severity_including_reminders_and_recovery_and_old_helpers() {
        let usage="synodsmnotify [-c className] [-p html/plain] [-l info/warn/error] user/group title msg | [--watch ]...";
        assert!(desktop_features_from_usage(usage).levels);
        assert!(
            !desktop_features_from_usage("synodsmnotify [-c className] user/group title msg ...")
                .levels
        );
        for (kind, health, expected) in [
            ("alarm", "critical", DesktopLevel::Error),
            ("alarm", "warning", DesktopLevel::Warn),
            ("repeat", "critical", DesktopLevel::Error),
            ("repeat", "warning", DesktopLevel::Warn),
            ("hardware_log", "critical", DesktopLevel::Error),
            ("hardware_log", "warning", DesktopLevel::Warn),
            ("recovery", "critical", DesktopLevel::Info),
        ] {
            let job = crate::notification::DesktopJob {
                language: Default::default(),
                event_id: 42,
                recipient: "verified-admin".into(),
                kind: kind.into(),
                health: health.into(),
                device: "Server with spaces".into(),
                message: "-c <b>text</b> \n$(literal) {0}".into(),
            };
            assert_eq!(DesktopLevel::for_event(kind, health), expected);
            let command = desktop_event_command(&job, DesktopFeatures { levels: true }).unwrap();
            let args: Vec<_> = command
                .as_std()
                .get_args()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(args[1], expected.argument());
            assert_eq!(
                &args[9..],
                &[
                    "Server with spaces",
                    " -c <b>text</b>  $(literal) {0}",
                    "42"
                ]
            );
            let old = desktop_event_command(&job, DesktopFeatures { levels: false }).unwrap();
            assert!(!old.as_std().get_args().any(|v| v == "-l"));
        }
        assert_eq!(desktop_text("a\0b\r\nc", 20), "a b  c");
        assert_eq!(desktop_text("abcdef", 3), "abc");
    }
    #[test]
    fn roles_fail_closed() {
        assert_eq!(role_for_groups(&[]), None);
        assert_eq!(role_for_groups(&["users".into()]), None);
        assert_eq!(
            role_for_groups(&["hardware-monitor-viewers".into()]),
            Some(Role::Viewer)
        );
        assert_eq!(
            role_for_groups(&["administrators".into()]),
            Some(Role::Administrator)
        );
    }
    #[tokio::test]
    async fn missing_cookie_and_missing_native_helper_deny_access() {
        assert!(authenticate(&AuthContext::default()).await.is_err());
        let c = AuthContext {
            environment: BTreeMap::from([
                ("HTTP_COOKIE".into(), "id=fake".into()),
                ("REMOTE_ADDR".into(), "127.0.0.1".into()),
                ("SERVER_ADDR".into(), "127.0.0.1".into()),
            ]),
            diagnostic: false,
        };
        assert!(authenticate(&c).await.is_err());
    }
    #[test]
    fn diagnostic_codes_never_echo_environment_values() {
        let mut context = AuthContext::default();
        assert_eq!(
            error_code(&context.validate().unwrap_err()),
            "cgi_cookie_missing_or_invalid"
        );
        context
            .environment
            .insert("HTTP_COOKIE".into(), "id=private-test-marker".into());
        assert_eq!(
            error_code(&context.validate().unwrap_err()),
            "cgi_client_address_missing_or_invalid"
        );
        context
            .environment
            .insert("REMOTE_ADDR".into(), "127.0.0.1".into());
        assert_eq!(
            error_code(&context.validate().unwrap_err()),
            "cgi_server_address_missing_or_invalid"
        );
        context
            .environment
            .insert("SERVER_ADDR".into(), "127.0.0.1".into());
        assert!(context.validate().is_ok());
        context
            .environment
            .insert("LD_PRELOAD".into(), "private-test-marker".into());
        assert_eq!(
            error_code(&context.validate().unwrap_err()),
            "cgi_context_invalid"
        );
        assert!(!context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("private-test-marker"));
    }
}
