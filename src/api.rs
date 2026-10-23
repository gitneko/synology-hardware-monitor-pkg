//! Server-side device administration. No caller-supplied identity is accepted.
use crate::{
    collector::Redfish,
    dsm::{self, AuthContext, BoundaryError, Role},
    model::Device,
    store::Store,
    vault::Vault,
};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

pub const MAX_REQUEST: usize = crate::archive::MAX_FILE + 16384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default)]
    pub locale: crate::i18n::Language,
    pub auth: AuthContext,
    #[serde(default)]
    pub operation: Operation,
    #[serde(default)]
    pub csrf: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    #[default]
    Dashboard,
    Save {
        device: DeviceInput,
    },
    Test {
        device: DeviceInput,
    },
    DesktopTest {
        #[serde(default)]
        level: crate::notification::DesktopLevel,
    },
    NotificationSave {
        settings: crate::notification::Input,
    },
    MailSave {
        mail: crate::mail::Input,
    },
    MailPreview {
        mail: crate::mail::Input,
    },
    MailTest {
        mail: crate::mail::Input,
    },
    MailReplayPreview {
        event_id: i64,
        recipient: String,
    },
    MailReplaySend {
        id: String,
    },
    MailReplayHistory {
        event_id: i64,
    },
    AlarmAcknowledge {
        id: String,
        revision: i64,
        key: String,
        token: String,
        acknowledged: bool,
        reason: String,
    },
    AlarmReset {
        id: String,
        revision: i64,
        key: String,
        token: String,
        #[serde(default)]
        confirm: bool,
    },
    EventsExport {
        filter: crate::history::Filter,
    },
    EventsClear {
        confirm: bool,
    },
    BackupExport {
        password: String,
    },
    BackupInspect {
        file: String,
        password: String,
    },
    BackupRestore {
        file: String,
        password: String,
        confirm: bool,
        expected_audit: i64,
    },
    Delete {
        id: String,
        revision: i64,
    },
}

impl Drop for Operation {
    fn drop(&mut self) {
        match self {
            Self::BackupExport { password }
            | Self::BackupInspect { password, .. }
            | Self::BackupRestore { password, .. } => password.zeroize(),
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteBody {
    pub operation: Operation,
    pub csrf: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    pub id: Option<String>,
    pub revision: Option<i64>,
    pub name: String,
    pub endpoint: String,
    pub username: String,
    pub password: Option<String>,
    pub interval_seconds: u64,
    pub repeat_seconds: Option<i64>,
    pub alerts_enabled: bool,
    pub enabled: bool,
    #[serde(default)]
    pub tls_profile: crate::model::TlsProfile,
    pub trust_mode: TrustMode,
    pub certificate_pem: Option<String>,
}
impl Drop for DeviceInput {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    Pinned,
    Keep,
    System,
    Custom,
}

pub struct Api {
    pub store: Arc<Mutex<Store>>,
    pub vault: Arc<Vault>,
    probes: tokio::sync::Semaphore,
    mail_gate: tokio::sync::Mutex<()>,
    archives: tokio::sync::Semaphore,
    replay_turn: std::sync::atomic::AtomicBool,
}
impl Api {
    pub fn new(store: Arc<Mutex<Store>>, vault: Arc<Vault>) -> Self {
        Self {
            store,
            vault,
            probes: tokio::sync::Semaphore::new(2),
            archives: tokio::sync::Semaphore::new(1),
            replay_turn: std::sync::atomic::AtomicBool::new(true),
            mail_gate: tokio::sync::Mutex::new(()),
        }
    }
    pub async fn handle(&self, request: Request) -> Value {
        let language = request.locale;
        let result = async {
            let (actor, role) = dsm::authenticate(&request.auth).await?;
            self.authorized(&request, &actor, role).await
        }
        .await;
        match result {
            Ok(mut value) => {
                for field in ["message", "error"] {
                    if let Some(text) = value[field].as_str() {
                        value[field] = json!(crate::i18n::text(text, language));
                    }
                }
                value
            }
            Err(error) => {
                json!({"ok":false,"code":dsm::error_code(&error),"error":crate::i18n::text(message(dsm::error_code(&error)),language)})
            }
        }
    }

    async fn authorized(&self, request: &Request, actor: &str, role: Role) -> Result<Value> {
        if matches!(request.operation, Operation::Dashboard) {
            if request.auth.diagnostic {
                return Ok(json!({"ok":true,"code":"authenticated"}));
            }
            let store = self.store.lock().unwrap();
            let mut data = store.dashboard()?;
            for item in data["devices"].as_array_mut().unwrap() {
                let device = item["device"].as_object_mut().unwrap();
                let custom = device.get("ca_file").is_some_and(|v| !v.is_null())
                    || device.get("ca_pem").is_some_and(|v| !v.is_null());
                device.remove("ca_file");
                device.remove("ca_pem");
                let fingerprint = device.remove("pinned_certificate_pem").and_then(|v| {
                    v.as_str()
                        .and_then(|pem| crate::legacy_tls::fingerprint(pem).ok())
                });
                device.insert("certificate_fingerprint".into(), json!(fingerprint));
                device.insert(
                    "custom_trust".into(),
                    json!(custom || device["certificate_fingerprint"].is_string()),
                );
                if role != Role::Administrator {
                    device.remove("username");
                }
            }
            crate::i18n::dashboard(&mut data, request.locale);
            data["user"] = json!({"name":actor,"role":role});
            let (mut policy, policy_revision) = store.notification_settings()?;
            if policy_revision == 0 {
                policy.language = request.locale;
            }
            data["notifications"] = json!({"automatic_delivery":store.mail_enabled()||policy.desktop_enabled,"mail_enabled":store.mail_enabled(),"desktop_enabled":policy.desktop_enabled,"desktop_self_test_available":dsm::desktop_test_available()});
            if role == Role::Administrator {
                data["notification_settings"] =
                    json!({"settings":policy,"revision":policy_revision});
                data["csrf"] = json!(mint_csrf(&self.vault, actor, &request.auth, crate::now())?);
                data["audit"] = store.audit_entries()?;
                for row in data["audit"].as_array_mut().unwrap() {
                    row["outcome"] = json!(crate::i18n::outcome(
                        row["outcome"].as_str().unwrap_or(""),
                        request.locale
                    ));
                }
                data["mail"] = match store.mail_settings()? {
                    Some((settings, secret, revision)) => {
                        json!({"settings":settings,"revision":revision,"has_password":!secret.is_empty()})
                    }
                    None => {
                        json!({"settings":crate::mail::Settings::default_for(request.locale),"revision":0,"has_password":false})
                    }
                };
            }
            return Ok(json!({"ok":true,"data":data}));
        }
        anyhow::ensure!(
            !request.auth.diagnostic,
            BoundaryError("write_operation_invalid")
        );
        anyhow::ensure!(
            role == Role::Administrator,
            BoundaryError("write_administrator_required")
        );
        dsm::validate_write_context(&request.auth)?;
        check_csrf(
            &self.vault,
            actor,
            &request.auth,
            request.csrf.as_deref().unwrap_or(""),
            crate::now(),
        )?;
        // Serialize config/device cancellation with SMTP submission. An already
        // submitted message cannot be recalled; no next recipient starts after a change.
        let _mail_guard = if matches!(request.operation, Operation::MailTest { .. }) {
            tokio::time::timeout(std::time::Duration::from_secs(3), self.mail_gate.lock())
                .await
                .context(BoundaryError("mail_busy"))?
        } else {
            self.mail_gate.lock().await
        };
        match &request.operation {
            Operation::MailReplayPreview {
                event_id,
                recipient,
            } => {
                let preview = self.store.lock().unwrap().preview_mail_replay(
                    *event_id,
                    recipient,
                    actor,
                    crate::now(),
                )?;
                Ok(json!({"ok":true,"preview":preview}))
            }
            Operation::MailReplaySend { id } => {
                let job =
                    self.store
                        .lock()
                        .unwrap()
                        .enqueue_mail_replay(id, actor, crate::now())?;
                Ok(json!({"ok":true,"job":job}))
            }
            Operation::MailReplayHistory { event_id } => {
                let history = self.store.lock().unwrap().mail_replay_history(*event_id)?;
                Ok(json!({"ok":true,"history":history}))
            }
            Operation::AlarmAcknowledge {
                id,
                revision,
                key,
                token,
                acknowledged,
                reason,
            } => {
                self.store.lock().unwrap().acknowledge_alarm(
                    id,
                    *revision,
                    key,
                    token,
                    *acknowledged,
                    reason,
                    actor,
                    crate::now(),
                )?;
                Ok(json!({"ok":true}))
            }
            Operation::AlarmReset {
                id,
                revision,
                key,
                token,
                confirm,
            } => {
                anyhow::ensure!(*confirm, BoundaryError("maintenance_confirmation_required"));
                self.store.lock().unwrap().reset_alarm(
                    id,
                    *revision,
                    key,
                    token,
                    actor,
                    crate::now(),
                )?;
                Ok(json!({"ok":true}))
            }
            Operation::EventsExport { filter } => {
                let store = self.store.lock().unwrap();
                let (csv, count) = store.events_csv_localized(filter, request.locale)?;
                store.audit(
                    actor,
                    "events.export",
                    "events",
                    &format!("{count} Ereignisse exportiert"),
                )?;
                Ok(json!({"ok":true,"file":csv,"count":count}))
            }
            Operation::EventsClear { confirm } => {
                anyhow::ensure!(*confirm, BoundaryError("maintenance_confirmation_required"));
                let count = self.store.lock().unwrap().clear_events(actor)?;
                Ok(json!({"ok":true,"count":count}))
            }
            Operation::BackupExport { password } => {
                let _permit = self
                    .archives
                    .try_acquire()
                    .context(BoundaryError("backup_busy"))?;
                let store = self.store.clone();
                let vault = self.vault.clone();
                let password = zeroize::Zeroizing::new(password.clone());
                let file = tokio::task::spawn_blocking(move || -> Result<String> {
                    let archive = store.lock().unwrap().make_archive(&vault)?;
                    crate::archive::encrypt(&archive, &password)
                })
                .await??;
                self.store
                    .lock()
                    .unwrap()
                    .audit(actor, "backup.export", "application", "ok")?;
                Ok(json!({"ok":true,"file":file}))
            }
            Operation::BackupInspect { file, password }
            | Operation::BackupRestore { file, password, .. } => {
                let _permit = self
                    .archives
                    .try_acquire()
                    .context(BoundaryError("backup_busy"))?;
                let file = file.clone();
                let password = zeroize::Zeroizing::new(password.clone());
                let archive =
                    tokio::task::spawn_blocking(move || crate::archive::decrypt(&file, &password))
                        .await??;
                let mut store = self.store.lock().unwrap();
                if let Operation::BackupRestore {
                    confirm,
                    expected_audit,
                    ..
                } = &request.operation
                {
                    anyhow::ensure!(*confirm, BoundaryError("maintenance_confirmation_required"));
                    store
                        .restore_archive(&archive, &self.vault, actor, *expected_audit)
                        .context(BoundaryError("backup_restore_failed"))?;
                    Ok(
                        json!({"ok":true,"message":"Wiederhergestellt. Geräteüberwachung und automatische Benachrichtigungen sind pausiert."}),
                    )
                } else {
                    Ok(
                        json!({"ok":true,"summary":archive.summary(),"expected_audit":store.audit_cursor()?}),
                    )
                }
            }
            Operation::NotificationSave { settings } => {
                self.store
                    .lock()
                    .unwrap()
                    .save_notifications(settings, actor)?;
                Ok(json!({"ok":true,"revision":settings.revision+1}))
            }
            Operation::MailPreview { mail } => {
                mail.settings.validate()?;
                let (subject, body) = mail.settings.preview(&crate::mail::Event::sample())?;
                Ok(json!({"ok":true,"preview":{"subject":subject,"body":body}}))
            }
            Operation::MailSave { mail } => {
                let mut store = self.store.lock().unwrap();
                let secret = prepare_mail(&store, &self.vault, mail)?;
                store.save_mail(&mail.settings, &secret, mail.revision, actor)?;
                Ok(json!({"ok":true,"revision":mail.revision+1}))
            }
            Operation::MailTest { mail } => {
                let (secret, audit_id) = {
                    let store = self.store.lock().unwrap();
                    let secret = prepare_mail(&store, &self.vault, mail)?;
                    (secret, store.reserve_mail_test(actor, crate::now())?)
                };
                let password = if secret.is_empty() {
                    None
                } else {
                    Some(self.vault.unseal("settings:smtp", &secret)?)
                };
                let event = crate::mail::Event::sample();
                let id = format!(
                    "<hm-test-{:032x}@hardwaremonitor.invalid>",
                    rand::random::<u128>()
                );
                let password = password
                    .as_ref()
                    .map(|p| std::str::from_utf8(p))
                    .transpose()?;
                let result = crate::mail::submit(
                    &mail.settings,
                    password,
                    &event,
                    &mail.settings.recipients[0],
                    &id,
                )
                .await;
                self.store
                    .lock()
                    .unwrap()
                    .finish_mail_test(audit_id, result.err().unwrap_or("submitted"))?;
                result.map_err(|code| anyhow::anyhow!(BoundaryError(code)))?;
                Ok(
                    json!({"ok":true,"message":"Die Testmail wurde vom SMTP-Server angenommen. Bitte das Postfach der ersten Empfängeradresse prüfen; dies bestätigt noch keine Postfachzustellung."}),
                )
            }
            Operation::Save { device: input } => {
                let mut store = self.store.lock().unwrap();
                let (device, secret) = prepare(&store, &self.vault, input)?;
                store.save_admin(&device, &secret, input.revision, actor)?;
                Ok(json!({"ok":true,"id":device.id}))
            }
            Operation::DesktopTest { level } => {
                let audit_id = self
                    .store
                    .lock()
                    .unwrap()
                    .reserve_desktop_test(actor, crate::now())?;
                let result = dsm::desktop_test_localized(actor, *level, request.locale).await;
                let outcome = result
                    .as_ref()
                    .map(|_| "submitted")
                    .unwrap_or_else(|e| dsm::error_code(e));
                self.store
                    .lock()
                    .unwrap()
                    .finish_desktop_test(audit_id, outcome)?;
                let applied = result?;
                Ok(
                    json!({"ok":true,"submitted":true,"level_requested":level,"level_applied":applied,"message":format!("{}: {} · Test-0017{}",crate::i18n::text("Desktop-Test an DSM übergeben",request.locale),applied.argument(),if applied!=*level {crate::i18n::text(" Dieser DSM-Helfer unterstützt keinen -l-Parameter; die Meldung wurde als Info übergeben.",request.locale)}else{String::new()})}),
                )
            }
            Operation::Delete { id, revision } => {
                self.store
                    .lock()
                    .unwrap()
                    .delete_admin(id, *revision, actor)?;
                Ok(json!({"ok":true}))
            }
            Operation::Test { device: input } => {
                let _permit = self
                    .probes
                    .try_acquire()
                    .map_err(|_| anyhow::anyhow!(BoundaryError("connection_busy")))?;
                let (device, secret) = {
                    let store = self.store.lock().unwrap();
                    prepare(&store, &self.vault, input)?
                };
                let password = self.vault.unseal(&device.id, &secret)?;
                let result = Redfish::new(&device)
                    .context(BoundaryError("device_certificate_invalid"))?
                    .probe(&device.username, std::str::from_utf8(&password)?)
                    .await;
                let outcome = result
                    .as_ref()
                    .map(|_| "ok")
                    .unwrap_or_else(|e| dsm::error_code(e));
                self.store.lock().unwrap().audit(
                    actor,
                    "device.test",
                    if input.id.is_some() {
                        &device.id
                    } else {
                        "unsaved"
                    },
                    outcome,
                )?;
                Ok(match result {
                    Ok(data) => json!({"ok":true,"connection":data}),
                    Err(error) => {
                        json!({"ok":false,"code":dsm::error_code(&error),"error":crate::i18n::text(message(dsm::error_code(&error)),request.locale)})
                    }
                })
            }
            Operation::Dashboard => unreachable!(),
        }
    }

    pub async fn deliver_legacy(&self) -> Result<()> {
        let _guard = self.mail_gate.lock().await;
        let pending = self.store.lock().unwrap().pending(crate::now())?;
        for (id, kind, health, message) in pending {
            let success = dsm::notify(&kind, &health, &message).await.is_ok();
            self.store
                .lock()
                .unwrap()
                .delivery(id, success, crate::now())?;
        }
        Ok(())
    }

    pub async fn deliver_one_mail(&self) -> Result<()> {
        let _guard = self.mail_gate.lock().await;
        let desktop = self.store.lock().unwrap().pending_desktop(crate::now())?;
        if let Some(job) = desktop {
            let result = dsm::desktop_event(&job).await;
            self.store.lock().unwrap().finish_desktop(
                &job,
                result.as_ref().err().map(dsm::error_code),
                crate::now(),
            )?;
        }
        let automatic = self.store.lock().unwrap().pending_mail(crate::now())?;
        let manual = self
            .store
            .lock()
            .unwrap()
            .pending_mail_replay(crate::now())?;
        // Alternate when both queues have work so manual parser testing cannot
        // starve automatic alarms (or be starved by their recipient backlog).
        let manual_first = if automatic.is_some() && manual.is_some() {
            self.replay_turn
                .fetch_xor(true, std::sync::atomic::Ordering::Relaxed)
        } else {
            automatic.is_none()
        };
        if let Some(job) = manual.filter(|_| manual_first) {
            let password = if job.secret.is_empty() {
                None
            } else {
                Some(self.vault.unseal("settings:smtp", &job.secret)?)
            };
            let password = password
                .as_ref()
                .map(|p| std::str::from_utf8(p))
                .transpose()?;
            let result = crate::mail::submit_rendered(&job.settings, password, &job).await;
            self.store
                .lock()
                .unwrap()
                .finish_mail_replay(&job, result.err(), crate::now())?;
            return Ok(());
        }
        let Some(job) = automatic else {
            return Ok(());
        };
        let password = if job.secret.is_empty() {
            None
        } else {
            Some(self.vault.unseal("settings:smtp", &job.secret)?)
        };
        let password = password
            .as_ref()
            .map(|p| std::str::from_utf8(p))
            .transpose()?;
        let result = crate::mail::submit(
            &job.settings,
            password,
            &job.event,
            &job.recipient,
            &job.message_id,
        )
        .await;
        self.store
            .lock()
            .unwrap()
            .finish_mail(&job, result.err(), crate::now())?;
        Ok(())
    }
}

fn prepare_mail(store: &Store, vault: &Vault, input: &crate::mail::Input) -> Result<Vec<u8>> {
    input.settings.validate()?;
    let existing = store.mail_settings()?;
    anyhow::ensure!(
        existing.as_ref().map(|x| x.2).unwrap_or(0) == input.revision,
        BoundaryError("mail_conflict")
    );
    if input.settings.username.is_empty() {
        return Ok(vec![]);
    }
    if let Some(password) = &input.password {
        anyhow::ensure!(
            !password.is_empty() && password.len() <= 4096,
            BoundaryError("mail_password_required")
        );
        return vault.seal("settings:smtp", password.as_bytes());
    }
    let Some((old, secret, _)) = existing else {
        anyhow::bail!(BoundaryError("mail_password_required"))
    };
    anyhow::ensure!(
        input.settings.same_auth_target(&old) && !secret.is_empty(),
        BoundaryError("mail_password_required")
    );
    Ok(secret)
}

fn prepare(store: &Store, vault: &Vault, input: &DeviceInput) -> Result<(Device, Vec<u8>)> {
    let existing = if let Some(id) = &input.id {
        Some(
            store
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!(BoundaryError("device_conflict")))?,
        )
    } else {
        None
    };
    anyhow::ensure!(
        existing.as_ref().map(|x| x.2) == input.revision,
        BoundaryError("device_conflict")
    );
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let id = input
        .id
        .clone()
        .unwrap_or_else(|| format!("d-{}", hex(&random)));
    let parsed =
        url::Url::parse(&input.endpoint).context(BoundaryError("device_config_invalid"))?;
    let mut device = Device {
        id,
        name: input.name.trim().into(),
        endpoint: parsed.to_string(),
        username: input.username.clone(),
        interval_seconds: input.interval_seconds,
        repeat_seconds: input.repeat_seconds,
        alerts_enabled: input.alerts_enabled,
        enabled: input.enabled,
        ca_file: None,
        ca_pem: None,
        tls_profile: input.tls_profile,
        pinned_certificate_pem: None,
    };
    match input.trust_mode {
        TrustMode::Keep => {
            if let Some((old, _, _)) = &existing {
                device.ca_file = old.ca_file.clone();
                device.ca_pem = old.ca_pem.clone();
                if old.pinned_certificate_pem.is_some() {
                    anyhow::ensure!(
                        old.endpoint == device.endpoint && old.tls_profile == device.tls_profile,
                        BoundaryError("device_pin_reimport_required")
                    );
                }
                device.pinned_certificate_pem = old.pinned_certificate_pem.clone();
            }
        }
        TrustMode::Pinned => {
            anyhow::ensure!(
                input.tls_profile == crate::model::TlsProfile::Idrac7,
                BoundaryError("device_certificate_invalid")
            );
            let pem = input
                .certificate_pem
                .as_ref()
                .context(BoundaryError("device_certificate_invalid"))?;
            crate::legacy_tls::certificate(pem)
                .context(BoundaryError("device_certificate_invalid"))?;
            device.pinned_certificate_pem = Some(pem.clone());
        }
        TrustMode::System => {}
        TrustMode::Custom => {
            let pem = input
                .certificate_pem
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(BoundaryError("device_certificate_invalid")))?;
            crate::model::validate_certificates(pem)
                .context(BoundaryError("device_certificate_invalid"))?;
            device.ca_pem = Some(pem.clone());
        }
    }
    device
        .validate()
        .context(BoundaryError("device_config_invalid"))?;
    let _validated_client =
        Redfish::new(&device).context(BoundaryError("device_certificate_invalid"))?;
    let secret = if let Some(password) = &input.password {
        anyhow::ensure!(
            !password.is_empty() && password.len() <= 4096,
            BoundaryError("device_password_required")
        );
        vault.seal(&device.id, password.as_bytes())?
    } else {
        let (old, secret, _) = existing
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(BoundaryError("device_password_required")))?;
        anyhow::ensure!(
            old.endpoint == device.endpoint && old.username == device.username,
            BoundaryError("device_password_required")
        );
        secret.clone()
    };
    Ok((device, secret))
}

fn binding(actor: &str, auth: &AuthContext) -> String {
    format!(
        "csrf:{actor}:{:x}",
        Sha256::digest(
            auth.environment
                .get("HTTP_COOKIE")
                .map(String::as_bytes)
                .unwrap_or_default()
        )
    )
}
fn mint_csrf(vault: &Vault, actor: &str, auth: &AuthContext, now: i64) -> Result<String> {
    Ok(hex(&vault.seal(&binding(actor, auth), &now.to_be_bytes())?))
}
fn check_csrf(vault: &Vault, actor: &str, auth: &AuthContext, token: &str, now: i64) -> Result<()> {
    let check = || -> Result<()> {
        let raw = unhex(token)?;
        let plain = vault.unseal(&binding(actor, auth), &raw)?;
        let issued = i64::from_be_bytes(plain.as_slice().try_into()?);
        anyhow::ensure!((0..=900).contains(&(now - issued)), "expired token");
        Ok(())
    };
    check().context(BoundaryError("write_csrf_invalid"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(value.len() == 72 && value.is_ascii(), "invalid token");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| Ok(u8::from_str_radix(std::str::from_utf8(c)?, 16)?))
        .collect()
}
pub fn message(code: &str) -> &'static str {
    match code {
        "connection_timeout"=>"Die Redfish-Datenbereiche haben nicht rechtzeitig geantwortet. Netzwerk und Auslastung des Controllers prüfen.",
        "backup_password_invalid"=>"Das Sicherungspasswort muss mindestens 12 Zeichen und höchstens 1024 UTF-8-Bytes lang sein.",
        "backup_busy"=>"Eine Sicherungsaktion läuft bereits. Bitte kurz warten.",
        "backup_invalid"=>"Sicherungsdatei oder Passwort ungültig. Es wurden keine Daten geändert.",
        "backup_too_large"=>"Die Sicherung überschreitet das derzeitige Limit von 16 MiB Nutzdaten / 24 MiB Datei.",
        "backup_conflict"=>"Seit der Prüfung wurden Einstellungen geändert. Bitte die Sicherung erneut prüfen.",
        "backup_restore_failed"=>"Wiederherstellung abgewiesen. Datei, Datenformat und zwischenzeitliche Änderungen prüfen; der bisherige Datenbestand bleibt erhalten.",
        "maintenance_confirmation_required"=>"Bitte die Aktion ausdrücklich bestätigen.",
        "history_filter_invalid"=>"Die Ereignisauswahl ist ungültig.",
        "history_too_large"=>"Der Export überschreitet das derzeitige Limit von 50.000 gespeicherten Ereignissen oder 16 MiB CSV.",
        "notification_conflict"=>"Benachrichtigungseinstellungen wurden geändert. Bitte neu laden.",
        "mail_time_invalid"=>"Zeitzone oder Zeitformat ist ungültig. Bitte eine IANA-Zone und gültige %-Formatzeichen verwenden.",
        "mail_busy"=>"Es läuft bereits ein E-Mail-Versand. Bitte in einigen Sekunden erneut versuchen.",
        "mail_config_invalid"=>"SMTP-Angaben prüfen: Servername ohne URL, gültige Adressen, Port, TLS und Vorlagen sind erforderlich.",
        "mail_template_invalid"=>"Die Vorlage enthält einen unbekannten oder unvollständigen Platzhalter.",
        "mail_password_required"=>"SMTP-Passwort erforderlich. Bei neuem Server, Port, TLS-Modus oder Benutzer bitte erneut eingeben.",
        "mail_conflict"=>"Die E-Mail-Einstellungen wurden geändert. Bitte neu laden.",
        "mail_replay_not_configured"=>"Bitte zuerst gültige SMTP-Einstellungen und Empfänger speichern.",
        "mail_replay_recipient_invalid"=>"Bitte eine gespeicherte Empfängeradresse auswählen.",
        "mail_replay_event_missing"=>"Das ursprüngliche Ereignis ist nicht mehr vorhanden. Bitte aktualisieren.",
        "mail_replay_conflict"=>"Die Versandvorschau ist abgelaufen oder wurde geändert. Bitte eine neue Vorschau erstellen.",
        "mail_replay_busy"=>"Es sind bereits viele manuelle Versandaufträge offen. Bitte offene Sendungen abwarten.",
        "mail_test_rate_limited"=>"Bitte mindestens 60 Sekunden bis zur nächsten Testmail warten.",
        "mail_timeout"=>"Keine rechtzeitige SMTP-Bestätigung. Die Mail könnte bereits angenommen worden sein; vor Wiederholung das Postfach prüfen.",
        "mail_rejected"=>"Der SMTP-Server hat Anmeldung oder Nachricht dauerhaft abgewiesen. Zugang, Absender und Empfänger prüfen.",
        "mail_connection_failed"=>"SMTP-Verbindung fehlgeschlagen. Server, Port, TLS-Zertifikat und Zugang prüfen.",
        "desktop_test_rate_limited"=>"Bitte mindestens 30 Sekunden bis zum nächsten Desktop-Test warten.",
        "desktop_test_unavailable"=>"Der DSM-Desktop-Aufruf ist unter der Paketidentität nicht verfügbar.",
        "desktop_test_rejected"=>"DSM hat den Desktop-Test abgewiesen. Es wurden keine Paketberechtigungen erweitert.",
        "desktop_test_timeout"=>"DSM hat den Desktop-Test nicht rechtzeitig bestätigt. Bitte vor einem erneuten Versuch die Benachrichtigungen prüfen.",
        "alarm_conflict"=>"Der Alarm wurde zwischenzeitlich geändert oder beendet. Bitte neu laden.",
        "alarm_not_acknowledgeable"=>"Bitte einen eigenständigen Hardwarealarm oder seine konkrete Ursache auswählen.",
        "alarm_reason_invalid"=>"Bitte eine Begründung mit höchstens 1000 UTF-8-Bytes ohne Steuerzeichen angeben.",
        "device_conflict"=>"Das Gerät wurde zwischenzeitlich geändert oder entfernt. Bitte neu laden.",
        "device_password_required"=>"Bitte ein Passwort angeben. Bei Wechsel von Adresse oder Benutzer ist ein neues Passwort erforderlich.",
        "device_certificate_invalid"=>"Das Zertifikat ist ungültig. Bitte nur PEM-Zertifikate ohne privaten Schlüssel importieren.",
        "device_config_invalid"=>"Geräteangaben prüfen: HTTPS-Adresse ohne Pfad, Name, Benutzer und gültige Intervalle sind erforderlich.",
        "write_csrf_invalid"=>"Die Bearbeitungssitzung ist abgelaufen. Bitte aktualisieren und erneut versuchen.",
        "write_administrator_required"=>"Nur DSM-Administratoren dürfen Geräte verwalten.",
        "write_https_required"=>"Geräteverwaltung erfordert eine HTTPS-Verbindung zu DSM.",
        "write_origin_invalid"=>"Die Herkunft der Anfrage wurde abgewiesen. Bitte die Anwendung direkt in DSM öffnen.",
        "connection_tls_or_network"=>"Verbindung fehlgeschlagen. Adresse, Netzwerk und Zertifikatsvertrauen prüfen; die TLS-Prüfung bleibt aktiv.",
        "device_pin_reimport_required"=>"Bei geänderter Adresse oder geändertem Verbindungsmodus das Serverzertifikat erneut importieren.",
        "connection_certificate_mismatch"=>"Das Serverzertifikat stimmt nicht mit dem importierten Zertifikat überein. An diese Verbindung wurden keine Zugangsdaten gesendet.",
        "connection_certificate_expired"=>"Das Serverzertifikat ist abgelaufen oder noch nicht gültig. An diese Verbindung wurden keine Zugangsdaten gesendet.",
        "connection_tls_incompatible"=>"Die TLS-Verbindung konnte nicht aufgebaut werden. TLS-Version und Verschlüsselungsverfahren des Controllers prüfen.",
        "connection_credentials_rejected"=>"Das Gerät hat die Zugangsdaten abgewiesen.",
        "connection_permission_denied"=>"Der Gerätebenutzer darf den Redfish-Dienst nicht lesen.",
        "connection_not_redfish"=>"Unter dieser Adresse wurde kein gültiger Redfish-Dienst gefunden.",
        "connection_response_invalid"=>"Das Gerät hat eine ungültige oder nicht unterstützte Redfish-Antwort geliefert.",
        "connection_response_too_large"=>"Die Redfish-Antwort überschreitet das Größenlimit des Verbindungstests.",
        "connection_http_error"=>"Der Redfish-Dienst hat eine HTTP-Fehlermeldung zurückgegeben.",
        "connection_busy"=>"Es laufen bereits Verbindungsprüfungen. Bitte kurz warten.",
        _=>"Die Anfrage konnte nicht ausgeführt werden. Bitte Anmeldung und Angaben prüfen.",
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn mail_replay_requires_native_admin_csrf_saved_recipient_and_owner_and_is_idempotent() {
        let (_dir, api) = instance();
        {
            let mut s = api.store.lock().unwrap();
            let settings = crate::mail::Settings {
                host: "localhost".into(),
                from_address: "sender@example.invalid".into(),
                recipients: vec!["alarm@example.invalid".into()],
                ..Default::default()
            };
            s.save_mail(&settings, b"", 0, "admin-test").unwrap();
            s.0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,'removed','fan','recovery','\"ok\"','Historical recovery',100)",[]).unwrap();
        }
        for operation in [
            Operation::MailReplayPreview {
                event_id: 1,
                recipient: "alarm@example.invalid".into(),
            },
            Operation::MailReplaySend {
                id: "invalid".into(),
            },
            Operation::MailReplayHistory { event_id: 1 },
        ] {
            let mut req = request(&api, operation);
            assert_eq!(
                dsm::error_code(
                    &api.authorized(&req, "viewer-test", Role::Viewer)
                        .await
                        .unwrap_err()
                ),
                "write_administrator_required"
            );
            req.csrf = None;
            assert_eq!(
                dsm::error_code(
                    &api.authorized(&req, "admin-test", Role::Administrator)
                        .await
                        .unwrap_err()
                ),
                "write_csrf_invalid"
            );
        }
        let wrong = request(
            &api,
            Operation::MailReplayPreview {
                event_id: 1,
                recipient: "external@example.invalid".into(),
            },
        );
        assert_eq!(
            dsm::error_code(
                &api.authorized(&wrong, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "mail_replay_recipient_invalid"
        );
        let p = api
            .authorized(
                &request(
                    &api,
                    Operation::MailReplayPreview {
                        event_id: 1,
                        recipient: "alarm@example.invalid".into(),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let id = p["preview"]["id"].as_str().unwrap().to_owned();
        let send = request(&api, Operation::MailReplaySend { id });
        let submission = api.mail_gate.lock().await;
        let mut action = Box::pin(api.authorized(&send, "admin-test", Role::Administrator));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut action)
                .await
                .is_err()
        );
        drop(submission);
        assert_eq!(action.await.unwrap()["job"]["state"], "queued");
        assert_eq!(
            api.authorized(&send, "admin-test", Role::Administrator)
                .await
                .unwrap()["job"]["state"],
            "queued"
        );
        assert_eq!(
            api.store
                .lock()
                .unwrap()
                .mail_replay_history(1)
                .unwrap()
                .len(),
            1
        );
        let dashboard = api
            .authorized(
                &request(&api, Operation::Dashboard),
                "viewer-test",
                Role::Viewer,
            )
            .await
            .unwrap();
        assert!(dashboard["data"]["mail"].is_null());
    }
    #[tokio::test]
    async fn acknowledgement_waits_for_submission_gate_and_later_polls_keep_the_decision() {
        let (_dir, api) = instance();
        let (device, secret) = prepare(&api.store.lock().unwrap(), &api.vault, &input()).unwrap();
        let now = crate::now();
        let snapshot = crate::model::Snapshot {
            observations: vec![crate::model::Observation {
                key: "fan".into(),
                label: "Fan".into(),
                health: crate::model::Health::Critical,
                reading: None,
                unit: None,
            }],
            ..Default::default()
        };
        {
            let mut s = api.store.lock().unwrap();
            s.put(&device, &secret).unwrap();
            s.apply(&device, &snapshot, now).unwrap();
        }
        let token = api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]
            ["fan"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let req = request(
            &api,
            Operation::AlarmAcknowledge {
                id: device.id.clone(),
                revision: 1,
                key: "fan".into(),
                token,
                acknowledged: true,
                reason: "Known input fault".into(),
            },
        );
        let submission = api.mail_gate.lock().await;
        let mut action = Box::pin(api.authorized(&req, "admin-test", Role::Administrator));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut action)
                .await
                .is_err()
        );
        assert_eq!(
            api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]["fan"]
                ["status"],
            "critical"
        );
        drop(submission);
        action.await.unwrap();
        api.store
            .lock()
            .unwrap()
            .apply(&device, &snapshot, now + 1)
            .unwrap();
        assert_eq!(
            api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]["fan"]
                ["status"],
            "acknowledged"
        );
        api.deliver_one_mail().await.unwrap();
    }
    #[tokio::test]
    async fn acknowledgement_uses_native_actor_and_rejects_viewers_stale_tokens_and_invalid_csrf() {
        let (_dir, api) = instance();
        let (device, secret) = prepare(&api.store.lock().unwrap(), &api.vault, &input()).unwrap();
        let now = crate::now();
        {
            let mut s = api.store.lock().unwrap();
            s.put(&device, &secret).unwrap();
            s.apply(
                &device,
                &crate::model::Snapshot {
                    observations: vec![crate::model::Observation {
                        key: "fan".into(),
                        label: "Fan".into(),
                        health: crate::model::Health::Critical,
                        reading: None,
                        unit: None,
                    }],
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        }
        let token = api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]
            ["fan"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let operation = || Operation::AlarmAcknowledge {
            id: device.id.clone(),
            revision: 1,
            key: "fan".into(),
            token: token.clone(),
            acknowledged: true,
            reason: "Verified sensor fault".into(),
        };
        let req = request(&api, operation());
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Viewer)
                    .await
                    .unwrap_err()
            ),
            "write_administrator_required"
        );
        let mut invalid = request(&api, operation());
        invalid.csrf = None;
        assert_eq!(
            dsm::error_code(
                &api.authorized(&invalid, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "write_csrf_invalid"
        );
        api.authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert_eq!(
            api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]["fan"]
                ["acknowledgement"]["actor"],
            "admin-test"
        );
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "alarm_conflict"
        );
    }

    #[tokio::test]
    async fn alarm_reset_requires_admin_csrf_confirmation_and_the_captured_incident() {
        let (_dir, api) = instance();
        let (device, secret) = prepare(&api.store.lock().unwrap(), &api.vault, &input()).unwrap();
        {
            let mut store = api.store.lock().unwrap();
            store.put(&device, &secret).unwrap();
            store
                .apply(
                    &device,
                    &crate::model::Snapshot {
                        observations: vec![crate::model::Observation {
                            key: "psu".into(),
                            label: "PSU".into(),
                            health: crate::model::Health::Warning,
                            reading: None,
                            unit: None,
                        }],
                        ..Default::default()
                    },
                    crate::now(),
                )
                .unwrap();
        }
        let token = api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]
            ["psu"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let operation = |confirm| Operation::AlarmReset {
            id: device.id.clone(),
            revision: 1,
            key: "psu".into(),
            token: token.clone(),
            confirm,
        };
        let req = request(&api, operation(true));
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Viewer)
                    .await
                    .unwrap_err()
            ),
            "write_administrator_required"
        );
        let mut invalid = request(&api, operation(true));
        invalid.csrf = None;
        assert_eq!(
            dsm::error_code(
                &api.authorized(&invalid, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "write_csrf_invalid"
        );
        let invalid = request(&api, operation(false));
        assert_eq!(
            dsm::error_code(
                &api.authorized(&invalid, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "maintenance_confirmation_required"
        );
        let gate = api.mail_gate.lock().await;
        let mut action = Box::pin(api.authorized(&req, "admin-test", Role::Administrator));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut action)
                .await
                .is_err()
        );
        assert!(
            api.store.lock().unwrap().dashboard().unwrap()["devices"][0]["alarm_statuses"]
                .get("psu")
                .is_some()
        );
        drop(gate);
        action.await.unwrap();
        {
            let store = api.store.lock().unwrap();
            assert!(store.dashboard().unwrap()["devices"][0]["alarm_statuses"]
                .get("psu")
                .is_none());
            assert_eq!(store.event_entries(-1).unwrap().len(), 1);
            assert!(store
                .audit_entries()
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "alarm.reset" && e["actor"] == "admin-test"));
        }
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "alarm_conflict"
        );
    }

    #[test]
    fn connection_response_errors_have_specific_translated_messages() {
        for code in [
            "connection_response_invalid",
            "connection_response_too_large",
            "connection_http_error",
        ] {
            let message = super::message(code);
            assert_ne!(message, super::message("unknown_error"));
            assert_ne!(
                crate::i18n::text(message, crate::i18n::Language::En),
                message
            );
        }
    }
    use super::*;
    use std::collections::BTreeMap;
    fn auth() -> AuthContext {
        AuthContext {
            environment: BTreeMap::from([
                ("HTTP_COOKIE".into(), "id=synthetic-dsm-session".into()),
                ("REMOTE_ADDR".into(), "127.0.0.1".into()),
                ("SERVER_ADDR".into(), "127.0.0.1".into()),
                ("HTTP_HOST".into(), "nas.example:5001".into()),
                ("HTTP_ORIGIN".into(), "https://nas.example:5001".into()),
                ("HTTPS".into(), "on".into()),
                ("REQUEST_METHOD".into(), "POST".into()),
                ("HTTP_X_SYNO_TOKEN".into(), "synthetic-dsm-token".into()),
                ("HTTP_SEC_FETCH_SITE".into(), "same-origin".into()),
            ]),
            diagnostic: false,
        }
    }
    fn input() -> DeviceInput {
        DeviceInput {
            id: None,
            revision: None,
            name: "Synthetic server".into(),
            endpoint: "https://bmc.example/".into(),
            username: "monitor".into(),
            password: Some("private-device-password-marker".into()),
            interval_seconds: 60,
            repeat_seconds: None,
            alerts_enabled: true,
            enabled: true,
            tls_profile: Default::default(),
            trust_mode: TrustMode::System,
            certificate_pem: None,
        }
    }
    #[tokio::test]
    async fn pinned_trust_is_explicit_bound_to_origin_and_not_returned_as_pem() {
        let (_dir, api) = instance();
        let mut input = input();
        let original_password = input.password.clone().unwrap();
        input.tls_profile = crate::model::TlsProfile::Idrac7;
        assert!(prepare(&api.store.lock().unwrap(), &api.vault, &input).is_err());
        input.certificate_pem = Some(crate::legacy_tls::tests::pem());
        input.trust_mode = TrustMode::Custom;
        assert!(prepare(&api.store.lock().unwrap(), &api.vault, &input).is_err());
        input.trust_mode = TrustMode::Pinned;
        let (device, secret) = prepare(&api.store.lock().unwrap(), &api.vault, &input).unwrap();
        api.store
            .lock()
            .unwrap()
            .save_admin(&device, &secret, None, "admin-test")
            .unwrap();
        let (_, _, revision) = api.store.lock().unwrap().get(&device.id).unwrap().unwrap();
        input.id = Some(device.id.clone());
        input.revision = Some(revision);
        input.password = None;
        input.certificate_pem = None;
        input.trust_mode = TrustMode::Keep;
        let (kept, secret) = prepare(&api.store.lock().unwrap(), &api.vault, &input).unwrap();
        assert_eq!(kept.pinned_certificate_pem, device.pinned_certificate_pem);
        assert_eq!(
            &*api.vault.unseal(&device.id, &secret).unwrap(),
            original_password.as_bytes()
        );
        let dashboard = api
            .authorized(
                &request(&api, Operation::Dashboard),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let row = &dashboard["data"]["devices"][0]["device"];
        assert_eq!(row["tls_profile"], "idrac7");
        assert!(row.get("pinned_certificate_pem").is_none());
        assert!(row["certificate_fingerprint"]
            .as_str()
            .is_some_and(|s| s.len() == 95));
        assert!(!dashboard.to_string().contains("BEGIN CERTIFICATE"));
        input.endpoint = "https://other.example/".into();
        input.password = Some("replacement-secret".into());
        assert_eq!(
            dsm::error_code(
                &prepare(&api.store.lock().unwrap(), &api.vault, &input)
                    .err()
                    .unwrap()
            ),
            "device_pin_reimport_required"
        );
        input.endpoint = device.endpoint;
        input.tls_profile = crate::model::TlsProfile::Standard;
        assert!(prepare(&api.store.lock().unwrap(), &api.vault, &input).is_err());
        input.trust_mode = TrustMode::System;
        assert!(prepare(&api.store.lock().unwrap(), &api.vault, &input)
            .unwrap()
            .0
            .pinned_certificate_pem
            .is_none());
    }

    fn instance() -> (tempfile::TempDir, Api) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(&dir.path().join("master.key")).unwrap());
        let store = Arc::new(Mutex::new(Store::open(dir.path()).unwrap()));
        (dir, Api::new(store, vault))
    }
    fn request(api: &Api, operation: Operation) -> Request {
        let auth = auth();
        let csrf = Some(mint_csrf(&api.vault, "admin-test", &auth, crate::now()).unwrap());
        Request {
            locale: Default::default(),
            auth,
            operation,
            csrf,
        }
    }
    #[tokio::test]
    async fn english_dashboard_defaults_keep_authorization_and_existing_settings() {
        let (_dir, api) = instance();
        let mut req = request(&api, Operation::Dashboard);
        req.locale = crate::i18n::Language::En;
        let result = api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert_eq!(result["data"]["mail"]["settings"]["language"], "en");
        assert!(result["data"]["mail"]["settings"]["body_template"]
            .as_str()
            .unwrap()
            .contains("Device:"));
        assert_eq!(
            result["data"]["notification_settings"]["settings"]["language"],
            "en"
        );
        let viewer = api
            .authorized(&req, "viewer-test", Role::Viewer)
            .await
            .unwrap();
        assert!(viewer["data"].get("csrf").is_none() && viewer["data"].get("mail").is_none());
        let denied = api.handle(req).await;
        assert_eq!(denied["ok"], false);
        assert!(denied.get("data").is_none());
        assert_eq!(
            denied["error"],
            "The request could not be completed. Check your sign-in and input."
        );
    }
    #[tokio::test]
    async fn maintenance_requires_admin_and_csrf_and_exports_only_ciphertext() {
        let (_dir, api) = instance();
        for operation in [
            Operation::EventsClear { confirm: true },
            Operation::EventsExport {
                filter: Default::default(),
            },
            Operation::BackupExport {
                password: "long password for backup".into(),
            },
            Operation::BackupInspect {
                file: "invalid".into(),
                password: "long password for backup".into(),
            },
            Operation::BackupRestore {
                file: "invalid".into(),
                password: "long password for backup".into(),
                confirm: true,
                expected_audit: 0,
            },
        ] {
            let mut req = request(&api, operation);
            assert_eq!(
                dsm::error_code(
                    &api.authorized(&req, "viewer-test", Role::Viewer)
                        .await
                        .unwrap_err()
                ),
                "write_administrator_required"
            );
            req.csrf = None;
            assert_eq!(
                dsm::error_code(
                    &api.authorized(&req, "admin-test", Role::Administrator)
                        .await
                        .unwrap_err()
                ),
                "write_csrf_invalid"
            );
        }
        let export = api
            .authorized(
                &request(
                    &api,
                    Operation::BackupExport {
                        password: "long password for backup".into(),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(export["ok"], true);
        let archive =
            crate::archive::decrypt(export["file"].as_str().unwrap(), "long password for backup")
                .unwrap();
        assert_eq!(archive.summary()["devices"], 0);
        let csv = api
            .authorized(
                &request(
                    &api,
                    Operation::EventsExport {
                        filter: Default::default(),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(csv["count"], 0);
        assert!(csv["file"]
            .as_str()
            .unwrap()
            .starts_with("\"Ereignis-ID\";"));
        assert!(api
            .authorized(
                &request(&api, Operation::EventsClear { confirm: false }),
                "admin-test",
                Role::Administrator
            )
            .await
            .is_err());
        let cleared = api
            .authorized(
                &request(&api, Operation::EventsClear { confirm: true }),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(cleared["count"], 0);
    }
    #[test]
    fn csrf_is_bound_to_session_user_and_expiry() {
        let (_dir, api) = instance();
        let context = auth();
        let token = mint_csrf(&api.vault, "a", &context, 100).unwrap();
        assert!(check_csrf(&api.vault, "a", &context, &token, 1000).is_ok());
        assert!(check_csrf(&api.vault, "a", &context, &token, 1001).is_err());
        assert!(check_csrf(&api.vault, "a", &context, &token, 99).is_err());
        assert!(check_csrf(&api.vault, "b", &context, &token, 100).is_err());
        let mut changed = auth();
        changed
            .environment
            .insert("HTTP_COOKIE".into(), "id=another-session".into());
        assert!(check_csrf(&api.vault, "a", &changed, &token, 100).is_err());
        for invalid in ["", "garbage", &"0".repeat(72)] {
            assert!(check_csrf(&api.vault, "a", &context, invalid, 100).is_err());
        }
    }
    #[tokio::test]
    async fn role_origin_https_and_both_csrf_proofs_fail_closed() {
        let (_dir, api) = instance();
        let req = request(&api, Operation::Save { device: input() });
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Viewer)
                    .await
                    .unwrap_err()
            ),
            "write_administrator_required"
        );
        for (key, value) in [
            ("HTTP_ORIGIN", "https://attacker.example"),
            ("HTTP_ORIGIN", "null"),
            ("HTTP_ORIGIN", "https://nas.example:5001/unexpected"),
            ("HTTPS", "off"),
            ("HTTP_X_SYNO_TOKEN", ""),
            ("HTTP_SEC_FETCH_SITE", "cross-site"),
            ("REQUEST_METHOD", "GET"),
        ] {
            let mut req = request(&api, Operation::Save { device: input() });
            req.auth.environment.insert(key.into(), value.into());
            assert!(
                api.authorized(&req, "admin-test", Role::Administrator)
                    .await
                    .is_err(),
                "{key}"
            );
        }
        let mut req = request(&api, Operation::Save { device: input() });
        req.csrf = Some("fake".into());
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Administrator)
                    .await
                    .unwrap_err()
            ),
            "write_csrf_invalid"
        );
        assert!(api.store.lock().unwrap().devices().unwrap().is_empty());
        // A plausible cookie and the package token cannot replace the real DSM helper.
        assert_eq!(
            api.handle(request(&api, Operation::Save { device: input() }))
                .await["ok"],
            false
        );
    }
    #[tokio::test]
    async fn notification_settings_require_admin_and_capture_native_actor() {
        let (_dir, api) = instance();
        assert!(serde_json::from_value::<Operation>(json!({"action":"notification_save","settings":{"revision":0,"desktop_enabled":true,"selection":{},"desktop_recipient":"other"}})).is_err());
        let req = request(
            &api,
            Operation::NotificationSave {
                settings: crate::notification::Input {
                    language: Default::default(),
                    revision: 0,
                    desktop_enabled: true,
                    selection: crate::notification::Selection {
                        monitoring: Some(false),
                        ..Default::default()
                    },
                },
            },
        );
        assert!(api
            .authorized(&req, "admin-test", Role::Viewer)
            .await
            .is_err());
        assert!(api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap()["ok"]
            .as_bool()
            .unwrap());
        let (policy, revision) = api.store.lock().unwrap().notification_settings().unwrap();
        assert_eq!(revision, 1);
        assert_eq!(policy.desktop_recipient.as_deref(), Some("admin-test"));
        assert_eq!(policy.selection.monitoring, Some(false));
        assert!(api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn desktop_test_is_admin_only_has_no_recipient_input_and_is_rate_limited() {
        let (_dir, api) = instance();
        assert!(serde_json::from_value::<Operation>(
            json!({"action":"desktop_test","recipient":"other-user"})
        )
        .is_err());
        assert!(
            serde_json::from_value::<Operation>(json!({"action":"desktop_test","level":"-c"}))
                .is_err()
        );
        assert!(matches!(
            serde_json::from_value::<Operation>(json!({"action":"desktop_test"})).unwrap(),
            Operation::DesktopTest {
                level: crate::notification::DesktopLevel::Info
            }
        ));
        let req = request(
            &api,
            Operation::DesktopTest {
                level: Default::default(),
            },
        );
        assert_eq!(
            dsm::error_code(
                &api.authorized(&req, "admin-test", Role::Viewer)
                    .await
                    .unwrap_err()
            ),
            "write_administrator_required"
        );
        let store = api.store.lock().unwrap();
        let now = crate::now();
        let audit_id = store.reserve_desktop_test("admin-test", now).unwrap();
        assert!(store.reserve_desktop_test("admin-test", now + 29).is_err());
        assert!(store.reserve_desktop_test("other-admin", now).is_ok());
        store.finish_desktop_test(audit_id, "submitted").unwrap();
        assert!(store.reserve_desktop_test("admin-test", now + 30).is_ok());
    }
    #[tokio::test]
    async fn device_crud_secret_preservation_conflicts_and_obsolete_poll_results() {
        let (dir, api) = instance();
        let created = api
            .authorized(
                &request(&api, Operation::Save { device: input() }),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let (original, sealed, revision) = api.store.lock().unwrap().get(&id).unwrap().unwrap();
        assert_eq!(revision, 1);
        assert_eq!(
            api.vault.unseal(&id, &sealed).unwrap().as_slice(),
            b"private-device-password-marker"
        );
        let mut edited = input();
        edited.id = Some(id.clone());
        edited.revision = Some(1);
        edited.password = None;
        edited.name = "Renamed".into();
        edited.enabled = false;
        api.authorized(
            &request(&api, Operation::Save { device: edited }),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert_eq!(
            api.store.lock().unwrap().get(&id).unwrap().unwrap().1,
            sealed
        );
        assert!(!api
            .store
            .lock()
            .unwrap()
            .apply_revision(&original, &Default::default(), crate::now(), Some(1))
            .unwrap());
        let mut stale = input();
        stale.id = Some(id.clone());
        stale.revision = Some(1);
        assert_eq!(
            dsm::error_code(
                &api.authorized(
                    &request(&api, Operation::Save { device: stale }),
                    "admin-test",
                    Role::Administrator
                )
                .await
                .unwrap_err()
            ),
            "device_conflict"
        );
        let mut redirected = input();
        redirected.id = Some(id.clone());
        redirected.revision = Some(2);
        redirected.password = None;
        redirected.endpoint = "https://other.example/".into();
        assert_eq!(
            dsm::error_code(
                &api.authorized(
                    &request(&api, Operation::Save { device: redirected }),
                    "admin-test",
                    Role::Administrator
                )
                .await
                .unwrap_err()
            ),
            "device_password_required"
        );
        let read = Request {
            locale: Default::default(),
            auth: auth(),
            operation: Operation::Dashboard,
            csrf: None,
        };
        let dashboard = api
            .authorized(&read, "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert!(dashboard["data"]["csrf"].is_string());
        let encoded = serde_json::to_string(&dashboard).unwrap();
        assert!(!encoded.contains("private-device-password-marker"));
        let viewer = api
            .authorized(&read, "viewer-test", Role::Viewer)
            .await
            .unwrap();
        assert!(viewer["data"].get("csrf").is_none() && viewer["data"].get("audit").is_none());
        assert!(viewer["data"]["devices"][0]["device"]
            .get("username")
            .is_none());
        assert!(viewer["data"]["devices"][0]["device"]
            .get("ca_file")
            .is_none());
        api.authorized(
            &request(
                &api,
                Operation::Delete {
                    id: id.clone(),
                    revision: 2,
                },
            ),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert!(api.store.lock().unwrap().get(&id).unwrap().is_none());
        assert!(!api
            .store
            .lock()
            .unwrap()
            .poll_error_revision(&original, crate::now(), Some(2))
            .unwrap());
        let audit = api.store.lock().unwrap().audit_entries().unwrap();
        assert_eq!(audit.as_array().unwrap().len(), 3);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                assert!(!std::fs::read(p)
                    .unwrap()
                    .windows(30)
                    .any(|s| s == b"private-device-password-marker"));
            }
        }
    }
    #[test]
    fn rejects_paths_private_keys_invalid_certificates_and_credential_reuse() {
        let (_dir, api) = instance();
        let store = api.store.lock().unwrap();
        for endpoint in [
            "http://bmc.example/",
            "https://user:pass@bmc.example/",
            "https://bmc.example/redfish/v1/",
            "https://bmc.example/?a=1",
        ] {
            let mut d = input();
            d.endpoint = endpoint.into();
            assert!(prepare(&store, &api.vault, &d).is_err());
        }
        for pem in [
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            "not a certificate",
            "",
        ] {
            let mut d = input();
            d.trust_mode = TrustMode::Custom;
            d.certificate_pem = Some(pem.into());
            assert!(prepare(&store, &api.vault, &d).is_err());
        }
        let forbidden = serde_json::json!({"ca_file":"/etc/shadow"});
        assert!(serde_json::from_value::<DeviceInput>(forbidden).is_err());
    }
    #[tokio::test]
    async fn mail_settings_are_admin_only_encrypted_and_bound_to_server() {
        let (dir, api) = instance();
        let settings = crate::mail::Settings {
            host: "smtp.example.invalid".into(),
            username: "monitor".into(),
            from_address: "monitor@example.invalid".into(),
            recipients: vec!["receiver@example.invalid".into()],
            ..crate::mail::Settings::default()
        };
        let mail = crate::mail::Input {
            revision: 0,
            settings: settings.clone(),
            password: Some("smtp-private-marker-password".into()),
        };
        let req = request(&api, Operation::MailSave { mail });
        assert!(api
            .authorized(&req, "admin-test", Role::Viewer)
            .await
            .is_err());
        assert!(api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap()["ok"]
            .as_bool()
            .unwrap());
        let stored = api.store.lock().unwrap().mail_settings().unwrap().unwrap();
        assert_eq!(
            &*api.vault.unseal("settings:smtp", &stored.1).unwrap(),
            b"smtp-private-marker-password"
        );
        let retained = crate::mail::Input {
            revision: 1,
            settings: settings.clone(),
            password: None,
        };
        assert_eq!(
            prepare_mail(&api.store.lock().unwrap(), &api.vault, &retained).unwrap(),
            stored.1
        );
        let mut moved = settings.clone();
        moved.host = "other.example.invalid".into();
        assert!(prepare_mail(
            &api.store.lock().unwrap(),
            &api.vault,
            &crate::mail::Input {
                revision: 1,
                settings: moved,
                password: None
            }
        )
        .is_err());
        let view = api
            .authorized(
                &Request {
                    locale: Default::default(),
                    auth: auth(),
                    operation: Operation::Dashboard,
                    csrf: None,
                },
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(view["data"]["mail"]["has_password"], true);
        assert!(!view.to_string().contains("smtp-private-marker-password"));
        let viewer = api
            .authorized(
                &Request {
                    locale: Default::default(),
                    auth: auth(),
                    operation: Operation::Dashboard,
                    csrf: None,
                },
                "viewer-test",
                Role::Viewer,
            )
            .await
            .unwrap();
        assert!(viewer["data"].get("mail").is_none());
        for file in ["monitor.db", "monitor.db-wal"] {
            if let Ok(bytes) = std::fs::read(dir.path().join(file)) {
                assert!(!bytes
                    .windows(28)
                    .any(|x| x == b"smtp-private-marker-password"));
            }
        }
        let test = request(&api, Operation::MailTest { mail: retained });
        assert!(api
            .authorized(&test, "viewer-test", Role::Viewer)
            .await
            .is_err());
        let store = api.store.lock().unwrap();
        store.reserve_mail_test("admin-test", 100).unwrap();
        assert!(store.reserve_mail_test("admin-test", 159).is_err());
        assert!(store.reserve_mail_test("another-admin", 101).is_ok());
    }
}
