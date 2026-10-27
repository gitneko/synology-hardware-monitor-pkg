//! Server-side device administration. No caller-supplied identity is accepted.
use crate::{
    collector::Redfish,
    dsm::{self, AuthContext, BoundaryError, Role},
    model::{Device, PrimaryProtocol},
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
// A backup export must fit through the CGI response as well as the upload path.
pub const MAX_RESPONSE: usize = crate::archive::MAX_FILE + 16384;

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
    SnmpTrapProbe {
        id: String,
        revision: i64,
    },
    SnmpReceipts {
        device: Option<String>,
        limit: usize,
    },
    SnmpReceiverSave {
        settings: crate::snmp::config::ReceiverSettings,
        revision: i64,
    },
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
    RetentionSave {
        settings: crate::retention::Settings,
        revision: i64,
    },
    CleanupPreview,
    CleanupRun {
        id: String,
        confirm: bool,
    },
    JobStatus {
        id: String,
    },
    JobCancel {
        id: String,
    },
    BackupExportStart {
        password: String,
    },
    BackupUploadStart,
    BackupUploadPart {
        id: String,
        offset: u64,
        data: String,
    },
    BackupInspectStart {
        id: String,
        bytes: u64,
        password: String,
    },
    BackupRestoreStart {
        id: String,
        expected_audit: i64,
        confirm: bool,
    },
    BackupDownload {
        id: String,
    },
    Delete {
        id: String,
        revision: i64,
    },
}

impl Drop for Operation {
    fn drop(&mut self) {
        match self {
            Self::BackupExportStart { password }
            | Self::BackupInspectStart { password, .. }
            | Self::BackupExport { password }
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
    #[serde(default)]
    pub hardware_log: crate::model::HardwareLogRead,
    pub id: Option<String>,
    pub revision: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub primary_protocol: PrimaryProtocol,
    #[serde(default)]
    pub snmp_poll: Option<crate::snmp::config::PollConfig>,
    #[serde(default)]
    pub snmp_traps: Option<crate::snmp::config::TrapConfig>,
    #[serde(default)]
    pub snmp_secrets: crate::snmp::secrets::SecretUpdates,
    pub password: Option<String>,
    pub interval_seconds: u64,
    pub repeat_seconds: Option<i64>,
    pub alerts_enabled: bool,
    pub enabled: bool,
    #[serde(default)]
    pub tls_profile: crate::model::TlsProfile,
    #[serde(default)]
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

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    Pinned,
    Keep,
    #[default]
    System,
    Custom,
}

pub struct Api {
    pub store: Arc<Mutex<Store>>,
    pub vault: Arc<Vault>,
    pub(crate) snmp_receiver: Option<Arc<crate::snmp::receiver::Controller>>,
    probes: tokio::sync::Semaphore,
    pub(crate) mail_gate: Arc<tokio::sync::Mutex<()>>,
    pub jobs: Arc<crate::jobs::Manager>,
    archives: tokio::sync::Semaphore,
    replay_turn: std::sync::atomic::AtomicBool,
}
impl Api {
    pub fn new(store: Arc<Mutex<Store>>, vault: Arc<Vault>) -> Self {
        let state = std::path::Path::new(
            store
                .lock()
                .unwrap()
                .0
                .path()
                .expect("file-backed application store"),
        )
        .parent()
        .unwrap()
        .to_path_buf();
        Self {
            jobs: Arc::new(crate::jobs::Manager::new(&state)),
            store,
            vault,
            snmp_receiver: None,
            probes: tokio::sync::Semaphore::new(2),
            archives: tokio::sync::Semaphore::new(1),
            replay_turn: std::sync::atomic::AtomicBool::new(true),
            mail_gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    pub fn submission_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.mail_gate.clone()
    }
    pub fn with_snmp_receiver(mut self, receiver: Arc<crate::snmp::receiver::Controller>) -> Self {
        self.snmp_receiver = Some(receiver);
        self
    }
    pub async fn handle(&self, request: Request) -> Value {
        let language = request.locale;
        let result = async {
            let (actor, role) = dsm::authenticate(&request.auth).await?;
            self.authorized(&request, &actor, role).await
        }
        .await;
        self.response(result, language)
    }

    fn response(&self, result: Result<Value>, language: crate::i18n::Language) -> Value {
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
                let code = dsm::error_code(&error);
                let mut response = json!({"ok":false,"code":code,"error":crate::i18n::text(message(code),language)});
                if code == "backup_too_large" {
                    if let Some(size) = error.downcast_ref::<crate::archive::SizeLimit>() {
                        let detail = crate::i18n::text(
                            "Sicherungsinhalt: mindestens {0} MiB ({1} Byte); Grenze: {2} MiB; Tabelle beim Abbruch: {3}.",
                            language,
                        )
                        .replace("{0}", &format!("{:.2}", size.bytes as f64 / 1048576.0))
                        .replace("{1}", &size.bytes.to_string())
                        .replace("{2}", &format!("{:.2}", size.limit as f64 / 1048576.0))
                        .replace("{3}", size.table.unwrap_or("—"));
                        response["error"] =
                            json!(format!("{} {detail}", response["error"].as_str().unwrap()));
                        response["backup_size"] = json!(size);
                    }
                }
                response
            }
        }
    }

    // Only the feature-gated loopback HTTP adapter can enter this path. Nothing
    // in the serialized DSM Request selects local authentication.
    #[cfg(feature = "local-dev")]
    pub(crate) async fn handle_local(&self, request: Request) -> Value {
        let language = request.locale;
        let result = self
            .authorized_inner(&request, "local-developer", Role::Administrator, true)
            .await;
        self.response(result, language)
    }

    async fn authorized(&self, request: &Request, actor: &str, role: Role) -> Result<Value> {
        self.authorized_inner(request, actor, role, false).await
    }

    async fn authorized_inner(
        &self,
        request: &Request,
        actor: &str,
        role: Role,
        local: bool,
    ) -> Result<Value> {
        if matches!(request.operation, Operation::Dashboard) {
            if request.auth.diagnostic {
                return Ok(json!({"ok":true,"code":"authenticated"}));
            }
            let store = self.store.lock().unwrap();
            let read = store.0.unchecked_transaction()?;
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
                    // Security identity/configuration is administrator-only, as
                    // with existing Redfish usernames. No secret is in either object.
                    device.remove("snmp_poll");
                    device.remove("snmp_traps");
                }
            }
            crate::i18n::dashboard(&mut data, request.locale);
            let (settings, revision) = store.retention_settings()?;
            data["history"] = json!({"settings":settings,"revision":revision,"audit_limit":10000});
            if local {
                data["runtime"] = json!("local-development");
            }
            data["user"] = json!({"name":actor,"role":role});
            let (receiver, revision) = store.receiver_settings()?;
            data["snmp_receiver"] = self
                .snmp_receiver
                .as_ref()
                .map(|service| json!(service.status()))
                .unwrap_or_else(
                    || json!({"enabled":receiver.enabled,"active":false,"state":"unavailable"}),
                );
            if role != Role::Administrator {
                if let Some(status) = data["snmp_receiver"].as_object_mut() {
                    status.remove("devices");
                    status.remove("listening");
                }
            }
            if data["snmp_receiver"]["epoch"]
                .as_i64()
                .is_some_and(|epoch| store.receiver_epoch().ok() != Some(epoch))
            {
                data["snmp_receiver"]["active"] = json!(false);
                data["snmp_receiver"]["state"] = json!("reconfiguring");
            }
            if role == Role::Administrator {
                data["snmp_receiver"]["settings"] = json!(receiver);
                data["snmp_receiver"]["revision"] = json!(revision);
            }
            let (mut policy, policy_revision) = store.notification_settings()?;
            if local {
                policy.desktop_enabled = false;
            }
            if policy_revision == 0 {
                policy.language = request.locale;
            }
            data["notifications"] = json!({"automatic_delivery":store.mail_enabled()||policy.desktop_enabled,"mail_enabled":store.mail_enabled(),"desktop_enabled":policy.desktop_enabled,"desktop_self_test_available":!local && dsm::desktop_test_available()});
            if role == Role::Administrator {
                data["jobs"] = json!(self.jobs.list(&binding(actor, &request.auth)));
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
            read.commit()?;
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
        let owner = binding(actor, &request.auth);
        if let Operation::BackupDownload { id } = &request.operation {
            anyhow::ensure!(
                local
                    || request
                        .auth
                        .environment
                        .iter()
                        .any(|(key, value)| key == "REQUEST_METHOD"
                            && matches!(value.as_str(), "GET" | "HEAD")),
                BoundaryError("write_operation_invalid")
            );
            let job = self.jobs.get(id, &owner)?;
            let (_file, length, _cancel) = self.jobs.open_download(&job.id)?;
            return Ok(json!({"ok":true,"download":id,"length":length}));
        }
        if !local {
            dsm::validate_write_context(&request.auth)?;
        }
        if local && matches!(request.operation, Operation::DesktopTest { .. }) {
            anyhow::bail!(BoundaryError("desktop_test_unavailable"));
        }
        check_csrf(
            &self.vault,
            actor,
            &request.auth,
            request.csrf.as_deref().unwrap_or(""),
            crate::now(),
        )?;
        if local
            && matches!(&request.operation, Operation::NotificationSave { settings } if settings.desktop_enabled)
        {
            anyhow::bail!(BoundaryError("desktop_test_unavailable"));
        }
        if let Operation::JobStatus { id } = &request.operation {
            let mut status = self.jobs.status(id, &owner)?;
            let code = status["status"]["code"].as_str().unwrap_or("job_failed");
            if code != "ok" {
                status["status"]["error"] = json!(crate::i18n::text(message(code), request.locale));
            }
            return Ok(status);
        }
        if let Operation::JobCancel { id } = &request.operation {
            self.jobs.cancel(id, &owner)?;
            return Ok(json!({"ok":true}));
        }
        if let Some(result) = self.job_operation(&request.operation, &owner, actor) {
            return result;
        }
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
            Operation::SnmpReceipts { device, limit } => Ok(
                json!({"ok":true,"receipts":self.store.lock().unwrap().snmp_receipts(device.as_deref(),*limit)?}),
            ),
            Operation::SnmpTrapProbe { id, revision } => {
                let _permit = self
                    .probes
                    .try_acquire()
                    .map_err(|_| BoundaryError("connection_busy"))?;
                let (config, cipher, epoch) = {
                    let store = self.store.lock().unwrap();
                    let read = store.0.unchecked_transaction()?;
                    let (device, _, current) =
                        store.get(id)?.context(BoundaryError("device_conflict"))?;
                    anyhow::ensure!(current == *revision, BoundaryError("device_conflict"));
                    let trap = device
                        .snmp_traps
                        .as_ref()
                        .context(BoundaryError("snmp_receiver_config_invalid"))?;
                    anyhow::ensure!(
                        matches!(trap.security, crate::snmp::config::Security::V3 { .. }),
                        BoundaryError("snmp_authentication")
                    );
                    let mut config = device
                        .snmp_poll
                        .clone()
                        .context(BoundaryError("snmp_responder_unconfigured"))?;
                    config.security = trap.security.clone();
                    config.context_name = trap.context_name.clone();
                    config.context_engine_id = None;
                    let cipher = store
                        .protocol_secret(id, crate::snmp::secrets::Purpose::SnmpTraps)?
                        .context(BoundaryError("snmp_credentials"))?;
                    let epoch = store.receiver_epoch()?;
                    read.commit()?;
                    (config, cipher, epoch)
                };
                let plain = self
                    .vault
                    .unseal(&crate::snmp::secrets::Purpose::SnmpTraps.aad(id), &cipher)
                    .context(BoundaryError("snmp_credentials"))?;
                let credentials =
                    serde_json::from_slice::<crate::snmp::secrets::Credentials>(&plain)
                        .map_err(|_| BoundaryError("snmp_credentials"))?;
                let result =
                    crate::snmp::polling::authenticated_identity(&config, &credentials).await;
                let store = self.store.lock().unwrap();
                anyhow::ensure!(
                    store.receiver_epoch()? == epoch
                        && store.get(id)?.is_some_and(|(_, _, r)| r == *revision),
                    BoundaryError("device_conflict")
                );
                store.audit(
                    actor,
                    "snmp.trap.probe",
                    id,
                    result
                        .as_ref()
                        .map(|_| "ok")
                        .unwrap_or_else(|e| dsm::error_code(e)),
                )?;
                let observed = result?;
                let time = observed
                    .engine
                    .authenticated_time()
                    .context(BoundaryError("snmp_authentication"))?;
                Ok(
                    json!({"ok":true,"revision":revision,"verified":true,"approval_required":true,"engine_id":crate::snmp::notifications::hex(observed.engine.engine_id()),"engine_boots":time.boots(),"target":observed.target,"sys_object_id":observed.sys_object_id}),
                )
            }
            Operation::SnmpReceiverSave { settings, revision } => {
                settings
                    .validate()
                    .context(BoundaryError("snmp_receiver_config_invalid"))?;
                if let Some(receiver) = &self.snmp_receiver {
                    receiver
                        .save(settings.clone(), *revision, actor.into())
                        .await?;
                } else {
                    anyhow::ensure!(
                        !settings.enabled,
                        BoundaryError("snmp_receiver_unavailable")
                    );
                    self.store
                        .lock()
                        .unwrap()
                        .save_receiver_settings(settings, *revision, actor)?;
                }
                Ok(json!({"ok":true,"revision":revision+1}))
            }
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
                let _ingestion = if matches!(request.operation, Operation::BackupRestore { .. }) {
                    if let Some(receiver) = &self.snmp_receiver {
                        Some(receiver.ingestion_gate().lock_owned().await)
                    } else {
                        None
                    }
                } else {
                    None
                };
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
                let credentials = crate::snmp::persistence::prepare_secrets(
                    &store,
                    &self.vault,
                    &device,
                    &input.snmp_secrets,
                )
                .map_err(|_| anyhow::anyhow!(BoundaryError("snmp_credentials_invalid")))?;
                store.save_admin_with_snmp(
                    &device,
                    &secret,
                    input.revision,
                    actor,
                    Some(&credentials),
                )?;
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
                    // Keep target/revision and kept credentials in one SQLite
                    // read snapshot, also against independent CLI writers.
                    let read = store.0.unchecked_transaction()?;
                    let (device, redfish) = prepare(&store, &self.vault, input)?;
                    let secret = if device.primary_protocol == PrimaryProtocol::Snmp {
                        crate::snmp::persistence::prepare_secrets(
                            &store,
                            &self.vault,
                            &device,
                            &input.snmp_secrets,
                        )
                        .context(BoundaryError("snmp_credentials_invalid"))?
                        .into_iter()
                        .find(|(p, _)| *p == crate::snmp::secrets::Purpose::SnmpPoll)
                        .and_then(|(_, cipher)| cipher)
                        .context(BoundaryError("snmp_credentials"))?
                    } else {
                        redfish
                    };
                    read.commit()?;
                    (device, secret)
                };
                let password = if device.primary_protocol == PrimaryProtocol::Redfish {
                    self.vault.unseal(&device.id, &secret)?
                } else {
                    self.vault
                        .unseal(
                            &crate::snmp::secrets::Purpose::SnmpPoll.aad(&device.id),
                            &secret,
                        )
                        .context(BoundaryError("snmp_credentials"))?
                };
                let result = crate::collector::probe(&device, &password).await;
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
            Operation::Dashboard
            | Operation::RetentionSave { .. }
            | Operation::CleanupPreview
            | Operation::CleanupRun { .. }
            | Operation::JobStatus { .. }
            | Operation::JobCancel { .. }
            | Operation::BackupExportStart { .. }
            | Operation::BackupUploadStart
            | Operation::BackupUploadPart { .. }
            | Operation::BackupInspectStart { .. }
            | Operation::BackupRestoreStart { .. }
            | Operation::BackupDownload { .. } => unreachable!(),
        }
    }

    pub(crate) fn state_path(&self) -> std::path::PathBuf {
        std::path::Path::new(
            self.store
                .lock()
                .unwrap()
                .0
                .path()
                .expect("file-backed application store"),
        )
        .parent()
        .unwrap()
        .to_path_buf()
    }
    pub fn automatic_cleanup(&self) -> Result<bool> {
        if self.jobs.busy() {
            return Ok(false);
        }
        let due: i64 = self.store.lock().unwrap().0.query_row(
            "SELECT value FROM counters WHERE name='history_cleanup_due'",
            [],
            |r| r.get(0),
        )?;
        if crate::now() < due {
            return Ok(false);
        }
        let job = self
            .jobs
            .create("automatic-maintenance", crate::jobs::Kind::Cleanup)?;
        let path = self.state_path();
        self.jobs.run(job, "automatic_cleanup", move |job| {
            let mut store = Store::open(&path)?;
            job.watch_sql(&store.0);
            let (settings, revision) = store.retention_settings()?;
            let result = crate::retention::cleanup_at_revision(
                &mut store.0,
                &settings,
                crate::now(),
                revision,
                |n| job.progress(n, 0),
            );
            crate::jobs::Job::unwatch_sql(&store.0);
            store.audit(
                "system",
                "history.cleanup",
                "application",
                &match &result {
                    Ok(counts) => serde_json::to_string(counts)?,
                    Err(error) => crate::dsm::error_code(error).into(),
                },
            )?;
            let counts = result?;
            store.0.execute(
                "UPDATE counters SET value=?1 WHERE name='history_cleanup_due'",
                [crate::now() + 86400],
            )?;
            Ok(json!({"counts":counts}))
        })?;
        Ok(true)
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
        self.deliver_mail(true).await
    }

    #[cfg(feature = "local-dev")]
    pub async fn deliver_local_mail(&self) -> Result<()> {
        self.deliver_mail(false).await
    }

    async fn deliver_mail(&self, desktop_enabled: bool) -> Result<()> {
        let _guard = self.mail_gate.lock().await;
        let desktop = if desktop_enabled {
            self.store.lock().unwrap().pending_desktop(crate::now())?
        } else {
            None
        };
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

pub(crate) fn validate_backup_password(password: &str) -> Result<()> {
    anyhow::ensure!(
        password.chars().count() >= 12 && password.len() <= 1024,
        BoundaryError("backup_password_invalid")
    );
    Ok(())
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
    let endpoint = if input.primary_protocol == PrimaryProtocol::Redfish {
        url::Url::parse(&input.endpoint)
            .context(BoundaryError("device_config_invalid"))?
            .to_string()
    } else {
        input.endpoint.clone()
    };
    let mut device = Device {
        hardware_log: input.hardware_log.clone(),
        id,
        primary_protocol: input.primary_protocol,
        snmp_poll: input.snmp_poll.clone(),
        snmp_traps: input.snmp_traps.clone(),
        name: input.name.trim().into(),
        endpoint,
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
    if device.primary_protocol == PrimaryProtocol::Redfish {
        match input.trust_mode {
            TrustMode::Keep => {
                if let Some((old, _, _)) = &existing {
                    device.ca_file = old.ca_file.clone();
                    device.ca_pem = old.ca_pem.clone();
                    if old.pinned_certificate_pem.is_some() {
                        anyhow::ensure!(
                            old.endpoint == device.endpoint
                                && old.tls_profile == device.tls_profile,
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
    }
    anyhow::ensure!(
        device.primary_protocol == PrimaryProtocol::Redfish
            || (input.password.is_none()
                && input.certificate_pem.is_none()
                && input.tls_profile == crate::model::TlsProfile::Standard
                && matches!(input.trust_mode, TrustMode::System)),
        BoundaryError("device_config_invalid")
    );
    device
        .validate()
        .context(BoundaryError("device_config_invalid"))?;
    if device.primary_protocol == PrimaryProtocol::Snmp {
        return Ok((device, Vec::new()));
    }
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
            old.primary_protocol == device.primary_protocol
                && old.endpoint == device.endpoint
                && old.username == device.username,
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
        "snmp_configuration" => "SNMP-Konfiguration ungültig.",
        "snmp_credentials" => "SNMP-Zugangsdaten fehlen oder passen nicht zur Konfiguration.",
        "snmp_dns" => "SNMP-Ziel konnte nicht innerhalb des Limits aufgelöst werden.",
        "snmp_timeout" | "snmp_deadline" => "Zeitlimit der SNMP-Abfrage erreicht. Netzwerk, SNMP-Version, Passphrasen und SHA-1/SHA-256-Auswahl prüfen; der Agent kann Sicherheitsfehler ohne Antwort verwerfen.",
        "snmp_authentication" => "SNMP-Anmeldung oder Sicherheitsprüfung fehlgeschlagen. Beide Passphrasen und die SHA-1/SHA-256-Auswahl prüfen; ein Digest-Fehler benennt keine eindeutige Ursache.",
        "snmp_engine_mismatch" => "Bestätigte SNMP-Engine stimmt nicht mit der Konfiguration überein.",
        "snmp_network" => "SNMP-Ziel ist nicht erreichbar.",
        "snmp_identity_incomplete" => "SNMP-Ziel antwortet ohne vollständige Systemidentität.",
        "snmp_request_limit" | "snmp_item_limit" | "snmp_byte_limit" | "snmp_response_limit" => "SNMP-Abfrage hat ein Ressourcenlimit erreicht.",
        "snmp_agent_error" => "SNMP-Agent hat die Abfrage abgewiesen.",
        "snmp_non_increasing_oid" | "snmp_invalid_response" => "Ungültige oder nicht fortschreitende SNMP-Antwort.",
        "snmp_receiver_unavailable" => "SNMP-Empfangsdienst ist nicht verfügbar.",
        "snmp_receiver_busy" => "SNMP-Empfang wird gerade umgestellt; Status erneut prüfen.",
        "snmp_receiver_permission" => "Keine Berechtigung für den privilegierten SNMP-Trap-Port. Ein DSM-Administrator muss das mitgelieferte Einrichtungsskript als root ausführen und den Paketdienst neu starten; bisherige Einstellung bleibt erhalten.",
        "snmp_receiver_bind" => "SNMP-Port oder lokale Adresse ist nicht verfügbar; bisherige Einstellung bleibt erhalten.",
        "snmp_receiver_rollback" => "SNMP-Portwechsel und Wiederherstellung fehlgeschlagen; Empfangsstatus prüfen.",
        "snmp_engine_state" => "Lokaler SNMP-Engine-Zustand ist ungültig; v3-Empfang bleibt gesperrt.",
        "snmp_responder_unconfigured" => "Für die Trap-Prüfung ist ein gespeichertes SNMP-Abfrageziel erforderlich.",
        "snmp_receipt_limit" => "Es können höchstens 100 SNMP-Empfangsbelege abgerufen werden.",
        "snmp_not_implemented" => "SNMP-Trap-Empfang ist in dieser Entwicklungsstufe noch nicht verfügbar.",
        "snmp_credentials_invalid" => "SNMP-Zugangsdaten prüfen. Nach Änderungen an Ziel oder Identität müssen sie ausdrücklich ersetzt oder gelöscht werden.",
        "snmp_receiver_config_invalid" => "SNMP-Empfang prüfen: Port 1–65535 und gültige, nicht überlappende NAS-Adressen sind erforderlich.",
        "connection_timeout"=>"Die Redfish-Datenbereiche haben nicht rechtzeitig geantwortet. Netzwerk und Auslastung des Controllers prüfen.",
        "retention_invalid"=>"Die Aufbewahrungsdauer muss zwischen 0 und 36.500 Tagen liegen. 0 bedeutet unbegrenzt.",
        "retention_conflict"=>"Die Aufbewahrungsregeln wurden geändert oder die Vorschau ist abgelaufen. Bitte erneut prüfen.",
        "job_invalid"=>"Der Auftrag ist abgelaufen, gehört zu einer anderen Sitzung oder ist nicht verfügbar.",
        "job_cancelled"=>"Der Auftrag wurde abgebrochen.",
        "job_failed"=>"Der Auftrag ist fehlgeschlagen. Dateiformat, freien Speicherplatz und Dienstprotokoll prüfen.",
        "jobs_full"=>"Zu viele gespeicherte Aufträge. Nicht mehr benötigte Aufträge beenden oder später erneut versuchen.",
        "upload_invalid"=>"Der Dateiabschnitt ist ungültig oder gehört nicht zum aktuellen Upload. Bitte Datei erneut auswählen.",
        "storage_full"=>"Für diesen Vorgang ist nicht genügend freier Speicherplatz vorhanden. Eine Reserve von 32 MiB bleibt frei.",
        "backup_record_large"=>"Ein einzelner Sicherungsdatensatz überschreitet die unterstützten 16 MiB.",
        "backup_password_invalid"=>"Das Sicherungspasswort muss mindestens 12 Zeichen und höchstens 1024 UTF-8-Bytes lang sein.",
        "backup_busy"=>"Eine Sicherungsaktion läuft bereits. Bitte kurz warten.",
        "backup_invalid"=>"Sicherungsdatei oder Passwort ungültig. Es wurden keine Daten geändert.",
        "backup_too_large"=>"Die Sicherung überschreitet das derzeitige Limit von 128 MiB Nutzdaten / 192 MiB Datei.",
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
        "device_config_invalid"=>"Geräteangaben prüfen: Protokoll, Zieladresse, Name, passende Zugangseinstellungen und gültige Intervalle sind erforderlich.",
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
            hardware_log: Default::default(),
            primary_protocol: Default::default(),
            snmp_poll: None,
            snmp_traps: None,
            snmp_secrets: Default::default(),
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
    #[test]
    fn backup_size_errors_localize_only_safe_numeric_and_schema_details() {
        let (_dir, api) = instance();
        for language in [crate::i18n::Language::De, crate::i18n::Language::En] {
            let error = anyhow::Error::new(crate::archive::SizeLimit {
                phase: "collection",
                table: Some("events"),
                bytes: 129 * 1024 * 1024,
                limit: crate::archive::MAX_PLAIN,
            })
            .context(BoundaryError("backup_too_large"))
            .context("private-record-content-must-not-leave");
            let response = api.response(Err(error), language);
            assert_eq!(response["code"], "backup_too_large");
            assert_eq!(response["backup_size"]["table"], "events");
            assert_eq!(response["backup_size"]["bytes"], 129 * 1024 * 1024);
            let message = response["error"].as_str().unwrap();
            assert!(message.contains("129.00") && message.contains("128.00"));
            assert!(message.contains(if language == crate::i18n::Language::De {
                "Tabelle beim Abbruch: events"
            } else {
                "table at rejection: events"
            }));
            assert!(!response.to_string().contains("private-record-content"));
        }
        let response = api.response(
            Err(anyhow::anyhow!("private-record-content-must-not-leave")),
            crate::i18n::Language::De,
        );
        assert!(response.get("backup_size").is_none());
        assert!(!response.to_string().contains("private-record-content"));
    }
    #[tokio::test]
    async fn snmp_api_is_revisioned_redacted_and_never_falls_back_to_redfish() {
        let (_dir, api) = instance();
        let make_input = |id: Option<&str>, revision: Option<i64>, replace: bool| -> DeviceInput {
            serde_json::from_value(json!({"id":id,"revision":revision,"name":"Synthetic SNMP","primary_protocol":"snmp","snmp_poll":{"host":"127.0.0.1","port":61999,"timeout_ms":100,"retries":0,"security":{"version":"v1"}},"snmp_secrets":{"snmp_poll":if replace {json!({"action":"replace","credentials":{"kind":"community","community":"api-synthetic-community"}})} else {json!({"action":"keep"})}},"interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"enabled":true})).unwrap()
        };
        let req = request(
            &api,
            Operation::Save {
                device: make_input(None, None, true),
            },
        );
        assert!(api.authorized(&req, "viewer", Role::Viewer).await.is_err());
        let result = api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap();
        let id = result["id"].as_str().unwrap();
        let admin = api
            .authorized(
                &request(&api, Operation::Dashboard),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(admin["data"]["devices"][0]["has_snmp_poll_secret"], true);
        assert!(!admin.to_string().contains("api-synthetic-community"));
        let viewer = api
            .authorized(&request(&api, Operation::Dashboard), "viewer", Role::Viewer)
            .await
            .unwrap();
        assert!(viewer["data"]["devices"][0]["device"]
            .get("snmp_poll")
            .is_none());
        let probe = api
            .authorized(
                &request(
                    &api,
                    Operation::Test {
                        device: make_input(Some(id), Some(1), false),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(probe["code"], "snmp_timeout");
        let mut changed = make_input(Some(id), Some(1), false);
        changed.snmp_poll.as_mut().unwrap().host = "other.example".into();
        let error = api
            .authorized(
                &request(&api, Operation::Save { device: changed }),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap_err();
        assert_eq!(dsm::error_code(&error), "snmp_credentials_invalid");
        assert_eq!(api.store.lock().unwrap().get(id).unwrap().unwrap().2, 1);
        let mut clear = make_input(Some(id), Some(1), false);
        clear.enabled = false;
        clear.snmp_secrets.snmp_poll = crate::snmp::secrets::SecretUpdate::Clear {};
        api.authorized(
            &request(&api, Operation::Save { device: clear }),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert!(api
            .store
            .lock()
            .unwrap()
            .protocol_secret(id, crate::snmp::secrets::Purpose::SnmpPoll)
            .unwrap()
            .is_none());
        let audit = api
            .store
            .lock()
            .unwrap()
            .audit_entries()
            .unwrap()
            .to_string();
        assert!(!audit.contains("api-synthetic-community"));
        assert_ne!(
            crate::i18n::text(message("snmp_not_implemented"), crate::i18n::Language::En),
            message("snmp_not_implemented")
        );
    }

    #[tokio::test]
    async fn receiver_configuration_requires_admin_csrf_revision_and_live_service() {
        let (_dir, api) = instance();
        let settings = crate::snmp::config::ReceiverSettings {
            listen_port: 2162,
            ..Default::default()
        };
        let mut req = request(
            &api,
            Operation::SnmpReceiverSave {
                settings: settings.clone(),
                revision: 0,
            },
        );
        assert!(api.authorized(&req, "viewer", Role::Viewer).await.is_err());
        req.csrf = None;
        assert!(api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .is_err());
        req.csrf = request(&api, Operation::Dashboard).csrf;
        api.authorized(&req, "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert_eq!(
            api.store
                .lock()
                .unwrap()
                .receiver_settings()
                .unwrap()
                .0
                .listen_port,
            2162
        );
        assert!(api
            .authorized(&req, "admin-test", Role::Administrator)
            .await
            .is_err());
        let enabled = crate::snmp::config::ReceiverSettings {
            enabled: true,
            ..settings
        };
        let error = api
            .authorized(
                &request(
                    &api,
                    Operation::SnmpReceiverSave {
                        settings: enabled,
                        revision: 1,
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap_err();
        assert_eq!(dsm::error_code(&error), "snmp_receiver_unavailable");
        assert!(
            !api.store
                .lock()
                .unwrap()
                .receiver_settings()
                .unwrap()
                .0
                .enabled
        );
        let invalid = crate::snmp::config::ReceiverSettings {
            listen_port: 0,
            ..Default::default()
        };
        let error = api
            .authorized(
                &request(
                    &api,
                    Operation::SnmpReceiverSave {
                        settings: invalid,
                        revision: 1,
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap_err();
        assert_eq!(dsm::error_code(&error), "snmp_receiver_config_invalid");
        assert_eq!(api.store.lock().unwrap().receiver_settings().unwrap().1, 1);
        // Privileged ports are valid saved configuration even without a live
        // receiver when disabled; the OS, rather than validation, gates bind.
        api.authorized(
            &request(
                &api,
                Operation::SnmpReceiverSave {
                    settings: crate::snmp::config::ReceiverSettings {
                        listen_port: 162,
                        ..Default::default()
                    },
                    revision: 1,
                },
            ),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert_eq!(
            api.store
                .lock()
                .unwrap()
                .receiver_settings()
                .unwrap()
                .0
                .listen_port,
            162
        );
    }

    #[tokio::test]
    async fn trap_diagnostics_require_admin_csrf_and_live_receiver_reports_actual_binding() {
        let (dir, api) = instance();
        let service =
            crate::snmp::receiver::Service::start(dir.path(), api.store.clone(), api.vault.clone());
        let api = api.with_snmp_receiver(service.controller.clone());
        for operation in [
            Operation::SnmpReceipts {
                device: None,
                limit: 20,
            },
            Operation::SnmpTrapProbe {
                id: "missing".into(),
                revision: 1,
            },
        ] {
            let mut req = request(&api, operation);
            assert_eq!(
                dsm::error_code(
                    &api.authorized(&req, "viewer", Role::Viewer)
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
        let receipt = api
            .authorized(
                &request(
                    &api,
                    Operation::SnmpReceipts {
                        device: None,
                        limit: 20,
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        assert_eq!(receipt["receipts"], json!([]));
        let invalid = api
            .authorized(
                &request(
                    &api,
                    Operation::SnmpReceipts {
                        device: None,
                        limit: 101,
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap_err();
        assert_eq!(dsm::error_code(&invalid), "snmp_receipt_limit");
        let reserve = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        api.authorized(
            &request(
                &api,
                Operation::SnmpReceiverSave {
                    settings: crate::snmp::config::ReceiverSettings {
                        enabled: true,
                        listen_port: port,
                        listen_addresses: vec!["127.0.0.1".parse().unwrap()],
                    },
                    revision: 0,
                },
            ),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while service.controller.status().epoch
                != api.store.lock().unwrap().receiver_epoch().unwrap()
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let admin = api
            .authorized(
                &request(&api, Operation::Dashboard),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let receiver = &admin["data"]["snmp_receiver"];
        assert_eq!(receiver["active"], true);
        assert_eq!(receiver["health_updates"], true);
        assert_eq!(receiver["listening"][0], format!("127.0.0.1:{port}"));
        let viewer = api
            .authorized(&request(&api, Operation::Dashboard), "viewer", Role::Viewer)
            .await
            .unwrap();
        assert!(viewer["data"]["snmp_receiver"].get("listening").is_none());
        assert!(viewer["data"]["snmp_receiver"].get("devices").is_none());
        service.stop().await;
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
            Operation::RetentionSave {
                settings: Default::default(),
                revision: 0,
            },
            Operation::CleanupPreview,
            Operation::CleanupRun {
                id: "0".repeat(32),
                confirm: true,
            },
            Operation::JobStatus { id: "0".repeat(32) },
            Operation::JobCancel { id: "0".repeat(32) },
            Operation::BackupExportStart {
                password: "synthetic-backup-password".into(),
            },
            Operation::BackupUploadStart,
            Operation::BackupUploadPart {
                id: "0".repeat(32),
                offset: 0,
                data: "eA==".into(),
            },
            Operation::BackupInspectStart {
                id: "0".repeat(32),
                bytes: 1,
                password: "synthetic-backup-password".into(),
            },
            Operation::BackupRestoreStart {
                id: "0".repeat(32),
                expected_audit: 0,
                confirm: true,
            },
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
    async fn completed_job(api: &Api, id: &str) -> Value {
        for _ in 0..2000 {
            let status = api
                .authorized(
                    &request(api, Operation::JobStatus { id: id.into() }),
                    "admin-test",
                    Role::Administrator,
                )
                .await
                .unwrap();
            match status["status"]["state"].as_str().unwrap() {
                "ready" => return status["status"]["result"].clone(),
                "failed" | "cancelled" => panic!("job failed: {status}"),
                _ => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        }
        panic!("job did not finish")
    }
    #[tokio::test]
    async fn file_jobs_export_upload_inspect_and_restore_through_authorized_api() {
        use base64::Engine;
        let (_dir, api) = instance();
        api.store.lock().unwrap().0.execute("INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,'removed','fan','alarm','\"critical\"','Original history',100)",[]).unwrap();
        let export = api
            .authorized(
                &request(
                    &api,
                    Operation::BackupExportStart {
                        password: "synthetic-backup-password".into(),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let id = export["job"].as_str().unwrap();
        completed_job(&api, id).await;
        let mut download = request(&api, Operation::BackupDownload { id: id.into() });
        assert!(api
            .authorized(&download, "admin-test", Role::Administrator)
            .await
            .is_err());
        download
            .auth
            .environment
            .insert("REQUEST_METHOD".into(), "GET".into());
        assert!(api
            .authorized(&download, "viewer-test", Role::Viewer)
            .await
            .is_err());
        assert!(api
            .authorized(&download, "other-admin", Role::Administrator)
            .await
            .is_err());
        let result = api
            .authorized(&download, "admin-test", Role::Administrator)
            .await
            .unwrap();
        let (mut file, length, _) = api.jobs.open_download(id).unwrap();
        assert_eq!(result["length"], length);
        download
            .auth
            .environment
            .insert("REQUEST_METHOD".into(), "HEAD".into());
        let checked = api
            .authorized(&download, "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert_eq!(checked["length"], length);
        assert!(api
            .authorized(&download, "viewer-test", Role::Viewer)
            .await
            .is_err());
        assert!(api
            .authorized(&download, "other-admin", Role::Administrator)
            .await
            .is_err());
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        let upload = api
            .authorized(
                &request(&api, Operation::BackupUploadStart),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let upload = upload["job"].as_str().unwrap();
        for (index, part) in bytes.chunks(crate::jobs::UPLOAD_CHUNK).enumerate() {
            api.authorized(
                &request(
                    &api,
                    Operation::BackupUploadPart {
                        id: upload.into(),
                        offset: (index * crate::jobs::UPLOAD_CHUNK) as u64,
                        data: base64::engine::general_purpose::STANDARD.encode(part),
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        }
        api.authorized(
            &request(
                &api,
                Operation::BackupInspectStart {
                    id: upload.into(),
                    bytes: length,
                    password: "synthetic-backup-password".into(),
                },
            ),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        let inspected = completed_job(&api, upload).await;
        assert_eq!(inspected["events"], 1);
        let expected = inspected["expected_audit"].as_i64().unwrap();
        let restore = || {
            request(
                &api,
                Operation::BackupRestoreStart {
                    id: upload.into(),
                    expected_audit: expected,
                    confirm: true,
                },
            )
        };
        api.authorized(&restore(), "admin-test", Role::Administrator)
            .await
            .unwrap();
        assert_eq!(completed_job(&api, upload).await["restored"], true);
        assert!(api
            .authorized(&restore(), "admin-test", Role::Administrator)
            .await
            .is_err());
        assert_eq!(
            api.store
                .lock()
                .unwrap()
                .0
                .query_row("SELECT message FROM events", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "Original history"
        );
    }
    #[tokio::test]
    async fn cleanup_previews_expire_on_policy_changes_and_cancelled_jobs_are_not_confirmable() {
        let (_dir, api) = instance();
        let preview = api
            .authorized(
                &request(&api, Operation::CleanupPreview),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap();
        let id = preview["job"].as_str().unwrap();
        completed_job(&api, id).await;
        api.store
            .lock()
            .unwrap()
            .save_retention(
                &crate::retention::Settings {
                    events_days: 0,
                    hardware_logs_days: 0,
                },
                0,
                "admin-test",
            )
            .unwrap();
        assert_eq!(
            dsm::error_code(
                &api.authorized(
                    &request(
                        &api,
                        Operation::CleanupRun {
                            id: id.into(),
                            confirm: true
                        }
                    ),
                    "admin-test",
                    Role::Administrator
                )
                .await
                .unwrap_err()
            ),
            "retention_conflict"
        );
        api.authorized(
            &request(&api, Operation::JobCancel { id: id.into() }),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert_eq!(
            dsm::error_code(
                &api.authorized(
                    &request(
                        &api,
                        Operation::CleanupRun {
                            id: id.into(),
                            confirm: true
                        }
                    ),
                    "admin-test",
                    Role::Administrator
                )
                .await
                .unwrap_err()
            ),
            "job_invalid"
        );
    }
    #[tokio::test]
    async fn automatic_cleanup_has_a_persisted_grace_period_and_daily_deadline() {
        let (dir, api) = instance();
        let due = api
            .store
            .lock()
            .unwrap()
            .0
            .query_row(
                "SELECT value FROM counters WHERE name='history_cleanup_due'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert!((crate::now() + 86395..=crate::now() + 86405).contains(&due));
        assert!(!api.automatic_cleanup().unwrap());
        let reopened = Store::open(dir.path()).unwrap();
        assert_eq!(
            reopened
                .0
                .query_row(
                    "SELECT value FROM counters WHERE name='history_cleanup_due'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            due
        );
        {
            let store = api.store.lock().unwrap();
            store
                .0
                .execute(
                    "UPDATE counters SET value=0 WHERE name='history_cleanup_due'",
                    [],
                )
                .unwrap();
            store.0.execute("INSERT INTO hardware_logs VALUES('removed','old','{\"fingerprint\":\"old\",\"message\":\"old log\",\"severity\":\"ok\",\"created\":\"2021-01-01T00:00:00Z\"}')",[]).unwrap();
        }
        assert!(api.automatic_cleanup().unwrap());
        for _ in 0..2000 {
            if !api.jobs.busy() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(!api.jobs.busy());
        assert_eq!(
            api.store
                .lock()
                .unwrap()
                .0
                .query_row("SELECT count(*) FROM hardware_logs", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(!api.automatic_cleanup().unwrap());
    }
    #[tokio::test]
    async fn restore_status_cancel_and_retention_guard_do_not_wait_for_application_store() {
        let (_dir, api) = instance();
        let owner = binding("admin-test", &auth());
        let job = api.jobs.create(&owner, crate::jobs::Kind::Upload).unwrap();
        api.jobs.upload(&job.id, &owner, 0, "eA==").unwrap();
        api.jobs.uploaded(&job.id, &owner, 1).unwrap();
        api.jobs
            .run(job.clone(), "inspect", |_| Ok(json!({"expected_audit":0})))
            .unwrap();
        completed_job(&api, &job.id).await;
        let (started, ready) = std::sync::mpsc::channel();
        let (release, until) = std::sync::mpsc::channel();
        let store = api.store.clone();
        api.jobs
            .run(job.clone(), "restore", move |job| {
                let _guard = store.lock().unwrap();
                started.send(()).unwrap();
                let _ = until.recv_timeout(std::time::Duration::from_secs(2));
                job.check()?;
                Ok(Value::Null)
            })
            .unwrap();
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(api.jobs.restoring());
        let start = std::time::Instant::now();
        assert_eq!(
            api.authorized(
                &request(&api, Operation::JobStatus { id: job.id.clone() }),
                "admin-test",
                Role::Administrator
            )
            .await
            .unwrap()["status"]["state"],
            "running"
        );
        let rejected = api
            .authorized(
                &request(
                    &api,
                    Operation::RetentionSave {
                        settings: Default::default(),
                        revision: 0,
                    },
                ),
                "admin-test",
                Role::Administrator,
            )
            .await
            .unwrap_err();
        assert_eq!(dsm::error_code(&rejected), "backup_busy");
        api.authorized(
            &request(&api, Operation::JobCancel { id: job.id.clone() }),
            "admin-test",
            Role::Administrator,
        )
        .await
        .unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        release.send(()).unwrap();
        while api.jobs.busy() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(!api.jobs.restoring());
    }
}
