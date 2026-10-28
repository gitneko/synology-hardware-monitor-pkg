use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hardware_monitor::{
    api::{Api, Operation, Request, WriteBody, MAX_REQUEST, MAX_RESPONSE},
    dsm::{self, AuthContext},
    model::{Device, PrimaryProtocol},
    now,
    store::Store,
    vault::{self, Vault},
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::Instant,
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(
        long,
        default_value = "/var/packages/HardwareMonitor/etc/private",
        global = true
    )]
    state: PathBuf,
    #[arg(
        long,
        default_value = "/var/packages/HardwareMonitor/etc/api.sock",
        global = true
    )]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Add/update a device from JSON; password is read only from stdin.
    DevicePut {
        #[arg(long)]
        file: PathBuf,
        /// Read a JSON credential document on stdin instead of a Redfish password.
        #[arg(long)]
        protocol_secrets: bool,
    },
    /// Check HTTPS and Redfish login without changing the device. Password from stdin.
    DeviceTest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Submit a synthetic mail to the first recipient. Password is read only from stdin.
    MailTest {
        #[arg(long)]
        file: PathBuf,
    },
    Snapshot,
    /// Prepare or migrate private state without starting monitoring or delivery.
    Initialize,
    Backup {
        #[arg(long)]
        directory: PathBuf,
    },
    PollOnce,
    Serve {
        #[arg(long)]
        notify_dsm: bool,
    },
    /// Run the full application on loopback without DSM login (development builds only).
    #[cfg(feature = "local-dev")]
    Dev {
        #[arg(long, default_value = "local-state")]
        directory: PathBuf,
        #[arg(long, default_value_t = 18774)]
        port: u16,
        #[arg(long, default_value = "web/dist")]
        web_root: PathBuf,
    },
    /// DSM CGI bridge with server-side role, origin and CSRF enforcement.
    Cgi,
    /// Native DSM 7 lifecycle control under the package identity.
    Service {
        #[arg(value_parser=["start","stop","status"])]
        action: String,
        #[arg(long)]
        notify_dsm: bool,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // State files stay private even when executed from a permissive package lifecycle environment.
    unsafe {
        libc::umask(0o077);
    }
    if std::env::args_os()
        .next()
        .is_some_and(|p| Path::new(&p).file_name().is_some_and(|n| n == "api.cgi"))
        || std::env::var("GATEWAY_INTERFACE").is_ok_and(|v| v.starts_with("CGI/"))
    {
        return cgi(Path::new("/var/packages/HardwareMonitor/etc/api.sock")).await;
    }
    #[allow(unused_mut)]
    let mut cli = Cli::parse();
    #[cfg(feature = "local-dev")]
    if let Command::Dev { directory, .. } = &cli.command {
        anyhow::ensure!(
            cli.state == Path::new("/var/packages/HardwareMonitor/etc/private"),
            "use dev --directory for isolated development state"
        );
        cli.state = directory.clone();
    }
    if matches!(cli.command, Command::Cgi) {
        return cgi(&cli.socket).await;
    }
    if let Command::Service { action, notify_dsm } = &cli.command {
        match service(&cli, action, *notify_dsm).await {
            Ok(running) => {
                if action == "status" && !running {
                    // DSM distinguishes stopped (3) from a dead process (1).
                    std::process::exit(3);
                }
                return Ok(());
            }
            Err(error) if action == "status" => {
                eprintln!("{error:#}");
                std::process::exit(4); // DSM: status could not be determined.
            }
            Err(error) => return Err(error),
        }
    }
    vault::private_dir(&cli.state)?;
    anyhow::ensure!(
        !cli.state.join("monitor.db").exists() || cli.state.join("master.key").exists(),
        "master key missing for existing database; restore key backup"
    );
    let vault = Arc::new(
        Vault::open(&cli.state.join("master.key")).context("open private credential key")?,
    );
    let mut store = Store::open(&cli.state).context("initialize package database")?;
    match cli.command {
        Command::DevicePut {
            file,
            protocol_secrets,
        } => {
            let d: Device = serde_json::from_slice(&std::fs::read(file)?)?;
            d.validate()?;
            use hardware_monitor::snmp::{
                persistence::prepare_secrets, secrets::DeviceCredentialsInput,
            };
            let input = if protocol_secrets {
                DeviceCredentialsInput::read()?
            } else {
                anyhow::ensure!(
                    d.primary_protocol == PrimaryProtocol::Redfish,
                    "SNMP configuration requires --protocol-secrets JSON on stdin"
                );
                DeviceCredentialsInput {
                    redfish_password: Some(std::str::from_utf8(&vault::read_secret()?)?.to_owned()),
                    snmp: Default::default(),
                }
            };
            let existing = store.get(&d.id)?;
            let secret = if d.primary_protocol == PrimaryProtocol::Snmp {
                anyhow::ensure!(
                    input.redfish_password.is_none(),
                    "SNMP primary must not carry a Redfish password"
                );
                Vec::new()
            } else if let Some(password) = &input.redfish_password {
                anyhow::ensure!(
                    !password.is_empty() && password.len() <= 4096,
                    "invalid Redfish password"
                );
                vault.seal(&d.id, password.as_bytes())?
            } else {
                let (old, secret, _) = existing.as_ref().context("Redfish password required")?;
                anyhow::ensure!(
                    old.primary_protocol == d.primary_protocol
                        && old.endpoint == d.endpoint
                        && old.username == d.username,
                    "Redfish password replacement required"
                );
                secret.clone()
            };
            let credentials = prepare_secrets(&store, &vault, &d, &input.snmp)?;
            store.save_admin_with_snmp(
                &d,
                &secret,
                existing.map(|v| v.2),
                "local-cli",
                Some(&credentials),
            )?;
            println!("Device {} saved", d.id);
        }
        Command::MailTest { file } => {
            let settings: hardware_monitor::mail::Settings =
                serde_json::from_slice(&std::fs::read(file)?)?;
            settings.validate()?;
            let secret = if settings.username.is_empty() {
                None
            } else {
                Some(vault::read_secret()?)
            };
            let password = secret
                .as_ref()
                .map(|p| std::str::from_utf8(p))
                .transpose()?;
            let id = format!(
                "<hm-test-{:032x}@hardwaremonitor.invalid>",
                rand::random::<u128>()
            );
            hardware_monitor::mail::submit(
                &settings,
                password,
                &hardware_monitor::mail::Event::sample(),
                &settings.recipients[0],
                &id,
            )
            .await
            .map_err(|code| anyhow::anyhow!(code))?;
            println!("SMTP accepted test message; mailbox delivery unconfirmed");
        }
        Command::DeviceTest { file } => {
            let d: Device = serde_json::from_slice(&std::fs::read(file)?)?;
            d.validate()?;
            let secret = if d.primary_protocol == PrimaryProtocol::Snmp {
                let input = hardware_monitor::snmp::secrets::DeviceCredentialsInput::read()?;
                let hardware_monitor::snmp::secrets::SecretUpdate::Replace { credentials } =
                    &input.snmp.snmp_poll
                else {
                    anyhow::bail!(hardware_monitor::dsm::BoundaryError("snmp_credentials"));
                };
                zeroize::Zeroizing::new(serde_json::to_vec(credentials)?)
            } else {
                vault::read_secret()?
            };
            let result = hardware_monitor::collector::probe(&d, &secret).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Backup { directory } => {
            anyhow::ensure!(!directory.exists(), "backup destination already exists");
            vault::private_dir(&directory)?;
            let output = directory.join("monitor.db");
            store.0.execute(
                "VACUUM INTO ?1",
                [output.to_str().context("invalid backup path")?],
            )?;
            std::fs::copy(cli.state.join("master.key"), directory.join("master.key"))?;
            println!("Private backup saved");
        }
        Command::Snapshot => println!("{}", serde_json::to_string_pretty(&store.dashboard()?)?),
        Command::Initialize => println!("Private state initialized"),
        Command::PollOnce => {
            let mut failed = false;
            for (device, secret, revision, epoch) in store.poll_targets()? {
                if !device.enabled {
                    continue;
                }
                if let Err(e) = poll(&mut store, &vault, &device, &secret, revision, epoch).await {
                    failed = true;
                    eprintln!("{}: {e}", device.id);
                }
            }
            anyhow::ensure!(!failed, "one or more devices failed to poll");
        }
        Command::Serve { notify_dsm } => {
            serve(cli.state, cli.socket, store, vault, notify_dsm, None).await?
        }
        #[cfg(feature = "local-dev")]
        Command::Dev { port, web_root, .. } => {
            let config = hardware_monitor::local::Config::bind(port, web_root).await?;
            serve(cli.state, cli.socket, store, vault, false, Some(config)).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

async fn poll(
    store: &mut Store,
    vault: &Vault,
    d: &Device,
    encrypted: &[u8],
    revision: i64,
    epoch: i64,
) -> Result<()> {
    let started = store.trap_sequence(&d.id)?;
    match hardware_monitor::collector::collect(vault, d, encrypted).await {
        Ok(snapshot) => store
            .apply_poll(
                d,
                &snapshot,
                now(),
                Some(revision),
                Some(epoch),
                Some(started),
            )
            .map(|_| ()),
        Err(e) => {
            store.poll_failure_epoch(d, now(), revision, epoch, &e)?;
            Err(e)
        }
    }
}

#[cfg(feature = "local-dev")]
type LocalConfig = hardware_monitor::local::Config;
#[cfg(not(feature = "local-dev"))]
type LocalConfig = ();

async fn serve(
    state: PathBuf,
    socket: PathBuf,
    store: Store,
    vault: Arc<Vault>,
    notify: bool,
    local: Option<LocalConfig>,
) -> Result<()> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("daemon.lock"))?;
    anyhow::ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "daemon already running"
    );
    let development = local.is_some();
    let store = Arc::new(Mutex::new(store));
    let api_service = Api::new(store.clone(), vault.clone());
    let snmp_receiver = hardware_monitor::snmp::receiver::Service::start_with_submission_gate(
        &state,
        store.clone(),
        vault.clone(),
        api_service.submission_gate(),
    );
    let snmp_control = snmp_receiver.controller.clone();
    let api_service = Arc::new(api_service.with_snmp_receiver(snmp_control.clone()));
    let worker_api = api_service.clone();
    let mut api = if !development {
        if socket.exists() {
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)
            .context("create local API socket (parent directory must exist)")?;
        // DSM operations always authenticate in the service.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
        tokio::spawn(api_loop(listener, api_service))
    } else {
        #[cfg(feature = "local-dev")]
        {
            tokio::spawn(hardware_monitor::local::serve(local.unwrap(), api_service))
        }
        #[cfg(not(feature = "local-dev"))]
        {
            unreachable!()
        }
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let snmp_poller = Arc::new(hardware_monitor::snmp::polling::Poller::default());
    let mut due = HashMap::<String, (i64, Instant)>::new();
    let mut running = HashSet::new();
    let mut jobs = JoinSet::new();
    let mut delivery = JoinSet::new();
    let mut webhooks = JoinSet::new();
    let mut next_delivery = Instant::now();
    worker_api.jobs.reap()?;
    let mut next_reap = Instant::now() + Duration::from_secs(60);
    let mut next_maintenance = Instant::now() + Duration::from_secs(60);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Publish readiness only after the listener and shutdown handler exist.
    std::fs::write(state.join("daemon.pid"), std::process::id().to_string())?;
    eprintln!("hardware-monitor started; legacy sysnotify delivery enabled={notify}; SMTP/desktop follow saved channel settings");
    loop {
        tokio::select! {
            result = &mut api => { result??; anyhow::bail!("API listener stopped unexpectedly"); },
            _=terminate.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            Some(completion)=jobs.join_next(),if !jobs.is_empty()=> {
                match completion {Ok((id,revision,interval))=>{running.remove(&id);due.insert(id,(revision,Instant::now()+Duration::from_secs(interval)));},Err(e)=>eprintln!("poll worker failed: {e}")}
            },
            Some(completion)=webhooks.join_next(),if !webhooks.is_empty()=>{if completion.is_err(){eprintln!("webhook worker failed; details excluded");}},
            Some(completion)=delivery.join_next(),if !delivery.is_empty()=>{if let Err(e)=completion {eprintln!("notification worker failed: {e}");}},
            _=ticker.tick()=> {
                while webhooks.len()<4 {
                    let api=worker_api.clone();
                    webhooks.spawn(async move {if api.deliver_one_webhook().await.is_err(){eprintln!("webhook worker failed; details excluded");}});
                }
                if Instant::now()>=next_reap {
                    next_reap=Instant::now()+Duration::from_secs(60);
                    let jobs=worker_api.jobs.clone();
                    tokio::task::spawn_blocking(move || {let _=jobs.reap();});
                }
                if Instant::now()>=next_maintenance {
                    let _=worker_api.automatic_cleanup();
                    next_maintenance=Instant::now()+Duration::from_secs(60);
                }
                if worker_api.jobs.restoring() { continue; }
                let mut devices=store.lock().unwrap().poll_targets()?;
                // A trap storm must not let early devices repeatedly take all
                // four slots while another device's ordinary poll is overdue.
                devices.sort_by_key(|(d,_,revision,_)|due.get(&d.id).is_some_and(|(r,t)|r==revision&&*t>Instant::now()));
                let valid=devices.iter().filter(|(d,_,_,_)|d.enabled && d.primary_protocol==PrimaryProtocol::Snmp).map(|(d,_,_,_)|d.id.clone()).collect();
                snmp_poller.retain(&valid);
                due.retain(|id,_|devices.iter().any(|(d,_,_,_)|&d.id==id));
                for (device,secret,revision,epoch) in devices {
                    if jobs.len()>=4 {break;}
                    if !device.enabled || running.contains(&device.id) || (due.get(&device.id).is_some_and(|(r,t)|*r==revision && *t>Instant::now()) && !snmp_control.urgent_due(&device.id,revision,epoch)) {continue;}
                    running.insert(device.id.clone());
                    snmp_control.poll_started(&device.id,revision,epoch);
                    let started=store.lock().unwrap().trap_sequence(&device.id)?;
                    let vault=vault.clone(); let store=store.clone(); let snmp_poller=snmp_poller.clone(); let api=worker_api.clone();
                    jobs.spawn(async move {
                        let snapshot=hardware_monitor::collector::collect_with_runtime(&vault,&device,&secret,&snmp_poller,revision,epoch).await;
                        let interval=if device.primary_protocol==PrimaryProtocol::Snmp {snmp_poller.delay(&device.id,device.interval_seconds).await}else{device.interval_seconds};
                        if api.jobs.restoring() { return (device.id,revision,interval); }
                        let mut s=store.lock().unwrap();
                        if api.jobs.restoring() { return (device.id,revision,interval); }
                        let applied=match snapshot {Ok(snapshot)=>s.apply_poll(&device,&snapshot,now(),Some(revision),Some(epoch),Some(started)),Err(error)=>{eprintln!("device {}: {}",device.id,hardware_monitor::collector::poll_failure_label(&error));s.poll_failure_epoch(&device,now(),revision,epoch,&error)}};
                        if applied.is_err() {eprintln!("device {}: database update failed",device.id);}
                        (device.id,revision,interval)
                    });
                }
                if !notify && delivery.is_empty() && Instant::now()>=next_delivery {
                    next_delivery=Instant::now()+Duration::from_secs(2);
                    let api=worker_api.clone();
                    delivery.spawn(async move {
                        #[cfg(feature = "local-dev")]
                        let result = if development { api.deliver_local_mail().await } else { api.deliver_one_mail().await };
                        #[cfg(not(feature = "local-dev"))]
                        let result = api.deliver_one_mail().await;
                        if result.is_err(){eprintln!("notification worker failed; details excluded");}
                    });
                }
                if notify && delivery.is_empty() && Instant::now()>=next_delivery {
                    next_delivery=Instant::now()+Duration::from_secs(10);
                    let api=worker_api.clone();
                    delivery.spawn(async move {if api.deliver_legacy().await.is_err(){eprintln!("legacy notification worker failed; details excluded");}});
                }
            }
        }
    }
    worker_api.jobs.shutdown();
    snmp_receiver.stop().await;
    jobs.abort_all();
    webhooks.abort_all();
    delivery.abort_all();
    api.abort();
    while jobs.join_next().await.is_some() {}
    while worker_api.jobs.busy() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !development {
        std::fs::remove_file(&socket)?;
    }
    std::fs::remove_file(state.join("daemon.pid"))?;
    drop(lock);
    Ok(())
}

async fn api_loop(listener: UnixListener, service: Arc<Api>) -> Result<()> {
    let slots = Arc::new(Semaphore::new(8));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let permit = match slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let operation = async {
                let length = tokio::time::timeout(Duration::from_secs(20), stream.read_u32())
                    .await?? as usize;
                anyhow::ensure!(length <= MAX_REQUEST, "request too large");
                let mut bytes = zeroize::Zeroizing::new(vec![0u8; length]);
                tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut bytes))
                    .await??;
                let request: Request = serde_json::from_slice(&bytes)?;
                let head = request
                    .auth
                    .environment
                    .get("REQUEST_METHOD")
                    .is_some_and(|method| method == "HEAD");
                let result =
                    tokio::time::timeout(Duration::from_secs(20), service.handle(request)).await?;
                if let Some(id) = result
                    .get("download")
                    .and_then(Value::as_str)
                    .filter(|_| result["ok"] == true)
                {
                    let (file, length, cancel) = service.jobs.open_download(id)?;
                    send_attachment(&mut stream, file, length, cancel, head).await?;
                    return Ok::<_, anyhow::Error>(());
                }
                let response = serde_json::to_vec(&result)?;
                stream.write_u32(response.len() as u32).await?;
                stream.write_all(&response).await?;
                Ok::<_, anyhow::Error>(())
            };
            let _ = tokio::time::timeout(Duration::from_secs(86400), operation).await;
        });
    }
}

// The native socket protocol uses a sentinel plus a 64-bit attachment length.
// HEAD sends the same metadata and never opens a body-transfer loop.
async fn send_attachment<W: tokio::io::AsyncWrite + Unpin>(
    output: &mut W,
    mut file: std::fs::File,
    length: u64,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    head: bool,
) -> Result<()> {
    use std::io::Read;
    output.write_u32(u32::MAX).await?;
    output.write_u64(length).await?;
    if !head {
        let mut buffer = [0; 65536];
        loop {
            anyhow::ensure!(
                !cancel.load(std::sync::atomic::Ordering::Relaxed),
                "download cancelled"
            );
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            tokio::time::timeout(Duration::from_secs(30), output.write_all(&buffer[..n])).await??;
        }
    }
    Ok(())
}
async fn receive_attachment<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    input: &mut R,
    output: &mut W,
    length: u64,
    head: bool,
) -> Result<()> {
    output.write_all(format!("Status: 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"HardwareMonitor-backup.hmbackup\"\r\nContent-Length: {length}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n").as_bytes()).await?;
    if !head {
        let mut left = length;
        let mut buffer = [0; 65536];
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            tokio::time::timeout(Duration::from_secs(30), input.read_exact(&mut buffer[..n]))
                .await??;
            output.write_all(&buffer[..n]).await?;
            left -= n as u64;
        }
    }
    output.flush().await?;
    Ok(())
}

async fn cgi(socket: &Path) -> Result<()> {
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let query = std::env::var("QUERY_STRING").unwrap_or_default();
    let probe = method == "GET" && query == "probe=1";
    let diagnostic = method == "GET" && query == "diagnose=1";
    let parsed_download = dsm::download_query(&query);
    let is_download = parsed_download.as_ref().is_ok_and(Option::is_some);
    let mut streamed = false;
    let response = async {
        anyhow::ensure!(
            matches!(method.as_str(), "GET" | "POST") || (method == "HEAD" && is_download),
            dsm::BoundaryError("method_not_allowed")
        );
        // A liveness marker only: no socket, authentication, identity or device data.
        if probe {
            return Ok(json!({"ok":true,"code":"cgi_ready"}));
        }
        let mut auth = AuthContext::from_cgi();
        auth.diagnostic = diagnostic;
        auth.validate()?;
        let parsed_download = parsed_download?;
        if let Some((_, token)) = &parsed_download {
            auth.download_token(token.as_deref())?;
        }
        let (operation, csrf) = if method == "POST" {
            let content_type = std::env::var("CONTENT_TYPE").unwrap_or_default();
            anyhow::ensure!(
                content_type.split(';').next().unwrap_or("").trim() == "application/json",
                dsm::BoundaryError("write_content_type_invalid")
            );
            let length = std::env::var("CONTENT_LENGTH")
                .unwrap_or_default()
                .parse::<usize>()
                .context(dsm::BoundaryError("write_body_invalid"))?;
            anyhow::ensure!(
                (1..=MAX_REQUEST - 16384).contains(&length),
                dsm::BoundaryError("write_body_invalid")
            );
            let mut input = zeroize::Zeroizing::new(Vec::new());
            tokio::io::stdin()
                .take(length as u64)
                .read_to_end(&mut input)
                .await
                .context(dsm::BoundaryError("write_body_invalid"))?;
            anyhow::ensure!(
                input.len() == length,
                dsm::BoundaryError("write_body_invalid")
            );
            let body: WriteBody =
                serde_json::from_slice(&input).context(dsm::BoundaryError("write_body_invalid"))?;
            anyhow::ensure!(
                !matches!(body.operation, Operation::Dashboard),
                dsm::BoundaryError("write_operation_invalid")
            );
            anyhow::ensure!(
                length <= 128 * 1024
                    || matches!(
                        &body.operation,
                        Operation::BackupInspect { .. }
                            | Operation::BackupRestore { .. }
                            | Operation::BackupUploadPart { .. }
                    ),
                dsm::BoundaryError("write_body_invalid")
            );
            (body.operation, Some(body.csrf))
        } else if let Some((id, _)) = parsed_download {
            (Operation::BackupDownload { id }, None)
        } else {
            (Operation::Dashboard, None)
        };
        let mut stream = UnixStream::connect(socket)
            .await
            .context(dsm::BoundaryError("api_socket_unavailable"))?;
        let body = zeroize::Zeroizing::new(serde_json::to_vec(&Request {
            locale: hardware_monitor::i18n::Language::header(
                &std::env::var("HTTP_X_HARDWAREMONITOR_LANGUAGE").unwrap_or_else(|_| "de".into()),
            ),
            auth,
            operation,
            csrf,
        })?);
        stream
            .write_u32(body.len() as u32)
            .await
            .context(dsm::BoundaryError("api_transport_failed"))?;
        stream
            .write_all(&body)
            .await
            .context(dsm::BoundaryError("api_transport_failed"))?;
        let length = stream
            .read_u32()
            .await
            .context(dsm::BoundaryError("api_transport_failed"))? as usize;
        if length == u32::MAX as usize {
            let remaining = stream.read_u64().await?;
            anyhow::ensure!(is_download, dsm::BoundaryError("api_response_invalid"));
            streamed = true;
            let mut stdout = tokio::io::stdout();
            receive_attachment(&mut stream, &mut stdout, remaining, method == "HEAD").await?;
            return Ok(Value::Null);
        }
        anyhow::ensure!(
            length <= MAX_RESPONSE,
            dsm::BoundaryError("api_response_invalid")
        );
        let mut bytes = vec![0u8; length];
        stream
            .read_exact(&mut bytes)
            .await
            .context(dsm::BoundaryError("api_transport_failed"))?;
        serde_json::from_slice::<Value>(&bytes).context(dsm::BoundaryError("api_response_invalid"))
    };
    let timeout = if is_download && method != "HEAD" {
        86400
    } else {
        25
    };
    let mut result = match tokio::time::timeout(Duration::from_secs(timeout), response).await {
        Ok(Ok(v)) => v,
        Ok(Err(error)) => {
            json!({"ok":false,"error":"DSM-Anmeldung prüfen; Monitoring-Dienst muss laufen", "code":dsm::error_code(&error)})
        }
        Err(_) => {
            json!({"ok":false,"error":"Zeitüberschreitung bei der Anmeldung", "code":"api_timeout"})
        }
    };
    if streamed {
        return Ok(());
    }
    // Diagnostics use a 200 transport envelope so nginx error_page cannot hide
    // the fixed failure code. Authorization remains mandatory; no dashboard is
    // returned in this mode, even for an authenticated user.
    if diagnostic {
        result = json!({"ok":result["ok"] == true, "code":result["code"].as_str().unwrap_or("api_response_invalid")});
    }
    if let Some(message) = result["error"].as_str() {
        result["error"] = json!(hardware_monitor::i18n::text(
            message,
            hardware_monitor::i18n::Language::header(
                &std::env::var("HTTP_X_HARDWAREMONITOR_LANGUAGE").unwrap_or_else(|_| "de".into())
            )
        ));
    }
    result["source"] = json!("hardware-monitor");
    result["version"] = json!(env!("CARGO_PKG_VERSION"));
    let status = if result["ok"] == true || diagnostic || method == "POST" {
        "200 OK"
    } else {
        "403 Forbidden"
    };
    let body = if method == "HEAD" {
        String::new()
    } else {
        serde_json::to_string(&result)?
    };
    print!("Status: {status}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n{body}");
    Ok(())
}

async fn live_service_pid(cli: &Cli) -> Option<i32> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(cli.state.join("daemon.lock"))
        .ok()?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return None;
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
        return None;
    }
    let pid = std::fs::read_to_string(cli.state.join("daemon.pid"))
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()?;
    if pid <= 1 {
        return None;
    }
    // File capabilities can make /proc/PID/exe unreadable even to the same
    // UID. Authenticate the actual API listener with kernel peer credentials
    // instead of weakening dumpability or trusting a PID file alone.
    let stream = tokio::time::timeout(Duration::from_millis(200), UnixStream::connect(&cli.socket))
        .await
        .ok()?
        .ok()?;
    let peer = stream.peer_cred().ok()?;
    if peer.pid()? != pid || peer.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    Some(pid)
}

async fn service(cli: &Cli, action: &str, notify: bool) -> Result<bool> {
    vault::private_dir(&cli.state)?;
    match action {
        "status" => return Ok(live_service_pid(cli).await.is_some()),
        "start" => {
            if live_service_pid(cli).await.is_some() {
                return Ok(true);
            }
            let log = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(cli.state.join("service.log"))?;
            let mut cmd = std::process::Command::new(std::env::current_exe()?);
            cmd.arg("--state")
                .arg(&cli.state)
                .arg("--socket")
                .arg(&cli.socket)
                .arg("serve");
            if notify {
                cmd.arg("--notify-dsm");
            }
            cmd.stdin(std::process::Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log);
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn()?;
            // Direct upgrades back up and migrate schema 1 before serve()
            // publishes its PID/socket. Allow slower or temporarily busy NASes.
            let deadline = Instant::now() + Duration::from_secs(120);
            while Instant::now() < deadline {
                if child.try_wait()?.is_some() {
                    anyhow::bail!("daemon startup failed; see private service.log");
                }
                if live_service_pid(cli).await.is_some() {
                    return Ok(true);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            child.kill()?;
            let _ = child.wait();
            anyhow::bail!("daemon startup timeout after 120 seconds; see private service.log");
        }
        "stop" => {
            if let Some(pid) = live_service_pid(cli).await {
                anyhow::ensure!(
                    unsafe { libc::kill(pid, libc::SIGTERM) } == 0,
                    "failed to stop daemon"
                );
                for _ in 0..100 {
                    if live_service_pid(cli).await.is_none() {
                        return Ok(false);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                anyhow::bail!("daemon did not stop within 10 seconds");
            }
        }
        _ => unreachable!(),
    }
    Ok(false)
}

#[cfg(test)]
mod download_tests {
    use super::*;
    async fn transferred(mut file: std::fs::File, length: u64, head: bool) -> Vec<u8> {
        use std::io::Seek;
        file.rewind().unwrap();
        let (mut sender, mut receiver) = tokio::io::duplex(8192);
        let producer = tokio::spawn(async move {
            send_attachment(
                &mut sender,
                file,
                length,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                head,
            )
            .await
            .unwrap();
        });
        assert_eq!(receiver.read_u32().await.unwrap(), u32::MAX);
        assert_eq!(receiver.read_u64().await.unwrap(), length);
        let mut response = Vec::new();
        receive_attachment(&mut receiver, &mut response, length, head)
            .await
            .unwrap();
        producer.await.unwrap();
        response
    }
    #[tokio::test]
    async fn native_attachment_streams_exact_bytes_and_head_only_returns_large_file_metadata() {
        use std::io::Write;
        let data = (0..300_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&data).unwrap();
        let response = transferred(file, data.len() as u64, false).await;
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert_eq!(&response[split + 4..], data);
        let headers = std::str::from_utf8(&response[..split]).unwrap();
        assert!(headers.contains("filename=\"HardwareMonitor-backup.hmbackup\""));
        assert!(headers.contains("Content-Length: 300000"));
        let file = tempfile::tempfile().unwrap();
        let length = 8u64 * 1024 * 1024 * 1024;
        file.set_len(length).unwrap();
        let response = transferred(file, length, true).await;
        let text = String::from_utf8(response).unwrap();
        assert!(text.contains("Content-Length: 8589934592"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(text.len() < 512);
    }
    #[tokio::test]
    async fn truncated_native_attachment_fails_instead_of_becoming_a_complete_download() {
        let (mut sender, mut receiver) = tokio::io::duplex(32);
        sender.write_all(b"abc").await.unwrap();
        drop(sender);
        let mut response = Vec::new();
        assert!(receive_attachment(&mut receiver, &mut response, 4, false)
            .await
            .is_err());
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;

    // Executed in a separate process by the test below: dumpability is never
    // changed in the test runner or in the production daemon.
    #[test]
    #[ignore]
    fn protected_daemon_fixture() {
        let Some(directory) = std::env::var_os("HM_PROTECTED_DAEMON_TEST") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("daemon.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let listener = std::os::unix::net::UnixListener::bind(directory.join("api.sock")).unwrap();
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }, 0);
        std::fs::write(directory.join("daemon.pid"), std::process::id().to_string()).unwrap();
        for connection in listener.incoming() {
            drop(connection.unwrap());
        }
    }

    #[tokio::test]
    async fn protected_daemon_identity_uses_kernel_peer_not_proc_or_pid_file_alone() {
        let directory = tempfile::tempdir().unwrap();
        let cli = Cli {
            state: directory.path().into(),
            socket: directory.path().join("api.sock"),
            command: Command::Service {
                action: "status".into(),
                notify_dsm: false,
            },
        };
        assert!(live_service_pid(&cli).await.is_none());
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "service_tests::protected_daemon_fixture",
            ])
            .env("HM_PROTECTED_DAEMON_TEST", directory.path())
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;
        let deadline = Instant::now() + Duration::from_secs(5);
        while live_service_pid(&cli).await != Some(pid) {
            assert!(Instant::now() < deadline, "protected daemon not detected");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Pointing the file at a different live process must not authorize a
        // signal to it, even while the real daemon still holds the lock.
        std::fs::write(cli.state.join("daemon.pid"), std::process::id().to_string()).unwrap();
        assert!(live_service_pid(&cli).await.is_none());
        std::fs::write(cli.state.join("daemon.pid"), pid.to_string()).unwrap();
        assert_eq!(live_service_pid(&cli).await, Some(pid));
        assert!(!service(&cli, "stop", false).await.unwrap());
        assert!(live_service_pid(&cli).await.is_none());
        drop(child);
    }
}
