use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hardware_monitor::{
    api::{Api, Operation, Request, WriteBody, MAX_REQUEST},
    collector::Redfish,
    dsm::{self, AuthContext},
    model::Device,
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
    Backup {
        #[arg(long)]
        directory: PathBuf,
    },
    PollOnce,
    Serve {
        #[arg(long)]
        notify_dsm: bool,
    },
    /// DSM CGI bridge with server-side role, origin and CSRF enforcement.
    Cgi,
    /// Native DSM 6/7 lifecycle control under the package identity.
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
    let cli = Cli::parse();
    if matches!(cli.command, Command::Cgi) {
        return cgi(&cli.socket).await;
    }
    if let Command::Service { action, notify_dsm } = &cli.command {
        return service(&cli, action, *notify_dsm).await;
    }
    vault::private_dir(&cli.state)?;
    anyhow::ensure!(
        !cli.state.join("monitor.db").exists() || cli.state.join("master.key").exists(),
        "master key missing for existing database; restore key backup"
    );
    let vault = Arc::new(Vault::open(&cli.state.join("master.key"))?);
    let mut store = Store::open(&cli.state)?;
    match cli.command {
        Command::DevicePut { file } => {
            let d: Device = serde_json::from_slice(&std::fs::read(file)?)?;
            d.validate()?;
            let secret = vault::read_secret()?;
            store.put(&d, &vault.seal(&d.id, &secret)?)?;
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
            let secret = vault::read_secret()?;
            let result = Redfish::new(&d)?
                .probe(&d.username, std::str::from_utf8(&secret)?)
                .await?;
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
        Command::PollOnce => {
            let mut failed = false;
            for (device, secret) in store.devices()? {
                if !device.enabled {
                    continue;
                }
                if let Err(e) = poll(&mut store, &vault, &device, &secret).await {
                    failed = true;
                    eprintln!("{}: {e}", device.id);
                }
            }
            anyhow::ensure!(!failed, "one or more devices failed to poll");
        }
        Command::Serve { notify_dsm } => {
            serve(cli.state, cli.socket, store, vault, notify_dsm).await?
        }
        _ => unreachable!(),
    }
    Ok(())
}

async fn collect(
    vault: &Vault,
    d: &Device,
    encrypted: &[u8],
) -> Result<hardware_monitor::model::Snapshot> {
    let secret = vault.unseal(&d.id, encrypted)?;
    Redfish::new(d)?
        .poll(&d.username, std::str::from_utf8(&secret)?)
        .await
}
async fn poll(store: &mut Store, vault: &Vault, d: &Device, encrypted: &[u8]) -> Result<()> {
    match collect(vault, d, encrypted).await {
        Ok(snapshot) => store.apply(d, &snapshot, now()),
        Err(e) => {
            store.poll_error(d, now())?;
            Err(e)
        }
    }
}

async fn serve(
    state: PathBuf,
    socket: PathBuf,
    store: Store,
    vault: Arc<Vault>,
    notify: bool,
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
    std::fs::write(state.join("daemon.pid"), std::process::id().to_string())?;
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)
        .context("create local API socket (parent directory must exist)")?;
    // Every operation authenticates in the service; writes additionally require
    // administrator role, trusted origin and a session-bound package CSRF token.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
    let store = Arc::new(Mutex::new(store));
    let api_service = Arc::new(Api::new(store.clone(), vault.clone()));
    let worker_api = api_service.clone();
    let api = tokio::spawn(async move { api_loop(listener, api_service).await });
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut due = HashMap::<String, (i64, Instant)>::new();
    let mut running = HashSet::new();
    let mut jobs = JoinSet::new();
    let mut delivery = JoinSet::new();
    let mut next_delivery = Instant::now();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!("hardware-monitor started; legacy sysnotify delivery enabled={notify}; SMTP/desktop follow saved channel settings");
    loop {
        tokio::select! {
            _=terminate.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            Some(completion)=jobs.join_next(),if !jobs.is_empty()=> {
                match completion {Ok((id,revision,interval))=>{running.remove(&id);due.insert(id,(revision,Instant::now()+Duration::from_secs(interval)));},Err(e)=>eprintln!("poll worker failed: {e}")}
            },
            Some(completion)=delivery.join_next(),if !delivery.is_empty()=>{if let Err(e)=completion {eprintln!("notification worker failed: {e}");}},
            _=ticker.tick()=> {
                let devices=store.lock().unwrap().versioned_devices()?;
                for (device,secret,revision) in devices {
                    if jobs.len()>=4 {break;}
                    if !device.enabled || running.contains(&device.id) || due.get(&device.id).is_some_and(|(r,t)|*r==revision && *t>Instant::now()) {continue;}
                    running.insert(device.id.clone());
                    let vault=vault.clone(); let store=store.clone();
                    jobs.spawn(async move {
                        let snapshot=collect(&vault,&device,&secret).await;
                        let mut s=store.lock().unwrap();
                        let applied=match snapshot {Ok(snapshot)=>s.apply_revision(&device,&snapshot,now(),Some(revision)),Err(_)=>{eprintln!("device {}: poll failed; details excluded from logs",device.id);s.poll_error_revision(&device,now(),Some(revision))}};
                        if applied.is_err() {eprintln!("device {}: database update failed",device.id);}
                        (device.id,revision,device.interval_seconds)
                    });
                }
                if !notify && delivery.is_empty() && Instant::now()>=next_delivery {
                    next_delivery=Instant::now()+Duration::from_secs(2);
                    let api=worker_api.clone();
                    delivery.spawn(async move {if api.deliver_one_mail().await.is_err(){eprintln!("notification worker failed; details excluded");}});
                }
                if notify && delivery.is_empty() && Instant::now()>=next_delivery {
                    next_delivery=Instant::now()+Duration::from_secs(10);
                    let store=store.clone();
                    delivery.spawn(async move {
                        let pending=store.lock().unwrap().pending(now()).unwrap_or_default();
                        for (id,kind,health,message) in pending {
                            let success=dsm::notify(&kind,&health,&message).await.is_ok();
                            if !success {eprintln!("DSM notification {id} failed; retry queued");}
                            if store.lock().unwrap().delivery(id,success,now()).is_err() {eprintln!("notification status persistence failed");}
                        }
                    });
                }
            }
        }
    }
    jobs.abort_all();
    delivery.abort_all();
    api.abort();
    while jobs.join_next().await.is_some() {}
    std::fs::remove_file(&socket)?;
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
                let length = stream.read_u32().await? as usize;
                anyhow::ensure!(length <= MAX_REQUEST, "request too large");
                let mut bytes = zeroize::Zeroizing::new(vec![0u8; length]);
                stream.read_exact(&mut bytes).await?;
                let request: Request = serde_json::from_slice(&bytes)?;
                let result = service.handle(request).await;
                let response = serde_json::to_vec(&result)?;
                stream.write_u32(response.len() as u32).await?;
                stream.write_all(&response).await?;
                Ok::<_, anyhow::Error>(())
            };
            let _ = tokio::time::timeout(Duration::from_secs(20), operation).await;
        });
    }
}

async fn cgi(socket: &Path) -> Result<()> {
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let query = std::env::var("QUERY_STRING").unwrap_or_default();
    let probe = method == "GET" && query == "probe=1";
    let diagnostic = method == "GET" && query == "diagnose=1";
    let response = async {
        anyhow::ensure!(
            matches!(method.as_str(), "GET" | "POST"),
            dsm::BoundaryError("method_not_allowed")
        );
        // A liveness marker only: no socket, authentication, identity or device data.
        if probe {
            return Ok(json!({"ok":true,"code":"cgi_ready"}));
        }
        let mut auth = AuthContext::from_cgi();
        auth.diagnostic = diagnostic;
        auth.validate()?;
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
                        Operation::BackupInspect { .. } | Operation::BackupRestore { .. }
                    ),
                dsm::BoundaryError("write_body_invalid")
            );
            (body.operation, Some(body.csrf))
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
        anyhow::ensure!(
            length <= 32 * 1024 * 1024,
            dsm::BoundaryError("api_response_invalid")
        );
        let mut bytes = vec![0u8; length];
        stream
            .read_exact(&mut bytes)
            .await
            .context(dsm::BoundaryError("api_transport_failed"))?;
        serde_json::from_slice::<Value>(&bytes).context(dsm::BoundaryError("api_response_invalid"))
    };
    let mut result = match tokio::time::timeout(Duration::from_secs(25), response).await {
        Ok(Ok(v)) => v,
        Ok(Err(error)) => {
            json!({"ok":false,"error":"DSM-Anmeldung prüfen; Monitoring-Dienst muss laufen", "code":dsm::error_code(&error)})
        }
        Err(_) => {
            json!({"ok":false,"error":"Zeitüberschreitung bei der Anmeldung", "code":"api_timeout"})
        }
    };
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
    print!("Status: {status}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{}",serde_json::to_string(&result)?);
    Ok(())
}

async fn service(cli: &Cli, action: &str, notify: bool) -> Result<()> {
    vault::private_dir(&cli.state)?;
    let pid_path = cli.state.join("daemon.pid");
    let live_pid = || -> Option<i32> {
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
        let pid = std::fs::read_to_string(&pid_path)
            .ok()?
            .trim()
            .parse::<i32>()
            .ok()?;
        if pid <= 1 {
            return None;
        }
        if std::fs::read_link(format!("/proc/{pid}/exe")).ok()? != std::env::current_exe().ok()? {
            return None;
        }
        let owner = std::fs::metadata(format!("/proc/{pid}")).ok()?;
        use std::os::unix::fs::MetadataExt;
        if owner.uid() != unsafe { libc::geteuid() } {
            return None;
        }
        Some(pid)
    };
    match action {
        "status" => anyhow::ensure!(live_pid().is_some(), "daemon stopped"),
        "start" => {
            if live_pid().is_some() {
                return Ok(());
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
            for _ in 0..50 {
                if child.try_wait()?.is_some() {
                    anyhow::bail!("daemon startup failed; see private service.log");
                }
                if live_pid().is_some() && cli.socket.exists() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            child.kill()?;
            anyhow::bail!("daemon startup timeout");
        }
        "stop" => {
            if let Some(pid) = live_pid() {
                anyhow::ensure!(
                    unsafe { libc::kill(pid, libc::SIGTERM) } == 0,
                    "failed to stop daemon"
                );
                for _ in 0..100 {
                    if live_pid().is_none() {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                anyhow::bail!("daemon did not stop within 10 seconds");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
