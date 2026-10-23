//! Supervised UDP ownership, fair bounded ingress, verified routing and receipts.
//! Verified partial evidence joins the shared reducer under the submission gate.
use super::{
    config::{ReceiverSettings, Security},
    engine,
    notifications::{self, Sender},
    secrets::{Credentials, Purpose},
};
use crate::{dsm::BoundaryError, model::Device, store::Store, vault::Vault};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify},
    task::{JoinHandle, JoinSet},
    time::Instant,
};

#[derive(Clone, Default, Serialize)]
pub struct Counters {
    pub received: u64,
    pub unknown_source: u64,
    pub oversized: u64,
    pub verification_limited: u64,
    pub queue_dropped: u64,
    pub rejected: u64,
    pub ambiguous: u64,
    pub pending: u64,
    pub verified: u64,
    pub unverified: u64,
    pub ingestion_limited: u64,
    pub duplicates: u64,
    pub stored: u64,
    pub stale: u64,
    pub retention_removed: u64,
    pub io_errors: u64,
    pub storage_errors: u64,
}
#[derive(Clone, Serialize)]
pub struct DeviceStatus {
    pub revision: i64,
    pub state: String,
    pub engine_id: Option<String>,
    pub last_received: Option<i64>,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub active: bool,
    pub state: String,
    pub revision: i64,
    pub epoch: i64,
    pub listening: Vec<SocketAddr>,
    pub devices: BTreeMap<String, DeviceStatus>,
    pub counters: Counters,
    pub health_updates: bool,
    pub omitted_devices: usize,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            enabled: false,
            active: false,
            state: "starting".into(),
            revision: 0,
            epoch: 0,
            listening: Vec::new(),
            devices: BTreeMap::new(),
            counters: Default::default(),
            health_updates: true,
            omitted_devices: 0,
        }
    }
}
#[derive(Clone)]
pub struct Urgent {
    pub revision: i64,
    pub epoch: i64,
}
struct Urgents {
    pending: HashMap<String, Urgent>,
    started: HashMap<String, Instant>,
}
struct Packet {
    data: Bytes,
    source: SocketAddr,
    received: i64,
}
struct Bucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    at: Instant,
}
impl Bucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            rate,
            at: Instant::now(),
        }
    }
    fn available(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.at = now;
        self.tokens >= 1.0
    }
    fn take(&mut self) -> bool {
        if self.available() {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
struct Ingress {
    allowed: HashMap<IpAddr, Bucket>,
    global: Bucket,
    queues: HashMap<IpAddr, VecDeque<Packet>>,
    order: VecDeque<IpAddr>,
    queued: usize,
    reconcile: HashSet<IpAddr>,
    counters: Counters,
}
impl Ingress {
    fn new() -> Self {
        Self {
            allowed: HashMap::new(),
            global: Bucket::new(200.0, 400.0),
            queues: HashMap::new(),
            order: VecDeque::new(),
            queued: 0,
            reconcile: HashSet::new(),
            counters: Default::default(),
        }
    }
    fn policies(&mut self, ips: HashSet<IpAddr>) {
        self.allowed = ips
            .into_iter()
            .map(|ip| (ip, Bucket::new(20.0, 40.0)))
            .collect();
        self.queues.clear();
        self.order.clear();
        self.queued = 0;
        self.reconcile.clear();
    }
    fn enqueue(&mut self, data: &[u8], source: SocketAddr) -> bool {
        self.counters.received += 1;
        let Some(bucket) = self.allowed.get_mut(&source.ip()) else {
            self.counters.unknown_source += 1;
            return false;
        };
        if data.len() > notifications::MAX_MESSAGE {
            self.counters.oversized += 1;
            return false;
        }
        // Check the sender before spending global quota: unknown/exhausted
        // sources cannot consume another approved sender's global tokens.
        if !bucket.available() || !self.global.available() {
            self.counters.verification_limited += 1;
            return false;
        }
        bucket.take();
        self.global.take();
        let queue = self.queues.entry(source.ip()).or_default();
        if self.queued >= 256 || queue.len() >= 16 {
            self.counters.queue_dropped += 1;
            self.reconcile.insert(source.ip());
            return false;
        }
        if queue.is_empty() {
            self.order.push_back(source.ip());
        }
        queue.push_back(Packet {
            data: Bytes::copy_from_slice(data),
            source,
            received: crate::now(),
        });
        self.queued += 1;
        true
    }
    fn pop(&mut self) -> Option<Packet> {
        let ip = self.order.pop_front()?;
        let queue = self.queues.get_mut(&ip)?;
        let packet = queue.pop_front();
        if !queue.is_empty() {
            self.order.push_back(ip);
        }
        if packet.is_some() {
            self.queued -= 1;
        }
        packet
    }
}
struct Shared {
    status: Mutex<Status>,
    ingress: Mutex<Ingress>,
    notify: Notify,
    urgent: Mutex<Urgents>,
    gate: Arc<AsyncMutex<()>>,
    submission_gate: Arc<AsyncMutex<()>>,
}
impl Shared {
    fn count(&self, f: impl FnOnce(&mut Counters)) {
        f(&mut self.ingress.lock().unwrap().counters);
    }
    fn urgent(&self, sender: &Sender) {
        let mut u = self.urgent.lock().unwrap();
        if u.pending.len() < 256 || u.pending.contains_key(&sender.device.id) {
            u.pending.insert(
                sender.device.id.clone(),
                Urgent {
                    revision: sender.revision,
                    epoch: sender.epoch,
                },
            );
        }
    }
}
enum Command {
    Save {
        settings: ReceiverSettings,
        revision: i64,
        actor: String,
        response: oneshot::Sender<Result<()>>,
    },
    Stop,
}
pub struct Controller {
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
}
impl Controller {
    pub fn status(&self) -> Status {
        let mut s = self.shared.status.lock().unwrap().clone();
        s.counters = self.shared.ingress.lock().unwrap().counters.clone();
        s
    }
    pub fn ingestion_gate(&self) -> Arc<AsyncMutex<()>> {
        self.shared.gate.clone()
    }
    pub async fn save(
        &self,
        settings: ReceiverSettings,
        revision: i64,
        actor: String,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Save {
                settings,
                revision,
                actor,
                response: tx,
            })
            .map_err(|_| BoundaryError("snmp_receiver_busy"))?;
        // Once queued the worker owns completion even if the HTTP caller leaves.
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .context(BoundaryError("snmp_receiver_busy"))?
            .context(BoundaryError("snmp_receiver_unavailable"))?
    }
    pub fn urgent_due(&self, id: &str, revision: i64, epoch: i64) -> bool {
        let u = self.shared.urgent.lock().unwrap();
        u.pending
            .get(id)
            .is_some_and(|p| p.revision == revision && p.epoch == epoch)
            && u.started
                .get(id)
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(10))
    }
    pub fn poll_started(&self, id: &str, revision: i64, epoch: i64) {
        let configured = self.shared.status.lock().unwrap().devices.contains_key(id);
        let mut u = self.shared.urgent.lock().unwrap();
        let pending = u
            .pending
            .get(id)
            .is_some_and(|p| p.revision == revision && p.epoch == epoch);
        if pending {
            u.pending.remove(id);
        }
        // Ordinary polls of devices without traps must not fill this bounded
        // table and defeat the minimum gap for actual trap-enabled devices.
        if (configured || pending) && (u.started.len() < 256 || u.started.contains_key(id)) {
            u.started.insert(id.into(), Instant::now());
        }
    }
}
pub struct Service {
    pub controller: Arc<Controller>,
    task: JoinHandle<()>,
}
impl Service {
    pub fn start(path: &Path, store: Arc<Mutex<Store>>, vault: Arc<Vault>) -> Self {
        Self::start_with_submission_gate(path, store, vault, Arc::new(AsyncMutex::new(())))
    }
    pub fn start_with_submission_gate(
        path: &Path,
        store: Arc<Mutex<Store>>,
        vault: Arc<Vault>,
        submission_gate: Arc<AsyncMutex<()>>,
    ) -> Self {
        let local = engine::authoritative(path).ok();
        let shared = Arc::new(Shared {
            status: Mutex::new(Status::default()),
            ingress: Mutex::new(Ingress::new()),
            notify: Notify::new(),
            urgent: Mutex::new(Urgents {
                pending: HashMap::new(),
                started: HashMap::new(),
            }),
            gate: Arc::new(AsyncMutex::new(())),
            submission_gate,
        });
        let (tx, rx) = mpsc::channel(8);
        let controller = Arc::new(Controller {
            shared: shared.clone(),
            commands: tx,
        });
        let task = tokio::spawn(worker(shared, store, vault, local, rx));
        Self { controller, task }
    }
    pub async fn stop(self) {
        let _ = self.controller.commands.send(Command::Stop).await;
        let _ = self.task.await;
    }
}
struct Bindings {
    settings: ReceiverSettings,
    sockets: Vec<Arc<UdpSocket>>,
    tasks: JoinSet<()>,
}
impl Bindings {
    fn empty() -> Self {
        Self {
            settings: ReceiverSettings::default(),
            sockets: Vec::new(),
            tasks: JoinSet::new(),
        }
    }
    async fn close(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.sockets.clear();
    }
    fn bind(&mut self, settings: &ReceiverSettings, shared: &Arc<Shared>) -> Result<()> {
        let mut sockets = Vec::new();
        if settings.enabled {
            for ip in &settings.listen_addresses {
                let socket = socket2::Socket::new(
                    if ip.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    },
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .context(BoundaryError("snmp_receiver_bind"))?;
                if ip.is_ipv6() {
                    socket
                        .set_only_v6(true)
                        .context(BoundaryError("snmp_receiver_bind"))?;
                }
                socket.set_nonblocking(true)?;
                socket
                    .bind(&SocketAddr::new(*ip, settings.listen_port).into())
                    .context(BoundaryError("snmp_receiver_bind"))?;
                let socket = Arc::new(UdpSocket::from_std(socket.into())?);
                sockets.push(socket);
            }
        }
        for socket in &sockets {
            let socket = socket.clone();
            let shared = shared.clone();
            self.tasks.spawn(async move {
                // One fixed receive task per socket, never one task per packet.
                let mut bytes = vec![0; 65536];
                loop {
                    match socket.recv_from(&mut bytes).await {
                        Ok((n, source)) => {
                            let queued =
                                shared.ingress.lock().unwrap().enqueue(&bytes[..n], source);
                            if queued {
                                shared.notify.notify_one();
                            }
                        }
                        Err(_) => {
                            shared.count(|c| c.io_errors += 1);
                            break;
                        }
                    }
                }
            });
        }
        self.sockets = sockets;
        self.settings = settings.clone();
        Ok(())
    }
    async fn replace(&mut self, settings: &ReceiverSettings, shared: &Arc<Shared>) -> Result<()> {
        let previous = self.settings.clone();
        self.close().await;
        match self.bind(settings, shared) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.close().await;
                if self.bind(&previous, shared).is_err() {
                    return Err(BoundaryError("snmp_receiver_rollback").into());
                }
                Err(error)
            }
        }
    }
}
struct Policy {
    sender: Arc<Sender>,
    cipher: Vec<u8>,
    next_probe: Instant,
    failures: u32,
    revalidate: bool,
    pending_reconcile: bool,
}
struct Accepted {
    sender: Arc<Sender>,
    receipt: super::records::Receipt,
    received: i64,
}
async fn consume(
    mut input: mpsc::Receiver<Accepted>,
    shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
) {
    while let Some(item) = input.recv().await {
        let _submission = shared.submission_gate.lock().await;
        let _gate = shared.gate.lock().await;
        let result = store.lock().unwrap().ingest_snmp_receipt(
            &item.sender.device.id,
            item.sender.revision,
            item.sender.epoch,
            &item.receipt,
            item.received,
        );
        match result {
            Ok((true, removed)) => {
                shared.urgent(&item.sender);
                shared.count(|c| {
                    c.stored += 1;
                    c.retention_removed += removed as u64;
                });
                if let Some(s) = shared
                    .status
                    .lock()
                    .unwrap()
                    .devices
                    .get_mut(&item.sender.device.id)
                {
                    s.last_received = Some(item.received);
                }
            }
            Ok((false, _)) => shared.count(|c| c.stale += 1),
            Err(_) => shared.count(|c| c.storage_errors += 1),
        }
        drop(_gate);
        drop(_submission);
        tokio::task::yield_now().await;
    }
}
async fn worker(
    shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    vault: Arc<Vault>,
    local: Option<async_snmp::AuthoritativeEngine>,
    mut commands: mpsc::Receiver<Command>,
) {
    let mut bindings = Bindings::empty();
    let mut policies = HashMap::<String, Policy>::new();
    let mut epoch = None;
    let mut revision = -1;
    let mut probes = JoinSet::<(Arc<Sender>, Result<super::polling::AuthenticatedIdentity>)>::new();
    let mut duplicates = super::traps::Duplicates::default();
    let mut post = HashMap::<String, Bucket>::new();
    let mut post_global = Bucket::new(50.0, 100.0);
    let (accepted_tx, accepted_rx) = mpsc::channel(256);
    let mut consumer = tokio::spawn(consume(accepted_rx, shared.clone(), store.clone()));
    let mut ingestion_failed = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_prune = Instant::now();
    let mut next_bind = Instant::now();
    loop {
        tokio::select! {
            _ = &mut consumer => {
                // A failed ingestion task must not leave apparently active UDP
                // reception. A service restart is required after task failure.
                shared.count(|c| c.storage_errors += 1);
                bindings.close().await;
                shared.ingress.lock().unwrap().policies(HashSet::new());
                shared.status.lock().unwrap().active = false;
                shared.status.lock().unwrap().state = "ingestion_failed".into();
                ingestion_failed = true;
                break;
            },
            command=commands.recv()=>match command {
                Some(Command::Stop)|None=>break,
                Some(Command::Save{settings,revision:expected,actor,response})=>{
                    let result=async {
                        settings.validate().context(BoundaryError("snmp_receiver_config_invalid"))?;
                        let _gate=shared.gate.lock().await;
                        let(current,rev)=store.lock().unwrap().receiver_settings()?;ensure!(rev==expected,BoundaryError("device_conflict"));
                        shared.ingress.lock().unwrap().policies(HashSet::new());
                        bindings.replace(&settings,&shared).await?;
                        let save=store.lock().unwrap().save_receiver_settings(&settings,expected,&actor);
                        if let Err(error)=save {bindings.replace(&current,&shared).await?;return Err(error);}
                        epoch=None;revision = -1;Ok(())
                    }.await;
                    epoch=None;
                    publish_binding(&shared,&bindings,store.lock().unwrap().receiver_settings().ok(),if result.is_ok(){None}else{Some("bind_failed")});
                    let _=response.send(result);
                }
            },
            completed=probes.join_next(),if !probes.is_empty()=>{
                if let Some(Ok((sender,result)))=completed {
                    let _gate=shared.gate.lock().await;
                    let current=store.lock().unwrap().receiver_epoch().ok();
                    if current==Some(sender.epoch) && policies.get(&sender.device.id).is_some_and(|p|Arc::ptr_eq(&p.sender,&sender)) {
                        let outcome=result.and_then(|identity:super::polling::AuthenticatedIdentity|sender.seed(identity.engine));
                        if let Some(policy)=policies.get_mut(&sender.device.id) {
                            if outcome.is_ok()&&policy.pending_reconcile {shared.urgent(&sender);policy.pending_reconcile=false;}
                            policy.revalidate=outcome.is_err();policy.failures=if outcome.is_ok(){0}else{policy.failures.saturating_add(1)};
                            policy.next_probe=Instant::now()+Duration::from_secs((10u64<<policy.failures.min(5)).min(300));
                        }
                        if let Some(status)=shared.status.lock().unwrap().devices.get_mut(&sender.device.id){match outcome {Ok(id)=>{status.state="verified".into();status.engine_id=Some(id);},Err(e)=>status.state=crate::dsm::error_code(&e).into()};}
                    }
                }
            },
            _=tick.tick()=>{
                let snapshot=load(&store);
                match snapshot {
                    Ok((settings,rev,current,targets))=>{
                        let failed_socket=bindings.tasks.try_join_next().is_some();
                        if failed_socket {bindings.close().await;next_bind=Instant::now()+Duration::from_secs(5);publish_binding(&shared,&bindings,Some((settings.clone(),rev)),Some("socket_failed"));}
                        if (bindings.settings!=settings || settings.enabled&&bindings.sockets.is_empty()) && Instant::now()>=next_bind {
                            let _gate=shared.gate.lock().await;
                            let result=bindings.replace(&settings,&shared).await;
                            next_bind=Instant::now()+Duration::from_secs(5);
                            epoch=None;
                            publish_binding(&shared,&bindings,Some((settings.clone(),rev)),result.err().map(|_|"bind_failed"));
                        }
                        if epoch!=Some(current)||revision!=rev {
                            let _gate=shared.gate.lock().await;
                            probes.abort_all();while probes.join_next().await.is_some(){}
                            policies.clear();post.clear();duplicates.clear();
                            {let mut u=shared.urgent.lock().unwrap();u.pending.clear();u.started.clear();}
                            shared.ingress.lock().unwrap().policies(HashSet::new());
                            shared.status.lock().unwrap().devices.clear();
                            shared.status.lock().unwrap().omitted_devices=if settings.enabled{targets.len().saturating_sub(256)}else{0};
                            if settings.enabled {
                                for(device,cipher,device_revision)in targets.into_iter().take(256) {
                                    let id=device.id.clone();
                                    let result=async {let plain=vault.unseal(&Purpose::SnmpTraps.aad(&id),&cipher).context(BoundaryError("snmp_credentials"))?;let credentials=serde_json::from_slice::<Credentials>(&plain).map_err(|_|BoundaryError("snmp_credentials"))?;Sender::build(device,device_revision,current,credentials,local.clone()).await}.await;
                                    match result {
                                        Ok(sender)=>{
                                            let state=if !matches!(sender.config.security,Security::V3{..}){"community_unverified"}else if sender.config.engine_ids.is_empty(){"identity_review_required"}else if sender.probe.is_none(){"responder_unconfigured"}else{"verification_pending"};
                                            shared.status.lock().unwrap().devices.insert(id.clone(),DeviceStatus{revision:device_revision,state:state.into(),engine_id:None,last_received:None});
                                            post.insert(id.clone(),Bucket::new(10.0,20.0));policies.insert(id,Policy{sender:Arc::new(sender),cipher,next_probe:Instant::now(),failures:0,revalidate:true,pending_reconcile:false});
                                        },Err(e)=>{shared.status.lock().unwrap().devices.insert(id,DeviceStatus{revision:device_revision,state:crate::dsm::error_code(&e).into(),engine_id:None,last_received:None});},
                                    }
                                    tokio::task::yield_now().await;
                                }
                            }
                            let ips=if bindings.settings==settings&&!bindings.sockets.is_empty(){policies.values().flat_map(|p|p.sender.config.allowed_sources.iter().copied()).collect()}else{HashSet::new()};shared.ingress.lock().unwrap().policies(ips);
                            epoch=Some(current);revision=rev;
                            {let mut status=shared.status.lock().unwrap();status.epoch=current;status.revision=rev;}
                            publish_binding(&shared,&bindings,Some((settings.clone(),rev)),None);
                        }
                        for policy in policies.values_mut() {
                            if probes.len()>=2 {break;}
                            if !matches!(policy.sender.config.security,Security::V3{..})||(!policy.revalidate&&policy.sender.ready())||policy.sender.config.engine_ids.is_empty()||policy.next_probe>Instant::now(){continue;}
                            let Some(config)=policy.sender.probe.clone() else{continue};
                            let sender=policy.sender.clone();let cipher=policy.cipher.clone();let vault=vault.clone();policy.next_probe=Instant::now()+Duration::from_secs(300);
                            probes.spawn(async move {let result=async {let plain=vault.unseal(&Purpose::SnmpTraps.aad(&sender.device.id),&cipher).context(BoundaryError("snmp_credentials"))?;let credentials=serde_json::from_slice::<Credentials>(&plain).map_err(|_|BoundaryError("snmp_credentials"))?;super::polling::authenticated_identity(&config,&credentials).await}.await;(sender,result)});
                        }
                    },Err(_)=>{epoch=None;let mut status=shared.status.lock().unwrap();status.state="storage_unavailable".into();status.active=false;drop(status);shared.ingress.lock().unwrap().policies(HashSet::new());},
                }
                let reconcile=std::mem::take(&mut shared.ingress.lock().unwrap().reconcile);
                for ip in reconcile {let mut matched=policies.values().filter(|p|p.sender.config.allowed_sources.contains(&ip));if let Some(policy)=matched.next(){if matched.next().is_none(){shared.urgent(&policy.sender);}}}
                if Instant::now()>=next_prune {next_prune=Instant::now()+Duration::from_secs(60);match store.lock().unwrap().prune_snmp_receipts(crate::now()){Ok(n)=>shared.count(|c|c.retention_removed+=n as u64),Err(_)=>shared.count(|c|c.storage_errors+=1)};}
                duplicates.prune();
            },
            _=shared.notify.notified()=>{
                let packet=shared.ingress.lock().unwrap().pop();
                if shared.ingress.lock().unwrap().queued>0{shared.notify.notify_one();}
                if let Some(packet)=packet {
                    let senders=policies.values().map(|p|p.sender.clone()).collect::<Vec<_>>();
                    let result=notifications::envelope(packet.data.clone()).and_then(|e|notifications::associate(&senders,packet.source,&e).map(|s|(e,s)));
                    match result {
                        Ok((envelope,Some(sender)))=>{
                            let _gate=shared.gate.lock().await;
                            if store.lock().unwrap().receiver_epoch().ok()!=Some(sender.epoch){shared.count(|c|c.stale+=1);continue;}
                            let time_failures=sender.receiver.usm_not_in_time_windows();
                            match sender.receive(packet.data,packet.source,&envelope).await {
                                Ok(Some(receipt))=>{
                                    if receipt.verified{shared.count(|c|c.verified+=1)}else{shared.count(|c|c.unverified+=1)};
                                    if duplicates.contains(&sender.device.id,&receipt) {
                                        let recovered=receipt.verified&&receipt.event.as_ref().is_some_and(|e|e.class==super::traps::Class::Fault)&&store.lock().unwrap().recovered_since_receipt(&sender.device.id,sender.revision,&receipt.fingerprint).unwrap_or(false);
                                        if !recovered{shared.count(|c|c.duplicates+=1);continue;}
                                    }
                                    if !post.get_mut(&sender.device.id).is_some_and(|b|b.take())||!post_global.take(){shared.count(|c|c.ingestion_limited+=1);shared.urgent(&sender);continue;}
                                    let remembered=receipt.clone();let device_id=sender.device.id.clone();
                                    shared.urgent(&sender);
                                    match accepted_tx.try_send(Accepted{sender,receipt,received:packet.received}){Ok(())=>{duplicates.insert(&device_id,&remembered);},Err(_)=>shared.count(|c|c.queue_dropped+=1)}
                                },
                                Ok(None)=>{shared.count(|c|c.rejected+=1);if sender.receiver.usm_not_in_time_windows()>time_failures {if let Some(p)=policies.get_mut(&sender.device.id){if !p.revalidate{p.next_probe=Instant::now()+Duration::from_secs(10);p.revalidate=true;}}}},
                                Err(e)=>{if crate::dsm::error_code(&e)=="snmp_verification_pending"{shared.count(|c|c.pending+=1);if let Some(p)=policies.get_mut(&sender.device.id){p.pending_reconcile=true;}}else{shared.count(|c|c.rejected+=1)}},
                            }
                        },Ok((envelope,None))=>{
                            shared.count(|c|c.rejected+=1);
                            if let notifications::Envelope::Usm{user,..}=envelope {
                                let matched=policies.iter().filter(|(_,p)|p.sender.config.allowed_sources.contains(&packet.source.ip()) && matches!(&p.sender.config.security,Security::V3{username,..} if username.as_bytes()==user.as_ref())).map(|(id,_)|id.clone()).collect::<Vec<_>>();
                                if matched.len()==1 {if let Some(p)=policies.get_mut(&matched[0]){if !p.revalidate&&p.next_probe<=Instant::now(){p.revalidate=true;p.next_probe=Instant::now();}}}
                            }
                        },Err(e)=>{if crate::dsm::error_code(&e)=="snmp_sender_ambiguous"{shared.count(|c|c.ambiguous+=1)}else{shared.count(|c|c.rejected+=1)}},
                    }
                }
            }
        }
    }
    bindings.close().await;
    probes.abort_all();
    while probes.join_next().await.is_some() {}
    if !ingestion_failed {
        consumer.abort();
        let _ = consumer.await;
    }
    let mut status = shared.status.lock().unwrap();
    status.active = false;
    status.state = if ingestion_failed {
        "ingestion_failed"
    } else {
        "stopped"
    }
    .into();
    status.listening.clear();
}
type Targets = Vec<(Device, Vec<u8>, i64)>;
fn load(store: &Arc<Mutex<Store>>) -> Result<(ReceiverSettings, i64, i64, Targets)> {
    let s = store.lock().unwrap();
    let read = s.0.unchecked_transaction()?;
    let (settings, revision) = s.receiver_settings()?;
    let epoch = s.receiver_epoch()?;
    let mut targets = Vec::new();
    for (device, _, revision) in s.versioned_devices()? {
        if device.enabled && device.snmp_traps.as_ref().is_some_and(|t| t.enabled) {
            if let Some(cipher) = s.protocol_secret(&device.id, Purpose::SnmpTraps)? {
                targets.push((device, cipher, revision));
            }
        }
    }
    read.commit()?;
    Ok((settings, revision, epoch, targets))
}
fn publish_binding(
    shared: &Shared,
    bindings: &Bindings,
    desired: Option<(ReceiverSettings, i64)>,
    error: Option<&str>,
) {
    let mut status = shared.status.lock().unwrap();
    let matches = desired
        .as_ref()
        .is_some_and(|(settings, _)| *settings == bindings.settings);
    if let Some((settings, revision)) = desired {
        status.enabled = settings.enabled;
        status.revision = revision;
    }
    status.listening = bindings
        .sockets
        .iter()
        .filter_map(|s| s.local_addr().ok())
        .collect();
    status.active = !status.listening.is_empty() && status.enabled && matches;
    status.state = error
        .unwrap_or(if status.active {
            "listening"
        } else if status.enabled {
            "bind_failed"
        } else {
            "disabled"
        })
        .into();
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{message::CommunityMessage, pdu::NotificationPdu, Version};
    use serde_json::json;
    use std::net::Ipv4Addr;
    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }
    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    fn packet(id: i32) -> Bytes {
        CommunityMessage::v2c(
            "synthetic-p3",
            NotificationPdu::trap_v2(
                Version::V2c,
                id,
                id as u32,
                &"1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
                vec![],
            )
            .unwrap()
            .into_raw(),
        )
        .unwrap()
        .encode()
        .unwrap()
    }
    fn instance() -> (tempfile::TempDir, Arc<Mutex<Store>>, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(Store::open(dir.path()).unwrap()));
        let vault = Arc::new(Vault::open(&dir.path().join("master.key")).unwrap());
        (dir, store, vault)
    }
    fn device(store: &Arc<Mutex<Store>>, vault: &Vault) -> Device {
        let device:Device=serde_json::from_value(json!({"id":"trap-test","name":"Synthetic trap target","endpoint":"https://example.invalid/","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"snmp_traps":{"enabled":true,"allowed_sources":["127.0.0.1"],"security":{"version":"v2c"}}})).unwrap();
        let secret = vault.seal(&device.id, b"synthetic-redfish").unwrap();
        let updates = super::super::secrets::SecretUpdates {
            snmp_traps: super::super::secrets::SecretUpdate::Replace {
                credentials: Credentials::Community {
                    community: "synthetic-p3".into(),
                },
            },
            ..Default::default()
        };
        let mut s = store.lock().unwrap();
        let prepared =
            super::super::persistence::prepare_secrets(&s, vault, &device, &updates).unwrap();
        s.save_admin_with_snmp(&device, &secret, None, "synthetic", Some(&prepared))
            .unwrap();
        device
    }
    async fn wait_until(test: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !test() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn unknown_source_cannot_spend_approved_quota_and_sources_are_round_robin() {
        let mut ingress = Ingress::new();
        ingress.policies([ip(1), ip(2)].into_iter().collect());
        for _ in 0..1000 {
            assert!(!ingress.enqueue(b"bad", SocketAddr::new(ip(3), 1000)));
        }
        assert_eq!(ingress.global.tokens, 400.0);
        assert!(ingress.queues.is_empty());
        for _ in 0..16 {
            assert!(ingress.enqueue(b"a", SocketAddr::new(ip(1), 1000)));
        }
        assert!(ingress.enqueue(b"b", SocketAddr::new(ip(2), 1000)));
        assert_eq!(ingress.pop().unwrap().source.ip(), ip(1));
        assert_eq!(ingress.pop().unwrap().source.ip(), ip(2));
        for _ in 0..1000 {
            ingress.enqueue(b"bad", SocketAddr::new(ip(1), 1000));
        }
        assert!(ingress.queued <= 256);
        assert!(ingress.counters.queue_dropped > 0);
        assert!(ingress.counters.verification_limited > 0);
        assert!(ingress.enqueue(b"b", SocketAddr::new(ip(2), 1001)));
    }
    #[tokio::test]
    async fn custom_port_receipts_duplicates_informs_and_disable_preserve_poll_state() {
        let (dir, store, vault) = instance();
        let d = device(&store, &vault);
        let service = Service::start(dir.path(), store.clone(), vault);
        let c = service.controller.clone();
        let port = free_port();
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![ip(1)],
            },
            0,
            "synthetic".into(),
        )
        .await
        .unwrap();
        wait_until(|| c.status().devices.contains_key(&d.id)).await;
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = SocketAddr::new(ip(1), port);
        sender.send_to(&packet(1), destination).await.unwrap();
        wait_until(|| c.status().counters.stored == 1).await;
        sender.send_to(&packet(1), destination).await.unwrap();
        wait_until(|| c.status().counters.duplicates == 1).await;
        let receipt = store
            .lock()
            .unwrap()
            .snmp_receipts(None, 20)
            .unwrap()
            .pop()
            .unwrap();
        assert!(!receipt.receipt.verified);
        assert_eq!(receipt.receipt.version.as_deref(), Some("v2c"));
        assert!(c.urgent_due(&d.id, 1, store.lock().unwrap().receiver_epoch().unwrap()));
        let snapshot: Option<String> = store
            .lock()
            .unwrap()
            .0
            .query_row("SELECT snapshot FROM devices", [], |r| r.get(0))
            .unwrap();
        assert!(snapshot.is_none());
        let inform = CommunityMessage::v2c(
            "synthetic-p3",
            NotificationPdu::inform(
                Version::V2c,
                99,
                2,
                &"1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
                vec![],
            )
            .unwrap()
            .into_raw(),
        )
        .unwrap()
        .encode()
        .unwrap();
        sender.send_to(&inform, destination).await.unwrap();
        let mut buffer = [0; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), sender.recv_from(&mut buffer))
                .await
                .is_err()
        );
        c.save(
            ReceiverSettings {
                enabled: false,
                listen_port: port,
                listen_addresses: vec![ip(1)],
            },
            1,
            "synthetic".into(),
        )
        .await
        .unwrap();
        assert!(!c.status().active);
        sender.send_to(&packet(3), destination).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(c.status().counters.stored, 1);
        service.stop().await;
        assert!(UdpSocket::bind(destination).await.is_ok());
    }
    #[tokio::test]
    async fn same_port_wildcard_rebind_and_occupied_port_rollback_use_one_local_engine() {
        let (dir, store, vault) = instance();
        let service = Service::start(dir.path(), store.clone(), vault);
        let c = service.controller.clone();
        let port = free_port();
        let state = std::fs::read(dir.path().join("snmp-engine.json")).unwrap();
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![ip(1)],
            },
            0,
            "synthetic".into(),
        )
        .await
        .unwrap();
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            },
            1,
            "synthetic".into(),
        )
        .await
        .unwrap();
        assert!(c.status().active);
        assert_eq!(
            c.status().listening[0].ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![ip(1)],
            },
            2,
            "synthetic".into(),
        )
        .await
        .unwrap();
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blocked = occupied.local_addr().unwrap().port();
        let error = c
            .save(
                ReceiverSettings {
                    enabled: true,
                    listen_port: blocked,
                    listen_addresses: vec![ip(1)],
                },
                3,
                "synthetic".into(),
            )
            .await
            .unwrap_err();
        assert_eq!(crate::dsm::error_code(&error), "snmp_receiver_bind");
        assert_eq!(
            store
                .lock()
                .unwrap()
                .receiver_settings()
                .unwrap()
                .0
                .listen_port,
            port
        );
        assert_eq!(store.lock().unwrap().receiver_settings().unwrap().1, 3);
        assert!(c.status().active);
        assert_eq!(c.status().listening[0].port(), port);
        assert_eq!(
            std::fs::read(dir.path().join("snmp-engine.json")).unwrap(),
            state
        );
        service.stop().await;
    }
    #[tokio::test]
    async fn dual_family_bind_and_queued_receipt_cannot_cross_restore_epoch() {
        let (dir, store, vault) = instance();
        let d = device(&store, &vault);
        let epoch = store.lock().unwrap().receiver_epoch().unwrap();
        let service = Service::start(dir.path(), store.clone(), vault.clone());
        let c = service.controller.clone();
        let port = free_port();
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![ip(1), "::1".parse().unwrap()],
            },
            0,
            "synthetic".into(),
        )
        .await
        .unwrap();
        assert_eq!(c.status().listening.len(), 2);
        assert!(UdpSocket::bind(SocketAddr::new(ip(1), port)).await.is_err());
        assert!(UdpSocket::bind(format!("[::1]:{port}")).await.is_err());
        let sender = Arc::new(
            Sender::build(
                d.clone(),
                1,
                epoch,
                Credentials::Community {
                    community: "synthetic-p3".into(),
                },
                None,
            )
            .await
            .unwrap(),
        );
        let bytes = packet(1);
        let envelope = notifications::envelope(bytes.clone()).unwrap();
        let receipt = sender
            .receive(bytes, SocketAddr::new(ip(1), 12345), &envelope)
            .await
            .unwrap()
            .unwrap();
        let (tx, rx) = mpsc::channel(1);
        let gate = c.ingestion_gate().lock_owned().await;
        let task = tokio::spawn(consume(rx, c.shared.clone(), store.clone()));
        tx.send(Accepted {
            sender,
            receipt,
            received: crate::now(),
        })
        .await
        .unwrap();
        // This models the same generation barrier that logical restore advances
        // while holding the ingestion gate, even with equal device revisions.
        store
            .lock()
            .unwrap()
            .0
            .execute("UPDATE snmp_runtime SET epoch=epoch+1 WHERE id=1", [])
            .unwrap();
        drop(gate);
        wait_until(|| c.status().counters.stale == 1).await;
        assert!(store
            .lock()
            .unwrap()
            .snmp_receipts(None, 20)
            .unwrap()
            .is_empty());
        drop(tx);
        task.await.unwrap();
        service.stop().await;
        assert!(UdpSocket::bind(format!("[::1]:{port}")).await.is_ok());
    }

    #[tokio::test]
    async fn urgent_polls_coalesce_and_respect_revision_epoch_and_ten_second_gap() {
        let (dir, store, vault) = instance();
        let d = device(&store, &vault);
        let epoch = store.lock().unwrap().receiver_epoch().unwrap();
        let sender = Sender::build(
            d.clone(),
            1,
            epoch,
            Credentials::Community {
                community: "synthetic-p3".into(),
            },
            None,
        )
        .await
        .unwrap();
        let service = Service::start(dir.path(), store, vault);
        let c = &service.controller;
        // Do not yield here: the worker's initial configuration reload clears
        // pending work, as it must after a restore or configuration change.
        for i in 0..300 {
            c.poll_started(&format!("ordinary-{i}"), 1, epoch);
        }
        assert!(c.shared.urgent.lock().unwrap().started.is_empty());
        for _ in 0..100 {
            c.shared.urgent(&sender);
        }
        assert_eq!(c.shared.urgent.lock().unwrap().pending.len(), 1);
        assert!(c.urgent_due(&d.id, 1, epoch));
        assert!(!c.urgent_due(&d.id, 2, epoch));
        assert!(!c.urgent_due(&d.id, 1, epoch + 1));
        c.poll_started(&d.id, 1, epoch);
        c.shared.urgent(&sender);
        assert!(!c.urgent_due(&d.id, 1, epoch));
        c.shared
            .urgent
            .lock()
            .unwrap()
            .started
            .insert(d.id.clone(), Instant::now() - Duration::from_secs(10));
        assert!(c.urgent_due(&d.id, 1, epoch));
        service.stop().await;
    }
    #[tokio::test]
    async fn receipt_commits_wait_for_the_shared_submission_gate() {
        let (dir, store, vault) = instance();
        let d = device(&store, &vault);
        let submission = Arc::new(AsyncMutex::new(()));
        let service = Service::start_with_submission_gate(
            dir.path(),
            store.clone(),
            vault,
            submission.clone(),
        );
        let c = service.controller.clone();
        let port = free_port();
        c.save(
            ReceiverSettings {
                enabled: true,
                listen_port: port,
                listen_addresses: vec![ip(1)],
            },
            0,
            "synthetic".into(),
        )
        .await
        .unwrap();
        wait_until(|| c.status().devices.contains_key(&d.id)).await;
        let held = submission.lock_owned().await;
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&packet(77), SocketAddr::new(ip(1), port))
            .await
            .unwrap();
        wait_until(|| c.status().counters.unverified == 1).await;
        assert_eq!(c.status().counters.stored, 0);
        assert!(store
            .lock()
            .unwrap()
            .snmp_receipts(None, 20)
            .unwrap()
            .is_empty());
        drop(held);
        wait_until(|| c.status().counters.stored == 1).await;
        service.stop().await;
    }
}
