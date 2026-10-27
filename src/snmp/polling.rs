//! Read-only bounded poll sessions. No version fallback and no SET surface.
use super::{
    config::{AuthProtocol, PollConfig, Profile, Security},
    profiles::{self, Data, Identity},
    secrets::Credentials,
    transport::{BoundedUdp, Budget, Statistics},
};
use crate::{
    dsm::BoundaryError,
    model::{Capability, Health, Observation, Snapshot},
};
use anyhow::{ensure, Context, Result};
use async_snmp::{
    Auth, Client, ClientBuilder, DecodeConfig, EngineCache, Error, ErrorStatus, Oid, PrivProtocol,
    ResponseShapePolicy, Retry, UsmConfig, Value, VarBind,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Mutex as AsyncMutex, time::Instant};
const POLL_TIME: Duration = Duration::from_secs(60);
const INVENTORY_TTL: Duration = Duration::from_secs(900);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub system_information: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<super::network::Inventory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpe: Option<super::hpe::Inventory>,
    pub version: String,
    pub profile: Profile,
    pub target: SocketAddr,
    pub sys_object_id: String,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub uptime_ticks: u32,
    pub generation: i64,
    pub agent_restart: bool,
    pub engine_id: Option<String>,
    pub engine_boots: Option<u32>,
    pub complete: bool,
    pub statistics: Statistics,
    pub identities: Vec<Identity>,
}
struct Runtime {
    config: PollConfig,
    revision: i64,
    epoch: i64,
    peer: Option<SocketAddr>,
    cache: Arc<EngineCache>,
    inventory: Data,
    inventory_at: Option<Instant>,
    uptime: Option<(u32, Instant)>,
    engine: Option<(String, u32)>,
    generation: i64,
    failures: u32,
}
impl Runtime {
    fn new(config: PollConfig, revision: i64, epoch: i64) -> Self {
        Self {
            config,
            revision,
            epoch,
            peer: None,
            cache: Arc::new(EngineCache::new().with_max_capacity(2)),
            inventory: Data::new(),
            inventory_at: None,
            uptime: None,
            engine: None,
            generation: (rand::random::<u64>() % (i64::MAX as u64 / 8)) as i64,
            failures: 0,
        }
    }
    fn reset_inventory(&mut self) {
        self.inventory.clear();
        self.inventory_at = None;
        self.generation += 1;
    }
}
#[derive(Default)]
pub struct Poller {
    states: Mutex<HashMap<String, Arc<AsyncMutex<Runtime>>>>,
}
impl Poller {
    pub fn retain(&self, ids: &HashSet<String>) {
        self.states.lock().unwrap().retain(|id, _| ids.contains(id));
    }
    fn state(
        &self,
        id: &str,
        c: &PollConfig,
        revision: i64,
        epoch: i64,
    ) -> Arc<AsyncMutex<Runtime>> {
        let mut states = self.states.lock().unwrap();
        if !states.contains_key(id) && states.len() >= 256 {
            if let Some(key) = states.keys().next().cloned() {
                states.remove(&key);
            }
        }
        states
            .entry(id.into())
            .or_insert_with(|| Arc::new(AsyncMutex::new(Runtime::new(c.clone(), revision, epoch))))
            .clone()
    }
    pub async fn poll(
        &self,
        id: &str,
        c: &PollConfig,
        credentials: &Credentials,
        revision: i64,
        epoch: i64,
    ) -> Result<Snapshot> {
        c.validate().context(BoundaryError("snmp_configuration"))?;
        credentials
            .validate(&c.security)
            .context(BoundaryError("snmp_credentials"))?;
        let state = self.state(id, c, revision, epoch);
        let mut runtime = state.lock().await;
        if runtime.config != *c || runtime.revision != revision || runtime.epoch != epoch {
            *runtime = Runtime::new(c.clone(), revision, epoch);
        }
        let result = poll(c, credentials, &mut runtime, POLL_TIME).await;
        if result.is_err() {
            // A replacement engine at the same IP must be rediscovered on the
            // next bounded poll. Discovery alone never makes that poll succeed.
            if let Some(peer) = runtime.peer {
                runtime.cache.remove(&peer);
            }
            runtime.inventory_at = None;
        }
        runtime.failures = if result
            .as_ref()
            .is_ok_and(|s| s.snmp.as_ref().is_some_and(|m| m.complete))
        {
            0
        } else {
            runtime.failures.saturating_add(1)
        };
        result
    }
    pub async fn delay(&self, id: &str, interval: u64) -> u64 {
        let state = self.states.lock().unwrap().get(id).cloned();
        let Some(state) = state else { return interval };
        let n = state.lock().await.failures;
        if n == 0 {
            interval
        } else {
            let base = interval
                .saturating_mul(1u64 << n.min(4))
                .min(interval.max(900));
            base.saturating_add(rand::random::<u64>() % (base / 10 + 1))
        }
    }
}
pub async fn probe(c: &PollConfig, credentials: &Credentials) -> Result<serde_json::Value> {
    let started = Instant::now();
    let mut runtime = Runtime::new(c.clone(), 0, 0);
    c.validate().context(BoundaryError("snmp_configuration"))?;
    credentials
        .validate(&c.security)
        .context(BoundaryError("snmp_credentials"))?;
    // A probe must fit the existing 20-second API envelope, while ordinary polls
    // retain their independent 60-second budget.
    let snapshot = poll(c, credentials, &mut runtime, Duration::from_secs(15)).await?;
    let metadata = snapshot.snmp.expect("SNMP snapshot");
    Ok(
        serde_json::json!({"protocol":"snmp","elapsed_ms":started.elapsed().as_millis(),"version":metadata.version,"target":metadata.target,"sys_object_id":metadata.sys_object_id,"sys_name":metadata.sys_name,"sys_descr":metadata.sys_descr,"engine_id":metadata.engine_id,"engine_boots":metadata.engine_boots,"profile":metadata.profile,"complete":metadata.complete,"capabilities":snapshot.capabilities,"statistics":metadata.statistics}),
    )
}
fn auth(c: &PollConfig, credentials: &Credentials) -> Result<Auth> {
    Ok(match (&c.security, credentials) {
        (Security::V1 {}, Credentials::Community { community }) => Auth::v1(community.clone()),
        (Security::V2c {}, Credentials::Community { community }) => Auth::v2c(community.clone()),
        (
            Security::V3 { username, auth, .. },
            Credentials::Usm {
                auth_password,
                priv_password,
            },
        ) => Auth::Usm(
            UsmConfig::new(username.clone())
                .auth_priv(
                    match auth {
                        AuthProtocol::Sha1 => async_snmp::AuthProtocol::Sha1,
                        AuthProtocol::Sha256 => async_snmp::AuthProtocol::Sha256,
                    },
                    auth_password.as_bytes(),
                    PrivProtocol::Aes128,
                    priv_password.as_bytes(),
                )
                .map_err(|_| BoundaryError("snmp_credentials"))?
                .context_name(c.context_name.clone()),
        ),
        _ => return Err(BoundaryError("snmp_credentials").into()),
    })
}
fn code(error: &Error) -> &'static str {
    match error.exchange_source() {
        Error::Timeout { .. } => "snmp_timeout",
        Error::Auth { .. } | Error::Report { .. } => "snmp_authentication",
        Error::Network { .. } => "snmp_network",
        Error::Config(s) if s.as_ref() == "snmp_request_limit" => "snmp_request_limit",
        Error::Config(s) if s.as_ref() == "snmp_byte_limit" => "snmp_byte_limit",
        Error::Config(s) if s.as_ref() == "snmp_item_limit" => "snmp_item_limit",
        Error::Config(s) if s.as_ref() == "snmp_response_limit" => "snmp_response_limit",
        Error::Snmp { .. } => "snmp_agent_error",
        _ => "snmp_invalid_response",
    }
}
fn mapped(e: Box<Error>) -> anyhow::Error {
    BoundaryError(code(&e)).into()
}
struct Session {
    client: Client<BoundedUdp>,
    v1: bool,
}
impl Session {
    fn values(&self, values: &[VarBind]) -> Result<()> {
        ensure!(
            !self.v1
                || !values.iter().any(|v| matches!(
                    v.value,
                    Value::Counter64(_)
                        | Value::NoSuchObject
                        | Value::NoSuchInstance
                        | Value::EndOfMibView
                )),
            BoundaryError("snmp_invalid_response")
        );
        Ok(())
    }
    /// Preserve every successful tooBig split; v1 removes exactly one failing
    /// cursor, using the error index relative to the *failed leaf*.
    async fn fixed(
        &self,
        oids: &[Oid],
        next: bool,
        data: &mut Data,
    ) -> Result<Vec<Option<VarBind>>> {
        let mut output = vec![None; oids.len()];
        let mut pending = VecDeque::from([(0..oids.len()).collect::<Vec<_>>()]);
        while let Some(indices) = pending.pop_front() {
            if indices.is_empty() {
                continue;
            }
            let requested = indices.iter().map(|i| oids[*i].clone()).collect::<Vec<_>>();
            let mut chunks = if next {
                self.client.get_next_many_chunks(&requested)
            } else {
                self.client.get_many_chunks(&requested)
            }
            .map_err(mapped)?;
            while let Some(item) = chunks.next().await {
                match item {
                    Ok(chunk) => {
                        let vals = chunk.response.varbinds;
                        self.values(&vals)?;
                        ensure!(
                            vals.len() == chunk.request_range.len(),
                            BoundaryError("snmp_invalid_response")
                        );
                        for (local, v) in chunk.request_range.zip(vals) {
                            let index = indices[local];
                            if !v.value.is_exception() {
                                data.insert(v.oid.clone(), v.value.clone());
                            }
                            output[index] = Some(v);
                        }
                    }
                    Err(failed) => {
                        let leaf = failed.failed_request_range.clone();
                        if let Error::Snmp {
                            status: ErrorStatus::NoSuchName,
                            index,
                            oid,
                            ..
                        } = failed.source.exchange_source()
                        {
                            ensure!(
                                self.v1 && *index > 0 && (*index as usize) <= leaf.len(),
                                BoundaryError("snmp_invalid_response")
                            );
                            let local = leaf.start + *index as usize - 1;
                            ensure!(
                                oid.as_deref().is_some_and(|o| *o == requested[local]),
                                BoundaryError("snmp_invalid_response")
                            );
                            let rest = indices
                                .iter()
                                .enumerate()
                                .skip(leaf.start)
                                .filter(|(i, _)| *i != local)
                                .map(|(_, i)| *i)
                                .collect::<Vec<_>>();
                            pending.push_front(rest);
                        } else {
                            return Err(mapped(failed.source));
                        }
                        break;
                    }
                }
            }
        }
        Ok(output)
    }
    async fn walk(&self, roots: &[Oid], data: &mut Data) -> Result<()> {
        for batch in roots.chunks(8) {
            let mut cursors = batch.to_vec();
            let mut active = vec![true; batch.len()];
            let mut repetitions = 10;
            let mut bulk = !self.v1;
            while active.iter().any(|b| *b) {
                let indices = (0..batch.len()).filter(|i| active[*i]).collect::<Vec<_>>();
                let requested = indices
                    .iter()
                    .map(|i| cursors[*i].clone())
                    .collect::<Vec<_>>();
                if !bulk {
                    let mut leaf = Data::new();
                    let values = match self.fixed(&requested, true, &mut leaf).await {
                        Ok(values) => values,
                        Err(error) => {
                            // Successful leaves of a split are already validated
                            // by the strict client. Preserve only approved roots.
                            for (oid, value) in leaf {
                                if batch.iter().enumerate().any(|(i, root)| {
                                    active[i]
                                        && oid > cursors[i]
                                        && oid.arcs().starts_with(root.arcs())
                                        && oid.len() > root.len()
                                }) {
                                    data.insert(oid, value);
                                }
                            }
                            return Err(error);
                        }
                    };
                    for (i, value) in indices.iter().zip(values) {
                        let Some(value) = value else {
                            active[*i] = false;
                            continue;
                        };
                        advance(&batch[*i], &mut cursors[*i], &mut active[*i], value, data)?;
                    }
                } else {
                    match self.client.get_bulk(&requested, 0, repetitions).await {
                        Ok(values) => {
                            self.values(&values)?;
                            ensure!(
                                values.len() <= indices.len() * repetitions as usize,
                                BoundaryError("snmp_invalid_response")
                            );
                            if values.is_empty() {
                                bulk = false;
                                continue;
                            }
                            for (position, value) in values.into_iter().enumerate() {
                                let i = indices[position % indices.len()];
                                if active[i] {
                                    advance(
                                        &batch[i],
                                        &mut cursors[i],
                                        &mut active[i],
                                        value,
                                        data,
                                    )?;
                                }
                            }
                            // Truncated repetitions are legal. Every live cursor
                            // must nevertheless make progress before the next call.
                            if indices.iter().any(|i| {
                                active[*i]
                                    && cursors[*i]
                                        == requested[indices.iter().position(|j| i == j).unwrap()]
                            }) {
                                bulk = false;
                            }
                        }
                        Err(e) => match e.exchange_source() {
                            Error::Snmp {
                                status: ErrorStatus::TooBig,
                                ..
                            }
                            | Error::OutboundMessageTooLarge { .. } => {
                                if repetitions > 1 {
                                    repetitions = (repetitions / 2).max(1)
                                } else {
                                    bulk = false;
                                }
                            }
                            Error::Config(s) if s.as_ref() == "snmp_response_limit" => {
                                if repetitions > 1 {
                                    repetitions = (repetitions / 2).max(1)
                                } else {
                                    bulk = false;
                                }
                            }
                            _ => return Err(mapped(e)),
                        },
                    }
                }
            }
        }
        Ok(())
    }
}
fn advance(
    root: &Oid,
    cursor: &mut Oid,
    active: &mut bool,
    v: VarBind,
    data: &mut Data,
) -> Result<()> {
    if v.value.is_exception() {
        *active = false;
        return Ok(());
    }
    ensure!(v.oid > *cursor, BoundaryError("snmp_non_increasing_oid"));
    if !v.oid.arcs().starts_with(root.arcs()) {
        *active = false;
        return Ok(());
    }
    ensure!(
        v.oid.len() > root.len(),
        BoundaryError("snmp_invalid_response")
    );
    *cursor = v.oid.clone();
    data.insert(v.oid, v.value);
    Ok(())
}
/// Modular uptime alone identifies an agent epoch, never a host power cycle.
fn restarted(previous: Option<(u32, Instant)>, now: u32, at: Instant) -> bool {
    let Some((old, observed)) = previous else {
        return false;
    };
    let elapsed = at.duration_since(observed).as_secs_f64() * 100.0;
    let delta = now.wrapping_sub(old) as f64;
    // Longer gaps are ambiguous, so discard index-only mappings conservatively.
    elapsed >= u32::MAX as f64 || (delta - elapsed).abs() > (elapsed * 0.1 + 500.0)
}
async fn poll(
    c: &PollConfig,
    credentials: &Credentials,
    r: &mut Runtime,
    duration: Duration,
) -> Result<Snapshot> {
    let v1 = matches!(c.security, Security::V1 {});
    let budget = Budget::new(v1, duration);
    let addresses = tokio::time::timeout_at(
        budget.deadline.min(Instant::now() + Duration::from_secs(3)),
        tokio::net::lookup_host((c.host.as_str(), c.port)),
    )
    .await
    .context(BoundaryError("snmp_dns"))?
    .context(BoundaryError("snmp_dns"))?
    .take(17)
    .collect::<Vec<_>>();
    ensure!(
        !addresses.is_empty() && addresses.len() <= 16,
        BoundaryError("snmp_dns")
    );
    let peer = r
        .peer
        .filter(|p| addresses.contains(p))
        .unwrap_or(addresses[0]);
    if r.peer.is_some_and(|p| p != peer) {
        r.cache = Arc::new(EngineCache::new().with_max_capacity(2));
        r.reset_inventory();
        r.uptime = None;
        r.engine = None;
    }
    r.peer = Some(peer);
    let transport = BoundedUdp::bind(peer, budget.clone())
        .await
        .context(BoundaryError("snmp_network"))?;
    let client = ClientBuilder::new(auth(c, credentials)?)
        .request_timeout(Duration::from_millis(c.timeout_ms))
        .exchange_timeout(Some(Duration::from_millis(
            c.timeout_ms * (c.retries as u64 + 1),
        )))
        .retry(Retry::fixed(c.retries.into(), Duration::ZERO).expect("validated retry"))
        .max_oids_per_request(8)
        .decode_config(DecodeConfig::STRICT)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .engine_cache(r.cache.clone())
        .allow_unauthenticated_v3_time_correction(false)
        .build_with_transport(transport)
        .map_err(mapped)?;
    let session = Session { client, v1 };
    let mut data = Data::new();
    let mut capabilities = Vec::new();
    let mut restarted_agent = false;
    let mut root_ok = false;
    let mut uptime = 0;
    let mut sys_object_id = String::new();
    let mut engine = None;
    let mut complete = true;
    let mut ups_alarm_after = None;
    let operation = async {
        // Establish actual current identity before optional profile operations.
        session
            .fixed(
                &[
                    profiles::oid("1.3.6.1.2.1.1.2.0"),
                    profiles::oid("1.3.6.1.2.1.1.3.0"),
                ],
                false,
                &mut data,
            )
            .await?;
        let Some(Value::ObjectIdentifier(id)) = data.get(&profiles::oid("1.3.6.1.2.1.1.2.0"))
        else {
            return Err(BoundaryError("snmp_identity_incomplete").into());
        };
        sys_object_id = id.to_string();
        let Some(Value::TimeTicks(ticks)) = data.get(&profiles::oid("1.3.6.1.2.1.1.3.0")) else {
            return Err(BoundaryError("snmp_identity_incomplete").into());
        };
        uptime = *ticks;
        if matches!(c.security, Security::V3 { .. }) {
            let state = r
                .cache
                .get(&peer)
                .ok_or(BoundaryError("snmp_authentication"))?;
            let time = state
                .authenticated_time()
                .ok_or(BoundaryError("snmp_authentication"))?;
            let id = state
                .engine_id()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            ensure!(
                c.context_engine_id
                    .as_ref()
                    .is_none_or(|expected| expected.eq_ignore_ascii_case(&id)),
                BoundaryError("snmp_engine_mismatch")
            );
            engine = Some((id, time.boots()));
        }
        let at = Instant::now();
        restarted_agent = restarted(r.uptime, uptime, at)
            || r.engine
                .as_ref()
                .zip(engine.as_ref())
                .is_some_and(|(a, b)| a != b);
        if restarted_agent {
            r.reset_inventory();
        }
        r.uptime = Some((uptime, at));
        r.engine = engine.clone();
        root_ok = true;
        capabilities.push(Capability {
            optional: false,
            uri: "snmp:system".into(),
            outcome: "available".into(),
            http_status: None,
            attempts: 1,
        });
        session
            .fixed(
                &profiles::scalar_oids(c.profile)
                    .into_iter()
                    .filter(|o| !data.contains_key(o))
                    .collect::<Vec<_>>(),
                false,
                &mut data,
            )
            .await?;
        let refresh = r
            .inventory_at
            .is_none_or(|at| at.elapsed() >= INVENTORY_TTL);
        if !refresh {
            // Physical identities are read every poll. Only descriptive inventory
            // may be reused; a cached serial must never authorize recovery.
            let identity_roots = profiles::tables(c.profile)
                .into_iter()
                .filter_map(|t| {
                    t.identity
                        .map(|column| profiles::oid(&format!("{}.{column}", t.entry)))
                })
                .collect::<Vec<_>>();
            data.extend(
                r.inventory
                    .iter()
                    .filter(|(o, _)| {
                        !identity_roots
                            .iter()
                            .any(|root| o.arcs().starts_with(root.arcs()))
                    })
                    .map(|(o, v)| (o.clone(), v.clone())),
            );
        }
        for table in profiles::tables(c.profile) {
            let roots = table
                .roots()
                .into_iter()
                .filter(|o| {
                    !(v1 && table.name == "interfaces_extended"
                        && matches!(o.arcs().last(), Some(6 | 10)))
                })
                .filter(|o| {
                    refresh
                        || !table.inventory.contains(o.arcs().last().unwrap())
                        || table.identity == o.arcs().last().copied()
                })
                .collect::<Vec<_>>();
            let result = session.walk(&roots, &mut data).await;
            // A newly appearing row requires identity discovery immediately.
            let unknown_row = !refresh
                && profiles::rows(&table, &data)
                    .values()
                    .any(|row| table.inventory.iter().any(|col| !row.contains_key(col)));
            let result = if result.is_ok() && unknown_row {
                session
                    .walk(
                        &table
                            .roots()
                            .into_iter()
                            .filter(|o| table.inventory.contains(o.arcs().last().unwrap()))
                            .collect::<Vec<_>>(),
                        &mut data,
                    )
                    .await
            } else {
                result
            };
            let base = profiles::oid(table.entry);
            let invalid_index = data
                .keys()
                .filter_map(|o| o.arcs().strip_prefix(base.arcs()))
                .any(|tail| tail.len() < 2 || !table.valid_index(&tail[1..]));
            let result = if invalid_index {
                Err(BoundaryError("snmp_invalid_response").into())
            } else {
                result
            };
            let populated = !profiles::rows(&table, &data).is_empty();
            let outcome = match &result {
                Ok(()) if populated => "available",
                Ok(()) => "unsupported",
                Err(e) => {
                    complete = false;
                    crate::dsm::error_code(e)
                }
            };
            capabilities.push(Capability {
                optional: profiles::optional_group(c.profile, table.name),
                uri: format!("snmp:{}:{}", table.name, table.entry),
                outcome: outcome.into(),
                http_status: None,
                attempts: 1,
            });
            if result.is_err() {
                result?;
            }
            if table.name == "ups_alarms" {
                if let Some(root) = super::ups::alarm_count_oid(c.profile) {
                    let mut after = Data::new();
                    session
                        .fixed(&[profiles::oid(root)], false, &mut after)
                        .await?;
                    ups_alarm_after = after.remove(&profiles::oid(root));
                }
            }
        }
        // Cache only inventory columns, never status, readings or proof of a
        // successful current poll. Missing rows disappear on the next refresh.
        let mut inventory = Data::new();
        for table in profiles::tables(c.profile) {
            for root in table
                .roots()
                .into_iter()
                .filter(|o| table.inventory.contains(o.arcs().last().unwrap()))
            {
                for (o, v) in &data {
                    if o.arcs().starts_with(root.arcs()) {
                        inventory.insert(o.clone(), v.clone());
                    }
                }
            }
        }
        if refresh && !r.inventory.is_empty() && r.inventory != inventory {
            // An inventory change makes unproven row identities ambiguous.
            // FQDD/serial keys are independent of this generation.
            r.generation += 1;
        }
        let cache_bytes = inventory
            .iter()
            .map(|(o, v)| {
                o.len() * 4
                    + match v {
                        Value::OctetString(bytes) => bytes.len(),
                        _ => 16,
                    }
                    + 64
            })
            .sum::<usize>();
        if inventory.len() > 512 || cache_bytes > 128 * 1024 {
            // Oversized inventory stays a bounded current-poll result. Rewalk
            // next time rather than growing every device's long-lived cache.
            r.inventory.clear();
            r.inventory_at = None;
        } else {
            r.inventory = inventory;
            if refresh {
                r.inventory_at = Some(Instant::now());
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::time::timeout_at(budget.deadline, operation)
        .await
        .unwrap_or_else(|_| Err(BoundaryError("snmp_deadline").into()));
    if !root_ok {
        return result.and_then(|_| Err(BoundaryError("snmp_identity_incomplete").into()));
    }
    if let Err(error) = result {
        complete = false;
        capabilities.push(Capability {
            optional: false,
            uri: "snmp:poll".into(),
            outcome: crate::dsm::error_code(&error).into(),
            http_status: None,
            attempts: 1,
        });
    }
    let (mut snapshot, identities) =
        profiles::normalize(c.profile, &data, r.generation, Some(uptime));
    if !super::ups::finish_alarms(
        c.profile,
        &data,
        ups_alarm_after.as_ref(),
        &mut snapshot,
        &mut capabilities,
    ) {
        complete = false;
    }
    snapshot.observations.push(Observation {
        key: "collector".into(),
        label: if complete {
            "SNMP-Abfrage erfolgreich"
        } else {
            "SNMP-Abfrage unvollständig"
        }
        .into(),
        health: if complete {
            Health::Ok
        } else {
            Health::Warning
        },
        reading: None,
        unit: None,
    });
    // Never regard an identity-only response or missing profile groups as full
    // hardware coverage, even when transport communication succeeded.
    if capabilities.iter().any(Capability::blocks_assessment) {
        snapshot.observations.push(Observation {
            key: "snmp:coverage".into(),
            label: "SNMP · Hardware-Abdeckung unvollständig".into(),
            health: Health::Unknown,
            reading: None,
            unit: None,
        });
    }
    snapshot.capabilities = capabilities;
    snapshot.snmp = Some(Metadata {
        system_information: [
            ("sys_name", "1.3.6.1.2.1.1.5.0"),
            ("sys_descr", "1.3.6.1.2.1.1.1.0"),
            ("sys_contact", "1.3.6.1.2.1.1.4.0"),
            ("sys_location", "1.3.6.1.2.1.1.6.0"),
        ]
        .into_iter()
        .filter_map(|(name, root)| {
            profiles::text(data.get(&profiles::oid(root))).map(|v| (name.into(), v))
        })
        .collect(),
        network: (c.profile == Profile::NetworkGeneric).then(|| {
            super::network::discover(
                &data,
                snapshot
                    .capabilities
                    .iter()
                    .any(|c| c.uri.starts_with("snmp:interfaces:") && c.outcome == "available"),
                &format!(
                    "{peer}:{sys_object_id}:{}",
                    engine.as_ref().map(|e| e.0.as_str()).unwrap_or("community")
                ),
            )
        }),
        hpe: (c.profile == Profile::HpeIlo5).then(|| super::hpe::inventory(&data)),
        version: match c.security {
            Security::V1 {} => "v1",
            Security::V2c {} => "v2c",
            Security::V3 { .. } => "v3",
        }
        .into(),
        profile: c.profile,
        target: peer,
        sys_object_id,
        sys_name: profiles::text(data.get(&profiles::oid("1.3.6.1.2.1.1.5.0"))),
        sys_descr: profiles::text(data.get(&profiles::oid("1.3.6.1.2.1.1.1.0"))),
        uptime_ticks: uptime,
        generation: r.generation,
        agent_restart: restarted_agent,
        engine_id: engine.as_ref().map(|e| e.0.clone()),
        engine_boots: engine.map(|e| e.1),
        complete,
        statistics: budget.stats(),
        identities,
    });
    if let Some(metadata) = &mut snapshot.snmp {
        metadata
            .system_information
            .extend(super::ups::system_information(c.profile, &data));
    }
    Ok(snapshot)
}

/// Dedicated saved-target enrollment/time read. It never walks hardware tables
/// or writes a measurement snapshot, including for Redfish-primary devices.
pub struct AuthenticatedIdentity {
    pub target: SocketAddr,
    pub engine: async_snmp::v3::EngineState,
    pub sys_object_id: String,
}
pub async fn authenticated_identity(
    c: &PollConfig,
    credentials: &Credentials,
) -> Result<AuthenticatedIdentity> {
    c.validate().context(BoundaryError("snmp_configuration"))?;
    ensure!(
        matches!(c.security, Security::V3 { .. }),
        BoundaryError("snmp_authentication")
    );
    credentials
        .validate(&c.security)
        .context(BoundaryError("snmp_credentials"))?;
    let budget = Budget::new(false, Duration::from_secs(8));
    let operation = async {
        let addresses = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((c.host.as_str(), c.port)),
        )
        .await
        .context(BoundaryError("snmp_dns"))?
        .context(BoundaryError("snmp_dns"))?
        .take(17)
        .collect::<Vec<_>>();
        ensure!(
            !addresses.is_empty() && addresses.len() <= 16,
            BoundaryError("snmp_dns")
        );
        let target = addresses[0];
        let transport = BoundedUdp::bind(target, budget.clone())
            .await
            .context(BoundaryError("snmp_network"))?;
        let cache = Arc::new(EngineCache::new().with_max_capacity(1));
        let client = ClientBuilder::new(auth(c, credentials)?)
            .request_timeout(Duration::from_millis(c.timeout_ms.min(2000)))
            .exchange_timeout(Some(Duration::from_secs(4)))
            .retry(Retry::none())
            .decode_config(DecodeConfig::STRICT)
            .response_shape_policy(ResponseShapePolicy::Strict)
            .engine_cache(cache.clone())
            .allow_unauthenticated_v3_time_correction(false)
            .build_with_transport(transport)
            .map_err(mapped)?;
        let response = client
            .get(&profiles::oid("1.3.6.1.2.1.1.2.0"))
            .await
            .map_err(mapped)?;
        let Some(Value::ObjectIdentifier(id)) = response.varbinds.first().map(|v| &v.value) else {
            return Err(BoundaryError("snmp_identity_incomplete").into());
        };
        let engine = cache
            .get(&target)
            .filter(|e| e.authenticated_time().is_some())
            .ok_or(BoundaryError("snmp_authentication"))?;
        let observed = engine
            .engine_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        ensure!(
            c.context_engine_id
                .as_ref()
                .is_none_or(|expected| expected.eq_ignore_ascii_case(&observed)),
            BoundaryError("snmp_engine_mismatch")
        );
        Ok(AuthenticatedIdentity {
            target,
            engine,
            sys_object_id: id.to_string(),
        })
    };
    tokio::time::timeout_at(budget.deadline, operation)
        .await
        .context(BoundaryError("snmp_timeout"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{
        message::CommunityMessage,
        pdu::{ErrorIndex, OutboundErrorStatus, PduType, ResponsePdu},
        Version,
    };
    use bytes::Bytes;
    use tokio::net::UdpSocket;
    fn config(port: u16, v1: bool, profile: Profile) -> PollConfig {
        serde_json::from_value(serde_json::json!({"host":"127.0.0.1","port":port,"security":{"version":if v1{"v1"}else{"v2c"}},"profile":profile,"timeout_ms":100,"retries":0})).unwrap()
    }
    fn community() -> Credentials {
        Credentials::Community {
            community: "synthetic-p2".into(),
        }
    }
    fn system() -> Data {
        [
            (
                "1.3.6.1.2.1.1.2.0",
                Value::ObjectIdentifier(profiles::oid("1.3.6.1.4.1.674.10892.5")),
            ),
            ("1.3.6.1.2.1.1.3.0", Value::TimeTicks(5000)),
            (
                "1.3.6.1.2.1.1.1.0",
                Value::OctetString(Bytes::from_static(b"synthetic BMC")),
            ),
            (
                "1.3.6.1.2.1.1.5.0",
                Value::OctetString(Bytes::from_static(b"synthetic")),
            ),
        ]
        .into_iter()
        .map(|(o, v)| (profiles::oid(o), v))
        .collect()
    }
    struct Agent {
        port: u16,
        task: tokio::task::JoinHandle<()>,
        requests: Arc<Mutex<Vec<PduType>>>,
        bulk: Arc<Mutex<Vec<u32>>>,
        data: Arc<Mutex<Data>>,
    }
    impl Drop for Agent {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn agent(data: Data, too_big: bool, drop_after: Option<usize>) -> Agent {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        let bulk = Arc::new(Mutex::new(Vec::new()));
        let repetitions = bulk.clone();
        let shared = Arc::new(Mutex::new(data));
        let input = shared.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65536];
            loop {
                let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let m = CommunityMessage::decode(
                    Bytes::copy_from_slice(&buffer[..n]),
                    DecodeConfig::STRICT,
                )
                .unwrap()
                .value;
                let data = input.lock().unwrap().clone();
                let version = m.version();
                let pdu = m.into_pdu().unwrap();
                let kind = pdu.pdu_type();
                let id = pdu.request_id();
                let vars = pdu.varbinds();
                let count = {
                    let mut count = log.lock().unwrap();
                    count.push(kind);
                    count.len()
                };
                if drop_after.is_some_and(|limit| count > limit) {
                    continue;
                }
                assert!(matches!(
                    kind,
                    PduType::GetRequest | PduType::GetNextRequest | PduType::GetBulkRequest
                ));
                let mut values = Vec::new();
                let mut missing = None;
                let mut big = false;
                if kind == PduType::GetRequest {
                    for (i, var) in vars.iter().enumerate() {
                        match data.get(&var.oid) {
                            Some(v) => values.push(VarBind::new(var.oid.clone(), v.clone())),
                            None if version == Version::V1 => {
                                missing = Some(i + 1);
                                break;
                            }
                            None => {
                                values.push(VarBind::new(var.oid.clone(), Value::NoSuchInstance))
                            }
                        }
                    }
                } else {
                    let reps = if kind == PduType::GetBulkRequest {
                        let (_, r) = pdu.get_bulk_fields().unwrap();
                        repetitions.lock().unwrap().push(r);
                        r
                    } else {
                        1
                    };
                    big = too_big && reps > 1;
                    let mut cursors = vars.iter().map(|v| v.oid.clone()).collect::<Vec<_>>();
                    for _ in 0..reps {
                        for (i, cursor) in cursors.iter_mut().enumerate() {
                            if let Some((oid, v)) = data
                                .range((
                                    std::ops::Bound::Excluded(cursor.clone()),
                                    std::ops::Bound::Unbounded,
                                ))
                                .next()
                            {
                                values.push(VarBind::new(oid.clone(), v.clone()));
                                *cursor = oid.clone();
                            } else if version == Version::V1 {
                                missing = Some(i + 1);
                                break;
                            } else {
                                values.push(VarBind::new(cursor.clone(), Value::EndOfMibView));
                            }
                        }
                    }
                }
                let response = if big {
                    ResponsePdu::too_big(version, id, Vec::new()).unwrap()
                } else if let Some(index) = missing {
                    ResponsePdu::new(
                        version,
                        id,
                        OutboundErrorStatus::NoSuchName,
                        Some(ErrorIndex::new(index as u32, vars.len()).unwrap()),
                        vars.to_vec(),
                    )
                    .unwrap()
                } else {
                    ResponsePdu::success(version, id, values).unwrap()
                };
                let message = if version == Version::V1 {
                    CommunityMessage::v1("synthetic-p2", response.into_raw())
                } else {
                    CommunityMessage::v2c("synthetic-p2", response.into_raw())
                }
                .unwrap();
                socket
                    .send_to(&message.encode().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Agent {
            port,
            task,
            requests,
            bulk,
            data: shared,
        }
    }
    #[tokio::test]
    async fn v1_sparse_multi_index_rows_and_missing_scalars_never_use_bulk_or_set() {
        let mut data = system();
        data.remove(&profiles::oid("1.3.6.1.2.1.1.5.0"));
        let base = "1.3.6.1.4.1.674.10892.5.4.600.12.1";
        for (column, index, value) in [
            (5, "1.2", Value::Integer(5)),
            (5, "2.2", Value::Integer(3)),
            (8, "2.2", Value::OctetString(Bytes::from_static(b"PSU B"))),
            (15, "1.2", Value::OctetString(Bytes::from_static(b"PSU.A"))),
            (15, "2.2", Value::OctetString(Bytes::from_static(b"PSU.B"))),
        ] {
            data.insert(profiles::oid(&format!("{base}.{column}.{index}")), value);
        }
        let a = agent(data, false, None).await;
        let poller = Poller::default();
        let c = config(a.port, true, Profile::DellIdrac);
        let snapshot = poller.poll("x", &c, &community(), 1, 0).await.unwrap();
        let psus = snapshot
            .observations
            .iter()
            .filter(|o| o.key.starts_with("snmp:power_supply:"))
            .collect::<Vec<_>>();
        assert_eq!(psus.len(), 2);
        assert!(psus.iter().any(|o| o.health == Health::Critical));
        assert!(psus
            .iter()
            .any(|o| o.label.contains("PSU B") && o.health == Health::Ok));
        assert!(a
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|p| matches!(p, PduType::GetRequest | PduType::GetNextRequest)));
        assert_eq!(
            snapshot.snmp.as_ref().unwrap().statistics.requests,
            a.requests.lock().unwrap().len()
        );
        let stable = psus
            .iter()
            .find(|o| o.health == Health::Critical)
            .unwrap()
            .key
            .clone();
        let snapshot = poller.poll("x", &c, &community(), 1, 0).await.unwrap();
        assert!(snapshot
            .observations
            .iter()
            .any(|o| o.key == stable && o.health == Health::Critical));
        let mut v2 = c.clone();
        v2.security = Security::V2c {};
        let snapshot = poller.poll("x", &v2, &community(), 2, 0).await.unwrap();
        assert!(snapshot
            .observations
            .iter()
            .any(|o| o.key == stable && o.health == Health::Critical));
    }
    #[tokio::test]
    async fn reboot_changes_unproven_generation_and_missing_rows_retain_faults() {
        let mut data = system();
        let base = "1.3.6.1.4.1.674.10892.5.4.600.12.1";
        data.insert(profiles::oid(&format!("{base}.5.1.1")), Value::Integer(5));
        data.insert(
            profiles::oid(&format!("{base}.15.1.1")),
            Value::OctetString(Bytes::from_static(b"PSU.Test")),
        );
        let a = agent(data, false, None).await;
        let c = config(a.port, true, Profile::DellIdrac);
        let poller = Poller::default();
        let first = poller
            .poll("fixture", &c, &community(), 1, 0)
            .await
            .unwrap();
        let key = first
            .observations
            .iter()
            .find(|o| o.health == Health::Critical)
            .unwrap()
            .key
            .clone();
        let generation = first.snmp.as_ref().unwrap().generation;
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::store::Store::open(dir.path()).unwrap();
        let d:crate::model::Device=serde_json::from_value(serde_json::json!({"id":"fixture","name":"Synthetic SNMP","primary_protocol":"snmp","snmp_poll":c,"interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true})).unwrap();
        let vault = crate::vault::Vault::open(&dir.path().join("master.key")).unwrap();
        let updates = super::super::secrets::SecretUpdates {
            snmp_poll: super::super::secrets::SecretUpdate::Replace {
                credentials: community(),
            },
            ..Default::default()
        };
        let prepared =
            super::super::persistence::prepare_secrets(&store, &vault, &d, &updates).unwrap();
        store
            .save_admin_with_snmp(&d, b"", None, "synthetic", Some(&prepared))
            .unwrap();
        store.apply(&d, &first, 100).unwrap();
        let target = store.poll_targets().unwrap().pop().unwrap();
        assert_eq!(target.0.id, d.id);
        assert!(!target.1.is_empty());
        assert_eq!(target.2, 1);
        assert!(vault
            .unseal(
                &super::super::secrets::Purpose::SnmpPoll.aad(&d.id),
                &target.1
            )
            .is_ok());
        super::super::persistence::invalidate(&store.0).unwrap();
        assert!(!store
            .apply_revision_epoch(&d, &first, 101, Some(target.2), Some(target.3))
            .unwrap());
        let error = anyhow::anyhow!(BoundaryError("snmp_timeout"));
        assert!(!store
            .poll_failure_epoch(&d, 101, target.2, target.3, &error)
            .unwrap());

        {
            let mut data = a.data.lock().unwrap();
            data.insert(profiles::oid("1.3.6.1.2.1.1.3.0"), Value::TimeTicks(1));
            data.remove(&profiles::oid(&format!("{base}.5.1.1")));
        }
        let second = poller
            .poll("fixture", &c, &community(), 1, 0)
            .await
            .unwrap();
        assert!(second.snmp.as_ref().unwrap().agent_restart);
        assert_ne!(second.snmp.as_ref().unwrap().generation, generation);
        store.apply(&d, &second, 110).unwrap();
        let health: String = store
            .0
            .query_row(
                "SELECT health FROM alarm_state WHERE device=?1 AND key=?2",
                rusqlite::params![d.id, key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Health>(&health).unwrap(),
            Health::Critical
        );
        assert!(!second
            .observations
            .iter()
            .any(|o| o.key == key && o.health == Health::Ok));
        assert!(poller.delay("fixture", 60).await >= 60);
    }
    #[tokio::test]
    async fn bulk_too_big_reduces_repetitions_then_keeps_values() {
        let mut data = system();
        for (c, v) in [
            (1, Value::Integer(8)),
            (2, Value::Integer(9)),
            (3, Value::Integer(1)),
            (4, Value::Integer(425)),
            (5, Value::Integer(1)),
            (7, Value::TimeTicks(5000)),
            (8, Value::Gauge32(1000)),
        ] {
            data.insert(profiles::oid(&format!("1.3.6.1.2.1.99.1.1.1.{c}.9")), v);
        }
        let a = agent(data, true, None).await;
        let c = config(a.port, false, Profile::Generic);
        let snapshot = Poller::default()
            .poll("x", &c, &community(), 1, 0)
            .await
            .unwrap();
        assert!(snapshot.observations.iter().any(|o| o.reading == Some(42.5)
            && o.unit.as_deref() == Some("°C")
            && o.health == Health::Unknown));
        let reps = a.bulk.lock().unwrap();
        assert!(reps.windows(4).any(|w| w == [10, 5, 2, 1]));
        assert!(snapshot.snmp.unwrap().complete);
    }
    #[tokio::test]
    async fn partial_poll_keeps_valid_identity_and_status() {
        let mut data = system();
        data.insert(
            profiles::oid("1.3.6.1.4.1.674.10892.5.2.1.0"),
            Value::Integer(5),
        );
        let a = agent(data, false, Some(2)).await;
        let c = config(a.port, false, Profile::DellIdrac);
        let snapshot = Poller::default()
            .poll("x", &c, &community(), 1, 0)
            .await
            .unwrap();
        assert!(!snapshot.snmp.as_ref().unwrap().complete);
        assert!(snapshot
            .observations
            .iter()
            .any(|o| o.key == "snmp:system" && o.health == Health::Critical));
        assert!(snapshot
            .capabilities
            .iter()
            .any(|c| c.outcome == "snmp_timeout"));
    }
    #[test]
    fn uptime_wrap_is_not_restart_but_backwards_or_ambiguous_gaps_are() {
        let at = Instant::now();
        assert!(!restarted(
            Some((u32::MAX - 99, at)),
            100,
            at + Duration::from_secs(2)
        ));
        assert!(restarted(
            Some((10000, at)),
            10,
            at + Duration::from_secs(1)
        ));
        assert!(restarted(
            Some((10, at)),
            10,
            at + Duration::from_secs(50_000_000)
        ));
    }
    #[test]
    fn repeated_oid_aborts_and_a_different_subtree_ends_only_that_cursor() {
        let root = profiles::oid("1.3.6.1.2.1.99.1.1.1.4");
        let mut cursor = profiles::oid("1.3.6.1.2.1.99.1.1.1.4.1");
        let mut active = true;
        let mut data = Data::new();
        let error = advance(
            &root,
            &mut cursor.clone(),
            &mut active,
            VarBind::new(cursor.clone(), Value::Integer(1)),
            &mut data,
        )
        .unwrap_err();
        assert_eq!(crate::dsm::error_code(&error), "snmp_non_increasing_oid");
        assert!(data.is_empty());
        advance(
            &root,
            &mut cursor,
            &mut active,
            VarBind::new(profiles::oid("1.3.6.1.2.1.99.1.1.1.5.1"), Value::Integer(1)),
            &mut data,
        )
        .unwrap();
        assert!(!active);
        assert!(data.is_empty());
    }
    #[tokio::test]
    async fn inconsistent_v1_error_index_is_rejected_without_consuming_values() {
        for (status, index) in [(2u8, 0u8), (2, 3), (0, 1)] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = socket.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let (n, origin) = socket.recv_from(&mut buffer).await.unwrap();
                let pdu = CommunityMessage::decode(
                    Bytes::copy_from_slice(&buffer[..n]),
                    DecodeConfig::STRICT,
                )
                .unwrap()
                .value
                .into_pdu()
                .unwrap();
                let response = ResponsePdu::new(
                    Version::V1,
                    pdu.request_id(),
                    OutboundErrorStatus::NoSuchName,
                    Some(ErrorIndex::new(1, 2).unwrap()),
                    pdu.varbinds().to_vec(),
                )
                .unwrap();
                let mut wire = CommunityMessage::v1("synthetic-p2", response.into_raw())
                    .unwrap()
                    .encode()
                    .unwrap()
                    .to_vec();
                // Deliberately corrupt only the error-index field in a test
                // packet; the production path uses the library's BER codec.
                let offset = wire
                    .windows(6)
                    .position(|w| w == [2, 1, 2, 2, 1, 1])
                    .unwrap();
                wire[offset + 2] = status;
                wire[offset + 5] = index;
                socket.send_to(&wire, origin).await.unwrap();
            });
            let budget = Budget::new(true, Duration::from_secs(1));
            let transport = BoundedUdp::bind(peer, budget).await.unwrap();
            let client = ClientBuilder::new(Auth::v1("synthetic-p2"))
                .request_timeout(Duration::from_millis(100))
                .retry(Retry::none())
                .build_with_transport(transport)
                .unwrap();
            let session = Session { client, v1: true };
            let mut data = Data::new();
            let error = session
                .fixed(
                    &[
                        profiles::oid("1.3.6.1.2.1.1.2.0"),
                        profiles::oid("1.3.6.1.2.1.1.3.0"),
                    ],
                    false,
                    &mut data,
                )
                .await
                .unwrap_err();
            assert_eq!(crate::dsm::error_code(&error), "snmp_invalid_response");
            assert!(data.is_empty());
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn request_budget_stops_a_large_v1_walk_with_partial_data() {
        let mut data = system();
        let base = "1.3.6.1.4.1.674.10892.5.4.600.12.1";
        for index in 1..=600 {
            data.insert(
                profiles::oid(&format!("{base}.5.1.{index}")),
                Value::Integer(5),
            );
            data.insert(
                profiles::oid(&format!("{base}.15.1.{index}")),
                Value::OctetString(Bytes::from(format!("PSU.{index}"))),
            );
        }
        let a = agent(data, false, None).await;
        let snapshot = Poller::default()
            .poll(
                "x",
                &config(a.port, true, Profile::DellIdrac),
                &community(),
                1,
                0,
            )
            .await
            .unwrap();
        let metadata = snapshot.snmp.as_ref().unwrap();
        assert!(!metadata.complete);
        assert_eq!(metadata.statistics.requests, 512);
        assert!(snapshot
            .capabilities
            .iter()
            .any(|c| c.outcome == "snmp_request_limit"));
        assert!(snapshot
            .observations
            .iter()
            .any(|o| o.health == Health::Critical));
    }

    #[tokio::test]
    async fn error_response_values_count_against_budget_but_never_become_observations() {
        let a = agent(Data::new(), false, None).await;
        let budget = Budget::new(true, Duration::from_secs(1));
        let transport = BoundedUdp::bind(
            format!("127.0.0.1:{}", a.port).parse().unwrap(),
            budget.clone(),
        )
        .await
        .unwrap();
        let client = ClientBuilder::new(Auth::v1("synthetic-p2"))
            .request_timeout(Duration::from_millis(100))
            .retry(Retry::none())
            .build_with_transport(transport)
            .unwrap();
        let session = Session { client, v1: true };
        let mut data = Data::new();
        let result = session
            .fixed(
                &[
                    profiles::oid("1.3.6.1.2.1.1.2.0"),
                    profiles::oid("1.3.6.1.2.1.1.3.0"),
                ],
                false,
                &mut data,
            )
            .await
            .unwrap();
        assert!(result.into_iter().all(|v| v.is_none()));
        assert!(data.is_empty());
        assert_eq!(budget.stats().varbinds, 3);
        assert_eq!(budget.stats().requests, 2);
    }

    #[tokio::test]
    async fn v1_rejects_smi_v2_only_values_before_consumption() {
        let budget = Budget::new(true, Duration::from_secs(1));
        let transport = BoundedUdp::bind("127.0.0.1:61999".parse().unwrap(), budget.clone())
            .await
            .unwrap();
        let client = ClientBuilder::new(Auth::v1("synthetic-p2"))
            .build_with_transport(transport)
            .unwrap();
        let session = Session { client, v1: true };
        for value in [
            Value::Counter64(1),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ] {
            let error = session
                .values(&[VarBind::new(profiles::oid("1.3.6.1.2.1.1.3.0"), value)])
                .unwrap_err();
            assert_eq!(crate::dsm::error_code(&error), "snmp_invalid_response");
        }
    }
}
