//! Loopback-only P0 harness. No daemon, vault, database or product API integration.
use anyhow::{anyhow, ensure, Context, Result};
use async_snmp::{
    client::ResponseShapePolicy,
    message::{RawV3Message, SecurityLevel},
    notification::{
        NotificationAcceptance, NotificationPduClass, NotificationReceiver,
        NotificationVarbindValidation,
    },
    v3::{DiscoveredEngine, EngineState, UsmSecurityParams},
    Auth, AuthProtocol, AuthoritativeEngine, Client, DecodeConfig, EngineCache, Error, ErrorStatus,
    Oid, PrivProtocol, Retry, UsmConfig,
};
use bytes::Bytes;
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UdpSocket,
};
use zeroize::Zeroizing;

const LIMIT: usize = 16 * 1024;

fn emit(value: Value) {
    // Compile the real product and its dependencies in the same Cargo graph.
    #[cfg(feature = "product-compat")]
    std::hint::black_box(hardware_monitor::now());
    println!("{value}");
}

fn string<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field]
        .as_str()
        .ok_or_else(|| anyhow!("missing string field"))
}

fn number(v: &Value, field: &str, fallback: u64) -> u64 {
    v[field].as_u64().unwrap_or(fallback)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &str) -> Result<Bytes> {
    ensure!(
        value.len() <= 64 && value.len().is_multiple_of(2),
        "invalid engine ID"
    );
    Ok(Bytes::from(
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn algorithm(v: &Value) -> Result<AuthProtocol> {
    match string(v, "algorithm")? {
        "sha1" => Ok(AuthProtocol::Sha1),
        "sha256" => Ok(AuthProtocol::Sha256),
        _ => Err(anyhow!("algorithm not permitted")),
    }
}

fn classify(error: &Error) -> Value {
    match error {
        Error::Snmp { status, index, .. } => {
            json!({"error":"snmp", "status":status.to_string(), "index":index})
        }
        Error::Timeout { .. } => json!({"error":"timeout"}),
        _ => json!({"error":"rejected", "kind":format!("{:?}",error.kind())}),
    }
}

fn values_json(values: &[async_snmp::VarBind], v1: bool) -> Value {
    // The generic inbound decoder accepts SMIv2 values even in a v1 envelope.
    // Enforce the application's version contract before consuming any value.
    if v1
        && values
            .iter()
            .any(|v| v.value.is_exception() || matches!(v.value, async_snmp::Value::Counter64(_)))
    {
        return json!({"error":"invalid_v1_type"});
    }
    json!({"values":values.iter().map(|v|json!({"oid":v.oid.to_string(),"value":v.value.to_string()})).collect::<Vec<_>>()})
}

async fn client(config: &Value, cache: Arc<EngineCache>) -> Result<Client> {
    let target: SocketAddr = string(config, "target")?.parse()?;
    ensure!(
        target.ip().is_loopback(),
        "P0 permits loopback targets only"
    );
    let auth = match string(config, "version")? {
        "v1" => Auth::v1(string(config, "community")?.to_owned()),
        "v2c" => Auth::v2c(string(config, "community")?.to_owned()),
        "v3" => UsmConfig::new(string(config, "username")?.to_owned())
            .auth_priv(
                algorithm(config)?,
                string(config, "auth_password")?.as_bytes(),
                PrivProtocol::Aes128,
                string(config, "priv_password")?.as_bytes(),
            )?
            .into(),
        _ => return Err(anyhow!("version not permitted")),
    };
    Ok(Client::builder(target, auth)
        .strict_source(true)
        .request_timeout(Duration::from_millis(300))
        .construction_timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .decode_config(DecodeConfig::STRICT)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .engine_cache(cache)
        .connect()
        .await?)
}

async fn poll(config: &Value) -> Result<()> {
    let v1 = string(config, "version")? == "v1";
    let cache = Arc::new(EngineCache::new().with_max_capacity(2));
    let peer = client(config, cache.clone()).await?;
    let operations = config["operations"]
        .as_array()
        .context("operations required")?;
    ensure!(operations.len() <= 32, "operation limit");
    let mut results = Vec::new();
    for operation in operations {
        let oids = operation["oids"]
            .as_array()
            .context("OID list required")?
            .iter()
            .map(|v| {
                v.as_str()
                    .context("OID string required")?
                    .parse::<Oid>()
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!oids.is_empty() && oids.len() <= 8, "OID limit");
        if string(operation, "op")? == "get_partial" {
            let mut pending = oids;
            let mut unsupported = Vec::new();
            loop {
                match peer.get_many(&pending).await {
                    Ok(response) => {
                        let mut result = values_json(&response.varbinds, v1);
                        result["unsupported"] = json!(unsupported);
                        results.push(result);
                        break;
                    }
                    Err(error) => match &*error {
                        Error::Snmp {
                            status: ErrorStatus::NoSuchName,
                            index,
                            ..
                        } if *index > 0 && (*index as usize) <= pending.len() => {
                            unsupported.push(pending.remove(*index as usize - 1).to_string());
                            if pending.is_empty() {
                                results.push(json!({"values":[],"unsupported":unsupported}));
                                break;
                            }
                        }
                        _ => {
                            results.push(classify(&error));
                            break;
                        }
                    },
                }
            }
            continue;
        }
        let result = match string(operation, "op")? {
            "get" => peer.get_many(&oids).await,
            "next" => peer.get_next_many(&oids).await,
            // Prove unsupported v1 operations are refused by the candidate.
            "bulk" => {
                match peer.get_bulk(&oids, 0, 2).await {
                    Ok(response) => {
                        results.push(json!({"values":response.iter().map(|v| json!({"oid":v.oid.to_string(),"value":v.value.to_string()})).collect::<Vec<_>>()}));
                    }
                    Err(e) => results.push(classify(&e)),
                }
                continue;
            }
            _ => return Err(anyhow!("read operation not permitted")),
        };
        results.push(match result {
            Ok(response) => values_json(&response.varbinds, v1),
            Err(e) => classify(&e),
        });
    }
    let engine = cache.get(&peer.peer_addr()).and_then(|s| {
        s.authenticated_time().map(|t|
        json!({"engine_id":hex(s.engine_id()),"boots":t.boots(),"time":t.received_time_base()}))
    });
    emit(json!({"results":results,"engine":engine}));
    Ok(())
}

struct Sender {
    name: String,
    ip: IpAddr,
    engine: Bytes,
    username: Bytes,
    receiver: NotificationReceiver,
}

async fn sender(config: &Value, index: usize) -> Result<Sender> {
    let ip: IpAddr = string(config, "ip")?.parse()?;
    ensure!(ip.is_loopback(), "P0 permits loopback senders only");
    let engine = unhex(string(config, "engine_id")?)?;
    let username = Bytes::copy_from_slice(string(config, "username")?.as_bytes());
    // Synthetic ephemeral state, NOT the product's persistent authoritative state.
    let local = AuthoritativeEngine::install(vec![0x80, 0, 0, 0, 0x42, index as u8 + 1], |_| {
        Ok::<(), std::io::Error>(())
    })?;
    let expected_user = username.clone();
    let expected_engine = engine.clone();
    let auth_protocol = algorithm(config)?;
    let auth_password = string(config, "auth_password")?;
    let priv_password = string(config, "priv_password")?;
    let master_keys = async_snmp::v3::MasterKeys::new(auth_protocol, auth_password.as_bytes())?
        .with_privacy(PrivProtocol::Aes128, priv_password.as_bytes())?;
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(local)
        .decode_config(DecodeConfig::STRICT)
        .varbind_validation(NotificationVarbindValidation::Strict)
        .max_message_size(LIMIT)
        .remote_engine_capacity(1)
        .usm_user(username.clone(), |u| u.with_master_keys(master_keys))?
        .acceptance_policy(move |envelope| {
            if envelope.pdu_class == NotificationPduClass::Trap
                && envelope.security_level == Some(SecurityLevel::AuthPriv)
                && envelope.username == Some(expected_user.as_ref())
                && envelope.context_name == Some(b"".as_slice())
                && envelope.context_engine_id == Some(expected_engine.as_ref())
                // The envelope excludes the two required v2/v3 prefix fields.
                && envelope.varbinds.len() <= 126
            {
                NotificationAcceptance::Accept
            } else {
                NotificationAcceptance::Reject
            }
        })
        .build()
        .await?;
    // Cancel a pending native recv before using the caller-routed path. The
    // shared FIFO gate must remain usable after that cancellation.
    ensure!(
        tokio::time::timeout(Duration::from_millis(2), receiver.recv())
            .await
            .is_err(),
        "unexpected native datagram"
    );
    seed(&receiver, &engine, config)?;
    Ok(Sender {
        name: string(config, "name")?.into(),
        ip,
        engine,
        username,
        receiver,
    })
}

fn seed(receiver: &NotificationReceiver, engine: &Bytes, config: &Value) -> Result<()> {
    let discovered = DiscoveredEngine::new(
        engine.clone(),
        async_snmp::message_size::MessageSize::new(LIMIT)?,
    )?;
    let age = Duration::from_secs(number(config, "age_seconds", 0));
    ensure!(age.as_secs() <= 366 * 86400, "observation age limit");
    receiver.seed_authenticated_remote(EngineState::from_authenticated_observation(
        discovered,
        u32::try_from(number(config, "boots", 1))?,
        u32::try_from(number(config, "time", 0))?,
        Instant::now()
            .checked_sub(age)
            .context("invalid observation instant")?,
    )?)?;
    Ok(())
}

async fn receive(
    config: &Value,
    lines: &mut tokio::io::Lines<BufReader<tokio::io::Stdin>>,
) -> Result<()> {
    let list = config["senders"]
        .as_array()
        .context("sender list required")?;
    ensure!(!list.is_empty() && list.len() <= 16, "sender count limit");
    let mut senders = Vec::new();
    for (i, config) in list.iter().enumerate() {
        senders.push(sender(config, i).await?);
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    emit(json!({"ready":socket.local_addr()?.to_string()}));
    let mut buffer = vec![0u8; LIMIT + 1];
    loop {
        tokio::select! {
            line=lines.next_line()=>{
                let Some(line)=line? else {break};
                let line=Zeroizing::new(line);
                let command:Value=serde_json::from_str(&line)?;
                match string(&command,"action")? {
                    "stop"=>break,
                    "seed"=>{
                        let selected=senders.iter().find(|s|s.name==command["name"]).context("unknown sender")?;
                        seed(&selected.receiver,&selected.engine,&command)?;
                        emit(json!({"seeded":true}));
                    }
                    _=>return Err(anyhow!("unknown control operation")),
                }
            }
            packet=socket.recv_from(&mut buffer)=>{
                let (len,source)=packet?;
                let result=route(&senders,Bytes::copy_from_slice(&buffer[..len]),source).await;
                emit(match result {
                    Ok(v)=>v,
                    // Deliberately no packet/error/config Debug formatting.
                    Err(_)=>json!({"accepted":false,"reason":"malformed"}),
                });
            }
        }
    }
    Ok(())
}

async fn route(senders: &[Sender], data: Bytes, source: SocketAddr) -> Result<Value> {
    if data.len() > LIMIT {
        return Ok(json!({"accepted":false,"reason":"size"}));
    }
    if !senders.iter().any(|s| s.ip == source.ip()) {
        return Ok(json!({"accepted":false,"reason":"source"}));
    }
    let raw = RawV3Message::decode(data.clone(), DecodeConfig::STRICT)?.value;
    if raw.security_level() != SecurityLevel::AuthPriv || raw.global_data().msg_flags().reportable {
        return Ok(json!({"accepted":false,"reason":"security"}));
    }
    let usm = UsmSecurityParams::decode(raw.security_params().clone(), DecodeConfig::STRICT)?.value;
    let Some(sender) = senders.iter().find(|s| {
        s.ip == source.ip() && s.engine == *usm.engine_id() && s.username == *usm.username()
    }) else {
        return Ok(json!({"accepted":false,"reason":"identity"}));
    };
    let result = sender.receiver.process_datagram(data, source).await;
    match result {
        Ok(Some(receipt)) => Ok(
            json!({"accepted":true,"sender":sender.name,"oid":receipt.notification.trap_oid()?.to_string(),"uptime":receipt.notification.uptime()}),
        ),
        Ok(None) => Ok(
            json!({"accepted":false,"reason":"policy_or_usm","wrong_digests":sender.receiver.usm_wrong_digests(),"time_failures":sender.receiver.usm_not_in_time_windows()}),
        ),
        Err(_) => Ok(json!({"accepted":false,"reason":"decode_or_usm"})),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let result = async {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let initial = Zeroizing::new(lines.next_line().await?.context("configuration required")?);
        ensure!(initial.len() <= 64 * 1024, "configuration limit");
        let config: Value = serde_json::from_str(&initial)?;
        match string(&config, "action")? {
            "poll" => poll(&config).await,
            "receive" => receive(&config, &mut lines).await,
            _ => Err(anyhow!("unknown operation")),
        }
    }
    .await;
    if result.is_err() {
        eprintln!("P0 configuration or operation failed; sensitive details excluded");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{
        message::CommunityMessage,
        pdu::{GenericTrap, NotificationPdu, ResponsePdu, TrapV1Notification},
        VarBind, Version,
    };

    #[test]
    fn v1_generic_and_nested_enterprise_normalization() {
        for n in 0..=5 {
            let trap = TrapV1Notification::new(
                "1.3.6.1.4.1.55555".parse().unwrap(),
                [127, 0, 0, 1],
                GenericTrap::from_i32(n),
                0,
                1,
                vec![],
            )
            .unwrap();
            assert_eq!(
                trap.into_raw().v2_trap_oid().unwrap().to_string(),
                format!("1.3.6.1.6.3.1.1.5.{}", n + 1)
            );
        }
        let trap = TrapV1Notification::new(
            "1.3.6.1.4.1.674.10892.5.3.2.5".parse().unwrap(),
            [127, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            10395,
            1,
            vec![],
        )
        .unwrap();
        assert_eq!(
            trap.into_raw().v2_trap_oid().unwrap().to_string(),
            "1.3.6.1.4.1.674.10892.5.3.2.5.0.10395"
        );
    }

    #[test]
    fn key_debug_is_redacted_and_sha256_mac_is_192_bits() {
        let password = b"p0-synthetic-auth-passphrase";
        let user = async_snmp::v3::UsmUser::new("p0")
            .auth_priv(
                AuthProtocol::Sha256,
                password,
                PrivProtocol::Aes128,
                password,
            )
            .unwrap();
        assert!(!format!("{user:?}").contains(std::str::from_utf8(password).unwrap()));
        let key = async_snmp::v3::LocalizedKey::from_password(
            AuthProtocol::Sha256,
            password,
            b"\x80\0\0\0\x42",
        )
        .unwrap();
        assert_eq!(key.mac_len(), 24);
        assert!(!format!("{key:?}").contains(std::str::from_utf8(password).unwrap()));
    }

    #[tokio::test]
    async fn rejected_inform_is_not_acknowledged() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .communities(["p0-community"])
            .decode_config(DecodeConfig::STRICT)
            .acceptance_policy(|e| {
                if e.pdu_class == NotificationPduClass::Trap {
                    NotificationAcceptance::Accept
                } else {
                    NotificationAcceptance::Reject
                }
            })
            .build()
            .await
            .unwrap();
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inform = NotificationPdu::inform(
            Version::V2c,
            123,
            1,
            &"1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
            vec![],
        )
        .unwrap();
        let packet = CommunityMessage::v2c("p0-community", inform.into_raw())
            .unwrap()
            .encode()
            .unwrap();
        assert!(receiver
            .process_datagram(packet, origin.local_addr().unwrap())
            .await
            .unwrap()
            .is_none());
        let mut buffer = [0u8; 1024];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), origin.recv(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v1_counter64_wire_response_requires_adapter_rejection() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (len, origin) = server.recv_from(&mut buffer).await.unwrap();
            let message = CommunityMessage::decode(
                Bytes::copy_from_slice(&buffer[..len]),
                DecodeConfig::STRICT,
            )
            .unwrap()
            .value;
            let (id, _, vars) = message.into_pdu().unwrap().into_raw_parts();
            let response = CommunityMessage::v2c(
                "p0",
                ResponsePdu::success(
                    Version::V2c,
                    id,
                    vec![VarBind::new(
                        vars[0].oid.clone(),
                        async_snmp::Value::Counter64(42),
                    )],
                )
                .unwrap()
                .into_raw(),
            )
            .unwrap()
            .encode()
            .unwrap();
            // Corrupt only the version of a typed short-form fixture to v1.
            let mut wire = response.to_vec();
            assert!(wire[1] < 128);
            assert_eq!(&wire[2..5], &[2, 1, 1]);
            wire[4] = 0;
            server.send_to(&wire, origin).await.unwrap();
        });
        let peer = client(
            &json!({"target":address.to_string(),"version":"v1","community":"p0"}),
            Arc::new(EngineCache::new()),
        )
        .await
        .unwrap();
        let response = peer
            .get(&"1.3.6.1.2.1.1.5.0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            values_json(&response.varbinds, true)["error"],
            "invalid_v1_type"
        );
        assert!(values_json(&response.varbinds, false)["values"].is_array());
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn off_peer_wrong_request_id_and_wrong_community_do_not_satisfy_poll() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (len, origin) = server.recv_from(&mut buffer).await.unwrap();
            let message = CommunityMessage::decode(
                Bytes::copy_from_slice(&buffer[..len]),
                DecodeConfig::STRICT,
            )
            .unwrap()
            .value;
            let (id, _, vars) = message.into_pdu().unwrap().into_raw_parts();
            let response = |request_id, community, value| {
                CommunityMessage::v2c(
                    community,
                    ResponsePdu::success(
                        Version::V2c,
                        request_id,
                        vec![VarBind::new(
                            vars[0].oid.clone(),
                            async_snmp::Value::Integer(value),
                        )],
                    )
                    .unwrap()
                    .into_raw(),
                )
                .unwrap()
                .encode()
                .unwrap()
            };
            let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            rogue
                .send_to(&response(id, "p0-community", 99), origin)
                .await
                .unwrap();
            server
                .send_to(&response(id.wrapping_add(1), "p0-community", 99), origin)
                .await
                .unwrap();
            server
                .send_to(&response(id, "p0-wrong", 99), origin)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            server
                .send_to(&response(id, "p0-community", 7), origin)
                .await
                .unwrap();
        });
        let peer = client(
            &json!({"target":address.to_string(),"version":"v2c","community":"p0-community"}),
            Arc::new(EngineCache::new()),
        )
        .await
        .unwrap();
        let response = peer
            .get(&"1.3.6.1.2.1.1.5.0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.single().unwrap().value,
            async_snmp::Value::Integer(7)
        );
        fixture.await.unwrap();
    }
}
