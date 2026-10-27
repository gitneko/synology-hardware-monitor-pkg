//! Exact sender routing and the pinned library's unchanged notification path.
use super::{
    config::{AuthProtocol, PollConfig, Security, TrapConfig},
    engine::decode_id,
    records::Receipt,
    secrets::Credentials,
};
use crate::{dsm::BoundaryError, model::Device};
use anyhow::{ensure, Result};
use async_snmp::{
    message::{CommunityMessage, RawV3Message, SecurityLevel},
    notification::{
        NotificationAcceptance, NotificationPduClass, NotificationReceiver,
        NotificationVarbindValidation,
    },
    v3::{EngineState, MasterKeys, UsmSecurityParams},
    AuthoritativeEngine, Community, DecodeConfig, PrivProtocol, Value, Version,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

pub const MAX_MESSAGE: usize = 16 * 1024;
// These are optional application filters, distinct from the authenticated
// sender engine identity. A contextual engine may legitimately differ.
fn context_rejection(
    config: &TrapConfig,
    name: Option<&[u8]>,
    engine: Option<&[u8]>,
) -> Option<&'static str> {
    if !name.is_some_and(|value| {
        config.context_name.is_empty() || value == config.context_name.as_bytes()
    }) {
        return Some("snmp_trap_context_name");
    }
    if !engine.is_some_and(|value| {
        config.context_engine_ids.is_empty()
            || config
                .context_engine_ids
                .iter()
                .any(|id| decode_id(id).is_ok_and(|id| id.as_ref() == value))
    }) {
        return Some("snmp_trap_context_engine");
    }
    None
}

pub struct Sender {
    pub device: Device,
    pub revision: i64,
    pub epoch: i64,
    pub config: TrapConfig,
    pub receiver: NotificationReceiver,
    pub probe: Option<PollConfig>,
    verified: Mutex<HashSet<Bytes>>,
    community: Option<Community>,
    policy_rejection: Arc<Mutex<Option<&'static str>>>,
}
impl Sender {
    pub async fn build(
        device: Device,
        revision: i64,
        epoch: i64,
        credentials: Credentials,
        local: Option<AuthoritativeEngine>,
    ) -> Result<Self> {
        let config = device
            .snmp_traps
            .clone()
            .ok_or(BoundaryError("snmp_receiver_config_invalid"))?;
        config.validate()?;
        credentials.validate(&config.security)?;
        let expected = config.clone();
        let mut builder = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .decode_config(DecodeConfig::STRICT)
            .varbind_validation(NotificationVarbindValidation::Strict)
            .max_message_size(MAX_MESSAGE)
            .remote_engine_capacity(16);
        let community = match (&config.security, &credentials) {
            (Security::V1 {} | Security::V2c {}, Credentials::Community { community }) => {
                let value = Community::new(community.clone());
                builder = builder.community(value.clone());
                Some(value)
            }
            (
                Security::V3 { username, auth, .. },
                Credentials::Usm {
                    auth_password,
                    priv_password,
                },
            ) => {
                let keys = MasterKeys::new(
                    match auth {
                        AuthProtocol::Sha1 => async_snmp::AuthProtocol::Sha1,
                        AuthProtocol::Sha256 => async_snmp::AuthProtocol::Sha256,
                    },
                    auth_password.as_bytes(),
                )?
                .with_privacy(PrivProtocol::Aes128, priv_password.as_bytes())?;
                builder = builder
                    .authoritative_engine(local.ok_or(BoundaryError("snmp_engine_state"))?)
                    .usm_user(username.clone(), |u| u.with_master_keys(keys))?;
                None
            }
            _ => return Err(BoundaryError("snmp_credentials").into()),
        };
        let policy_rejection = Arc::new(Mutex::new(None));
        let rejected = policy_rejection.clone();
        let receiver = builder
            .acceptance_policy(move |e| {
                let maximum = if e.version == Version::V1 { 128 } else { 126 };
                let security = match &expected.security {
                    Security::V1 {} => {
                        e.version == Version::V1
                            && !e.varbinds.iter().any(|v| {
                                matches!(
                                    v.value,
                                    Value::Counter64(_)
                                        | Value::NoSuchObject
                                        | Value::NoSuchInstance
                                        | Value::EndOfMibView
                                )
                            })
                    }
                    Security::V2c {} => e.version == Version::V2c,
                    Security::V3 { username, .. } => {
                        e.version == Version::V3
                            && e.security_level == Some(SecurityLevel::AuthPriv)
                            && e.username == Some(username.as_bytes())
                            && context_rejection(&expected, e.context_name, e.context_engine_id)
                                .is_none()
                    }
                };
                if e.pdu_class == NotificationPduClass::Trap
                    && security
                    && e.varbinds.len() <= maximum
                    && expected.allowed_sources.contains(&e.source.ip())
                {
                    NotificationAcceptance::Accept
                } else {
                    // Only fixed reason codes are retained; never packet values.
                    *rejected.lock().unwrap() =
                        Some(if e.pdu_class != NotificationPduClass::Trap {
                            "snmp_trap_pdu"
                        } else if e.version == Version::V3 {
                            context_rejection(&expected, e.context_name, e.context_engine_id)
                                .unwrap_or("snmp_trap_policy")
                        } else {
                            "snmp_trap_policy"
                        });
                    NotificationAcceptance::Reject
                }
            })
            .build()
            .await?;
        let probe = device.snmp_poll.clone().map(|mut c| {
            c.security = config.security.clone();
            c.context_name = config.context_name.clone();
            c.context_engine_id = None;
            c
        });
        Ok(Self {
            device,
            revision,
            epoch,
            config,
            receiver,
            probe,
            verified: Mutex::new(HashSet::new()),
            community,
            policy_rejection,
        })
    }
    pub fn seed(&self, state: EngineState) -> Result<String> {
        let id = hex(state.engine_id());
        ensure!(
            self.config
                .engine_ids
                .iter()
                .any(|approved| approved.eq_ignore_ascii_case(&id)),
            BoundaryError("snmp_engine_mismatch")
        );
        self.receiver.seed_authenticated_remote(state.clone())?;
        self.verified
            .lock()
            .unwrap()
            .insert(state.engine_id().clone());
        Ok(id)
    }
    pub fn ready(&self) -> bool {
        !matches!(self.config.security, Security::V3 { .. })
            || !self.verified.lock().unwrap().is_empty()
    }
    /// Only a polling request can leave this boundary. A successful HMAC with
    /// an untrusted clock must never be represented as a verified Receipt.
    pub async fn poll_hint(&self, data: Bytes, source: SocketAddr, envelope: &Envelope) -> bool {
        if !self.config.timeliness_poll_only
            || !self.config.allowed_sources.contains(&source.ip())
            || !self.matches(envelope)
        {
            return false;
        }
        let Envelope::Usm { engine, .. } = envelope else {
            return false;
        };
        if !self.verified.lock().unwrap().contains(engine) {
            return false;
        }
        self.receiver
            .authenticated_trap_poll_hint(data, source)
            .await
            .unwrap_or(false)
    }
    fn matches(&self, identity: &Envelope) -> bool {
        match (&self.config.security, identity) {
            (
                Security::V1 {},
                Envelope::Community {
                    version: Version::V1,
                    community,
                },
            )
            | (
                Security::V2c {},
                Envelope::Community {
                    version: Version::V2c,
                    community,
                },
            ) => self
                .community
                .as_ref()
                .is_some_and(|v| v.matches(community.as_bytes())),
            (Security::V3 { username, .. }, Envelope::Usm { engine, user, .. }) => {
                user.as_ref() == username.as_bytes()
                    && self
                        .config
                        .engine_ids
                        .iter()
                        .any(|id| decode_id(id).is_ok_and(|id| id == *engine))
            }
            _ => false,
        }
    }
    fn usm_counts(&self) -> [u32; 6] {
        [
            self.receiver.usm_unknown_engine_ids(),
            self.receiver.usm_unknown_usernames(),
            self.receiver.usm_wrong_digests(),
            self.receiver.usm_not_in_time_windows(),
            self.receiver.usm_unsupported_sec_levels(),
            self.receiver.usm_decryption_errors(),
        ]
    }
    fn rejection_reason(
        &self,
        before: [u32; 6],
        error: Option<&async_snmp::Error>,
    ) -> &'static str {
        let after = self.usm_counts();
        for (index, code) in [
            "snmp_trap_sender",
            "snmp_trap_sender",
            "snmp_trap_authentication",
            "snmp_trap_timeliness",
            "snmp_trap_security_level",
            "snmp_trap_decryption",
        ]
        .into_iter()
        .enumerate()
        {
            if before[index] != after[index] {
                return code;
            }
        }
        self.policy_rejection
            .lock()
            .unwrap()
            .unwrap_or(match error {
                // The pinned library intentionally does not increment the USM
                // time-window counter for a remote authoritative trap sender.
                Some(async_snmp::Error::Auth { .. }) => "snmp_trap_timeliness",
                Some(async_snmp::Error::Decode(_)) => "snmp_trap_payload",
                Some(async_snmp::Error::MalformedResponse { .. }) => "snmp_trap_pdu",
                _ => "snmp_trap_policy",
            })
    }
    pub async fn receive(
        &self,
        data: Bytes,
        source: SocketAddr,
        envelope: &Envelope,
    ) -> Result<Option<Receipt>> {
        if let Envelope::Usm { engine, .. } = envelope {
            ensure!(
                self.verified.lock().unwrap().contains(engine),
                BoundaryError("snmp_verification_pending")
            );
        }
        *self.policy_rejection.lock().unwrap() = None;
        let before = self.usm_counts();
        let outcome = self.receiver.process_datagram(data, source).await;
        let reason = self.rejection_reason(before, outcome.as_ref().err().map(|e| e.as_ref()));
        let received = outcome
            .map_err(|_| BoundaryError(reason))?
            .ok_or(BoundaryError(reason))?;
        ensure!(
            received.inform_ack.is_none() && !received.notification.is_confirmed(),
            BoundaryError("snmp_trap_rejected")
        );
        let notification = received.notification;
        let oid = notification
            .trap_oid()
            .map_err(|_| BoundaryError("snmp_trap_rejected"))?;
        ensure!(oid.len() <= 128, BoundaryError("snmp_trap_rejected"));
        let oid_text = oid.to_string();
        let version = match notification.version() {
            Version::V1 => "v1",
            Version::V2c => "v2c",
            Version::V3 => "v3",
            _ => return Err(BoundaryError("snmp_trap_rejected").into()),
        };
        let engine = received
            .wire_identity
            .v3
            .as_ref()
            .map(|v| hex(&v.authoritative_engine_id));
        let verified = notification.security_level() == Some(SecurityLevel::AuthPriv);
        let engine_boots = match envelope {
            Envelope::Usm { boots, .. } => Some(*boots),
            _ => None,
        };
        let mut fingerprint = Sha256::new();
        for text in [
            &self.device.id,
            &self.revision.to_string(),
            &self.epoch.to_string(),
            version,
            engine.as_deref().unwrap_or(""),
            &oid_text,
            &notification.uptime().to_string(),
        ] {
            field(&mut fingerprint, text.as_bytes());
        }
        field(&mut fingerprint, &engine_boots.unwrap_or(0).to_be_bytes());
        // Semantic payload/uptime are retained in the hash; outer message IDs
        // and source ports are intentionally absent. No raw values are stored.
        for var in notification.varbinds() {
            field(&mut fingerprint, var.oid.to_string().as_bytes());
            field(
                &mut fingerprint,
                format!("{:?}", var.value.kind()).as_bytes(),
            );
            if let Some(bytes) = var.value.as_bytes() {
                field(&mut fingerprint, bytes)
            } else {
                field(&mut fingerprint, var.value.to_string().as_bytes())
            }
        }
        let pet = oid.arcs().starts_with(&[1, 3, 6, 1, 4, 1, 3183, 1, 1]);
        let event = super::traps::normalize(self.config.profile, &oid, notification.varbinds());
        Ok(Some(Receipt {
            event: Some(event),
            fingerprint: hex(&fingerprint.finalize()),
            trap_oid: oid_text,
            source: source.ip(),
            verified,
            component_key: None,
            restored: false,
            version: Some(version.into()),
            engine_id: engine,
            engine_boots,
            uptime: Some(notification.uptime()),
            handling: Some(
                if pet {
                    "unsupported_pet"
                } else {
                    "unclassified"
                }
                .into(),
            ),
        }))
    }
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub enum Envelope {
    Community {
        version: Version,
        community: Community,
    },
    Usm {
        engine: Bytes,
        user: Bytes,
        boots: u32,
    },
}
/// Both parsers are the library's bounded strict codecs; no second BER parser.
pub fn envelope(data: Bytes) -> Result<Envelope> {
    ensure!(data.len() <= MAX_MESSAGE, BoundaryError("snmp_trap_size"));
    if let Ok(decoded) = RawV3Message::decode(data.clone(), DecodeConfig::STRICT) {
        let raw = decoded.value;
        ensure!(
            raw.security_level() == SecurityLevel::AuthPriv,
            BoundaryError("snmp_trap_security_level")
        );
        ensure!(
            !raw.global_data().msg_flags().reportable,
            BoundaryError("snmp_trap_pdu")
        );
        let usm = UsmSecurityParams::decode(raw.security_params().clone(), DecodeConfig::STRICT)
            .map_err(|_| BoundaryError("snmp_trap_encoding"))?
            .value;
        return Ok(Envelope::Usm {
            engine: usm.engine_id().clone(),
            user: usm.username().clone(),
            boots: usm.engine_boots(),
        });
    }
    let message = CommunityMessage::decode(data, DecodeConfig::STRICT)
        .map_err(|_| BoundaryError("snmp_trap_encoding"))?
        .value;
    Ok(Envelope::Community {
        version: message.version(),
        community: message.community().clone(),
    })
}
pub fn associate(
    senders: &[Arc<Sender>],
    source: SocketAddr,
    envelope: &Envelope,
) -> Result<Option<Arc<Sender>>> {
    let mut matches = senders
        .iter()
        .filter(|s| s.config.allowed_sources.contains(&source.ip()) && s.matches(envelope));
    let first = matches.next().cloned();
    ensure!(
        matches.next().is_none(),
        BoundaryError("snmp_sender_ambiguous")
    );
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::pdu::{GenericTrap, NotificationPdu, TrapV1Notification};
    use serde_json::json;
    fn device(version: &str) -> Device {
        serde_json::from_value(json!({"id":"sender","name":"Synthetic","endpoint":"https://example.invalid","username":"reader","interval_seconds":60,"repeat_seconds":null,"alerts_enabled":true,"snmp_traps":{"enabled":true,"allowed_sources":["127.0.0.1"],"security":{"version":version}}})).unwrap()
    }
    async fn make_sender(version: &str) -> Arc<Sender> {
        Arc::new(
            Sender::build(
                device(version),
                1,
                2,
                Credentials::Community {
                    community: "synthetic-p3".into(),
                },
                None,
            )
            .await
            .unwrap(),
        )
    }
    #[test]
    fn optional_context_filters_are_independent_of_authenticated_sender_identity() {
        let mut config: TrapConfig = serde_json::from_value(serde_json::json!({
            "enabled":true,"allowed_sources":["127.0.0.1"],
            "security":{"version":"v3","username":"sender"},
            "engine_ids":["8000000001"]
        }))
        .unwrap();
        let alternate = decode_id("8000000002").unwrap();
        assert_eq!(
            context_rejection(&config, Some(b"controller"), Some(&alternate)),
            None
        );
        assert_eq!(
            context_rejection(&config, Some(b""), Some(&alternate)),
            None
        );
        config.context_name = "production".into();
        assert_eq!(
            context_rejection(&config, Some(b"other"), Some(&alternate)),
            Some("snmp_trap_context_name")
        );
        config.context_engine_ids = vec!["8000000002".into()];
        assert_eq!(
            context_rejection(&config, Some(b"production"), Some(&alternate)),
            None
        );
        let different = decode_id("8000000003").unwrap();
        assert_eq!(
            context_rejection(&config, Some(b"production"), Some(&different)),
            Some("snmp_trap_context_engine")
        );
        assert!(context_rejection(&config, None, Some(&alternate)).is_some());
        assert!(context_rejection(&config, Some(b"production"), None).is_some());
        // The sender allowlist is retained rather than repurposed as context.
        assert_eq!(config.engine_ids, vec!["8000000001"]);
    }

    #[tokio::test]
    async fn v1_conversion_preserves_exact_enterprise_source_and_uptime() {
        let sender = make_sender("v1").await;
        let source = "127.0.0.1:54999".parse().unwrap();
        for generic in 0..=6 {
            let trap = TrapV1Notification::new(
                "1.3.6.1.4.1.674.10892.5.3.2.5".parse().unwrap(),
                [192, 0, 2, 99],
                GenericTrap::from_i32(generic),
                10395,
                987,
                vec![],
            )
            .unwrap();
            let data = CommunityMessage::v1_trap("synthetic-p3", trap)
                .unwrap()
                .encode()
                .unwrap();
            let envelope = envelope(data.clone()).unwrap();
            let receipt = sender
                .receive(data, source, &envelope)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                receipt.trap_oid,
                if generic < 6 {
                    format!("1.3.6.1.6.3.1.1.5.{}", generic + 1)
                } else {
                    "1.3.6.1.4.1.674.10892.5.3.2.5.0.10395".into()
                }
            );
            assert_eq!(receipt.source, source.ip());
            assert_eq!(receipt.uptime, Some(987));
            assert!(!receipt.verified);
        }
    }
    #[tokio::test]
    async fn ambiguous_identity_wrong_community_version_and_source_are_not_routed() {
        let sender = make_sender("v2c").await;
        let source = "127.0.0.1:54999".parse().unwrap();
        let make = |community: &str| {
            CommunityMessage::v2c(
                community.to_owned(),
                NotificationPdu::trap_v2(
                    Version::V2c,
                    1,
                    2,
                    &"1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
                    vec![],
                )
                .unwrap()
                .into_raw(),
            )
            .unwrap()
            .encode()
            .unwrap()
        };
        let identity = envelope(make("synthetic-p3")).unwrap();
        assert!(associate(&[sender.clone(), sender.clone()], source, &identity).is_err());
        assert!(associate(
            std::slice::from_ref(&sender),
            source,
            &envelope(make("wrong")).unwrap()
        )
        .unwrap()
        .is_none());
        assert!(associate(
            std::slice::from_ref(&sender),
            "127.0.0.2:1234".parse().unwrap(),
            &identity
        )
        .unwrap()
        .is_none());
        let v1 = make_sender("v1").await;
        assert!(associate(&[v1], source, &identity).unwrap().is_none());
    }
    #[tokio::test]
    async fn pet_is_explicitly_unsupported_and_fingerprint_ignores_port_and_request_id() {
        let sender = make_sender("v2c").await;
        let make = |id| {
            CommunityMessage::v2c(
                "synthetic-p3",
                NotificationPdu::trap_v2(
                    Version::V2c,
                    id,
                    100,
                    &"1.3.6.1.4.1.3183.1.1.0.5".parse().unwrap(),
                    vec![],
                )
                .unwrap()
                .into_raw(),
            )
            .unwrap()
            .encode()
            .unwrap()
        };
        let a = make(1);
        let b = make(2);
        let first = sender
            .receive(
                a.clone(),
                "127.0.0.1:45000".parse().unwrap(),
                &envelope(a).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let second = sender
            .receive(
                b.clone(),
                "127.0.0.1:45001".parse().unwrap(),
                &envelope(b).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.handling.as_deref(), Some("unsupported_pet"));
        assert_eq!(first.fingerprint, second.fingerprint);
    }
    #[test]
    fn malformed_and_oversized_inputs_use_the_library_boundary() {
        for bytes in [
            Bytes::new(),
            Bytes::from_static(b"malformed"),
            Bytes::from(vec![0u8; MAX_MESSAGE + 1]),
        ] {
            assert!(envelope(bytes).is_err());
        }
    }

    #[tokio::test]
    async fn seeded_decoder_corpus_preserves_bounds_and_unverified_community_policy() {
        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        let sender = make_sender("v2c").await;
        let source = "127.0.0.1:45000".parse().unwrap();
        let valid = CommunityMessage::v2c(
            "synthetic-p3".to_owned(),
            NotificationPdu::trap_v2(
                Version::V2c,
                1,
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
        let mut rng = StdRng::seed_from_u64(0x9050);
        for index in 0..1000 {
            let mut data = match index % 3 {
                0 => valid.to_vec(),
                1 => valid[..rng.gen_range(0..valid.len())].to_vec(),
                _ => vec![0; rng.gen_range(0..=MAX_MESSAGE + 1)],
            };
            if index % 3 == 0 {
                let offset = rng.gen_range(0..data.len());
                data[offset] ^= 1 << rng.gen_range(0..8);
            } else if index % 3 == 2 {
                rng.fill_bytes(&mut data);
            }
            let data = Bytes::from(data);
            if let Ok(envelope) = envelope(data.clone()) {
                if let Ok(Some(receipt)) = sender.receive(data, source, &envelope).await {
                    assert!(!receipt.verified);
                    assert!(serde_json::to_vec(&receipt).unwrap().len() <= 4096);
                }
            }
        }
        let receipt = sender
            .receive(valid.clone(), source, &envelope(valid).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(!receipt.verified);
    }
}
