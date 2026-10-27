//! Per-poll UDP ownership: every datagram and every transmission consumes budget.
//! Correlation, BER and USM remain in the pinned protocol library.
use async_snmp::{
    transport::{Candidate, RequestRegistration, ResponseIdentity, Transport},
    Error, ReceiveLimits,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Mutex as AsyncMutex, time::Instant};

pub const MAX_MESSAGE: usize = 16 * 1024;
pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_VARBINDS: usize = 4096;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Statistics {
    pub requests: usize,
    pub received_bytes: usize,
    pub varbinds: usize,
    pub rejected_datagrams: usize,
}
pub struct Budget {
    pub deadline: Instant,
    max_requests: usize,
    stats: Mutex<Statistics>,
}
impl Budget {
    pub fn new(v1: bool, duration: Duration) -> Arc<Self> {
        Arc::new(Self {
            deadline: Instant::now() + duration,
            max_requests: if v1 { 512 } else { 128 },
            stats: Mutex::new(Statistics::default()),
        })
    }
    pub fn stats(&self) -> Statistics {
        self.stats.lock().unwrap().clone()
    }
    fn transmit(&self) -> async_snmp::Result<()> {
        let mut s = self.stats.lock().unwrap();
        if s.varbinds > MAX_VARBINDS {
            return Err(limit("snmp_item_limit"));
        }
        if Instant::now() >= self.deadline || s.requests >= self.max_requests {
            return Err(limit("snmp_request_limit"));
        }
        s.requests += 1;
        Ok(())
    }
    fn receive(&self, bytes: usize) -> async_snmp::Result<()> {
        let mut s = self.stats.lock().unwrap();
        s.received_bytes += bytes;
        if s.varbinds > MAX_VARBINDS {
            return Err(limit("snmp_item_limit"));
        }
        if s.received_bytes > MAX_BYTES {
            return Err(limit("snmp_byte_limit"));
        }
        Ok(())
    }
    pub fn decoded(&self, count: usize) -> anyhow::Result<()> {
        let mut s = self.stats.lock().unwrap();
        s.varbinds += count;
        anyhow::ensure!(
            s.varbinds <= MAX_VARBINDS,
            crate::dsm::BoundaryError("snmp_item_limit")
        );
        Ok(())
    }
    fn reject(&self) {
        self.stats.lock().unwrap().rejected_datagrams += 1;
    }
}
fn limit(code: &str) -> Box<Error> {
    Box::new(Error::Config(code.into()))
}
pub struct BoundedUdp {
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    gate: AsyncMutex<()>,
    pub budget: Arc<Budget>,
}
impl BoundedUdp {
    pub async fn bind(peer: SocketAddr, budget: Arc<Budget>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        let local = socket.local_addr()?;
        Ok(Self {
            socket,
            peer,
            local,
            gate: AsyncMutex::new(()),
            budget,
        })
    }
    fn network(&self, source: std::io::Error) -> Box<Error> {
        Box::new(Error::Network {
            target: self.peer,
            source,
        })
    }
    fn timeout(&self) -> Box<Error> {
        Box::new(Error::Timeout {
            target: self.peer,
            elapsed: Duration::ZERO,
            retries: 0,
        })
    }
    async fn transmit(&self, data: &[u8]) -> async_snmp::Result<()> {
        if data.len() > MAX_MESSAGE {
            return Err(Box::new(Error::OutboundMessageTooLarge {
                size: data.len(),
                limit: MAX_MESSAGE,
            }));
        }
        self.budget.transmit()?;
        self.socket
            .send_to(data, self.peer)
            .await
            .map_err(|e| self.network(e))?;
        Ok(())
    }
}
impl Transport for BoundedUdp {
    fn observe_decoded_pdu(&self, pdu: &async_snmp::pdu::Pdu) -> async_snmp::Result<()> {
        let values = pdu.varbinds();
        self.budget
            .decoded(values.len())
            .map_err(|_| limit("snmp_item_limit"))?;
        if let Some((status, index)) = pdu.error_fields() {
            let maximum = if self.budget.max_requests == 512 {
                5
            } else {
                18
            };
            let zero_index = matches!(status, 0 | 1 | 15 | 16);
            if !(0..=maximum).contains(&status)
                || (zero_index && index != 0)
                || (!zero_index && (index <= 0 || index as usize > values.len()))
            {
                return Err(limit("snmp_invalid_response"));
            }
        }
        if self.budget.max_requests == 512
            && values.iter().any(|v| {
                matches!(
                    v.value,
                    async_snmp::Value::Counter64(_)
                        | async_snmp::Value::NoSuchObject
                        | async_snmp::Value::NoSuchInstance
                        | async_snmp::Value::EndOfMibView
                )
            })
        {
            return Err(limit("snmp_invalid_response"));
        }
        Ok(())
    }
    async fn send(&self, data: &[u8]) -> async_snmp::Result<()> {
        tokio::time::timeout_at(self.budget.deadline, self.transmit(data))
            .await
            .map_err(|_| self.timeout())?
    }
    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: RequestRegistration,
        mut validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> async_snmp::Result<Candidate<T>> + Send,
    {
        let operation = async {
            let _guard = self.gate.lock().await;
            self.transmit(data).await?;
            // Maximum UDP payload fits in this buffer; oversized packets cannot
            // be accepted as a silently truncated valid BER message.
            let mut buffer = vec![0u8; 65536];
            loop {
                let (n, source) = self
                    .socket
                    .recv_from(&mut buffer)
                    .await
                    .map_err(|e| self.network(e))?;
                self.budget.receive(n)?;
                if source != self.peer {
                    self.budget.reject();
                    continue;
                }
                if registration.evaluate_response_identity(&buffer[..n], true)
                    != ResponseIdentity::Match
                {
                    self.budget.reject();
                    continue;
                }
                if n > MAX_MESSAGE {
                    return Err(limit("snmp_response_limit"));
                }
                match validate(Bytes::copy_from_slice(&buffer[..n]), source)? {
                    Candidate::Accept(value) => return Ok(value),
                    Candidate::Reject => self.budget.reject(),
                }
            }
        };
        tokio::time::timeout_at(registration.deadline().min(self.budget.deadline), operation)
            .await
            .map_err(|_| self.timeout())?
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn local_addr(&self) -> SocketAddr {
        self.local
    }
    fn is_reliable(&self) -> bool {
        false
    }
    // The exact-size policy is transport independent despite its constructor's
    // name; advertise and enforce the same 16 KiB for this UDP adapter.
    fn receive_limits(&self) -> ReceiveLimits {
        ReceiveLimits::tcp(MAX_MESSAGE).expect("constant valid size")
    }
    fn send_capacity(&self) -> usize {
        MAX_MESSAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{
        message::CommunityMessage, pdu::ResponsePdu, Auth, ClientBuilder, DecodeConfig, Oid,
        ResponseShapePolicy, Retry, Value, VarBind, Version,
    };
    #[tokio::test]
    async fn correlation_rejects_spoofed_peer_id_community_and_version_and_counts_bytes() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let budget = Budget::new(false, Duration::from_secs(2));
        let transport = BoundedUdp::bind(peer, budget.clone()).await.unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let (n, origin) = server.recv_from(&mut buffer).await.unwrap();
            let m = CommunityMessage::decode(
                Bytes::copy_from_slice(&buffer[..n]),
                DecodeConfig::STRICT,
            )
            .unwrap()
            .value;
            let pdu = m.into_pdu().unwrap();
            let oid = pdu.varbinds()[0].oid.clone();
            let id = pdu.request_id();
            let response = |version, community: &str, id, value| {
                let p = ResponsePdu::success(
                    version,
                    id,
                    vec![VarBind::new(oid.clone(), Value::Integer(value))],
                )
                .unwrap()
                .into_raw();
                if version == Version::V1 {
                    CommunityMessage::v1(community.to_owned(), p)
                } else {
                    CommunityMessage::v2c(community.to_owned(), p)
                }
                .unwrap()
                .encode()
                .unwrap()
            };
            let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            rogue
                .send_to(&response(Version::V2c, "synthetic-p2", id, 99), origin)
                .await
                .unwrap();
            for data in [
                response(Version::V2c, "synthetic-p2", id + 1, 99),
                response(Version::V2c, "wrong", id, 99),
                response(Version::V1, "synthetic-p2", id, 99),
                Bytes::from_static(b"malformed"),
            ] {
                server.send_to(&data, origin).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            server
                .send_to(&response(Version::V2c, "synthetic-p2", id, 7), origin)
                .await
                .unwrap();
        });
        let client = ClientBuilder::new(Auth::v2c("synthetic-p2"))
            .request_timeout(Duration::from_millis(200))
            .retry(Retry::none())
            .decode_config(DecodeConfig::STRICT)
            .response_shape_policy(ResponseShapePolicy::Strict)
            .build_with_transport(transport)
            .unwrap();
        let response = client
            .get(&Oid::parse("1.3.6.1.2.1.1.5.0").unwrap())
            .await
            .unwrap();
        assert_eq!(response.varbinds[0].value, Value::Integer(7));
        task.await.unwrap();
        let stats = budget.stats();
        assert_eq!(stats.requests, 1);
        assert_eq!(stats.rejected_datagrams, 5);
        assert!(stats.received_bytes > 100);
    }
    #[test]
    fn every_retry_and_discovery_transmission_is_subject_to_the_same_budget() {
        for (v1, maximum) in [(true, 512), (false, 128)] {
            let b = Budget::new(v1, Duration::from_secs(60));
            for _ in 0..maximum {
                b.transmit().unwrap();
            }
            assert!(b.transmit().is_err());
            assert_eq!(b.stats().requests, maximum);
            b.receive(MAX_BYTES).unwrap();
            assert!(b.receive(1).is_err());
            b.decoded(MAX_VARBINDS).unwrap();
            assert!(b.decoded(1).is_err());
        }
    }
    #[tokio::test]
    async fn per_poll_deadline_also_bounds_a_longer_request_and_cancellation_releases_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let budget = Budget::new(false, Duration::from_millis(30));
        let transport = BoundedUdp::bind(peer, budget).await.unwrap();
        let local = transport.local;
        let client = ClientBuilder::new(Auth::v2c("synthetic-p2"))
            .request_timeout(Duration::from_secs(10))
            .retry(Retry::none())
            .build_with_transport(transport)
            .unwrap();
        let at = Instant::now();
        assert!(client
            .get(&Oid::parse("1.3.6.1.2.1.1.5.0").unwrap())
            .await
            .is_err());
        assert!(at.elapsed() < Duration::from_secs(1));
        drop(client);
        let rebound = UdpSocket::bind(local).await.unwrap();
        drop(rebound);
    }
}
