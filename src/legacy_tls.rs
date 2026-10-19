//! Explicit certificate pinning for older controllers, before any HTTP data.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, Response};
use hyper_util::rt::TokioIo;
use openssl::{
    asn1::Asn1Time,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, pin::Pin, time::Duration};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_openssl::SslStream;
use url::Url;

use crate::dsm::BoundaryError;

pub struct PinnedClient {
    connector: SslConnector,
    certificate: Vec<u8>,
    connection: Mutex<Option<Connection>>,
}

#[derive(Clone, Copy)]
pub(crate) enum Auth<'a> {
    None,
    Basic(&'a str, &'a str),
    Token(&'a str),
}

struct Connection {
    origin: url::Origin,
    peer: X509,
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    _driver: Driver,
}

pub fn certificate(pem: &str) -> Result<X509> {
    crate::model::validate_certificates(pem)?;
    let mut certificates = X509::stack_from_pem(pem.as_bytes())?;
    anyhow::ensure!(
        certificates.len() == 1,
        "pin exactly one server certificate"
    );
    Ok(certificates.remove(0))
}

pub fn fingerprint(pem: &str) -> Result<String> {
    Ok(Sha256::digest(certificate(pem)?.to_der()?)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn check_certificate(expected: &[u8], presented: &X509) -> Result<()> {
    let actual = presented.to_der()?;
    anyhow::ensure!(
        openssl::memcmp::eq(&Sha256::digest(expected), &Sha256::digest(&actual)),
        BoundaryError("connection_certificate_mismatch")
    );
    let now = Asn1Time::days_from_now(0)?;
    anyhow::ensure!(
        presented.not_before().compare(&now)? != Ordering::Greater
            && presented.not_after().compare(&now)? == Ordering::Greater,
        BoundaryError("connection_certificate_expired")
    );
    Ok(())
}

// Cancelling a poll/restore or exceeding the deadline must also stop its driver.
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl PinnedClient {
    pub fn new(pem: &str) -> Result<Self> {
        let certificate = certificate(pem)?.to_der()?;
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_security_level(2);
        builder.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256")?;
        // This mode authenticates the exact imported leaf, not its CA/hostname.
        // No HTTP handshake, headers or credentials may precede check_certificate.
        builder.set_verify(SslVerifyMode::NONE);
        Ok(Self {
            connector: builder.build(),
            certificate,
            connection: Mutex::new(None),
        })
    }

    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.certificate)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub async fn get(
        &self,
        origin: &Url,
        url: Url,
        credentials: Option<(&str, &str)>,
    ) -> Result<reqwest::Response> {
        self.get_authenticated(
            origin,
            url,
            credentials.map_or(Auth::None, |(u, p)| Auth::Basic(u, p)),
        )
        .await
    }

    pub(crate) async fn get_authenticated(
        &self,
        origin: &Url,
        mut url: Url,
        auth: Auth<'_>,
    ) -> Result<reqwest::Response> {
        tokio::time::timeout(Duration::from_secs(20), async {
            for redirects in 0..=4 {
                crate::collector::safe_link(origin, url.as_str())?;
                let response = self
                    .request(&url, hyper::Method::GET, auth, Bytes::new())
                    .await?;
                if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                    anyhow::ensure!(redirects < 4, "excessive Redfish redirect");
                    let location = response
                        .headers()
                        .get(hyper::header::LOCATION)
                        .context("redirect location missing")?
                        .to_str()?;
                    url = url.join(location)?;
                    crate::collector::safe_link(origin, url.as_str())?;
                } else {
                    return Ok(response);
                }
            }
            unreachable!()
        })
        .await?
    }

    pub(crate) async fn session_request(
        &self,
        origin: &Url,
        url: Url,
        method: hyper::Method,
        auth: Auth<'_>,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        crate::collector::safe_link(origin, url.as_str())?;
        anyhow::ensure!(
            (method == hyper::Method::POST
                && crate::collector::session_collection_path(url.path()))
                || (method == hyper::Method::DELETE
                    && crate::collector::session_resource_path(url.path())
                    && body.is_empty()),
            "only authentication session operations are permitted"
        );
        tokio::time::timeout(
            Duration::from_secs(20),
            self.request(&url, method, auth, Bytes::from(body)),
        )
        .await?
    }

    async fn request(
        &self,
        url: &Url,
        method: hyper::Method,
        auth: Auth<'_>,
        body: Bytes,
    ) -> Result<reqwest::Response> {
        let mut slot = self.connection.lock().await;
        // Take ownership before awaiting: cancellation must discard the stream.
        let cached = slot.take().filter(|connection| {
            // Controllers can silently close an idle stream. Authenticate writes
            // on a fresh verified connection rather than replaying a POST after
            // an ambiguous network failure. Hardware GETs still reuse streams.
            method == hyper::Method::GET
                && connection.origin == url.origin()
                && !connection.sender.is_closed()
        });
        let reused = cached.is_some();
        let mut connection = match cached {
            Some(connection) => connection,
            None => self.connect(url).await?,
        };
        // Recheck time validity even on a previously authenticated connection.
        check_certificate(&self.certificate, &connection.peer)?;
        let response = match self
            .send(&mut connection, url, method.clone(), auth, body.clone())
            .await
        {
            Ok(response) => response,
            Err(error)
                if reused
                    && method == hyper::Method::GET
                    && error.downcast_ref::<hyper::Error>().is_some() =>
            {
                // A controller may close an idle keep-alive stream. GET is safe to
                // repeat once, after authenticating the replacement TLS stream.
                drop(connection);
                connection = self.connect(url).await?;
                self.send(&mut connection, url, method, auth, body).await?
            }
            Err(error) => return Err(error),
        };
        if !connection.sender.is_closed() {
            *slot = Some(connection);
        }
        Ok(response)
    }

    async fn connect(&self, url: &Url) -> Result<Connection> {
        let host = url.host_str().context("HTTPS host missing")?;
        let socket_host = host.trim_matches(['[', ']']);
        let tcp = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect((socket_host, url.port_or_known_default().unwrap_or(443))),
        )
        .await??;
        let mut config = self.connector.configure()?;
        config.set_verify_hostname(false);
        let ssl = config.into_ssl(socket_host)?;
        let mut stream = SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|_| anyhow::anyhow!(BoundaryError("connection_tls_incompatible")))?;
        let peer = stream
            .ssl()
            .peer_certificate()
            .context(BoundaryError("connection_certificate_mismatch"))?;
        check_certificate(&self.certificate, &peer)?;

        // Only an authenticated stream is handed to the HTTP client.
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(65536)
            .handshake(TokioIo::new(stream))
            .await?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        Ok(Connection {
            origin: url.origin(),
            peer,
            sender,
            _driver: driver,
        })
    }

    async fn send(
        &self,
        connection: &mut Connection,
        url: &Url,
        method: hyper::Method,
        auth: Auth<'_>,
        body: Bytes,
    ) -> Result<reqwest::Response> {
        let host = url.host_str().context("HTTPS host missing")?;
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(hyper::header::HOST, authority)
            .header("OData-Version", "4.0")
            .header(
                "User-Agent",
                concat!("hardware-monitor/", env!("CARGO_PKG_VERSION")),
            );
        if method == hyper::Method::POST {
            request = request.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        if let Auth::Basic(username, password) = auth {
            let secret = zeroize::Zeroizing::new(format!("{username}:{password}"));
            let encoded =
                zeroize::Zeroizing::new(format!("Basic {}", STANDARD.encode(secret.as_bytes())));
            let mut value = hyper::header::HeaderValue::from_str(&encoded)?;
            value.set_sensitive(true);
            request = request.header(hyper::header::AUTHORIZATION, value);
        } else if let Auth::Token(token) = auth {
            let mut value = hyper::header::HeaderValue::from_str(token)?;
            value.set_sensitive(true);
            request = request.header("X-Auth-Token", value);
        }
        let response = connection
            .sender
            .send_request(request.body(Full::new(body))?)
            .await?;
        let (parts, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                anyhow::ensure!(
                    bytes.len() + data.len() <= 2 * 1024 * 1024,
                    BoundaryError("connection_response_too_large")
                );
                bytes.extend_from_slice(&data);
            }
        }
        Ok(reqwest::Response::from(Response::from_parts(parts, bytes)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use openssl::{
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{extension::BasicConstraints, X509NameBuilder},
    };

    pub fn cert(before: i64, after: i64) -> X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "synthetic-old-controller")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(before).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::from_unix(after).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().ca().build().unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        cert.build()
    }

    pub fn pem() -> String {
        String::from_utf8(
            cert(crate::now() - 60, crate::now() + 86400)
                .to_pem()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn exact_leaf_and_dates_replace_only_ca_and_name_checks() {
        let now = crate::now();
        let valid = cert(now - 60, now + 86400);
        let der = valid.to_der().unwrap();
        assert!(check_certificate(&der, &valid).is_ok());
        let other = cert(now - 60, now + 86400);
        assert_eq!(
            crate::dsm::error_code(&check_certificate(&der, &other).unwrap_err()),
            "connection_certificate_mismatch"
        );
        for certificate in [cert(now - 3600, now - 60), cert(now + 3600, now + 86400)] {
            assert_eq!(
                crate::dsm::error_code(
                    &check_certificate(&certificate.to_der().unwrap(), &certificate).unwrap_err()
                ),
                "connection_certificate_expired"
            );
        }
    }

    #[test]
    fn import_requires_one_certificate_and_fingerprint_is_der_based() {
        let pem = pem();
        assert!(certificate(&(pem.clone() + &pem)).is_err());
        assert!(
            certificate("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----").is_err()
        );
        assert_eq!(
            fingerprint(&pem).unwrap(),
            fingerprint(&pem.replace('\n', "\r\n")).unwrap()
        );
    }
}
