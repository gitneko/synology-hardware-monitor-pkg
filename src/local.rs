//! Explicit, feature-gated development adapter. Never included in the DSM build.
use crate::{
    api::{Api, Operation, Request, WriteBody, MAX_REQUEST},
    dsm::AuthContext,
};
use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    header,
    service::service_fn,
    Method, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};

pub struct Config {
    listener: TcpListener,
    root: PathBuf,
    authority: String,
    binding: String,
}
impl Config {
    pub async fn bind(port: u16, root: PathBuf) -> Result<Self> {
        let root = root
            .canonicalize()
            .context("build the frontend first: npm run build --prefix web")?;
        anyhow::ensure!(
            root.join("index.html").is_file(),
            "frontend index.html missing; build the frontend first"
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let authority = listener.local_addr()?.to_string();
        eprintln!("Local development: http://{authority}/ (no application login; real device credentials still required)");
        Ok(Self {
            listener,
            root,
            authority,
            binding: format!("local-{:032x}", rand::random::<u128>()),
        })
    }
}

pub async fn serve(config: Config, api: Arc<Api>) -> Result<()> {
    let config = Arc::new(config);
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            connection = config.listener.accept() => {
                let (stream, peer) = connection?;
                if !peer.ip().is_loopback() || clients.len() >= 16 { continue; }
                let config = config.clone();
                let api = api.clone();
                clients.spawn(async move {
                    let service = service_fn(move |request| {
                        let config = config.clone(); let api = api.clone();
                        async move { Ok::<_, Infallible>(match route(request, &config, &api).await {
                            Ok(response) => response,
                            Err(_) => json_response(StatusCode::BAD_REQUEST, json!({"ok":false,"code":"local_request_invalid","error":"Invalid local development request"})),
                        }) }
                    });
                    let _ = tokio::time::timeout(Duration::from_secs(120), hyper::server::conn::http1::Builder::new()
                        .max_buf_size(32768).serve_connection(TokioIo::new(stream), service)).await;
                });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

type Reply = Response<Full<Bytes>>;
fn reply(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "frame-ancestors 'none'")
        .header("Cross-Origin-Resource-Policy", "same-origin")
        .body(Full::new(body.into()))
        .unwrap()
}
fn json_response(status: StatusCode, value: Value) -> Reply {
    reply(
        status,
        "application/json; charset=utf-8",
        serde_json::to_vec(&value).unwrap(),
    )
}

async fn route(request: hyper::Request<Incoming>, config: &Config, api: &Api) -> Result<Reply> {
    // Exact Host defeats DNS rebinding. Cross-site reads and writes are refused;
    // writes additionally require the package CSRF token from the local dashboard.
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    };
    let origin = format!("http://{}", config.authority);
    if header("host") != config.authority
        || request.uri().authority().is_some()
        || !matches!(header("sec-fetch-site"), "" | "none" | "same-origin")
        || (!header("origin").is_empty() && header("origin") != origin)
        || (request.method() == Method::POST && header("origin") != origin)
    {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            json!({"ok":false,"code":"local_origin_invalid"}),
        ));
    }
    if request.uri().path() == "/api.cgi" {
        let locale = crate::i18n::Language::header(header("x-hardwaremonitor-language"));
        let method = request.method().clone();
        let diagnostic = request.uri().query() == Some("diagnose=1");
        let (operation, csrf) = if method == Method::GET {
            (Operation::Dashboard, None)
        } else if method == Method::POST {
            anyhow::ensure!(
                header("content-type")
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    == "application/json",
                "JSON required"
            );
            let bytes = zeroize::Zeroizing::new(
                Limited::new(request.into_body(), MAX_REQUEST - 16384)
                    .collect()
                    .await
                    .map_err(|_| anyhow::anyhow!("invalid or oversized request body"))?
                    .to_bytes()
                    .to_vec(),
            );
            let body: WriteBody = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                !matches!(body.operation, Operation::Dashboard),
                "invalid write operation"
            );
            anyhow::ensure!(
                bytes.len() <= 128 * 1024
                    || matches!(
                        body.operation,
                        Operation::BackupInspect { .. } | Operation::BackupRestore { .. }
                    ),
                "request too large"
            );
            (body.operation, Some(body.csrf))
        } else {
            return Ok(reply(
                StatusCode::METHOD_NOT_ALLOWED,
                "text/plain",
                "GET or POST required",
            ));
        };
        let auth = AuthContext {
            environment: [("HTTP_COOKIE".into(), config.binding.clone())].into(),
            diagnostic,
        };
        let mut result = api
            .handle_local(Request {
                auth,
                locale,
                operation,
                csrf,
            })
            .await;
        result["source"] = json!("hardware-monitor");
        result["version"] = json!(env!("CARGO_PKG_VERSION"));
        return Ok(json_response(StatusCode::OK, result));
    }
    if request.method() != Method::GET {
        return Ok(reply(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            "GET required",
        ));
    }
    let path = request.uri().path();
    if path == "/local-runtime.js" {
        return Ok(reply(
            StatusCode::OK,
            "text/javascript",
            "globalThis.HARDWARE_MONITOR_LOCAL = true;",
        ));
    }
    // Serve only the built UI, never arbitrary workspace/state files.
    let relative = if path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    if !(relative == "index.html" || relative == "ui-build.json" || relative.starts_with("assets/"))
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || relative.contains(['%', '\\'])
    {
        return Ok(reply(StatusCode::NOT_FOUND, "text/plain", "Not found"));
    }
    let file = config.root.join(relative);
    let Ok(file) = file.canonicalize() else {
        return Ok(reply(StatusCode::NOT_FOUND, "text/plain", "Not found"));
    };
    if !file.starts_with(&config.root) || !file.is_file() {
        return Ok(reply(StatusCode::NOT_FOUND, "text/plain", "Not found"));
    }
    let (content_type, body) = if relative == "index.html" {
        let html = std::fs::read_to_string(file)?;
        (
            "text/html; charset=utf-8",
            html.replace(
                "</head>",
                "<script src=\"/local-runtime.js\"></script></head>",
            )
            .into_bytes(),
        )
    } else {
        let mime = match file.extension().and_then(|s| s.to_str()).unwrap_or("") {
            "js" => "text/javascript",
            "css" => "text/css",
            "json" => "application/json",
            "svg" => "image/svg+xml",
            "png" => "image/png",
            "woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        (mime, std::fs::read(file)?)
    };
    Ok(reply(StatusCode::OK, content_type, body))
}
