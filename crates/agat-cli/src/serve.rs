//! `agat serve`: a local HTTP endpoint over the scan engine, so SOAR
//! playbooks, mail gateways, and pipelines can submit bytes and get a
//! `ScanResult` back without shelling out.
//!
//! It is still offline: agat makes no outbound connection. The server only
//! accepts connections, on loopback by default. There is no built-in
//! authentication; anything beyond localhost belongs behind a reverse
//! proxy that does auth and TLS.
//!
//! Routes:
//!
//! - `POST /v1/scan`: body = raw file bytes. Optional `?name=<path>` is
//!   echoed in the result; `?format=sarif` returns a SARIF log instead.
//!   Responds `200` with the result for every verdict (the severity is in
//!   the body and the `X-Agat-Severity` header), `413` over the size limit,
//!   `400` for an empty body, `500` if analysis fails.
//! - `GET /v1/model`: the active model's provenance (`ModelRef`).
//! - `GET /healthz`: liveness, with the agat version and model.

use std::net::SocketAddr;
use std::sync::Arc;

use agat_engine::ImmuneModel;
use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

/// Shared, read-only server state: the model loaded once at startup.
#[derive(Clone)]
pub struct AppState {
    model: Arc<ImmuneModel>,
}

/// Build the router. Split from [`run`] so tests can drive it directly.
pub fn router(model: ImmuneModel, max_bytes: usize) -> Router {
    Router::new()
        .route("/v1/scan", post(scan))
        .route("/v1/model", get(model_info))
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(max_bytes))
        .with_state(AppState {
            model: Arc::new(model),
        })
}

#[derive(Debug, Deserialize)]
struct ScanQuery {
    name: Option<String>,
    format: Option<String>,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn scan(State(state): State<AppState>, Query(q): Query<ScanQuery>, body: Bytes) -> Response {
    if body.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "empty body: POST the file's raw bytes",
        );
    }
    let sarif = match q.format.as_deref() {
        None | Some("json") => false,
        Some("sarif") => true,
        Some(other) => {
            return error(
                StatusCode::BAD_REQUEST,
                format!("unknown format '{other}' (json or sarif)"),
            )
        }
    };
    // Analysis is CPU-bound; keep it off the async workers.
    let model = state.model.clone();
    let outcome = tokio::task::spawn_blocking(move || model.scan_bytes(&body, q.name)).await;
    let result = match outcome {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scan task failed: {e}"),
            )
        }
    };
    let severity = result.severity().label();
    let mut response = if sarif {
        Json(agat_engine::sarif::to_sarif(std::slice::from_ref(&result))).into_response()
    } else {
        Json(&result).into_response()
    };
    response
        .headers_mut()
        .insert("x-agat-severity", HeaderValue::from_static(severity));
    response
}

async fn model_info(State(state): State<AppState>) -> Response {
    Json(state.model.model_ref()).into_response()
}

async fn healthz(State(state): State<AppState>) -> Response {
    Json(json!({
        "status": "ok",
        "agat_version": env!("CARGO_PKG_VERSION"),
        "model": state.model.model_ref(),
    }))
    .into_response()
}

/// `agat serve`: bind and serve until Ctrl-C / SIGTERM.
pub fn run(
    model: ImmuneModel,
    listen: SocketAddr,
    allow_remote: bool,
    max_bytes: usize,
) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_remote {
        bail!(
            "refusing to listen on non-loopback address {listen}: agat serve has no \
             authentication. Put it behind an authenticating reverse proxy and pass \
             --allow-remote if you really mean to expose it."
        );
    }
    let model_line = crate::immune::describe_model(model.model_ref());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        eprintln!(
            "agat serve listening on http://{} · model: {model_line} · max body {} bytes",
            listener.local_addr()?,
            max_bytes
        );
        axum::serve(listener, router(model, max_bytes))
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("serving")
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    eprintln!("agat serve shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_antigen::Antigen;
    use agat_immune::{generate_repertoire, MemoryPool, NsaConfig, SelfModel};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    /// A tiny model in the default antigen dimension.
    fn model() -> ImmuneModel {
        let dim = agat_antigen::signature_labels(&agat_engine::antigen_config()).len();
        let ag = |v: f64| Antigen {
            signature: vec![v; dim],
            block_tokens: BTreeSet::new(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        };
        let points: Vec<(String, Antigen)> = (0..3)
            .map(|i| (format!("b{i}"), ag(0.1 + i as f64 * 0.01)))
            .collect();
        let labelled: Vec<(&str, &Antigen)> = points.iter().map(|(n, a)| (n.as_str(), a)).collect();
        let self_model = SelfModel::build(&labelled, 2);
        let repertoire = generate_repertoire(
            &self_model,
            dim,
            &NsaConfig {
                seed: 1,
                ..NsaConfig::default()
            },
        );
        ImmuneModel::from_parts(repertoire, &MemoryPool::new(dim), Some(self_model))
    }

    async fn call(
        app: Router,
        req: Request<Body>,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let sev = res
            .headers()
            .get("x-agat-severity")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, sev, serde_json::from_slice(&bytes).unwrap())
    }

    fn post(uri: &str, body: &'static [u8]) -> Request<Body> {
        Request::post(uri).body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn scan_returns_a_scan_result_with_severity_header() {
        let (status, sev, body) = call(
            router(model(), 1 << 20),
            post(
                "/v1/scan?name=upload.bin",
                b"\x7fELF definitely not a real binary",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema_version"], agat_core::SCAN_SCHEMA_VERSION);
        assert_eq!(body["sample"]["name"], "upload.bin");
        assert_eq!(body["model"]["source"], "local");
        assert_eq!(sev.as_deref(), body["verdict"]["severity"].as_str());
    }

    #[tokio::test]
    async fn scan_can_return_sarif() {
        let (status, _, body) = call(
            router(model(), 1 << 20),
            post("/v1/scan?format=sarif", b"some bytes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["version"], "2.1.0");
    }

    #[tokio::test]
    async fn rejects_empty_oversized_and_unknown_format() {
        let (status, _, _) = call(router(model(), 1 << 20), post("/v1/scan", b"")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, body) = call(
            router(model(), 1 << 20),
            post("/v1/scan?format=xml", b"abc"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("xml"));

        let res = router(model(), 8)
            .oneshot(post("/v1/scan", b"more than eight bytes"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn healthz_and_model_report_the_model() {
        let (status, _, body) = call(
            router(model(), 1024),
            Request::get("/healthz").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["model"]["source"], "local");

        let (status, _, body) = call(
            router(model(), 1024),
            Request::get("/v1/model").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["antigen_fingerprint"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn refuses_non_loopback_without_opt_in() {
        let err = run(model(), "0.0.0.0:0".parse().unwrap(), false, 1024).unwrap_err();
        assert!(err.to_string().contains("non-loopback"));
    }
}
