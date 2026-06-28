//! CONNECT-proxy TLS interception (DESIGN §8 v5).
//!
//! Clients configure SCRUB as their HTTP proxy. For HTTPS they send
//! `CONNECT host:port`; SCRUB answers `200`, then — for hosts with a configured
//! interception route — performs the client TLS handshake itself (presenting a
//! per-host cert minted from the CA), decrypts, masks/forwards/rehydrates, and
//! re-encrypts. Hosts without a route are blind-tunnelled untouched.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::proxy::{intercepts_host, proxy_to_host, AppState};

/// Run the CONNECT-proxy accept loop until the listener errors fatally.
pub async fn serve(listener: TcpListener, state: Arc<AppState>, tls: Arc<rustls::ServerConfig>) {
    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let state = state.clone();
        let acceptor = TlsAcceptor::from(tls.clone());
        tokio::spawn(async move {
            let io = TokioIo::new(tcp);
            let service =
                service_fn(move |req| handle_connect(req, state.clone(), acceptor.clone()));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!(error = %e, "proxy connection closed");
            }
        });
    }
}

/// Status-only response (CONNECT 200, or an error).
fn status(code: StatusCode) -> Response<Empty<Bytes>> {
    let mut resp = Response::new(Empty::new());
    *resp.status_mut() = code;
    resp
}

async fn handle_connect(
    req: Request<Incoming>,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
) -> Result<Response<Empty<Bytes>>, hyper::Error> {
    if req.method() != Method::CONNECT {
        // Plain-HTTP proxying isn't supported; clients should use CONNECT for TLS.
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = req.uri().authority().cloned() else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    let mitm = intercepts_host(&state, &host);

    // The upgrade completes after the 200 below is flushed to the client.
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let result = if mitm {
                    mitm_connection(io, host, state, acceptor).await
                } else {
                    tunnel(io, &host, port).await
                };
                if let Err(e) = result {
                    tracing::debug!(error = %e, "tunnel/mitm ended");
                }
            }
            Err(e) => tracing::warn!(error = %e, "CONNECT upgrade failed"),
        }
    });

    Ok(status(StatusCode::OK)) // 200 Connection Established
}

/// Terminate the client TLS with a minted cert, then serve the inner HTTP request
/// through the masking pipeline (routed by the CONNECT host).
async fn mitm_connection(
    io: TokioIo<Upgraded>,
    host: String,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(io).await?;
    let io = TokioIo::new(tls);
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let host = host.clone();
        async move {
            let req = req.map(axum::body::Body::new);
            Ok::<_, std::convert::Infallible>(proxy_to_host(&state, &host, req).await)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Blind byte tunnel for hosts SCRUB does not intercept.
async fn tunnel(mut client: TokioIo<Upgraded>, host: &str, port: u16) -> anyhow::Result<()> {
    let mut upstream = TcpStream::connect((host, port)).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
