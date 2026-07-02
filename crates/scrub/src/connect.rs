//! CONNECT-proxy TLS interception (DESIGN §8 v5).
//!
//! Clients configure SCRUB as their HTTP proxy. For HTTPS they send
//! `CONNECT host:port`; SCRUB answers `200`, then — for hosts with a configured
//! interception route — performs the client TLS handshake itself (presenting a
//! per-host cert minted from the CA), decrypts, masks/forwards/rehydrates, and
//! re-encrypts. Hosts without a route are blind-tunnelled untouched.

use std::net::IpAddr;
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
///
/// The target `host` is client-controlled, so SCRUB would otherwise be an open
/// proxy: we refuse to tunnel to loopback / link-local addresses (blocks the
/// cloud metadata endpoint at 169.254.169.254 and localhost pivots) and connect
/// to the exact vetted IP (no DNS-rebinding window between check and connect).
async fn tunnel(mut client: TokioIo<Upgraded>, host: &str, port: u16) -> anyhow::Result<()> {
    let mut target = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        if is_blocked(&addr.ip()) {
            tracing::warn!(%host, ip = %addr.ip(), "refusing to tunnel to blocked address");
            continue;
        }
        target = Some(addr);
        break;
    }
    let target =
        target.ok_or_else(|| anyhow::anyhow!("no permitted address to tunnel for {host}"))?;
    let mut upstream = TcpStream::connect(target).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Addresses SCRUB must never proxy to: loopback, link-local (incl. cloud
/// metadata 169.254.169.254), and the unspecified address.
fn is_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_link_local() || mapped.is_unspecified();
            }
            // fe80::/10 is IPv6 link-local.
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_blocked;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_metadata_loopback_linklocal() {
        // Cloud metadata + localhost + link-local + unspecified are refused.
        assert!(is_blocked(&ip("169.254.169.254"))); // AWS/GCP/Azure metadata
        assert!(is_blocked(&ip("127.0.0.1")));
        assert!(is_blocked(&ip("0.0.0.0")));
        assert!(is_blocked(&ip("::1")));
        assert!(is_blocked(&ip("fe80::1")));
        assert!(is_blocked(&ip("::ffff:127.0.0.1"))); // v4-mapped loopback
    }

    #[test]
    fn allows_public_and_private_hosts() {
        // Public internet and ordinary private ranges are tunnelable.
        assert!(!is_blocked(&ip("1.1.1.1")));
        assert!(!is_blocked(&ip("104.18.0.1")));
        assert!(!is_blocked(&ip("10.0.0.5")));
        assert!(!is_blocked(&ip("2606:4700::1")));
    }
}
