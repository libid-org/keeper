//! Obtaining a [`NotarizedSession`] — the notarized reading of an issuer's JWKS:
//! an MPC-TLS session against a running libid notary's TCP wire port, driven
//! by this crate's own prover-side helpers
//! ([`crate::jwks::prover::notarize_jwks`]). What comes back is the
//! platform-ceremonies section 4.1 bytes and the notary's signature over
//! them — exactly what the roots contract's `rotate` takes.

use std::time::Duration;

use crate::jwks::{
    self,
    Issuer,
    NotarizedSession,
};
use anyhow::{
    bail,
    Context,
    Result,
};
use tokio::net::TcpStream;

use crate::config::KeeperConfig;

/// Sessions to try per reading while the reply comes back encoded, which
/// Telegram does for some requests even unasked, or a session runs out of
/// time. A reading that fails all of them is left to the next tick.
const ATTEMPTS: usize = 10;

/// How long one session may take, connect included. A reading takes about
/// 10 s in a debug build.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Where notarized readings come from.
#[derive(Debug, Clone)]
pub enum ProofSource {
    /// A libid notary's TCP wire port (`host:port`).
    Notary(String),
}

impl ProofSource {
    /// Derive the proof source from config; errors when `notary_url` is unset.
    pub fn from_config(config: &KeeperConfig) -> Result<Self> {
        if let Some(url) = &config.notary_url {
            let addr = url
                .strip_prefix("tcp://")
                .unwrap_or(url)
                .trim_end_matches('/');
            if addr.is_empty() || !addr.contains(':') {
                bail!("notary_url '{url}' is not tcp://host:port");
            }
            return Ok(Self::Notary(addr.to_string()));
        }
        bail!(
            "no proof source is configured — set notary_url (or use --dry-run to \
             only report)"
        );
    }

    /// Obtain one notarized reading of `issuer`'s JWKS, in a new session
    /// while the reply comes back encoded or a session times out.
    pub async fn obtain(&self, issuer: Issuer) -> Result<NotarizedSession> {
        let Self::Notary(addr) = self;
        for attempt in 1..=ATTEMPTS {
            tracing::info!(notary = %addr, issuer = %issuer, attempt, "starting MPC-TLS JWKS notarization");
            if let Some(session) = read_once(addr, issuer, SESSION_TIMEOUT).await? {
                tracing::info!(
                    issuer = %issuer,
                    attested_bytes = session.attested_data.len(),
                    "notary signed the JWKS reading"
                );
                return Ok(session);
            }
        }
        bail!("{issuer}'s reading failed {ATTEMPTS} times in a row, encoded or timed out")
    }
}

/// One session, bounded by `deadline`. `None` when the reply came back
/// encoded or the session ran out of time, which another session may not.
async fn read_once(
    addr: &str,
    issuer: Issuer,
    deadline: Duration,
) -> Result<Option<NotarizedSession>> {
    let session = async {
        let socket = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to notary at {addr}"))?;
        anyhow::Ok(jwks::prover::notarize_jwks(issuer, socket).await)
    };
    let Ok(connected) = tokio::time::timeout(deadline, session).await else {
        tracing::warn!(issuer = %issuer, ?deadline, "session timed out, reading again");
        return Ok(None);
    };
    match connected? {
        Ok(session) => Ok(Some(session)),
        Err(jwks::Error::Encoded) => {
            tracing::warn!(issuer = %issuer, "reply was encoded, reading again");
            Ok(None)
        }
        Err(e) => Err(e).context("MPC-TLS JWKS notarization failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> KeeperConfig {
        toml::from_str("").unwrap()
    }

    #[test]
    fn notary_url_accepts_tcp_scheme_and_bare_host_port() {
        for url in ["tcp://127.0.0.1:7047", "127.0.0.1:7047"] {
            let config = KeeperConfig {
                notary_url: Some(url.into()),
                ..base_config()
            };
            let ProofSource::Notary(addr) = ProofSource::from_config(&config).unwrap();
            assert_eq!(addr, "127.0.0.1:7047");
        }
    }

    #[test]
    fn notary_url_without_port_is_rejected() {
        let config = KeeperConfig {
            notary_url: Some("tcp://localhost".into()),
            ..base_config()
        };
        assert!(ProofSource::from_config(&config).is_err());
    }

    #[test]
    fn missing_proof_source_is_an_error() {
        assert!(ProofSource::from_config(&base_config()).is_err());
    }

    /// A notary that accepts and never answers costs one attempt, not the
    /// tick.
    #[tokio::test]
    async fn a_silent_notary_times_the_session_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let read = read_once(&addr, Issuer::Telegram, Duration::from_millis(200));
        assert!(read.await.unwrap().is_none());
    }
}
