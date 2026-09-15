//! Obtaining a [`NotarizedSession`] — the notarized reading of Google's JWKS:
//! an MPC-TLS session against a running libid notary's TCP wire port, driven
//! by this crate's own prover-side helpers
//! ([`crate::jwks::prover::notarize_jwks`]). What comes back is the section
//! 9.1 bytes and the notary's signature over them — exactly what
//! `GoogleJwtRoots.rotate` takes.

use crate::jwks::NotarizedSession;
use anyhow::{
    bail,
    Context,
    Result,
};
use tokio::net::TcpStream;
use tracing::info;

use crate::config::KeeperConfig;

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

    /// Obtain one notarized reading of Google's JWKS.
    pub async fn obtain(&self) -> Result<NotarizedSession> {
        match self {
            Self::Notary(addr) => {
                info!(notary = %addr, "starting MPC-TLS JWKS notarization");
                let socket = TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connecting to notary at {addr}"))?;
                let session = crate::jwks::prover::notarize_jwks(socket)
                    .await
                    .context("MPC-TLS JWKS notarization failed")?;
                info!(
                    attested_bytes = session.attested_data.len(),
                    "notary signed the JWKS reading"
                );
                Ok(session)
            }
        }
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
}
