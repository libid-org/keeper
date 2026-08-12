//! Obtaining a `JwksRotationProof` — the notarized reading of Google's JWKS.
//!
//! The production path is the real thing: an MPC-TLS session against a
//! running libid notary's TCP wire port, driven by the notary crate's own
//! prover-side helpers ([`notary::jwks::prover::notarize_jwks`]). The mock
//! path exists for end-to-end tests only (see
//! [`crate::config::KeeperConfig::mock_notary`]).

use anyhow::{
    bail,
    Context,
    Result,
};
use libid_crypto::hex_to_signing_key;
use notary::jwks::{
    mock::{
        MockProver,
        MockProverConfig,
    },
    JwksRotationProof,
};
use tokio::net::TcpStream;
use tracing::info;

use crate::config::KeeperConfig;

/// Where rotation proofs come from.
#[derive(Debug, Clone)]
pub enum ProofSource {
    /// A libid notary's TCP wire port (`host:port`).
    Notary(String),
    /// TEST-ONLY: mock proofs signed with a local key, JWKS fetched over
    /// plain TLS (optionally from an overridden URL).
    Mock {
        /// Hex secp256k1 signing key.
        signing_key: String,
        /// JWKS URL override.
        jwks_url: Option<String>,
    },
}

impl ProofSource {
    /// Derive the proof source from config; errors when neither (or both —
    /// caught at config load) is set.
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
        if let Some(mock) = &config.mock_notary {
            return Ok(Self::Mock {
                signing_key: mock.signing_key.clone(),
                jwks_url: mock.jwks_url.clone(),
            });
        }
        bail!(
            "a rotation is needed but no proof source is configured — set \
             notary_url (or run with --dry-run to only report)"
        );
    }

    /// Obtain one notarized reading of Google's JWKS.
    pub async fn obtain(&self) -> Result<JwksRotationProof> {
        match self {
            Self::Notary(addr) => {
                info!(notary = %addr, "starting MPC-TLS JWKS notarization");
                let socket = TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("connecting to notary at {addr}"))?;
                let response = notary::jwks::prover::notarize_jwks(socket)
                    .await
                    .context("MPC-TLS JWKS notarization failed")?;
                info!(
                    claims = response.proof.claims.len(),
                    timestamp = response.proof.timestamp,
                    "notary signed the JWKS reading"
                );
                Ok(response.proof)
            }
            Self::Mock {
                signing_key,
                jwks_url,
            } => {
                info!("building MOCK rotation proof (test seam, no MPC-TLS)");
                let key = hex_to_signing_key(signing_key)
                    .map_err(|e| anyhow::anyhow!("mock_notary.signing_key: {e}"))?;
                let mut prover = MockProver::new(
                    key,
                    MockProverConfig {
                        jwks_url: jwks_url.clone(),
                        ..MockProverConfig::default()
                    },
                );
                let proof = prover
                    .build_proof()
                    .await
                    .context("mock proof construction failed")?;
                Ok(proof)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MockNotary;

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
            match ProofSource::from_config(&config).unwrap() {
                ProofSource::Notary(addr) => assert_eq!(addr, "127.0.0.1:7047"),
                other => panic!("expected notary source, got {other:?}"),
            }
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

    #[test]
    fn mock_notary_is_selected_when_configured() {
        let config = KeeperConfig {
            mock_notary: Some(MockNotary {
                signing_key: "ab".repeat(32),
                jwks_url: Some("http://127.0.0.1:1/certs".into()),
            }),
            ..base_config()
        };
        assert!(matches!(
            ProofSource::from_config(&config).unwrap(),
            ProofSource::Mock { .. }
        ));
    }
}
