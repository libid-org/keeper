//! The needs-rotation decision, as pure functions over plain data.
//!
//! The chain is read elsewhere ([`crate::chain`]); this module turns "what
//! Google publishes" plus "what the contract trusts until when" into a
//! verdict, so the logic is unit-testable without a node.

use alloy::primitives::B256;
use anyhow::{
    bail,
    Context,
    Result,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use libid_crypto::keccak256;
use num_bigint::BigUint;
use serde::Deserialize;

/// Google's JWKS endpoint — the same URL the notary attests.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// One key from Google's live JWKS, with the hashes the contracts key
/// their storage by.
#[derive(Debug, Clone)]
pub struct GoogleKey {
    /// Key id, as published.
    pub kid: String,
    /// `keccak256(kid)` — `modulusOfKid` / `expiresAtKid` storage key.
    pub kid_hash: B256,
    /// keccak of the 18×120-bit limb rendering of `n` — what
    /// `trustedHashExpiresAt` is keyed by and `modulusOfKid` stores.
    pub modulus_hash: B256,
}

/// Wire shape of `oauth2/v3/certs`, reduced to what the decision needs.
#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// One JWK entry.
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
}

/// Parse a JWKS response body into [`GoogleKey`]s.
pub fn parse_google_jwks(body: &[u8]) -> Result<Vec<GoogleKey>> {
    let jwks: Jwks = serde_json::from_slice(body).context("parsing JWKS JSON")?;
    if jwks.keys.is_empty() {
        bail!("Google's JWKS response contains no keys");
    }
    jwks.keys
        .iter()
        .map(|jwk| {
            Ok(GoogleKey {
                kid: jwk.kid.clone(),
                kid_hash: kid_hash(&jwk.kid),
                modulus_hash: modulus_hash(&jwk.n)
                    .with_context(|| format!("kid {}", jwk.kid))?,
            })
        })
        .collect()
}

/// `keccak256(kid)` — matches the contracts' `_processClaim` storage key.
pub fn kid_hash(kid: &str) -> B256 {
    B256::from(keccak256(kid.as_bytes()))
}

/// keccak256 of the modulus rendered as 18 little-endian 120-bit limbs, each
/// as a 32-byte big-endian word — the exact value the contracts store and
/// the JWT circuit exposes.
///
/// Vendored from the original monorepo's `oidc-core::compute_modulus_hash`
/// (now `libid-oidc-core` in the libid repo); an upstream candidate for a
/// shared libid-rs crate so the keeper, the circuits and the backend can
/// never drift apart.
pub fn modulus_hash(n_b64url: &str) -> Result<B256> {
    const NUM_LIMBS: usize = 18;
    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_b64url)
        .context("modulus is not base64url")?;
    let n = BigUint::from_bytes_be(&n_bytes);
    let mask = (BigUint::from(1u8) << 120u32) - BigUint::from(1u8);
    let mut buf = Vec::with_capacity(NUM_LIMBS * 32);
    for i in 0..NUM_LIMBS {
        let limb = (&n >> (120 * i)) & &mask;
        let mut word = [0u8; 32];
        let lb = limb.to_bytes_be();
        word[32 - lb.len()..].copy_from_slice(&lb);
        buf.extend_from_slice(&word);
    }
    Ok(B256::from(keccak256(&buf)))
}

/// The verdict for one Google-published key on one contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyVerdict {
    /// The contract does not trust this key (never rotated in, or the kid
    /// now carries a different modulus).
    Untrusted,
    /// Trusted once, but the on-chain expiry has passed.
    Expired,
    /// Trusted, expiring within the renewal threshold.
    Expiring {
        /// Seconds until the on-chain expiry.
        secs_left: u64,
    },
    /// Trusted with comfortable margin.
    Fresh {
        /// Seconds until the on-chain expiry.
        secs_left: u64,
    },
}

impl KeyVerdict {
    /// True when this key alone justifies submitting a rotation.
    pub fn needs_rotation(&self) -> bool {
        !matches!(self, Self::Fresh { .. })
    }

    /// Stable label for logs and the status table.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Untrusted => "UNTRUSTED",
            Self::Expired => "EXPIRED",
            Self::Expiring { .. } => "EXPIRING",
            Self::Fresh { .. } => "fresh",
        }
    }
}

/// Classify one key. `trusted_until` is `None` when the contract does not
/// trust the key's current modulus at all, `Some(expiry)` otherwise. `now`
/// is CHAIN time (the latest block timestamp — the clock the contracts
/// compare expiries against), `threshold` the renewal window in seconds.
pub fn key_verdict(trusted_until: Option<u64>, now: u64, threshold: u64) -> KeyVerdict {
    match trusted_until {
        None | Some(0) => KeyVerdict::Untrusted,
        Some(expiry) if expiry <= now => KeyVerdict::Expired,
        Some(expiry) => {
            let secs_left = expiry - now;
            if secs_left <= threshold {
                KeyVerdict::Expiring { secs_left }
            } else {
                KeyVerdict::Fresh { secs_left }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `keccak256("oidc-1")`, precomputed via `cast keccak "oidc-1"` — the
    /// same vector the original monorepo's rotation listener asserted
    /// against.
    #[test]
    fn kid_hash_matches_cast_keccak() {
        let expected = "22f02000da44e4b96e6ba14598619cce801d51d062fe5392dc68ad5fbd641b86";
        assert_eq!(hex::encode(kid_hash("oidc-1")), expected);
    }

    /// The vendored limb math is byte-identical to the origin implementation
    /// (the original monorepo's `oidc-core::compute_modulus_hash`): both the
    /// base64url input and the expected hash below were produced by running
    /// the original against a deterministic 256-byte modulus.
    #[test]
    fn modulus_hash_matches_origin_implementation() {
        let n_b64url = "BAsSGSAnLjU8Q0pRWF9mbXR7gomQl56lrLO6wcjP1t3k6_L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ-mrbS7wsnQ197l7PP6Bg0UGyIpMDc-RUxTWmFob3Z9hIuSmaCnrrW8w8rR2N_m7fT7Bw4VHCMqMTg_Rk1UW2JpcHd-hYyTmqGor7a9xMvS2eDn7vUBCA8WHSQrMjlAR05VXGNqcXh_ho2Um6KpsLe-xczT2uHo7_YCCRAXHiUsMzpBSE9WXWRrcnmAh46VnKOqsbi_xs3U2-Lp8PcDChEYHyYtNDtCSVBXXmVsc3qBiI-WnaSrsrnAx87V3OPq8fgECxIZIA";
        let expected = "c5c1457ba4adf8bb84324e8595bf883639aa7ebd7aa7e7626a0b51f90e6838bc";
        assert_eq!(hex::encode(modulus_hash(n_b64url).unwrap()), expected);
    }

    #[test]
    fn parse_google_jwks_extracts_every_key() {
        let body = br#"{"keys":[
            {"alg":"RS256","e":"AQAB","n":"AQAB","kty":"RSA","kid":"k1","use":"sig"},
            {"use":"sig","kty":"RSA","kid":"k2","alg":"RS256","n":"eyJh","e":"AQAB"}
        ]}"#;
        let keys = parse_google_jwks(body).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid, "k1");
        assert_eq!(keys[1].kid, "k2");
        assert_ne!(keys[0].modulus_hash, keys[1].modulus_hash);
    }

    #[test]
    fn parse_google_jwks_rejects_empty_key_set() {
        assert!(parse_google_jwks(br#"{"keys":[]}"#).is_err());
    }

    // ── the needs-rotation matrix ──────────────────────────────────────────

    const NOW: u64 = 1_700_000_000;
    const WEEK: u64 = 7 * 24 * 60 * 60;

    /// New kid on Google, never rotated in: rotate.
    #[test]
    fn verdict_untrusted_when_chain_has_no_expiry() {
        let v = key_verdict(None, NOW, WEEK);
        assert_eq!(v, KeyVerdict::Untrusted);
        assert!(v.needs_rotation());
    }

    /// A zero expiry is the contracts' "not trusted" sentinel, not an epoch.
    #[test]
    fn verdict_untrusted_when_expiry_is_zero() {
        assert_eq!(key_verdict(Some(0), NOW, WEEK), KeyVerdict::Untrusted);
    }

    /// Expiry in the past: rotate.
    #[test]
    fn verdict_expired_when_expiry_passed() {
        let v = key_verdict(Some(NOW - 1), NOW, WEEK);
        assert_eq!(v, KeyVerdict::Expired);
        assert!(v.needs_rotation());
    }

    /// Expiry exactly now counts as expired (the contract comparison is
    /// `block.timestamp < expiry` for trust).
    #[test]
    fn verdict_expired_at_the_boundary() {
        assert_eq!(key_verdict(Some(NOW), NOW, WEEK), KeyVerdict::Expired);
    }

    /// Inside the renewal threshold: rotate early.
    #[test]
    fn verdict_expiring_inside_threshold() {
        let v = key_verdict(Some(NOW + WEEK - 1), NOW, WEEK);
        assert_eq!(
            v,
            KeyVerdict::Expiring {
                secs_left: WEEK - 1
            }
        );
        assert!(v.needs_rotation());
    }

    /// Exactly at the threshold still rotates — a tick later it would be
    /// inside, and rotation is idempotent.
    #[test]
    fn verdict_expiring_at_threshold_boundary() {
        assert!(key_verdict(Some(NOW + WEEK), NOW, WEEK).needs_rotation());
    }

    /// Comfortable margin: up-to-date, no rotation.
    #[test]
    fn verdict_fresh_beyond_threshold() {
        let v = key_verdict(Some(NOW + WEEK + 1), NOW, WEEK);
        assert_eq!(
            v,
            KeyVerdict::Fresh {
                secs_left: WEEK + 1
            }
        );
        assert!(!v.needs_rotation());
    }
}
