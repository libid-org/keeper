//! On-chain reads and the rotation submission.
//!
//! Both target contracts expose the identical permissionless
//! `rotate(NotarizedJwksProof, JwkClaim[])`; they differ only in how trust
//! is read back:
//!
//! * `IdentityJwksRoots` — trust is by MODULUS: `trustedHashExpiresAt`
//!   (the JWT circuit does not expose `kid`).
//! * `GoogleOidcVerifier` — trust is by KID: `modulusOfKid` +
//!   `expiresAtKid`; a kid carrying a different modulus than Google's live
//!   one counts as untrusted.
//!
//! FOLLOW-UP (libid-contracts 0.3.1): both contracts grow keeper-facing
//! views — `currentRoots()`, `freshestObservedAt()`, `needsRotation()`.
//! `currentRoots()` can collapse the per-key reads below into one call per
//! contract once that release is picked up. `needsRotation()` is NOT a
//! substitute for the per-key verdicts: it is contract-side only (it cannot
//! see Google's live set, so a freshly published kid does not trip it while
//! an older key still has runway) and its 7-day runway is fixed where
//! `renewal_threshold_secs` is configurable — so the decision stays here.

use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    primitives::{
        Address,
        Bytes,
        FixedBytes,
        TxHash,
        U256,
    },
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use anyhow::{
    bail,
    Context,
    Result,
};
use libid_contracts::bindings::{
    identity::IdentityJwksRoots,
    oidc::GoogleOidcVerifier,
};
use notary::jwks::JwksRotationProof;

use crate::{
    config::{
        ContractKind,
        Target,
    },
    decision::{
        key_verdict,
        GoogleKey,
        KeyVerdict,
    },
};

/// The verdicts for one target contract, one entry per live Google key.
#[derive(Debug, Clone)]
pub struct TargetReading {
    /// The contract read.
    pub target: Target,
    /// `(kid, verdict)` for every key Google currently publishes.
    pub keys: Vec<(String, KeyVerdict)>,
}

impl TargetReading {
    /// True when any key justifies a rotation.
    pub fn needs_rotation(&self) -> bool {
        self.keys.iter().any(|(_, v)| v.needs_rotation())
    }
}

/// The latest block timestamp — the clock the contracts compare expiries
/// against, so decisions use it instead of the keeper host's wall clock.
pub async fn chain_now<P: Provider>(provider: &P) -> Result<u64> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .context("fetching latest block")?
        .context("chain has no latest block")?;
    Ok(block.header.timestamp)
}

/// Read one target's trust state for every live Google key and classify it.
pub async fn read_target<P: Provider>(
    provider: &P,
    target: &Target,
    google_keys: &[GoogleKey],
    now: u64,
    threshold: u64,
) -> Result<TargetReading> {
    let mut keys = Vec::with_capacity(google_keys.len());
    for key in google_keys {
        let trusted_until = match target.kind {
            ContractKind::IdentityJwksRoots => {
                let roots = IdentityJwksRoots::new(target.address, provider);
                let expiry = roots
                    .trustedHashExpiresAt(key.modulus_hash)
                    .call()
                    .await
                    .with_context(|| {
                        format!("trustedHashExpiresAt({}) failed", key.kid)
                    })?;
                to_expiry(expiry)
            }
            ContractKind::GoogleOidcVerifier => {
                let verifier = GoogleOidcVerifier::new(target.address, provider);
                let on_chain_modulus =
                    verifier
                        .modulusOfKid(key.kid_hash)
                        .call()
                        .await
                        .with_context(|| format!("modulusOfKid({}) failed", key.kid))?;
                if on_chain_modulus != key.modulus_hash {
                    // Never rotated in, or the kid now carries a different
                    // modulus — either way the live key is not trusted.
                    None
                } else {
                    let expiry = verifier
                        .expiresAtKid(key.kid_hash)
                        .call()
                        .await
                        .with_context(|| format!("expiresAtKid({}) failed", key.kid))?;
                    to_expiry(expiry)
                }
            }
        };
        keys.push((key.kid.clone(), key_verdict(trusted_until, now, threshold)));
    }
    Ok(TargetReading {
        target: target.clone(),
        keys,
    })
}

/// Collapse a U256 expiry to the `Option<u64>` the verdict works over. Zero
/// is the contracts' "not trusted" sentinel; anything beyond u64 is treated
/// as far-future.
fn to_expiry(expiry: U256) -> Option<u64> {
    if expiry.is_zero() {
        None
    } else {
        Some(expiry.try_into().unwrap_or(u64::MAX))
    }
}

/// ABI-encode `rotate(proof, claims)` from a notary wire proof. Encoded via
/// the `IdentityJwksRoots` bindings; the `GoogleOidcVerifier` ABI is
/// identical (same selector, same tuple layout), so one encoding serves both
/// targets.
pub fn rotate_calldata(proof: &JwksRotationProof) -> Vec<u8> {
    let sol_proof = IdentityJwksRoots::NotarizedJwksProof {
        notarySignature: Bytes::from(proof.notary_signature.clone()),
        domainHash: FixedBytes::from(proof.domain_hash),
        clientRandom: FixedBytes::from(proof.client_random),
        serverRandom: FixedBytes::from(proof.server_random),
        serverEphemeralKey: Bytes::from(proof.server_ephemeral_key.clone()),
        transcriptRoot: FixedBytes::from(proof.transcript_root),
        timestamp: U256::from(proof.timestamp),
        domainPath: proof
            .domain_path
            .iter()
            .copied()
            .map(FixedBytes::from)
            .collect(),
        endpointPath: proof
            .endpoint_path
            .iter()
            .copied()
            .map(FixedBytes::from)
            .collect(),
    };
    let sol_claims: Vec<IdentityJwksRoots::JwkClaim> = proof
        .claims
        .iter()
        .map(|c| IdentityJwksRoots::JwkClaim {
            jwkBytes: Bytes::from(c.jwk_bytes.clone()),
            jwkPath: c.jwk_path.iter().copied().map(FixedBytes::from).collect(),
            kid: Bytes::from(c.kid.as_bytes().to_vec()),
            nB64url: Bytes::from(c.n_b64url.as_bytes().to_vec()),
        })
        .collect();
    IdentityJwksRoots::rotateCall {
        proof: sol_proof,
        claims: sol_claims,
    }
    .abi_encode()
}

/// Submit `rotate(...)` and wait for the receipt. Returns the transaction
/// hash and gas used; errors when the transaction reverts.
pub async fn submit_rotation<P: Provider>(
    provider: &P,
    contract: Address,
    calldata: Vec<u8>,
) -> Result<(TxHash, u64)> {
    let tx = TransactionRequest::default()
        .with_to(contract)
        .with_input(Bytes::from(calldata));
    let receipt = provider
        .send_transaction(tx)
        .await
        .context("rotate() send failed")?
        .get_receipt()
        .await
        .context("rotate() receipt failed")?;
    if !receipt.status() {
        bail!(
            "rotate() reverted on chain (tx {})",
            receipt.transaction_hash
        );
    }
    Ok((receipt.transaction_hash, receipt.gas_used))
}

#[cfg(test)]
mod tests {
    use notary::jwks::JwkRotationClaim;

    use super::*;

    /// Every wire field lands in the corresponding ABI slot: decode the
    /// encoded calldata back and compare. This is the seam between the
    /// notary's wire format and the 0.3.0 rotate() ABI.
    #[test]
    fn rotate_calldata_round_trips_through_the_abi() {
        let proof = JwksRotationProof {
            notary_signature: vec![0xab; 65],
            domain_hash: [0x01; 32],
            client_random: [0x02; 32],
            server_random: [0x03; 32],
            server_ephemeral_key: vec![0xcd; 65],
            transcript_root: [0x04; 32],
            timestamp: 1_700_000_000,
            domain_path: vec![[0x10; 32], [0x11; 32]],
            endpoint_path: vec![[0x20; 32]],
            claims: vec![JwkRotationClaim {
                kid: "oidc-1".into(),
                n_b64url: "AQAB".into(),
                jwk_bytes: br#"{"kty":"RSA","kid":"oidc-1"}"#.to_vec(),
                jwk_path: vec![[0x30; 32]],
            }],
        };

        let calldata = rotate_calldata(&proof);
        assert_eq!(&calldata[..4], IdentityJwksRoots::rotateCall::SELECTOR);

        let decoded = IdentityJwksRoots::rotateCall::abi_decode(&calldata).unwrap();
        assert_eq!(
            decoded.proof.notarySignature.as_ref(),
            proof.notary_signature.as_slice()
        );
        assert_eq!(decoded.proof.domainHash.as_slice(), &proof.domain_hash);
        assert_eq!(decoded.proof.clientRandom.as_slice(), &proof.client_random);
        assert_eq!(decoded.proof.serverRandom.as_slice(), &proof.server_random);
        assert_eq!(
            decoded.proof.serverEphemeralKey.as_ref(),
            proof.server_ephemeral_key.as_slice()
        );
        assert_eq!(
            decoded.proof.transcriptRoot.as_slice(),
            &proof.transcript_root
        );
        assert_eq!(decoded.proof.timestamp, U256::from(proof.timestamp));
        assert_eq!(decoded.proof.domainPath.len(), 2);
        assert_eq!(decoded.proof.endpointPath.len(), 1);
        assert_eq!(decoded.claims.len(), 1);
        assert_eq!(decoded.claims[0].kid.as_ref(), b"oidc-1");
        assert_eq!(decoded.claims[0].nB64url.as_ref(), b"AQAB");
        assert_eq!(
            decoded.claims[0].jwkBytes.as_ref(),
            proof.claims[0].jwk_bytes.as_slice()
        );
        assert_eq!(decoded.claims[0].jwkPath.len(), 1);
    }

    /// The two target ABIs must stay interchangeable for one shared
    /// encoding path to be sound.
    #[test]
    fn both_contracts_share_the_rotate_selector() {
        assert_eq!(
            IdentityJwksRoots::rotateCall::SELECTOR,
            GoogleOidcVerifier::rotateCall::SELECTOR,
        );
    }
}
