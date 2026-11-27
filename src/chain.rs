//! On-chain reads and the rotation submission.
//!
//! The one target is `GoogleJwtRoots`. Trust is by MODULUS:
//! `trustedHashExpiresAt(modulusHash)` is what `GooglePlatformVerifier` reads
//! (the JWT circuit does not expose `kid`), so it is what the keeper reads
//! too. A rotation is `rotate(attestedData, proof)` — the notarized session
//! as the notary handed it over, nothing re-encoded — sent with the Notary
//! Fee attached: the contract forwards `msg.value` whole to the Notary
//! Service, which refuses anything but the exact fee.
//!
//! The contract keeps two generations of Google's key set (the latest
//! reading and the one before it) and exposes them as `currentKeys()`, with
//! `freshestObservedAt()` and `needsRotation()` beside them. `needsRotation()`
//! is NOT a substitute for the per-key verdicts: it is contract-side only (it
//! cannot see Google's live set, so a freshly published key does not trip it
//! while the current reading still has runway) and its 7-day runway is fixed
//! where `renewal_threshold_secs` is configurable — so the decision stays here.

use crate::jwks::NotarizedSession;
use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    primitives::{
        Address,
        Bytes,
        TxHash,
        B256,
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
use libid_contracts::bindings::ceremony::GoogleJwtRoots;

use crate::{
    config::DROP_HOLD,
    decision::{
        drop_held,
        key_verdict,
        GoogleKey,
        KeyVerdict,
    },
};

/// The verdicts for one `GoogleJwtRoots`, one entry per live Google key.
#[derive(Debug, Clone)]
pub struct RootsReading {
    /// `(kid, verdict)` for every key Google currently publishes.
    pub keys: Vec<(String, KeyVerdict)>,
    /// Moduli in the contract's current generation that Google no longer
    /// publishes. A rotation moves them to `previous`, where they lose trust
    /// after its grace period instead of at the next renewal.
    pub dropped: Vec<B256>,
    /// True while the chain's reading is younger than the drop hold, so
    /// `dropped` calls for no rotation yet.
    pub drop_held: bool,
}

impl RootsReading {
    /// True when any key justifies a rotation, or Google dropped a key the
    /// current generation still lists and the hold has passed.
    pub fn needs_rotation(&self) -> bool {
        (!self.drop_held && !self.dropped.is_empty())
            || self.keys.iter().any(|(_, v)| v.needs_rotation())
    }
}

/// The latest block timestamp — the clock the contract compares expiries
/// against, so decisions use it instead of the keeper host's wall clock.
pub async fn chain_now<P: Provider>(provider: &P) -> Result<u64> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .context("fetching latest block")?
        .context("chain has no latest block")?;
    Ok(block.header.timestamp)
}

/// Read the trust state of the `GoogleJwtRoots` at `roots` for every live
/// Google key and classify it.
pub async fn read_roots<P: Provider>(
    provider: &P,
    roots: Address,
    google_keys: &[GoogleKey],
    now: u64,
    threshold: u64,
) -> Result<RootsReading> {
    let contract = GoogleJwtRoots::new(roots, provider);
    let mut keys = Vec::with_capacity(google_keys.len());
    for key in google_keys {
        let expiry = contract
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .with_context(|| format!("trustedHashExpiresAt({}) failed", key.kid))?;
        keys.push((
            key.kid.clone(),
            key_verdict(to_expiry(expiry), now, threshold),
        ));
    }
    let current = contract
        .currentKeys()
        .call()
        .await
        .context("currentKeys() failed")?
        .current;
    let dropped = current
        .moduli
        .into_iter()
        .filter(|modulus| !google_keys.iter().any(|key| key.modulus_hash == *modulus))
        .collect();
    Ok(RootsReading {
        keys,
        dropped,
        drop_held: drop_held(current.observedAt, now, DROP_HOLD),
    })
}

/// Collapse a U256 expiry to the `Option<u64>` the verdict works over. Zero
/// is the contract's "not trusted" sentinel; anything beyond u64 is treated
/// as far-future.
fn to_expiry(expiry: U256) -> Option<u64> {
    if expiry.is_zero() {
        None
    } else {
        Some(expiry.try_into().unwrap_or(u64::MAX))
    }
}

/// ABI-encode `rotate(attestedData, proof)` from a notarized session. The
/// record goes in as the notary encoded it: the signature is over exactly
/// those bytes, and the contract derives the notary key from the pair alone.
pub fn rotate_calldata(session: &NotarizedSession) -> Vec<u8> {
    GoogleJwtRoots::rotateCall {
        attestedData: Bytes::from(session.attested_data.clone()),
        proof: Bytes::from(session.notary_signature.clone()),
    }
    .abi_encode()
}

/// Submit `rotate(...)` to `roots` with the Notary Fee attached and wait for
/// the receipt. Returns the transaction hash and gas used; errors when the
/// transaction reverts.
///
/// The fee is quoted right before sending, not at read time: `rotate` takes
/// exactly `quoteRotation()` (the Notary Service's current `fee()`), so a fee
/// change between the decision and the submission would otherwise revert
/// with `WrongValue` after the MPC-TLS session was already paid for.
pub async fn submit_rotation<P: Provider>(
    provider: &P,
    roots: Address,
    calldata: Vec<u8>,
) -> Result<(TxHash, u64)> {
    let fee = GoogleJwtRoots::new(roots, provider)
        .quoteRotation()
        .call()
        .await
        .context("quoteRotation() failed")?;
    tracing::info!(contract = %roots, fee_wei = %fee, "rotate() costs the Notary Fee");
    let tx = TransactionRequest::default()
        .with_to(roots)
        .with_value(fee)
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
    use std::slice;

    use alloy::{
        primitives::B256,
        providers::ProviderBuilder,
        transports::mock::Asserter,
    };
    use libid_contracts::bindings::ceremony::GoogleJwtRoots::{
        currentKeysCall,
        currentKeysReturn,
        trustedHashExpiresAtCall,
        Generation,
    };

    use super::*;

    const NOW: u64 = 1_700_000_000;
    const WEEK: u64 = 7 * 24 * 60 * 60;

    fn key(kid: &str, seed: u8) -> GoogleKey {
        GoogleKey {
            kid: kid.into(),
            modulus_hash: B256::repeat_byte(seed),
        }
    }

    /// `read_roots` over a contract that trusts every one of `google` for a
    /// month and lists `current` as its current generation, read at
    /// `observed_at`.
    async fn reading(
        google: &[GoogleKey],
        current: Vec<B256>,
        observed_at: u64,
    ) -> RootsReading {
        let asserter = Asserter::new();
        for _ in google {
            let expiry = U256::from(NOW + 4 * WEEK);
            asserter.push_success(&Bytes::from(
                trustedHashExpiresAtCall::abi_encode_returns(&expiry),
            ));
        }
        let generations = currentKeysReturn {
            current: Generation {
                observedAt: observed_at,
                moduli: current,
            },
            previous: Generation {
                observedAt: 0,
                moduli: Vec::new(),
            },
        };
        asserter.push_success(&Bytes::from(currentKeysCall::abi_encode_returns(
            &generations,
        )));
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        read_roots(&provider, Address::ZERO, google, NOW, WEEK)
            .await
            .unwrap()
    }

    /// Google dropped K2 and still publishes K1, both fresh on chain, and the
    /// chain's reading is as old as the hold: the current generation's K2 is
    /// what calls for the rotation.
    #[tokio::test]
    async fn a_current_key_google_dropped_needs_a_rotation_once_the_hold_passed() {
        let k1 = key("k1", 1);
        let k2 = key("k2", 2);
        let reading = reading(
            slice::from_ref(&k1),
            vec![k1.modulus_hash, k2.modulus_hash],
            NOW - DROP_HOLD.as_secs(),
        )
        .await;
        assert!(reading.needs_rotation(), "{reading:?}");
    }

    /// The same drop a second inside the hold: a backend that still lists K2
    /// may have served the reading, so no rotation yet.
    #[tokio::test]
    async fn a_current_key_google_dropped_needs_no_rotation_inside_the_hold() {
        let k1 = key("k1", 1);
        let k2 = key("k2", 2);
        let reading = reading(
            slice::from_ref(&k1),
            vec![k1.modulus_hash, k2.modulus_hash],
            NOW - DROP_HOLD.as_secs() + 1,
        )
        .await;
        assert_eq!(reading.dropped, vec![k2.modulus_hash]);
        assert!(!reading.needs_rotation(), "{reading:?}");
    }

    /// The current generation is exactly Google's set, every key fresh.
    #[tokio::test]
    async fn a_current_generation_matching_google_needs_no_rotation() {
        let google = [key("k1", 1), key("k2", 2)];
        let current = google.iter().map(|key| key.modulus_hash).collect();
        let reading = reading(&google, current, NOW).await;
        assert!(!reading.needs_rotation(), "{reading:?}");
    }

    /// Both halves of the record land in the corresponding ABI slot,
    /// untouched: decode the encoded calldata back and compare. This is the
    /// seam between the notary's wire format and the `rotate(bytes,bytes)`
    /// ABI — the signature is over `attested_data`, so a byte moved here is
    /// a rotation the Notary Service refuses.
    #[test]
    fn rotate_calldata_round_trips_through_the_abi() {
        let session = NotarizedSession {
            attested_data: (0..=255u8).cycle().take(700).collect(),
            notary_signature: vec![0xab; 65],
        };

        let calldata = rotate_calldata(&session);
        assert_eq!(&calldata[..4], GoogleJwtRoots::rotateCall::SELECTOR);

        let decoded = GoogleJwtRoots::rotateCall::abi_decode(&calldata).unwrap();
        assert_eq!(
            decoded.attestedData.as_ref(),
            session.attested_data.as_slice()
        );
        assert_eq!(decoded.proof.as_ref(), session.notary_signature.as_slice());
    }
}
