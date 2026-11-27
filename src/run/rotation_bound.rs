//! What a disagreement between Google's backends costs: the tick against a
//! model of `GoogleJwtRoots` with a two-hour grace for a key only the previous
//! generation lists, while the poll and the notary each see one backend.

use std::{
    cell::{
        Cell,
        RefCell,
    },
    collections::BTreeSet,
    time::Duration,
};

use alloy::{
    primitives::{
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::ProviderBuilder,
    sol_types::SolCall,
    transports::mock::Asserter,
};
use anyhow::{
    bail,
    Result,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use libid_contracts::bindings::ceremony::GoogleJwtRoots::{
    currentKeysCall,
    currentKeysReturn,
    rotateCall,
    trustedHashExpiresAtCall,
    Generation,
};

use super::{
    tick_with,
    Io,
};
use crate::{
    chain::{
        self,
        RootsReading,
    },
    config::{
        ResolvedNetwork,
        DROP_HOLD,
    },
    decision::{
        self,
        GoogleKey,
        Jwk,
        Jwks,
    },
    jwks::{
        NotarizedJwks,
        NotarizedSession,
    },
};

const HOUR: u64 = 60 * 60;
/// How long a reading keeps its keys trusted.
const READING_LIFETIME: u64 = 30 * 24 * HOUR;
/// How long a key only the previous generation lists stays trusted.
const PREVIOUS_GRACE: u64 = 2 * HOUR;
/// The keeper's default renewal threshold.
const THRESHOLD: u64 = 7 * 24 * HOUR;
const START: u64 = 1_700_000_000;

/// Google's JWKS body listing `kids`, each with a 2048-bit modulus of its own.
fn body(kids: &[u8]) -> Vec<u8> {
    let keys = kids
        .iter()
        .map(|&kid| Jwk {
            kid: format!("k{kid}"),
            n: URL_SAFE_NO_PAD.encode([kid; 256]),
        })
        .collect();
    serde_json::to_vec(&Jwks { keys }).unwrap()
}

fn moduli(kids: &[u8]) -> BTreeSet<B256> {
    decision::parse_google_jwks(&body(kids))
        .unwrap()
        .into_iter()
        .map(|key| key.modulus_hash)
        .collect()
}

/// `GoogleJwtRoots` as it answers with the previous grace: the current
/// generation trusted for a reading's lifetime, a key only the previous one
/// lists until the grace set when it moved there.
struct Roots {
    current: (u64, BTreeSet<B256>),
    previous: BTreeSet<B256>,
    previous_until: u64,
}

impl Roots {
    fn trusted_until(&self, modulus: &B256) -> u64 {
        if self.current.1.contains(modulus) {
            self.current.0 + READING_LIFETIME
        } else if self.previous.contains(modulus) {
            self.previous_until
        } else {
            0
        }
    }

    /// The answers to `read_roots`' calls for `google_keys`, in its order.
    fn answers(&self, google_keys: &[GoogleKey]) -> Asserter {
        let asserter = Asserter::new();
        for key in google_keys {
            let expiry = U256::from(self.trusted_until(&key.modulus_hash));
            asserter.push_success(&Bytes::from(
                trustedHashExpiresAtCall::abi_encode_returns(&expiry),
            ));
        }
        let generations = currentKeysReturn {
            current: Generation {
                observedAt: self.current.0,
                moduli: self.current.1.iter().copied().collect(),
            },
            previous: Generation {
                observedAt: 0,
                moduli: self.previous.iter().copied().collect(),
            },
        };
        asserter.push_success(&Bytes::from(currentKeysCall::abi_encode_returns(
            &generations,
        )));
        asserter
    }

    /// `rotate` with a reading of `moduli` made at `observed_at`, mined at
    /// `block`: the same set refreshes the current generation, another set
    /// moves it to previous.
    fn apply(
        &mut self,
        observed_at: u64,
        moduli: BTreeSet<B256>,
        block: u64,
    ) -> Result<()> {
        if observed_at <= self.current.0 {
            bail!("NotNewer");
        }
        if moduli != self.current.1 {
            self.previous_until =
                (self.current.0 + READING_LIFETIME).min(block + PREVIOUS_GRACE);
            self.previous = std::mem::replace(&mut self.current.1, moduli);
        }
        self.current.0 = observed_at;
        Ok(())
    }
}

/// One network, one poll backend and one notary backend per tick, and the
/// chain's clock.
struct Backends {
    now: Cell<u64>,
    roots: RefCell<Roots>,
    poll: RefCell<Vec<u8>>,
    session: RefCell<Vec<u8>>,
    submissions: Cell<usize>,
}

impl Backends {
    fn new(roots: Roots, now: u64) -> Self {
        Self {
            now: Cell::new(now),
            roots: RefCell::new(roots),
            poll: RefCell::default(),
            session: RefCell::default(),
            submissions: Cell::new(0),
        }
    }

    /// One tick at the current clock, the poll answering `poll` and the
    /// notary `session`; then the clock moves an hour.
    async fn tick(&self, poll: &[u8], session: &[u8]) {
        self.poll.replace(body(poll));
        self.session.replace(body(session));
        let outcome = tick_with(self, &[network()], false).await;
        assert!(outcome.is_success(), "{outcome:?}");
        self.now.set(self.now.get() + HOUR);
    }
}

impl Io for Backends {
    async fn poll(&self) -> Result<Vec<GoogleKey>> {
        decision::parse_google_jwks(&self.poll.borrow())
    }

    async fn read(
        &self,
        _network: &ResolvedNetwork,
        google_keys: &[GoogleKey],
    ) -> Result<RootsReading> {
        let asserter = self.roots.borrow().answers(google_keys);
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        chain::read_roots(
            &provider,
            Address::ZERO,
            google_keys,
            self.now.get(),
            THRESHOLD,
        )
        .await
    }

    /// The record carries the body it reveals; the model reads it back.
    async fn notarize(&self) -> Result<NotarizedJwks> {
        let body = self.session.borrow().clone();
        Ok(NotarizedJwks {
            session: NotarizedSession {
                attested_data: body.clone(),
                notary_signature: Vec::new(),
            },
            body,
        })
    }

    async fn submit(&self, _network: &ResolvedNetwork, calldata: Vec<u8>) -> Result<()> {
        let call = rotateCall::abi_decode(&calldata)?;
        let moduli = decision::parse_google_jwks(&call.attestedData)?
            .into_iter()
            .map(|key| key.modulus_hash)
            .collect();
        let now = self.now.get();
        self.roots.borrow_mut().apply(now, moduli, now)?;
        self.submissions.set(self.submissions.get() + 1);
        Ok(())
    }
}

fn network() -> ResolvedNetwork {
    ResolvedNetwork {
        name: "n".into(),
        rpc_url: "http://127.0.0.1:1".parse().unwrap(),
        rpc_timeout: Duration::from_secs(10),
        signer: None,
        google_jwt_roots: Address::ZERO,
    }
}

/// The chain dropped K2 an hour ago and the poll's backend lists it again,
/// while every notarized reading comes from a backend without it: K2 is
/// expiring each tick and no reading can restore it, so the keeper pays
/// nothing. Without the set check every tick buys a refresh of {K1}.
#[tokio::test]
async fn a_notary_on_the_lagging_backend_pays_nothing() {
    let dropped_at = START + 6 * HOUR;
    let backends = Backends::new(
        Roots {
            current: (dropped_at, moduli(&[1])),
            previous: moduli(&[1, 2]),
            previous_until: dropped_at + PREVIOUS_GRACE,
        },
        dropped_at + HOUR,
    );
    for _ in 0..24 {
        backends.tick(&[1, 2], &[1]).await;
    }
    assert_eq!(backends.submissions.get(), 0);
}

/// Two backends, one listing K1 and K2 and one only K1, answer in turn for two
/// days of hourly ticks: the poll mostly reaches the first and the notary
/// mostly the second, each crossing over one tick in five. Each hold buys at
/// most a drop and a restore. Without the hold every crossing pays; without
/// the set check each reading of K1 alone refreshes a set the poll calls
/// stale.
///
/// The shares are uneven because with an even split (poll A,B,A,B and
/// notary A,A,B,B) a wrong-set reading only refreshes and so delays the next
/// drop, and the set check's removal costs nothing (11 rotations either way).
#[tokio::test]
async fn alternating_backends_cost_two_rotations_per_hold() {
    const TICKS: u64 = 48;
    let both: &[u8] = &[1, 2];
    let one: &[u8] = &[1];
    let backends = Backends::new(
        Roots {
            current: (START, moduli(both)),
            previous: BTreeSet::new(),
            previous_until: 0,
        },
        START + HOUR,
    );
    for tick in 0..TICKS {
        let poll = if tick % 5 == 0 { one } else { both };
        let session = if tick % 5 == 4 { both } else { one };
        backends.tick(poll, session).await;
    }
    let bound = 2 * TICKS.div_ceil(DROP_HOLD.as_secs() / HOUR);
    let submissions = backends.submissions.get() as u64;
    assert!(
        submissions <= bound,
        "{submissions} rotations, bound {bound}"
    );
}
