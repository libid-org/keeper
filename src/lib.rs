//! The libID JWKS keeper.
//!
//! Keeps Google's JWKS roots fresh ON-CHAIN, permissionlessly, across every
//! network it is configured for. Each tick it:
//!
//! 1. fetches Google's live JWKS over plain HTTPS (the cheap poll);
//! 2. reads each configured contract's trusted-key state;
//! 3. decides whether a rotation is needed (a key Google publishes is not
//!    trusted on-chain, or a trusted key is nearing its on-chain expiry);
//! 4. only then obtains a NOTARIZED reading of the same endpoint — an
//!    MPC-TLS session against a libid notary server — and submits
//!    `rotate(proof, claims)` to every contract that needs it.
//!
//! The keeper holds no privileged key. `rotate()` is permissionless: the
//! notary attestation is the authorization, and the contracts enforce
//! monotonicity (a replayed older proof cannot roll a key back). The only
//! keys here are gas keys. Chain state is the only state — the keeper is
//! crash-safe and any number of keepers can run concurrently.

pub mod chain;
pub mod config;
pub mod decision;
pub mod proof;
pub mod run;

pub use config::KeeperConfig;
