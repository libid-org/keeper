//! The JWKS reading: an issuer's OIDC signing keys, notarized like any other
//! session.
//!
//! The keeper points the same MPC-TLS machinery at an [`Issuer`]'s JWKS
//! endpoint and gets back the record every session gets -- a
//! [`NotarizedSession`] -- which it submits to that issuer's roots contract
//! (`GoogleJwtRoots`, `TelegramJwtRoots`). That contract authenticates the signature
//! through the Notary Service and reads the key set straight out of the
//! revealed transcript. The notary special-cases nothing here: it signs what it
//! observed, and which host it observed is in the record (`authorityId`), for
//! the contract to compare against the authority it pins.
//!
//! What makes the reading readable on chain is its [`layout`]: everything
//! revealed, nothing committed. The contract concatenates the revealed ranges
//! and parses request line, `Host` header, status line, framing and JSON out
//! of the result; a commitment anywhere in either direction is refused,
//! because a hidden range is where a second `Host` header or a decoy `"keys"`
//! member would live.
//!
//! The entry point is [`prover::notarize_jwks`]: it runs the MPC-TLS prover
//! against a live notary over any async socket and reads the record back.

/// The record as the notary hands it back: the platform-ceremonies
/// section 4.1 attested data and the notary's signature over it, and nothing
/// else. An alias of libid-transcript's wire struct, so the keeper and the
/// notary agree on the frame by construction.
pub type NotarizedSession = libid_transcript::AttestationWire;

/// Errors from building or obtaining a JWKS reading.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The reading could not be built: request construction.
    #[error("jwks: {detail}")]
    Jwks {
        /// Human-readable failure detail.
        detail: String,
    },
    /// The issuer compressed its reply, which the contract refuses. Telegram
    /// does so for some requests, so another session may come back plain.
    #[error("the issuer's reply carries a Content-Encoding")]
    Encoded,
    /// MPC-TLS session driving failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),
    /// Wire protocol / transcript range failure.
    #[error(transparent)]
    Transcript(#[from] libid_transcript::Error),
    /// Crypto primitive failure.
    #[error(transparent)]
    Crypto(#[from] libid_crypto::Error),
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, Error>;

pub mod prover;

use libid_tlsn::{
    Bytes,
    HttpBody,
    HttpRequest,
};
use libid_transcript::ceremony::Layout;

/// An OIDC issuer whose signing keys the keeper keeps trusted on chain.
///
/// Host and request line are copies of `CeremonyProfile.jwksHost` and
/// `jwksRequestLine`, which the roots contract pins byte for byte: the record
/// carries `keccak256` of the host as `authorityId`, and the contract also
/// requires the one `Host` header to name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issuer {
    /// `GoogleJwtRoots`, read by `google/v1`.
    Google,
    /// `TelegramJwtRoots`, read by `telegram/v1`.
    Telegram,
}

/// One issuer's constants.
struct Profile {
    /// Name for logs and the status table.
    name: &'static str,
    /// The TLS server name and `Host` value.
    host: &'static str,
    /// The request path.
    path: &'static str,
}

const GOOGLE: Profile = Profile {
    name: "google",
    host: "www.googleapis.com",
    path: "/oauth2/v3/certs",
};

const TELEGRAM: Profile = Profile {
    name: "telegram",
    host: "oauth.telegram.org",
    path: "/.well-known/jwks.json",
};

impl Issuer {
    /// Every issuer, in the order a tick serves them.
    pub const ALL: [Self; 2] = [Self::Google, Self::Telegram];

    fn profile(self) -> &'static Profile {
        match self {
            Self::Google => &GOOGLE,
            Self::Telegram => &TELEGRAM,
        }
    }

    /// The TLS server name and `Host` value.
    pub fn host(self) -> &'static str {
        self.profile().host
    }

    /// The request path.
    pub fn path(self) -> &'static str {
        self.profile().path
    }

    /// The URL both the poll and the notarized reading fetch.
    pub fn url(self) -> String {
        format!("https://{}{}", self.host(), self.path())
    }
}

impl std::fmt::Display for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.profile().name)
    }
}

/// What the JWKS reading discloses: everything, in both directions.
///
/// One revealed range per direction covering the whole transcript, and no
/// commitment. A public key set has nothing to hide, and zero commitments is
/// what lets the contract read the transcript by concatenation safely: with
/// exact coverage and nothing committed, no cut can hide bytes between the
/// request line and the last key.
///
/// The JWKS session is not part of a ceremony, so it states its own layout
/// rather than calling `libid_transcript::ceremony`. The shape is the same --
/// the reveals are named and the commitments are their complement, here empty
/// -- so each direction tiles by construction, which is what the contract's
/// `requireExactCoverage` demands.
///
/// `None` when the reply's head carries a `Content-Encoding`: the contract
/// refuses any (`EncodedBody`), so the session stops before the notary signs.
pub fn layout(sent: &[u8], recv: &[u8]) -> Option<(Layout, Layout)> {
    if is_encoded(recv) {
        return None;
    }
    let whole = |bytes: &[u8]| Layout {
        reveal: std::iter::once(0..bytes.len()).collect(),
        commit: Vec::new(),
    };
    Some((whole(sent), whole(recv)))
}

/// Whether the response head names a `Content-Encoding`, in any case.
fn is_encoded(recv: &[u8]) -> bool {
    let head = recv
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(recv, |end| &recv[..end]);
    head.split(|&b| b == b'\n').any(|line| {
        line.len() >= 17 && line[..17].eq_ignore_ascii_case(b"content-encoding:")
    })
}

/// The request the reading sends.
///
/// The URI is absolute because `prover_generic` derives the server to reach
/// from it; on the wire the request-target is origin-form (`prover_generic`
/// rewrites it before sending), so the transcript's first line is the one the
/// contract pins. hyper writes header names in lowercase, in the order they
/// were set, and adds none of its own to a bodiless `GET`, so the sent
/// transcript is exactly:
///
/// ```text
/// GET <path> HTTP/1.1\r\n
/// host: <host>\r\n
/// connection: close\r\n
/// accept: application/json\r\n
/// user-agent: <user_agent>\r\n
/// \r\n
/// ```
///
/// `connection: close` makes the server delimit the response, so the prover
/// reads to EOF and the transcript ends where the body does.
pub(crate) fn request(
    issuer: Issuer,
    user_agent: &str,
) -> Result<HttpRequest<HttpBody<Bytes>>> {
    HttpRequest::builder()
        .method("GET")
        .uri(issuer.url())
        .header("Host", issuer.host())
        .header("Connection", "close")
        .header("Accept", "application/json")
        .header("User-Agent", user_agent)
        .body(HttpBody::new(Bytes::new()))
        .map_err(|e| Error::Jwks {
            detail: format!("request build: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's coverage rule: reveals and commitments account for every
    /// byte of the direction exactly, no gap and no overlap.
    fn assert_tiles(layout: &Layout, length: usize) {
        let mut spans: Vec<_> = layout
            .reveal
            .iter()
            .chain(layout.commit.iter())
            .cloned()
            .collect();
        spans.sort_by_key(|range| range.start);
        let mut at = 0;
        for range in spans {
            assert_eq!(range.start, at, "gap or overlap before {}", range.start);
            at = range.end;
        }
        assert_eq!(at, length, "the spans do not reach the transcript end");
    }

    #[test]
    fn reveals_both_directions_whole_and_commits_nothing() {
        let sent = b"GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com\r\n\r\n";
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"keys\":[]}";
        let (s, r) = layout(sent, recv).unwrap();

        assert_eq!(s.reveal.len(), 1, "one range, not several to cut between");
        assert_eq!(s.reveal[0], 0..sent.len());
        assert_eq!(r.reveal.len(), 1, "one range, not several to cut between");
        assert_eq!(r.reveal[0], 0..recv.len());
        assert!(s.commit.is_empty(), "a commitment would hide request bytes");
        assert!(
            r.commit.is_empty(),
            "a commitment would hide response bytes"
        );
        assert_tiles(&s, sent.len());
        assert_tiles(&r, recv.len());
    }

    /// An encoded reply, as Telegram sends some even unasked. The contract
    /// refuses it, so the notary must not sign.
    #[test]
    fn an_encoded_reply_is_not_laid_out() {
        let sent =
            b"GET /.well-known/jwks.json HTTP/1.1\r\nhost: oauth.telegram.org\r\n\r\n";
        for header in ["Content-Encoding: gzip", "content-encoding: identity"] {
            let recv = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n{header}\r\n\r\n\x1f\u{8b}.."
            );
            assert!(layout(sent, recv.as_bytes()).is_none(), "{header}");
        }
    }

    /// Only the head counts: a body that mentions the header is plain.
    #[test]
    fn a_body_naming_the_header_is_still_laid_out() {
        let recv = b"HTTP/1.1 200 OK\r\n\r\n\ncontent-encoding: gzip";
        assert!(layout(b"GET / HTTP/1.1\r\n\r\n", recv).is_some());
    }

    #[test]
    fn the_request_names_the_host_the_path_and_the_four_headers() {
        for issuer in Issuer::ALL {
            let request = request(issuer, "libid-keeper/test").unwrap();
            assert_eq!(request.method(), "GET");
            assert_eq!(request.uri().host(), Some(issuer.host()));
            assert_eq!(request.uri().path(), issuer.path());
            let headers: Vec<(&str, &[u8])> = request
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes()))
                .collect();
            let expected: Vec<(&str, &[u8])> = vec![
                ("host", issuer.host().as_bytes()),
                ("connection", b"close"),
                ("accept", b"application/json"),
                ("user-agent", b"libid-keeper/test"),
            ];
            assert_eq!(headers, expected);
        }
    }

    /// The contracts' `CeremonyProfile` constants, written out: the request
    /// line and the host each roots contract pins.
    #[test]
    fn each_issuer_requests_what_its_contract_pins() {
        let pinned = [
            (
                Issuer::Google,
                "www.googleapis.com",
                "GET /oauth2/v3/certs HTTP/1.1\r\n",
            ),
            (
                Issuer::Telegram,
                "oauth.telegram.org",
                "GET /.well-known/jwks.json HTTP/1.1\r\n",
            ),
        ];
        for (issuer, host, line) in pinned {
            assert_eq!(issuer.host(), host);
            assert_eq!(format!("GET {} HTTP/1.1\r\n", issuer.path()), line);
        }
    }

    /// The poll and the notarized session must read ONE endpoint, or the
    /// verdicts describe one key set and the record attests another. The
    /// poll fetches `Issuer::url`; this is what the session requests.
    #[test]
    fn the_request_targets_the_url_the_poll_reads() {
        for issuer in Issuer::ALL {
            let request = request(issuer, "libid-keeper/test").unwrap();
            assert_eq!(request.uri().to_string(), issuer.url());
        }
    }
}
