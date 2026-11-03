//! The JSON-RPC endpoint every network read and rotation goes through. A
//! hosted node's URL holds its API key (Alchemy's `/v2/<key>`) and errors end
//! up in the logs, so neither the endpoint's `Debug` nor an error from its
//! client names more than the host; [`Logs`](crate::logs::Logs) keeps alloy's
//! transport span, which names the whole URL, out of the logs. Each call
//! fails once its endpoint leaves it unanswered past the configured limit, and
//! is sent again a few times after an error a moment's outage explains.

mod deadline;
mod retry;

use std::{
    fmt,
    net::SocketAddr,
    str::FromStr,
    task::{
        Context,
        Poll,
    },
    time::Duration,
};

use alloy::{
    rpc::{
        client::{
            ClientBuilder,
            RpcClient,
        },
        json_rpc::{
            RequestPacket,
            ResponsePacket,
        },
    },
    transports::{
        HttpError,
        RpcError,
        TransportError,
        TransportErrorKind,
        TransportFut,
    },
};
use reqwest::redirect::Policy;
use tower::{
    Layer,
    Service,
};
use url::Url;

use self::{
    deadline::Deadline,
    retry::Retry,
};

/// What an error shows where the endpoint's URL stood.
const REDACTED: &str = "<RPC_URL>";

/// An `http` or `https` JSON-RPC endpoint. It has no `Display`, and its
/// `Debug` names only the host: the rest of the URL may hold an API key.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcUrl(Url);

/// An `rpc_url` the keeper cannot call.
#[derive(Debug, thiserror::Error)]
pub enum RpcUrlError {
    /// Not a URL at all.
    #[error(transparent)]
    Url(#[from] url::ParseError),
    /// A URL of another scheme.
    #[error("the RPC URL has to be http or https, not {0}")]
    Scheme(String),
}

impl RpcUrl {
    /// A client for this endpoint whose errors never name it, each call and
    /// each connect failing once unanswered for `limit` and sent again after
    /// a transient error ([`Retry::STANDARD`]). It follows no
    /// redirect: the error of a redirected request names the URL the server
    /// picked.
    pub fn client(&self, limit: Duration) -> reqwest::Result<RpcClient> {
        self.client_with(limit, Retry::STANDARD)
    }

    fn client_with(&self, limit: Duration, retry: Retry) -> reqwest::Result<RpcClient> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(limit)
            .build()?;
        Ok(ClientBuilder::default()
            .layer(retry)
            .layer(Redact(self.clone()))
            .layer(Deadline(limit))
            .http_with_client(http, self.0.clone()))
    }

    /// `text` with the endpoint's URL replaced, and its path and query too:
    /// a server may echo the path it was asked for ("Cannot POST /v2/<key>").
    fn redact(&self, text: &str) -> String {
        let path = Some(self.0.path()).filter(|path| *path != "/");
        [Some(self.0.as_str()), path, self.0.query()]
            .into_iter()
            .flatten()
            .filter(|part| !part.is_empty())
            .fold(text.to_owned(), |text, part| text.replace(part, REDACTED))
    }
}

impl FromStr for RpcUrl {
    type Err = RpcUrlError;

    /// `localhost:port` and `ip:port` mean plain HTTP, as alloy's `connect`
    /// reads them.
    fn from_str(url: &str) -> Result<Self, RpcUrlError> {
        let url = if url.starts_with("localhost:") || url.parse::<SocketAddr>().is_ok() {
            Url::parse(&format!("http://{url}"))
        } else {
            Url::parse(url)
        }?;
        match url.scheme() {
            "http" | "https" => Ok(Self(url)),
            other => Err(RpcUrlError::Scheme(other.to_string())),
        }
    }
}

impl fmt::Debug for RpcUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RpcUrl")
            .field(&self.0.host_str().unwrap_or_default())
            .finish()
    }
}

/// The client layer that takes its endpoint out of every transport error.
#[derive(Clone, Debug)]
pub(crate) struct Redact(RpcUrl);

/// A transport whose errors never name its endpoint.
#[derive(Clone)]
pub(crate) struct Redacted<S> {
    inner: S,
    redact: Redact,
}

impl Redact {
    /// `error` without the endpoint. reqwest names the URL in every error it
    /// returns, alloy writes a failed read of an error body into the HTTP
    /// error's body text, and a server's own text may echo the path.
    fn apply(&self, error: TransportError) -> TransportError {
        match error {
            RpcError::Transport(TransportErrorKind::Custom(source)) => {
                match source.downcast::<reqwest::Error>() {
                    Ok(error) => TransportErrorKind::custom(error.without_url()),
                    Err(source) => {
                        RpcError::Transport(TransportErrorKind::Custom(source))
                    }
                }
            }
            RpcError::Transport(TransportErrorKind::HttpError(error)) => {
                RpcError::Transport(TransportErrorKind::HttpError(self.http(error)))
            }
            RpcError::Transport(TransportErrorKind::HttpErrorWithRetryAfter {
                error,
                retry_after,
            }) => RpcError::Transport(TransportErrorKind::HttpErrorWithRetryAfter {
                error: self.http(error),
                retry_after,
            }),
            RpcError::DeserError { err, text } => RpcError::DeserError {
                err,
                text: self.0.redact(&text),
            },
            other => other,
        }
    }

    fn http(&self, error: HttpError) -> HttpError {
        HttpError {
            status: error.status,
            body: self.0.redact(&error.body),
        }
    }
}

impl<S> Layer<S> for Redact {
    type Service = Redacted<S>;

    fn layer(&self, inner: S) -> Redacted<S> {
        Redacted {
            inner,
            redact: self.clone(),
        }
    }
}

impl<S> Service<RequestPacket> for Redacted<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>,
    S::Future: Send + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| self.redact.apply(error))
    }

    fn call(&mut self, request: RequestPacket) -> TransportFut<'static> {
        let redact = self.redact.clone();
        let answer = self.inner.call(request);
        Box::pin(async move { answer.await.map_err(|error| redact.apply(error)) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{
            AtomicUsize,
            Ordering,
        },
        Arc,
    };

    use alloy::{
        providers::{
            Provider,
            RootProvider,
        },
        transports::TransportResult,
    };
    use tokio::{
        io::{
            AsyncBufReadExt,
            AsyncReadExt,
            AsyncWriteExt,
            BufReader,
        },
        net::TcpListener,
    };

    use super::{
        deadline::Unanswered,
        *,
    };

    const KEY: &str = "fake-api-key";
    const TOKEN: &str = "fake-token";

    /// The limit of a call to an endpoint that answers at once.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// A 500 whose body stops short of its `content-length`, so the client's
    /// read of the error body fails.
    const CUT_OFF: &str =
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 64\r\n\r\ncut";

    /// A redirect to another path on the same host.
    const REDIRECT: &str = "HTTP/1.1 307 Temporary Redirect\r\n\
        location: /v3/other-key\r\ncontent-length: 0\r\n\r\n";

    /// A 503 with the body Eden's endpoint sent.
    const UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\n\
        content-length: 18\r\nconnection: close\r\n\r\nserver unavailable";

    /// Where an answer takes the id of the request it answers.
    const REQUEST_ID: &str = "REQUEST_ID";

    /// The answer to `eth_blockNumber` naming block `number`, its body ending
    /// where the connection does.
    fn block(number: u64) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n\
             {{\"jsonrpc\":\"2.0\",\"id\":{REQUEST_ID},\"result\":\"{number:#x}\"}}"
        )
    }

    /// The part of a JSON-RPC request an answer echoes.
    #[derive(serde::Deserialize)]
    struct Request {
        id: u64,
    }

    /// An endpoint that reads each request and sends back the next of its
    /// answers, the last one again for every later request. `None` keeps the
    /// connection open without an answer.
    struct Endpoint {
        listener: TcpListener,
        answers: Vec<Option<String>>,
        requests: Arc<AtomicUsize>,
    }

    impl Endpoint {
        /// The error a call gets, sent once, from an endpoint that answers
        /// `answer`.
        async fn error_for(answer: String) -> TransportError {
            let (block, _) = Self::call(vec![Some(answer)], PATIENCE, Retry::NONE).await;
            block.unwrap_err()
        }

        /// What `eth_blockNumber` gets from an endpoint that answers
        /// `answers`, through a client that waits `limit` for each call and
        /// sends it again as `retry` allows, and how many requests the
        /// endpoint read.
        async fn call(
            answers: Vec<Option<String>>,
            limit: Duration,
            retry: Retry,
        ) -> (TransportResult<u64>, usize) {
            let endpoint = Self {
                listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
                answers,
                requests: Arc::default(),
            };
            let provider: RootProvider =
                RootProvider::new(endpoint.rpc_url().client_with(limit, retry).unwrap());
            let requests = endpoint.requests.clone();
            let server = tokio::spawn(endpoint.serve());
            let block = tokio::time::timeout(PATIENCE, provider.get_block_number())
                .await
                .expect("the call ended within its tries");
            server.abort();
            (block, requests.load(Ordering::SeqCst))
        }

        /// The endpoint's URL, holding [`KEY`] in its path and [`TOKEN`] in its
        /// query, the way hosted nodes hold their API keys.
        fn rpc_url(&self) -> RpcUrl {
            let address = self.listener.local_addr().unwrap();
            format!("http://{address}/v2/{KEY}?token={TOKEN}")
                .parse()
                .unwrap()
        }

        async fn serve(self) {
            loop {
                let (stream, _) = self.listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    let read = stream.read_line(&mut line).await.unwrap();
                    if read == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let Request { id } = serde_json::from_slice(&body).unwrap();
                let seen = self.requests.fetch_add(1, Ordering::SeqCst);
                let answer = self.answers[seen.min(self.answers.len() - 1)]
                    .as_ref()
                    .map(|answer| answer.replace(REQUEST_ID, &id.to_string()));
                tokio::spawn(async move {
                    let Some(answer) = answer else {
                        // Holds the connection open until the test ends.
                        return std::future::pending().await;
                    };
                    stream.write_all(answer.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
        }
    }

    #[tokio::test]
    async fn a_cut_off_error_body_names_no_endpoint() {
        let error = Endpoint::error_for(CUT_OFF.to_owned()).await;
        let Some(TransportErrorKind::HttpError(HttpError { status, body })) =
            error.as_transport_err()
        else {
            panic!("expected an HTTP error, got {error:?}");
        };
        assert_eq!(*status, 500);
        assert!(body.contains("failed to read response body"), "{body}");
        assert!(body.contains(REDACTED), "{body}");
        assert!(!body.contains(KEY), "{body}");
        assert!(!body.contains(TOKEN), "{body}");
    }

    #[tokio::test]
    async fn an_error_body_that_echoes_the_path_names_no_endpoint() {
        let error = Endpoint::error_for(format!(
            "HTTP/1.1 429 Too Many Requests\r\nretry-after: 1\r\nconnection: close\r\n\r\n\
             no capacity left for POST /v2/{KEY}?token={TOKEN}"
        ))
        .await;
        let Some(TransportErrorKind::HttpErrorWithRetryAfter {
            error: HttpError { status, body },
            ..
        }) = error.as_transport_err()
        else {
            panic!("expected an HTTP error with a retry delay, got {error:?}");
        };
        assert_eq!(*status, 429);
        assert_eq!(
            body,
            &format!("no capacity left for POST {REDACTED}?{REDACTED}")
        );
    }

    #[tokio::test]
    async fn a_body_that_is_no_json_names_no_endpoint() {
        let error = Endpoint::error_for(format!(
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nCannot POST /v2/{KEY}"
        ))
        .await;
        let RpcError::DeserError { text, .. } = &error else {
            panic!("expected a deserialization error, got {error:?}");
        };
        assert_eq!(text, &format!("Cannot POST {REDACTED}"));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let error = Endpoint::error_for(REDIRECT.to_owned()).await;
        let Some(TransportErrorKind::HttpError(HttpError { status, .. })) =
            error.as_transport_err()
        else {
            panic!("expected an HTTP error, got {error:?}");
        };
        assert_eq!(*status, 307);
    }

    /// An endpoint that takes the request but never answers fails the call
    /// at its limit.
    #[tokio::test]
    async fn a_call_left_unanswered_fails_at_the_deadline() {
        let limit = Duration::from_millis(200);
        let (block, requests) = Endpoint::call(vec![None], limit, Retry::NONE).await;
        let error = block.unwrap_err();
        let Some(TransportErrorKind::Custom(source)) = error.as_transport_err() else {
            panic!("expected the deadline's error, got {error:?}");
        };
        assert_eq!(source.downcast_ref(), Some(&Unanswered(limit)));
        assert_eq!(requests, 1);
    }

    /// The run of 06:17 on 2026-11-03: Eden answered one read with a 503.
    #[tokio::test]
    async fn a_read_answered_after_one_503_succeeds() {
        let answers = vec![Some(UNAVAILABLE.to_owned()), Some(block(42))];
        let (block, requests) = Endpoint::call(answers, PATIENCE, Retry::STANDARD).await;
        assert_eq!(block.unwrap(), 42);
        assert_eq!(requests, 2);
    }

    #[tokio::test]
    async fn a_read_that_keeps_getting_503_fails_with_the_last_503() {
        let answers = vec![Some(UNAVAILABLE.to_owned())];
        let (block, requests) = Endpoint::call(answers, PATIENCE, Retry::STANDARD).await;
        let error = block.unwrap_err();
        let Some(TransportErrorKind::HttpError(HttpError { status, body })) =
            error.as_transport_err()
        else {
            panic!("expected the endpoint's 503, got {error:?}");
        };
        assert_eq!((*status, body.as_str()), (503, "server unavailable"));
        assert_eq!(requests, 6);
    }

    #[tokio::test]
    async fn a_read_refused_for_what_it_asks_is_sent_once() {
        let (block, requests) =
            Endpoint::call(vec![Some(REDIRECT.to_owned())], PATIENCE, Retry::STANDARD)
                .await;
        let error = block.unwrap_err();
        let Some(TransportErrorKind::HttpError(HttpError { status, .. })) =
            error.as_transport_err()
        else {
            panic!("expected an HTTP error, got {error:?}");
        };
        assert_eq!(*status, 307);
        assert_eq!(requests, 1);
    }

    /// Each unanswered try costs the whole deadline, so a dead endpoint gets
    /// one more try, not three.
    #[tokio::test]
    async fn an_unanswered_read_is_sent_again_once() {
        let limit = Duration::from_millis(200);
        let (block, requests) = Endpoint::call(vec![None], limit, Retry::STANDARD).await;
        let error = block.unwrap_err();
        let Some(TransportErrorKind::Custom(source)) = error.as_transport_err() else {
            panic!("expected the deadline's error, got {error:?}");
        };
        assert_eq!(source.downcast_ref(), Some(&Unanswered(limit)));
        assert_eq!(requests, 2);
    }

    /// A rotation sent into a 503 is not sent again: its first send may have
    /// landed. A read after it on the same client is.
    #[tokio::test]
    async fn a_transaction_is_sent_once_and_a_read_on_its_client_again() {
        let endpoint = Endpoint {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            answers: vec![
                Some(UNAVAILABLE.to_owned()),
                Some(UNAVAILABLE.to_owned()),
                Some(block(42)),
            ],
            requests: Arc::default(),
        };
        let provider: RootProvider =
            RootProvider::new(endpoint.rpc_url().client(PATIENCE).unwrap());
        let requests = endpoint.requests.clone();
        let server = tokio::spawn(endpoint.serve());
        let sent = provider.send_raw_transaction(&[0x02]).await;
        assert!(sent.is_err(), "the 503 reached the caller");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(provider.get_block_number().await.unwrap(), 42);
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        server.abort();
    }

    #[test]
    fn a_websocket_endpoint_is_refused() {
        let error = format!("ws://127.0.0.1:1/v2/{KEY}")
            .parse::<RpcUrl>()
            .unwrap_err();
        assert!(
            matches!(&error, RpcUrlError::Scheme(scheme) if scheme == "ws"),
            "{error:?}"
        );
    }

    #[test]
    fn host_and_port_mean_plain_http() {
        for (bare, full) in [
            ("localhost:8545", "http://localhost:8545"),
            ("127.0.0.1:8545", "http://127.0.0.1:8545"),
        ] {
            assert_eq!(
                bare.parse::<RpcUrl>().unwrap(),
                full.parse::<RpcUrl>().unwrap()
            );
        }
    }

    #[test]
    fn debug_names_only_the_host() {
        let url: RpcUrl = format!("https://eth-mainnet.g.alchemy.com/v2/{KEY}")
            .parse()
            .unwrap();
        assert_eq!(format!("{url:?}"), r#"RpcUrl("eth-mainnet.g.alchemy.com")"#);
    }
}
