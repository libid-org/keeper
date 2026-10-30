//! The JSON-RPC endpoint every network read and rotation goes through. A
//! hosted node's URL holds its API key (Alchemy's `/v2/<key>`) and errors end
//! up in the logs, so neither the endpoint's `Debug` nor an error from its
//! client names more than the host.

use std::{
    fmt,
    net::SocketAddr,
    str::FromStr,
    task::{
        Context,
        Poll,
    },
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
use tower::{
    Layer,
    Service,
};
use url::Url;

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
    /// A client for this endpoint whose errors never name it.
    pub fn client(&self) -> RpcClient {
        ClientBuilder::default()
            .layer(Redact(self.clone()))
            .http(self.0.clone())
    }

    /// `text` with the endpoint's URL replaced.
    fn redact(&self, text: &str) -> String {
        text.replace(self.0.as_str(), REDACTED)
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
#[derive(Clone, Debug)]
pub(crate) struct Redacted<S> {
    inner: S,
    redact: Redact,
}

impl Redact {
    /// `error` without the endpoint. reqwest names the URL in every error it
    /// returns, and alloy writes a failed read of an error body into the
    /// HTTP error's body text.
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
    use alloy::providers::{
        Provider,
        RootProvider,
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

    use super::*;

    const KEY: &str = "fake-api-key";

    /// An endpoint that answers one request with a 500 whose body stops short
    /// of its `content-length`, so the client's read of the error body fails.
    struct CutOffErrorBody(TcpListener);

    impl CutOffErrorBody {
        const ANSWER: &[u8] =
            b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 64\r\n\r\ncut";

        async fn bind() -> Self {
            Self(TcpListener::bind("127.0.0.1:0").await.unwrap())
        }

        /// The endpoint's URL, holding [`KEY`] the way a hosted node's does.
        fn rpc_url(&self) -> RpcUrl {
            format!("http://{}/v2/{KEY}", self.0.local_addr().unwrap())
                .parse()
                .unwrap()
        }

        async fn answer(self) {
            let (stream, _) = self.0.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
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
            stream.write_all(Self::ANSWER).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_cut_off_error_body_names_no_endpoint() {
        let endpoint = CutOffErrorBody::bind().await;
        let provider: RootProvider = RootProvider::new(endpoint.rpc_url().client());
        let server = tokio::spawn(endpoint.answer());

        let error = provider.get_block_number().await.unwrap_err();
        server.await.unwrap();

        let Some(TransportErrorKind::HttpError(HttpError { status, body })) =
            error.as_transport_err()
        else {
            panic!("expected an HTTP error, got {error:?}");
        };
        assert_eq!(*status, 500);
        assert!(body.contains("failed to read response body"), "{body}");
        assert!(body.contains(REDACTED), "{body}");
        assert!(!body.contains(KEY), "{body}");
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
