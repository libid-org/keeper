//! The JSON-RPC client every network read and rotation goes through. A hosted
//! node's URL holds its API key (Alchemy's `/v2/<key>`) and every error ends
//! up in the logs, so no error from this client names the endpoint.

use std::task::{
    Context,
    Poll,
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
use anyhow::{
    bail,
    Context as _,
    Result,
};
use reqwest::Url;
use tower::{
    Layer,
    Service,
};

use crate::config::ResolvedNetwork;

/// What an error shows where the endpoint's URL stood.
const REDACTED: &str = "<RPC_URL>";

impl ResolvedNetwork {
    /// A client for this network's endpoint whose errors never name it.
    pub fn rpc_client(&self) -> Result<RpcClient> {
        let endpoint: Url = self
            .rpc_url
            .parse()
            .with_context(|| format!("network '{}': rpc_url is not a URL", self.name))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            bail!(
                "network '{}': rpc_url has to be http or https, not {}",
                self.name,
                endpoint.scheme()
            );
        }
        Ok(ClientBuilder::default()
            .layer(Redact(endpoint.clone()))
            .http(endpoint))
    }
}

/// The client layer that takes its endpoint out of every transport error.
#[derive(Clone, Debug)]
pub(crate) struct Redact(Url);

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
            body: error.body.replace(self.0.as_str(), REDACTED),
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
    use alloy::{
        primitives::Address,
        providers::{
            Provider,
            RootProvider,
        },
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

    fn network(rpc_url: String) -> ResolvedNetwork {
        ResolvedNetwork {
            name: "n".into(),
            rpc_url,
            signer: None,
            google_jwt_roots: Address::ZERO,
        }
    }

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
        fn rpc_url(&self) -> String {
            format!("http://{}/v2/{KEY}", self.0.local_addr().unwrap())
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
        let provider: RootProvider =
            RootProvider::new(network(endpoint.rpc_url()).rpc_client().unwrap());
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
        let error = network(format!("ws://127.0.0.1:1/v2/{KEY}"))
            .rpc_client()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("has to be http or https, not ws"),
            "{error:#}"
        );
    }
}
