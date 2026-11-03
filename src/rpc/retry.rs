//! Another try of a call the endpoint failed for a moment. A hosted node
//! answers `503` or drops a connection now and then; without a retry one such
//! blip fails the whole tick. A call is sent again only after an error that
//! says nothing about the request itself, and the error of the last try is
//! returned as it came, so the logs keep its status and body. alloy's
//! `RetryBackoffLayer` replaces that error with a "Max retries exceeded" text.

use std::{
    task::{
        Context,
        Poll,
    },
    time::Duration,
};

use alloy::{
    rpc::json_rpc::{
        RequestPacket,
        ResponsePacket,
    },
    transports::{
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

use super::deadline::Unanswered;

/// The client layer that sends a call again after a transient error, waiting
/// the entry of `backoff` for each try. An error that cost the call its whole
/// deadline is tried again at most once, so an endpoint that never answers
/// fails a call within two deadlines.
#[derive(Clone, Copy, Debug)]
pub struct Retry {
    backoff: &'static [Duration],
}

/// A transport whose calls are sent again after a transient error.
#[derive(Clone, Debug)]
pub struct Retrying<S> {
    inner: S,
    retry: Retry,
}

/// What kind of transient error a call ended in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transient {
    /// The endpoint answered or refused at once.
    Quick,
    /// The call waited out its deadline.
    Unanswered,
}

impl Retry {
    /// For calls that are safe to send twice: three more tries, 0.2 s, 0.4 s
    /// and 0.8 s apart. An endpoint still failing after them is down for the
    /// tick.
    pub const READS: Self = Self {
        backoff: &[
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
        ],
    };

    /// Every call sent once. A transaction resent after its first send landed
    /// comes back "already known" or "nonce too low", which reads as a failure.
    pub const NONE: Self = Self { backoff: &[] };
}

impl<S> Layer<S> for Retry {
    type Service = Retrying<S>;

    fn layer(&self, inner: S) -> Retrying<S> {
        Retrying {
            inner,
            retry: *self,
        }
    }
}

impl<S> Service<RequestPacket> for Retrying<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> TransportFut<'static> {
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let mut waits = self.retry.backoff.iter();
        Box::pin(async move {
            let mut waited_out = false;
            loop {
                let error = match inner.call(request.clone()).await {
                    Ok(answer) => return Ok(answer),
                    Err(error) => error,
                };
                let again = match Transient::of(&error) {
                    Some(Transient::Quick) => true,
                    Some(Transient::Unanswered) => {
                        !std::mem::replace(&mut waited_out, true)
                    }
                    None => false,
                };
                match waits.next() {
                    Some(wait) if again => {
                        tracing::debug!(%error, ?wait, "RPC call failed; trying again");
                        tokio::time::sleep(*wait).await;
                    }
                    _ => return Err(error),
                }
            }
        })
    }
}

impl Transient {
    /// The kind of `error`, if the same call may pass when sent again: any
    /// 5xx, what alloy counts as a rate limit, a request that never reached
    /// the endpoint or lost its connection, and no answer within the deadline.
    fn of(error: &TransportError) -> Option<Self> {
        let RpcError::Transport(kind) = error else {
            return None;
        };
        match kind {
            TransportErrorKind::HttpError(http)
            | TransportErrorKind::HttpErrorWithRetryAfter { error: http, .. }
                if (500..600).contains(&http.status) =>
            {
                Some(Self::Quick)
            }
            TransportErrorKind::Custom(source) if source.is::<Unanswered>() => {
                Some(Self::Unanswered)
            }
            TransportErrorKind::Custom(source) => {
                match source.downcast_ref::<reqwest::Error>() {
                    Some(error) if error.is_timeout() => Some(Self::Unanswered),
                    Some(error) if error.is_connect() || error.is_request() => {
                        Some(Self::Quick)
                    }
                    _ => kind.is_retry_err().then_some(Self::Quick),
                }
            }
            _ => kind.is_retry_err().then_some(Self::Quick),
        }
    }
}
