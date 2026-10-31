//! A deadline on every call an RPC client makes. alloy waits for an answer
//! as long as the connection stays open, so an endpoint that keeps its
//! socket open but stops answering would otherwise hold a tick forever.

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
        TransportError,
        TransportErrorKind,
        TransportFut,
    },
};
use tower::{
    Layer,
    Service,
};

/// The client layer that fails a call left unanswered past its limit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(pub(crate) Duration);

/// A transport whose calls fail once they go unanswered past `limit`.
#[derive(Clone, Debug)]
pub(crate) struct Bounded<S> {
    inner: S,
    limit: Duration,
}

/// The error of a call the endpoint left unanswered past the limit.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("no answer within {0:?}")]
pub(crate) struct Unanswered(pub(crate) Duration);

impl<S> Layer<S> for Deadline {
    type Service = Bounded<S>;

    fn layer(&self, inner: S) -> Bounded<S> {
        Bounded {
            inner,
            limit: self.0,
        }
    }
}

impl<S> Service<RequestPacket> for Bounded<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>,
    S::Future: Send + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> TransportFut<'static> {
        let limit = self.limit;
        let answer = self.inner.call(request);
        Box::pin(async move {
            tokio::time::timeout(limit, answer)
                .await
                .map_err(|_| TransportErrorKind::custom(Unanswered(limit)))?
        })
    }
}
