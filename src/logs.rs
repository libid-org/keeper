//! The keeper's log output.

use tracing::{
    Level,
    Subscriber,
};
use tracing_subscriber::{
    filter::filter_fn,
    fmt::MakeWriter,
    layer::SubscriberExt,
    EnvFilter,
};

/// The target of alloy's HTTP transport, whose debug span around every
/// request names the endpoint's whole URL.
const TRANSPORT: &str = "alloy_transport_http";

/// Formatted log lines that `filter` lets through, with alloy's HTTP
/// transport held at `info` whatever `filter` says: every event inside a
/// request prints the transport's span, and the span names the whole URL.
pub struct Logs<W> {
    /// What to log, in `RUST_LOG`'s syntax.
    pub filter: EnvFilter,
    /// Where the lines go.
    pub writer: W,
}

impl<W> Logs<W>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    /// The subscriber that writes these lines.
    pub fn subscriber(self) -> impl Subscriber + Send + Sync + 'static {
        tracing_subscriber::fmt()
            .with_env_filter(self.filter)
            .with_writer(self.writer)
            .finish()
            .with(filter_fn(|metadata| {
                let transport = metadata
                    .target()
                    .strip_prefix(TRANSPORT)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"));
                !transport || *metadata.level() <= Level::INFO
            }))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tracing_subscriber::filter::LevelFilter;

    use super::*;

    #[test]
    fn the_level_follows_the_filter() {
        let logs = Logs {
            filter: EnvFilter::new("info"),
            writer: io::sink,
        };
        assert_eq!(logs.subscriber().max_level_hint(), Some(LevelFilter::INFO));
    }
}
