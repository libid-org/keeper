//! The log output the binary installs.

use std::{
    io,
    sync::{
        Arc,
        Mutex,
    },
    time::Duration,
};

use alloy::providers::{
    Provider,
    RootProvider,
};
use keeper::{
    logs::Logs,
    rpc::RpcUrl,
};
use tracing_subscriber::{
    util::SubscriberInitExt,
    EnvFilter,
};

const KEY: &str = "fake-api-key";

/// Far longer than a refused connection takes.
const PATIENCE: Duration = Duration::from_secs(10);

/// Every line a subscriber writes, kept to read back.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Log {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The only test in this binary: it installs the process-wide subscriber, as
// the binary does.
#[tokio::test]
async fn trace_logs_name_no_endpoint() {
    let log = Log::default();
    let writer = log.clone();
    Logs {
        filter: EnvFilter::new("trace"),
        writer: move || writer.clone(),
    }
    .subscriber()
    .init();
    tracing::trace!("logging at trace");
    let url: RpcUrl = format!("http://127.0.0.1:1/v2/{KEY}").parse().unwrap();
    let provider: RootProvider = RootProvider::new(url.client(PATIENCE).unwrap());
    provider.get_block_number().await.unwrap_err();
    let log = log.text();
    assert!(log.contains("logging at trace"), "{log}");
    assert!(log.contains("connecting to 127.0.0.1:1"), "{log}");
    assert!(log.contains("starting new connection"), "{log}");
    assert!(!log.contains(KEY), "{log}");
}
