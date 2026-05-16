//! A [`ReadAt`] adapter that translates random-access reads into HTTP Range requests.
//!
//! This allows ms-pdb to read PDB metadata (~20-30 KB in 5-7 requests) directly from
//! an HTTP server without buffering the entire file in memory.
//!
//! Networking and buffering are delegated to [`http_range_client`], which keeps an
//! internal buffer so repeated or adjacent reads are served without extra network
//! round-trips. A custom [`SyncHttpRangeClient`] implementation is used so we can:
//!   * attach a Bearer token for authenticated upstreams, and
//!   * require `206 Partial Content` responses, guarding against servers that ignore
//!     the `Range` header and return the entire file (which would otherwise be
//!     misinterpreted as the bytes at the requested offset).

use bytes::Bytes;
use http_range_client::{HttpError, SyncBufferedHttpRangeClient, SyncHttpRangeClient};
use ms_pdb::ReadAt;
use std::io::{self, Read};
use std::sync::Mutex;
use std::time::Duration;

/// Read/write timeout applied to each underlying HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum number of bytes fetched per HTTP request. ms-pdb issues small, scattered
/// reads; fetching a modest window at a time amortizes per-request overhead and lets
/// the buffer satisfy nearby follow-up reads without another round-trip.
const MIN_REQUEST_SIZE: usize = 16 * 1024;

/// A [`SyncHttpRangeClient`] backed by `ureq` that adds an optional Bearer token and
/// enforces that the server actually honored the `Range` request.
struct UreqRangeClient {
    agent: ureq::Agent,
    bearer_token: Option<String>,
}

impl SyncHttpRangeClient for UreqRangeClient {
    fn get_range(&self, url: &str, range: &str) -> http_range_client::Result<Bytes> {
        let mut req = self.agent.get(url).set("Range", range);
        if let Some(token) = &self.bearer_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        let response = req.call().map_err(HttpError::from)?;

        // A server that honors the `Range` header responds with `206 Partial Content`.
        // A `200 OK` means the server ignored the range and returned the full body, in
        // which case the bytes would not correspond to the requested offset and must
        // not be treated as partial content.
        if response.status() != 206 {
            return Err(HttpError::HttpError(format!(
                "expected 206 Partial Content for range request, got {} \
                 (server may not support HTTP Range requests)",
                response.status()
            )));
        }

        let mut buf = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| HttpError::HttpError(e.to_string()))?;
        Ok(Bytes::from(buf))
    }

    fn head_response_header(
        &self,
        url: &str,
        header: &str,
    ) -> http_range_client::Result<Option<String>> {
        let mut req = self.agent.head(url);
        if let Some(token) = &self.bearer_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        let response = req.call().map_err(HttpError::from)?;
        Ok(response.header(header).map(|val| val.to_string()))
    }
}

/// Implements [`ReadAt`] over buffered HTTP Range requests.
///
/// This is intended for use with ms-pdb's `Pdb::open()`, which makes a small number
/// of scattered reads totaling ~20-30 KB regardless of file size. The underlying
/// buffered client caches fetched bytes, so overlapping or adjacent reads avoid
/// redundant network requests.
pub struct HttpRangeReader {
    // `ReadAt::read_at` takes `&self`, but the buffered client requires `&mut self`,
    // so interior mutability is needed. Reads are cheap and short-lived, so a plain
    // `Mutex` is sufficient (and keeps the reader `Send + Sync`).
    client: Mutex<SyncBufferedHttpRangeClient<UreqRangeClient>>,
}

impl HttpRangeReader {
    /// Create a new reader for the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self::build(&url.into(), None)
    }

    /// Create a new reader that attaches a Bearer token to every request.
    pub fn with_bearer_token(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self::build(&url.into(), Some(token.into()))
    }

    fn build(url: &str, bearer_token: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_read(REQUEST_TIMEOUT)
            .timeout_write(REQUEST_TIMEOUT)
            .build();
        let inner = UreqRangeClient {
            agent,
            bearer_token,
        };
        let mut client = SyncBufferedHttpRangeClient::with(inner, url);
        client.set_min_req_size(MIN_REQUEST_SIZE);
        Self {
            client: Mutex::new(client),
        }
    }
}

impl ReadAt for HttpRangeReader {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let begin = usize::try_from(offset)
            .map_err(|_| io::Error::other("read offset exceeds usize range"))?;

        let mut client = self
            .client
            .lock()
            .map_err(|_| io::Error::other("HTTP range reader mutex poisoned"))?;

        let data = client
            .get_range(begin, buf.len())
            .map_err(io::Error::other)?;

        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}
