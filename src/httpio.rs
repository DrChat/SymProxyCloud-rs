//! A [`ReadAt`] adapter that translates random-access reads into HTTP range requests.

use ms_pdb::ReadAt;
use object_store::GetRange;
use reqwest::header::RANGE;
use reqwest_middleware::RequestBuilder;
use std::io;

pub struct IoClient {
    request: RequestBuilder,
    runtime: tokio::runtime::Handle,
}

pub trait IoClientExt {
    fn io(self) -> IoClient;
}

impl IoClientExt for RequestBuilder {
    fn io(self) -> IoClient {
        IoClient {
            request: self,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl ReadAt for IoClient {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let end = offset.saturating_add(buf.len() as u64);
        let range = GetRange::Bounded(offset..end);

        let data = self.runtime.block_on(async {
            let request = self
                .request
                .try_clone()
                .ok_or_else(|| io::Error::other("HTTP request cannot be cloned"))?
                .header(RANGE, range.to_string());

            let response = request.send().await.map_err(io::Error::other)?;
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(io::Error::other(format!(
                    "expected 206 Partial Content for range request, got {}",
                    response.status()
                )));
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/206
            // TODO: Validate the Content-Range header. There can be a number of valid responses.

            response.bytes().await.map_err(io::Error::other)
        })?;

        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}
