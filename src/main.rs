use anyhow::Context;
use axum::{
    body::Body,
    extract::{FromRef, Path, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::RequestContent,
    time::{Duration, OffsetDateTime},
};
use azure_storage_blob::{
    models::{BlockBlobClientCommitBlockListOptions, BlockLookupList},
    BlobClient, BlobServiceClient,
};
use base64::Engine;
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, LevelFilter, Verbosity};
use figment::{providers::Format, Figment};
use futures::{Stream, StreamExt};
use ms_pdb::{Container, Pdb};
use reqwest::{header, StatusCode};
use reqwest_middleware::{ClientWithMiddleware, RequestBuilder};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::Instant,
};
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tower_http::trace::TraceLayer;
use tracing::{error, info, trace, warn};
use url::Url;
use uuid::Uuid;

mod httpio;
mod pdb_filter;
use httpio::IoClientExt;
use pdb_filter::PdbFilter;

use crate::pdb_filter::pdb_flags;

/// The header used to indicate the upstream source where a symbol came from.
const UPSTREAM_SOURCE: &str = "X-Upstream-Source";

/// The header used to indicate the upstream server that a symbol was fetched from.
const UPSTREAM_SERVER: &str = "X-Upstream-Server";

/// The internal authentication token provided to us from Azure.
const INTERNAL_AUTH_TOKEN: &str = "x-ms-auth-internal-token";

/// The media type used by symbol servers to describe the compressed PDB (PDZ/MSFZ) container.
const MSFZ_CONTENT_TYPE: &str = "application/msfz0";

/// The header symbol servers use to report which container format they actually served.
///
/// An empty value means an ordinary PDB; `application/msfz0` means a PDZ.
const SYMBOL_FORMAT_HEADER: &str = "x-ms-symbol-format";

/// The maximum number of redirects to follow when fetching a symbol from upstream.
const MAX_REDIRECTS: usize = 10;

/// The container format of a symbol file.
///
/// Symbol servers negotiate this via `Accept`/`x-ms-symbol-format`, and store each format under a
/// distinct client key, so the two must never be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolFormat {
    /// An uncompressed PDB (MSF) file.
    Pdb,
    /// A compressed PDB (PDZ/MSFZ) file.
    Pdz,
}

impl SymbolFormat {
    /// The value to report in `x-ms-symbol-format`, mirroring the upstream contract where an
    /// empty value denotes an ordinary PDB.
    fn symbol_format_header(self) -> &'static str {
        match self {
            Self::Pdb => "",
            Self::Pdz => MSFZ_CONTENT_TYPE,
        }
    }

    /// Builds the symbol store key for this format.
    ///
    /// Per the symsrv convention, a PDZ keeps the original file name but is nested one level
    /// deeper under an `msfz0` directory, so the two representations never collide:
    ///
    /// ```text
    /// ntdll.pdb/<index>/ntdll.pdb          MSF
    /// ntdll.pdb/<index>/msfz0/ntdll.pdb    MSFZ
    /// ```
    fn client_key(self, name1: &str, hash: &str, name2: &str) -> String {
        match self {
            Self::Pdb => format!("{name1}/{hash}/{name2}"),
            Self::Pdz => format!("{name1}/{hash}/msfz0/{name2}"),
        }
    }

    /// Interprets a media type. Returns `None` when the value does not identify a format we
    /// recognise, so the caller can fall back to its own default.
    fn from_media_type(value: &HeaderValue) -> Option<Self> {
        let media_type = value.to_str().ok()?.split(';').next()?.trim();
        media_type
            .eq_ignore_ascii_case(MSFZ_CONTENT_TYPE)
            .then_some(Self::Pdz)
    }

    /// Determines the container format from the `x-ms-symbol-format` header, if present.
    /// The Internal Symbol Server reports this format in the 302 redirect.
    fn from_headers(headers: &reqwest::header::HeaderMap) -> Option<Self> {
        headers
            .get(SYMBOL_FORMAT_HEADER)
            .and_then(Self::from_media_type)
    }
}

/// Rejects request path segments that could escape the cache directory or the upstream URL path.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".." && !segment.contains(['/', '\\', '\0'])
}

/// `axum`-compatible error handler.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        error!("{:?}", self.0);

        // N.B: Normally returning the error in the response is not secure for
        // a production server, but since this server is only intended for local
        // use this is fine.
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{:?}", self.0)).into_response()
    }
}

/// A token credential that authenticates using a managed identity when running in
/// Azure, falling back to local developer tooling (e.g. the Azure CLI) otherwise.
///
/// This mirrors the behaviour of the default credential chain that previously shipped
/// with the Azure SDK, which was removed in the 1.0 release.
#[derive(Debug)]
struct MultiCredential {
    sources: Vec<Arc<dyn TokenCredential>>,
    cached_token: Mutex<Option<AccessToken>>,
}

impl MultiCredential {
    #[allow(unused)]
    fn new() -> anyhow::Result<Self> {
        let sources: Vec<Arc<dyn TokenCredential>> = vec![
            azure_identity::DeveloperToolsCredential::new(None)
                .context("failed to create developer tools credential")?,
            azure_identity::ManagedIdentityCredential::new(None)
                .context("failed to create managed identity credential")?,
        ];

        Ok(Self {
            sources,
            cached_token: Mutex::new(None),
        })
    }

    fn with_sources(sources: impl IntoIterator<Item = Arc<dyn TokenCredential>>) -> Self {
        Self {
            sources: sources.into_iter().collect(),
            cached_token: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl TokenCredential for MultiCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let mut cached = self.cached_token.lock().await;
        if let Some(tok) = &*cached {
            if OffsetDateTime::now_utc() < tok.expires_on.saturating_sub(Duration::minutes(1)) {
                return Ok(tok.clone());
            }
        }

        let mut last_error = None;
        for source in self.sources.iter() {
            match source.get_token(scopes, options.clone()).await {
                Ok(token) => {
                    *cached = Some(token.clone());
                    return Ok(token);
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            azure_core::Error::with_message(
                azure_core::error::ErrorKind::Credential,
                "no token credential sources are available",
            )
        }))
    }
}

fn azure_blob_client(
    account: &str,
    container: &str,
    token: Arc<dyn TokenCredential>,
    blob_name: &str,
) -> anyhow::Result<BlobClient> {
    let service_url = Url::parse(&format!("https://{}.blob.core.windows.net/", account))
        .context("failed to build storage account url")?;

    Ok(BlobServiceClient::new(service_url, Some(token), None)
        .context("failed to create blob service client")?
        .blob_client(container, blob_name))
}

#[derive(Deserialize, Debug, Clone)]
struct ConfigAuth {
    /// The scope of the authentication token
    scope: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ConfigAzureCache {
    /// The Azure storage account to use
    storage_account: String,
    /// The container within the storage account to use
    storage_container: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ConfigFsCache {
    /// The path to the cache directory
    path: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ConfigCache {
    Azure(ConfigAzureCache),
    Fs(ConfigFsCache),
}

#[derive(Deserialize, Debug, Clone)]
struct ConfigServer {
    /// The URL of the upstream server
    url: Url,
    /// Authentication settings
    auth: Option<ConfigAuth>,
}

fn default_max_retries() -> u32 {
    4
}

fn default_request_pdz() -> bool {
    true
}

fn default_user_agent() -> String {
    format!(
        "Microsoft-Symbol-Server/10.0.0.0 SymProxyCloud/{}",
        env!("CARGO_PKG_VERSION")
    )
}

#[derive(Deserialize, Debug, Clone)]
struct AppConfig {
    listen_address: Option<SocketAddr>,
    i_am_not_an_idiot: bool,
    cache: Option<ConfigCache>,
    servers: Vec<ConfigServer>,
    /// Maximum number of retries for transient request failures
    #[serde(default = "default_max_retries")]
    max_retries: u32,
    /// PDB validation filter mode (default: any)
    #[serde(default)]
    pdb_filter: PdbFilter,
    /// Whether to negotiate for the compressed PDZ (MSFZ) container format.
    #[serde(default = "default_request_pdz")]
    request_pdz: bool,
    /// The `User-Agent` presented to upstream symbol servers.
    #[serde(default = "default_user_agent")]
    user_agent: String,
    /// The client ID to use when retrieving the managed identity token.
    managed_identity_client_id: Option<Uuid>,
}

impl AppConfig {
    /// The container formats to probe in the cache, in priority order.
    fn cache_formats(&self) -> &'static [SymbolFormat] {
        if self.request_pdz {
            &[SymbolFormat::Pdz, SymbolFormat::Pdb]
        } else {
            &[SymbolFormat::Pdb]
        }
    }
}

#[derive(Parser, Debug, Clone)]
struct Args {
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,

    /// Path to the configuration file
    #[arg(short, long, default_value = "default.toml")]
    config: PathBuf,
}

#[derive(Clone, FromRef)]
struct AppState {
    config: AppConfig,
    token: Arc<dyn TokenCredential>,
    client: ClientWithMiddleware,
}

/// Builds a request to an upstream symbol server, applying content negotiation, identification
/// and (optionally) authentication.
fn build_upstream_request(
    client: &ClientWithMiddleware,
    url: &Url,
    bearer: Option<&str>,
    config: &AppConfig,
) -> RequestBuilder {
    let mut builder = client
        .get(url.clone())
        .header(header::USER_AGENT, config.user_agent.as_str());

    if config.request_pdz {
        builder = builder.header(header::ACCEPT, MSFZ_CONTENT_TYPE);
    }

    match bearer {
        Some(token) => builder.bearer_auth(token),
        None => builder,
    }
}

/// An upstream symbol request that has been followed to its final destination.
struct Resolved {
    response: reqwest::Response,
    /// The URL that ultimately served the response.
    url: Url,
    /// The container format the server advertised, if it advertised one.
    format: Option<SymbolFormat>,
    /// Whether the bearer token survived the redirect chain.
    authenticated: bool,
}

/// Fetches a symbol from upstream, following redirects manually.
///
/// Redirects are followed by hand rather than by `reqwest` because symbol servers report the
/// container format on the `302` response itself (`x-ms-symbol-format: application/msfz0` for a
/// PDZ). The redirect target is blob storage, which knows nothing about the negotiation, so that
/// header is lost once the redirect has been transparently followed.
async fn resolve(
    client: &ClientWithMiddleware,
    url: Url,
    bearer: Option<&str>,
    config: &AppConfig,
) -> anyhow::Result<Resolved> {
    let origin = url.origin();
    let mut url = url;
    let mut authenticated = bearer.is_some();
    let mut format = None;

    for _ in 0..=MAX_REDIRECTS {
        let credential = authenticated.then_some(bearer).flatten();
        let response = build_upstream_request(client, &url, credential, config)
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;

        if !response.status().is_redirection() {
            return Ok(Resolved {
                response,
                url,
                format,
                authenticated,
            });
        }

        if let Some(detected) = SymbolFormat::from_headers(response.headers()) {
            format = Some(detected);
        }

        // Copy the location out so the borrow on `response` ends before it is moved or replaced.
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().map(str::to_owned));

        let location = match location {
            Some(Ok(location)) => location,
            Some(Err(_)) => anyhow::bail!("redirect from {url} has a malformed Location header"),
            // A redirect without a location is not actionable; let the caller deal with it.
            None => {
                return Ok(Resolved {
                    response,
                    url,
                    format,
                    authenticated,
                })
            }
        };

        let next = url
            .join(&location)
            .with_context(|| format!("failed to resolve redirect from {url}"))?;

        // Never carry the bearer token across an origin boundary.
        authenticated = bearer.is_some() && next.origin() == origin;
        url = next;
    }

    anyhow::bail!("exceeded {MAX_REDIRECTS} redirects while fetching {url}")
}

/// Attempts to serve a symbol out of the cache. Returns `Ok(None)` on a cache miss.
async fn cache_lookup(
    cache: &ConfigCache,
    token: &Arc<dyn TokenCredential>,
    key: &str,
    format: SymbolFormat,
) -> anyhow::Result<Option<Response>> {
    match cache {
        ConfigCache::Azure(cache) => {
            let client = azure_blob_client(
                &cache.storage_account,
                &cache.storage_container,
                token.clone(),
                key,
            )?;

            let Ok(result) = client.download(None).await else {
                return Ok(None);
            };

            // N.B: Get the blob's data and stream it out directly instead of generating a SAS URL and returning a 302.
            //
            // This is important because this application may be placed behind a reverse proxy that supports auth,
            // and returning an SAS URL subverts the authority of the reverse proxy (e.g. reverse proxy may want
            // to log requests or set a time limit, but an SAS URL will allow users to bypass that).
            let r = Response::builder();
            let r = if let Some(content_length) = &result.properties.content_length {
                r.header(header::CONTENT_LENGTH, content_length.to_string())
            } else {
                r
            };

            Ok(Some(
                r.header(UPSTREAM_SOURCE, "cache")
                    .header(SYMBOL_FORMAT_HEADER, format.symbol_format_header())
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .status(StatusCode::OK)
                    .body(Body::from_stream(result.body))
                    .context("failed to build response body")?,
            ))
        }
        ConfigCache::Fs(cache) => {
            let Ok(f) = tokio::fs::File::open(cache.path.join(key)).await else {
                return Ok(None);
            };

            let meta = f.metadata().await.context("failed to get file metadata")?;
            let body = ReaderStream::new(f);

            Ok(Some(
                Response::builder()
                    .header(UPSTREAM_SOURCE, "cache")
                    .header(SYMBOL_FORMAT_HEADER, format.symbol_format_header())
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CONTENT_LENGTH, meta.len().to_string())
                    .status(StatusCode::OK)
                    .body(Body::from_stream(body))
                    .context("failed to build response body")?,
            ))
        }
    }
}

/// Primary endpoint used to proxy a symbol file from the configured upstream server.
async fn symbol(
    State(token): State<Arc<dyn TokenCredential>>,
    State(config): State<AppConfig>,
    State(client): State<ClientWithMiddleware>,
    Path((name1, hash, name2)): Path<(String, String, String)>,
) -> Result<Response, Error> {
    // Reject any segment that could escape the cache directory or the upstream URL path.
    if ![name1.as_str(), hash.as_str(), name2.as_str()]
        .into_iter()
        .all(valid_segment)
    {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .context("failed to build response body")?);
    }

    // Attempt the cache first, if one is set. PDZ and PDB are stored under separate client keys,
    // so each candidate format has to be probed in turn.
    if let Some(cache) = &config.cache {
        for &format in config.cache_formats() {
            let key = format.client_key(&name1, &hash, &name2);
            if let Some(response) = cache_lookup(cache, &token, &key, format).await? {
                return Ok(response);
            }
        }
    }

    let mut last_send_error: Option<anyhow::Error> = None;
    for server in &config.servers {
        let url = server
            .url
            .join(&format!("{name1}/{hash}/{name2}"))
            .context("failed to build request url")?;

        // N.B: Normally we'd probably want to use a HEAD request here to determine what the server supports.
        // But Azure doesn't support HEAD requests.

        // If there is a scope attached to this server, attempt to authenticate.
        let bearer = match &server.auth {
            Some(auth) => Some(
                token
                    .get_token(&[auth.scope.as_str()], None)
                    .await
                    .context("failed to get token")?
                    .token
                    .secret()
                    .to_string(),
            ),
            None => None,
        };

        let resolved = match resolve(&client, url.clone(), bearer.as_deref(), &config).await {
            Ok(resolved) => resolved,
            Err(e) => {
                warn!("request to {} failed after retries: {:#}", url, e);
                last_send_error = Some(e);
                continue;
            }
        };

        // Check to see if the server returned a successful status code. If it didn't, continue on to the next server.
        trace!("{}: {}", resolved.url, resolved.response.status());
        if !resolved.response.status().is_success() {
            continue;
        }

        // Prefer the format advertised during redirection, then whatever the final response
        // reports, and assume an ordinary PDB when the server tells us nothing.
        let mut format = resolved
            .format
            .or_else(|| SymbolFormat::from_headers(resolved.response.headers()));

        let mut response = resolved.response;

        // If a PDB filter is enabled, attempt to determine whether the PDB passes the filter.
        if config.pdb_filter != PdbFilter::Any {
            let t = Instant::now();

            // The filter reads the symbol with random I/O (via HTTP range requests) against the
            // already-resolved URL, so abandon the response we are holding and re-fetch on success.
            drop(response);

            let credential = resolved
                .authenticated
                .then_some(bearer.as_deref())
                .flatten();
            let reader = build_upstream_request(&client, &resolved.url, credential, &config).io();

            let uri = resolved.url.clone();
            let pdb_filter = config.pdb_filter;
            let r = tokio::task::spawn_blocking(move || {
                let pdb = Pdb::open_from_random_file(reader).context("failed to open PDB")?;
                let flags = pdb_flags(&pdb).context("failed to determine PDB flags")?;

                // The container tells us definitively which format the server actually served.
                let format = match pdb.container() {
                    Container::Msfz(_) => SymbolFormat::Pdz,
                    Container::Msf(_) => SymbolFormat::Pdb,
                };

                trace!("{}: {:?} ({}ms)", &uri, flags, t.elapsed().as_millis());
                Ok::<_, Error>((pdb_filter::filter_matches(flags, pdb_filter), format))
            })
            .await
            .context("PDB validation task panicked")?;

            match r {
                Ok((true, detected)) => format = Some(detected),
                Err(e) => {
                    warn!("failed to apply PDB filter to {url}: {e}");
                    continue;
                }
                Ok((false, _)) => {
                    // TODO: Set a flag, and if all upstream sources are filtered then return it in the response.
                    trace!(
                        "upstream PDB from {} failed filter, trying next server ({}ms)",
                        resolved.url,
                        t.elapsed().as_millis(),
                    );
                    continue;
                }
            }

            response = match build_upstream_request(&client, &resolved.url, credential, &config)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("request to {} failed after retries: {:#}", resolved.url, e);
                    last_send_error = Some(anyhow::Error::new(e));
                    continue;
                }
            };

            if !response.status().is_success() {
                continue;
            }
        }

        let format = format.unwrap_or(SymbolFormat::Pdb);

        // Forward out the full response from the upstream server, including headers and status code.
        let mut response_builder = Response::builder().status(response.status());

        if let Some(headers) = response_builder.headers_mut() {
            *headers = response.headers().clone();

            // Insert an additional header describing where this symbol originated from.
            headers.insert(UPSTREAM_SOURCE, HeaderValue::from_static("server"));
            headers.insert(
                UPSTREAM_SERVER,
                HeaderValue::from_str(server.url.as_str()).unwrap(),
            );

            // The redirect target is blob storage, which does not carry the symbol server's
            // format negotiation, so restate it on the way out.
            headers.insert(
                SYMBOL_FORMAT_HEADER,
                HeaderValue::from_static(format.symbol_format_header()),
            );
        }

        // Now, we'll want to do one of two things depending on if caching is enabled:
        // If enabled, we will split the response stream into two and direct one end to the storage account,
        // and the other end to the requesting user. This also has the side effect of throttling the user's
        // download speed if our upload is slower, but this is the cost to pay to keep things out of memory.
        //
        // If disabled, we can simply direct the response stream back out to the requester directly.
        let stream: Pin<Box<dyn Stream<Item = _> + Send>> = if let Some(cache) = &config.cache {
            let mut stream = response.bytes_stream();
            let (tx, rx) = tokio::sync::mpsc::channel(32);

            // Clone the cache into the task below.
            let cache = cache.clone();

            // PDZ and PDB are distinct representations, so each is mirrored under its own key.
            let key = format.client_key(&name1, &hash, &name2);

            tokio::spawn(async move {
                match cache {
                    ConfigCache::Azure(cache) => {
                        // Wrap the client in an `Option`. If an error occurs, the client will be set to `None` and
                        // mirroring will be aborted.
                        let mut client = match azure_blob_client(
                            &cache.storage_account,
                            &cache.storage_container,
                            token.clone(),
                            &key,
                        ) {
                            Ok(client) => Some(client.block_blob_client()),
                            Err(e) => {
                                error!(
                                    "{:?}",
                                    e.context(
                                        "failed to create blob client while mirroring symbol"
                                    )
                                );
                                None
                            }
                        };

                        let mut block_ids: Vec<Vec<u8>> = Vec::new();
                        while let Some(chunk) = stream.next().await {
                            let chunk = chunk.context("failed to read chunk")?;

                            // N.B: `block_id` must be <= 64 bytes in size.
                            // Use a randomly generated ID to avoid conflicts.
                            let block_id = Uuid::new_v4();

                            if let Err(e) = match &client {
                                Some(client) => client
                                    .stage_block(
                                        block_id.as_bytes(),
                                        chunk.len() as u64,
                                        RequestContent::from(chunk.to_vec()),
                                        None,
                                    )
                                    .await
                                    .map(|_| ()),
                                None => Ok(()),
                            } {
                                error!(
                                    "{:?}",
                                    anyhow::Error::new(e)
                                        .context("failed to stage block while mirroring symbol")
                                );

                                // If an error occurs, set the client to `None` to abort mirroring.
                                client = None;
                            }

                            // N.B: This _MUST_ be the same layout as what was passed to `stage_block`!
                            block_ids.push(block_id.as_bytes().to_vec());

                            // Forward the data on to the original requesting client.
                            // Ignore errors since we want mirroring to continue even if the client
                            // closes their connection.
                            let _ = tx.send(Ok(chunk)).await;
                        }

                        // Finalize the blob upload if mirroring has not been aborted.
                        //
                        // N.B: If multiple instances of this server attempt to upload the same blob at the same
                        // time, the last one wins. Unfortunately we cannot acquire a lease on a blob that has not
                        // been created so we cannot prevent this race.
                        if let Some(client) = client {
                            let mut metadata = HashMap::new();
                            metadata.insert(
                                "UpstreamServer".to_string(),
                                form_urlencoded::byte_serialize(url.as_str().as_bytes())
                                    .collect::<String>(),
                            );

                            let block_list = BlockLookupList {
                                latest: Some(block_ids),
                                ..Default::default()
                            };

                            let options = BlockBlobClientCommitBlockListOptions {
                                metadata: Some(metadata),
                                ..Default::default()
                            };

                            let f = async {
                                let content = block_list
                                    .try_into()
                                    .context("failed to serialize block list")?;
                                client
                                    .commit_block_list(content, Some(options))
                                    .await
                                    .context("failed to mirror symbol")?;

                                Ok::<_, anyhow::Error>(())
                            };

                            match f.await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{:?}", e.context("failed to mirror symbol"));
                                }
                            }
                        }

                        Ok::<(), anyhow::Error>(())
                    }
                    ConfigCache::Fs(cache) => {
                        let path = cache.path.join(&key);

                        let mut f = {
                            let _ = tokio::fs::create_dir_all(path.parent().unwrap()).await;

                            tokio::fs::File::create(path.clone()).await.ok()
                        };

                        while let Some(chunk) = stream.next().await {
                            let chunk = chunk.context("failed to read chunk")?;

                            if let Err(e) = match &mut f {
                                Some(f) => f.write_all(&chunk).await.map(|_| ()),
                                None => Ok(()),
                            } {
                                error!(
                                    "{:?}",
                                    anyhow::Error::new(e)
                                        .context("failed to write chunk while mirroring symbol")
                                );

                                f = None;
                            }

                            let _ = tx.send(Ok(chunk)).await;
                        }

                        Ok::<(), anyhow::Error>(())
                    }
                }
            });

            Box::pin(ReceiverStream::new(rx))
        } else {
            Box::pin(response.bytes_stream())
        };

        // Stream out the response from the upstream server as we receive it.
        return Ok(response_builder
            .body(Body::from_stream(stream))
            .context("failed to build response body")?);
    }

    // N.B: We intentionally do not include the error details in the response body
    // to avoid leaking sensitive information.
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(if last_send_error.is_some() {
            Body::from("failed to reach one or more upstream servers")
        } else {
            Body::empty()
        })
        .context("failed to build response body")?)
}

/// Endpoint used by Azure to query this application's health status.
async fn health(State(config): State<AppConfig>, headers: HeaderMap) -> Result<Response, Error> {
    // Check to see if the request originates from Azure.
    // https://learn.microsoft.com/en-us/azure/app-service/monitor-instances-health-check?tabs=dotnet#authentication-and-security
    if let Some(key) = std::env::var_os("WEBSITE_AUTH_ENCRYPTION_KEY") {
        let f = || {
            // FIXME: According to the documentation, this header is only provided on Windows instances. Sigh.
            let auth_token = headers
                .get(INTERNAL_AUTH_TOKEN)
                .context("missing internal auth token")?;

            let hash = {
                let mut sha = Sha256::new();
                sha.update(key.as_encoded_bytes());
                let hash = sha.finalize();

                base64::prelude::BASE64_STANDARD.encode(hash.as_slice())
            };

            if hash.as_bytes() == auth_token.as_bytes() {
                Ok(())
            } else {
                anyhow::bail!("invalid authentication hash");
            }
        };

        match (f)() {
            // Continue on.
            Ok(_) => (),
            // If validation fails for any reason, just return an opaque 401 response.
            Err(_e) => {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .context("failed to build response body")?)
            }
        }
    }

    // Run through every configured server and ensure they are reachable.
    for server in &config.servers {
        // Send a request to the root of the symbol server. Ignore the response
        // since we are only interested in seeing if the symbol server responds.
        let _req = reqwest::get(server.url.clone())
            .await
            .with_context(|| format!("symbol server \"{}\" is unreachable", server.url))?;
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .context("failed to build response body")?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up trace logging to console and account for the user-provided verbosity flag.
    if args.verbosity.log_level_filter() != LevelFilter::Off {
        let lvl = match args.verbosity.log_level_filter() {
            LevelFilter::Off => tracing::Level::INFO,
            LevelFilter::Error => tracing::Level::ERROR,
            LevelFilter::Warn => tracing::Level::WARN,
            LevelFilter::Info => tracing::Level::INFO,
            LevelFilter::Debug => tracing::Level::DEBUG,
            LevelFilter::Trace => tracing::Level::TRACE,
        };
        tracing_subscriber::fmt().with_max_level(lvl).init();
    }

    // Read and parse the user-provided configuration.
    let mut config: AppConfig = Figment::new()
        .merge(figment::providers::Toml::file(args.config).required(true))
        .merge(figment::providers::Env::prefixed("SYMPROXY_"))
        .extract()
        .context("failed to load configuration")?;

    // Validation.
    if config.servers.is_empty() {
        anyhow::bail!("You must provide at least one upstream server in your configuration file.");
    }

    // Authenticate.
    //
    // N.B: We are _not_ going to add support for secret-based authentication.
    // It is insecure and strongly discouraged, so to encourage best practices
    // we should just not support it :)
    let token: Arc<dyn TokenCredential> = Arc::new(MultiCredential::with_sources([
        // Developer tools authentication (Azure CLI) for local testing.
        azure_identity::DeveloperToolsCredential::new(None)? as Arc<dyn TokenCredential>,
        azure_identity::ManagedIdentityCredential::new(Some(
            azure_identity::ManagedIdentityCredentialOptions {
                user_assigned_id: config
                    .managed_identity_client_id
                    .map(|u| azure_identity::UserAssignedId::ClientId(u.to_string())),
                client_options: azure_core::http::ClientOptions::default(),
            },
        ))? as Arc<dyn TokenCredential>,
    ]));

    // Run through every configured server and ensure they are reachable.
    for server in &mut config.servers {
        // Ensure the URL ends with a trailing slash, as `url` will treat the last
        // segment as a filename without it.
        if !server.url.as_str().ends_with('/') {
            // HACK: It doesn't seem like there is a better way to do this for now.
            server.url = Url::from_str(&format!("{}/", server.url.as_str()))
                .context("failed to append trailing slash to URL")?;
        }

        // Send a request to the root of the symbol server. Ignore the response
        // since we are only interested in seeing if the symbol server responds.
        if let Err(e) = reqwest::get(server.url.clone()).await {
            // Log the error, but do not abort startup since it's possible that
            // this could be a spurious network failure.
            error!(
                "{:?}",
                anyhow::Error::new(e)
                    .context(format!("symbol server \"{}\" is unreachable", server.url))
            );
        }

        // Attempt to acquire a token upon startup just to surface any configuration errors early.
        if let Some(auth) = &server.auth {
            info!("acquiring token for server: {}", server.url);
            let _tok = token
                .get_token(&[auth.scope.as_str()], None)
                .await
                .with_context(|| format!("failed to get token for {}", server.url))?;
        }
    }

    let addr = config
        .listen_address
        .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 5000)));

    let has_auth = config.servers.iter().any(|s| s.auth.is_some());
    if has_auth && !config.i_am_not_an_idiot && !addr.ip().is_loopback() {
        anyhow::bail!("You have configured the proxy to listen on a routable IP address with an upstream server that requires authentication, but `i_am_not_an_idiot` is still `false` in your configuration file. Read the documentation carefully before enabling the setting.");
    }

    let listener = TcpListener::bind(&addr)
        .await
        .context("failed to bind address")?;

    // Build the HTTP client with retry middleware for transient failures.
    // The internal symbol server returns 302s for found symbols, but we need to get the `x-ms-symbol-format` header from the 302 response, so we disable automatic redirect following.
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(config.max_retries);
    let client = reqwest_middleware::ClientBuilder::new(
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build HTTP client")?,
    )
    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
    .build();

    // Set up the `axum` application with a single endpoint to handle symbol server requests.
    let app = Router::new()
        .route("/:name1/:hash/:name2", get(symbol))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            config,
            token,
            client,
        });

    tracing::info!("listening on {addr}");

    // Serve the application :)
    axum::serve(listener, app.into_make_service())
        .await
        .context("failed to start server")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdz_client_key_uses_the_msfz0_subdirectory() {
        assert_eq!(
            SymbolFormat::Pdz.client_key("ntdll.pdb", "ABC1", "ntdll.pdb"),
            "ntdll.pdb/ABC1/msfz0/ntdll.pdb"
        );
        assert_eq!(
            SymbolFormat::Pdb.client_key("ntdll.pdb", "ABC1", "ntdll.pdb"),
            "ntdll.pdb/ABC1/ntdll.pdb"
        );
    }

    #[test]
    fn pdz_and_pdb_client_keys_never_collide() {
        let pdb = SymbolFormat::Pdb.client_key("ntdll.pdb", "ABC1", "ntdll.pdb");
        let pdz = SymbolFormat::Pdz.client_key("ntdll.pdb", "ABC1", "ntdll.pdb");

        assert_ne!(pdb, pdz);
        assert!(pdz.starts_with("ntdll.pdb/ABC1/"));
    }

    #[test]
    fn format_comes_only_from_the_symbol_format_header() {
        let headers = |pairs: &[(&str, &str)]| {
            let mut map = reqwest::header::HeaderMap::new();
            for (k, v) in pairs {
                map.insert(
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            map
        };

        // The symbol server states the format explicitly.
        assert_eq!(
            SymbolFormat::from_headers(&headers(&[(SYMBOL_FORMAT_HEADER, "application/msfz0")])),
            Some(SymbolFormat::Pdz)
        );

        // An empty value means a plain PDB.
        assert_eq!(
            SymbolFormat::from_headers(&headers(&[(SYMBOL_FORMAT_HEADER, "")])),
            None
        );

        // `Content-Type` is blob storage's, not the symbol server's, so it is never consulted.
        assert_eq!(
            SymbolFormat::from_headers(&headers(&[("content-type", "application/msfz0")])),
            None
        );
        assert_eq!(
            SymbolFormat::from_headers(&headers(&[("content-type", "application/octet-stream")])),
            None
        );
    }

    #[test]
    fn msfz_content_type_is_recognised() {
        let parse = |v: &str| SymbolFormat::from_media_type(&HeaderValue::from_str(v).unwrap());

        assert_eq!(parse("application/msfz0"), Some(SymbolFormat::Pdz));
        assert_eq!(parse("Application/MSFZ0; q=1"), Some(SymbolFormat::Pdz));
        assert_eq!(parse("application/octet-stream"), None);
    }

    #[test]
    fn path_segments_cannot_escape_the_cache() {
        assert!(valid_segment("ntdll.pdb"));
        assert!(!valid_segment(".."));
        assert!(!valid_segment(""));
        assert!(!valid_segment("a/b"));
        assert!(!valid_segment("a\\b"));
    }
}
