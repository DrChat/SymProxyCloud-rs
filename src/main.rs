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
use ms_pdb::Pdb;
use reqwest::{header, StatusCode};
use reqwest_middleware::ClientWithMiddleware;
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
    /// The client ID to use when retrieving the managed identity token.
    managed_identity_client_id: Option<Uuid>,
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

/// Primary endpoint used to proxy a symbol file from the configured upstream server.
async fn symbol(
    State(token): State<Arc<dyn TokenCredential>>,
    State(config): State<AppConfig>,
    State(client): State<ClientWithMiddleware>,
    Path((name1, hash, name2)): Path<(String, String, String)>,
) -> Result<Response, Error> {
    // Attempt the storage account first, if one is set.
    if let Some(cache) = &config.cache {
        match &cache {
            ConfigCache::Azure(cache) => {
                let client = azure_blob_client(
                    &cache.storage_account,
                    &cache.storage_container,
                    token.clone(),
                    &format!("{name1}/{hash}/{name2}"),
                )?;

                if let Ok(result) = client.download(None).await {
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

                    return Ok(r
                        .header(UPSTREAM_SOURCE, "cache")
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .status(StatusCode::OK)
                        .body(Body::from_stream(result.body))
                        .context("failed to build response body")?);
                }
            }
            ConfigCache::Fs(cache) => {
                let path = cache.path.join(format!("{name1}/{hash}/{name2}"));
                if let Ok(f) = tokio::fs::File::open(path.clone()).await {
                    let meta = f.metadata().await.context("failed to get file metadata")?;
                    let body = ReaderStream::new(f);

                    return Ok(Response::builder()
                        .header(UPSTREAM_SOURCE, "cache")
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CONTENT_LENGTH, meta.len().to_string())
                        .status(StatusCode::OK)
                        .body(Body::from_stream(body))
                        .context("failed to build response body")?);
                }
            }
        }
    }

    let mut last_send_error = None;
    for server in &config.servers {
        let url = server
            .url
            .join(&format!("{name1}/{hash}/{name2}"))
            .context("failed to build request url")?;

        // N.B: Normally we'd probably want to use a HEAD request here to determine what the server supports.
        // But Azure doesn't support HEAD requests.

        // Dispatch a reqwest request to upstream, and serve the response.
        // https://github.com/tokio-rs/axum/blob/680cdcba7cfa0b4fb37aba0c129ab6e4379bae3b/examples/reqwest-response/src/main.rs#L53-L68
        let req_builder = client.get(url.clone());

        // If there is a scope attached to this server, attempt to authenticate.
        let req_builder = if let Some(auth) = &server.auth {
            req_builder.bearer_auth(
                token
                    .get_token(&[auth.scope.as_str()], None)
                    .await
                    .context("failed to get token")?
                    .token
                    .secret(),
            )
        } else {
            req_builder
        };

        // If a PDB filter is enabled, attempt to determine whether the PDB passes the filter.
        if config.pdb_filter != PdbFilter::Any {
            let t = Instant::now();

            // Read the PDB from the upstream server using random I/O (via HTTP range requests)
            let reader = req_builder
                .try_clone()
                .context("failed to clone request for PDB validation")?
                .io();

            let uri = url.clone();
            let r = tokio::task::spawn_blocking(move || {
                let pdb = Pdb::open_from_random_file(reader).context("failed to open PDB")?;
                let flags = pdb_flags(&pdb).context("failed to determine PDB flags")?;

                trace!("{}: {:?} ({}ms)", &uri, flags, t.elapsed().as_millis());
                Ok::<_, Error>(pdb_filter::filter_matches(flags, config.pdb_filter))
            })
            .await
            .context("PDB validation task panicked")?;

            match r {
                Ok(true) => (),
                Err(e) => {
                    warn!("failed to apply PDB filter to {url}: {e}");
                    continue;
                }
                Ok(false) => {
                    // TODO: Set a flag, and if all upstream sources are filtered then return it in the response.
                    trace!(
                        "upstream PDB from {} failed filter, trying next server ({}ms)",
                        url,
                        t.elapsed().as_millis(),
                    );
                    continue;
                }
            }
        }

        let req = match req_builder.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("request to {} failed after retries: {:#}", url, e);
                last_send_error = Some(e);
                continue;
            }
        };

        // Check to see if the server returned a successful status code. If it didn't, continue on to the next server.
        trace!("{}: {}", url, req.status());
        if !req.status().is_success() {
            continue;
        }

        // Forward out the full response from the upstream server, including headers and status code.
        let mut response_builder = Response::builder().status(req.status());

        if let Some(headers) = response_builder.headers_mut() {
            *headers = req.headers().clone();

            // Insert an additional header describing where this symbol originated from.
            headers.insert(UPSTREAM_SOURCE, HeaderValue::from_static("server"));
            headers.insert(
                UPSTREAM_SERVER,
                HeaderValue::from_str(server.url.as_str()).unwrap(),
            );
        }

        // Now, we'll want to do one of two things depending on if caching is enabled:
        // If enabled, we will split the response stream into two and direct one end to the storage account,
        // and the other end to the requesting user. This also has the side effect of throttling the user's
        // download speed if our upload is slower, but this is the cost to pay to keep things out of memory.
        //
        // If disabled, we can simply direct the response stream back out to the requester directly.
        let stream: Pin<Box<dyn Stream<Item = _> + Send>> = if let Some(cache) = &config.cache {
            let mut stream = req.bytes_stream();
            let (tx, rx) = tokio::sync::mpsc::channel(32);

            // Clone the cache into the task below.
            let cache = cache.clone();

            tokio::spawn(async move {
                match cache {
                    ConfigCache::Azure(cache) => {
                        // Wrap the client in an `Option`. If an error occurs, the client will be set to `None` and
                        // mirroring will be aborted.
                        let mut client = match azure_blob_client(
                            &cache.storage_account,
                            &cache.storage_container,
                            token.clone(),
                            &format!("{name1}/{hash}/{name2}"),
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
                        let path = cache.path.join(format!("{name1}/{hash}/{name2}"));

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
            Box::pin(req.bytes_stream())
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
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(config.max_retries);
    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
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
