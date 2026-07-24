# SymProxyCloud-rs
Rewrite of [`SymProxyCloud`](https://github.com/microsoft/SymProxyCloud/tree/main) leveraging `axum` and `tokio`.

This tool provides a way to access symbols from one or more upstream sources, with or without authentication.
By default, this tool will host a SymSrv-compatible HTTP server at `http://localhost:5000`.

## Quick start
Read through and adjust the symbol server configuration in `default.toml`.
Then, build and run the server:

```
cargo run --release
```

Afterwards, use the server by adding it to your symbol path: `SRV*http://localhost:XXXX`

## Features
* High throughput and performance 🚀
* Minimal memory and CPU footprint. On my system, <1% CPU and ~30MB RAM _even under full load_.
* Proxying to _multiple_ upstream server sources.
* Filtering PDBs (e.g. serve only private symbols, or public symbols, or etc.)
* Symbol mirroring to either an Azure storage account or filesystem.
* Layered configurability with TOML file and environment variable overrides (e.g. `SYMPROXY_LISTEN_ADDRESS`).
* Health check endpoint at `/health` that can be used [directly by Azure](https://learn.microsoft.com/en-us/azure/app-service/monitor-instances-health-check?tabs=dotnet) to monitor the service's health.
