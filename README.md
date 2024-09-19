# SymProxyCloud-rs
Rewrite of [`SymProxyCloud`](https://github.com/microsoft/SymProxyCloud/tree/main) leveraging `axum` and `tokio`.

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
* Symbol mirroring to an Azure storage account.
* Layered configurability with TOML file and environment variable overrides (e.g. `SYMPROXY_LISTEN_ADDRESS`).
