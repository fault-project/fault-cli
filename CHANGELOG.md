# Changes

## [0.20.15] - 2026-06-08

### Fixed

- **CI: fix `cargo +nightly zigbuild` subcommand not found** — `cargo-binstall`
  was used to install `cargo-zigbuild` but when called as `cargo +nightly
  zigbuild` the nightly cargo couldn't find the subcommand. Replaced
  `cargo-binstall` + `cargo binstall` with `cargo install --locked
  cargo-zigbuild` (which the Swatinem cache handles), and dropped the
  `+nightly` qualifier from the `cargo zigbuild` calls since `rustup override
  set nightly` already sets nightly as the active toolchain for the directory.

## [0.20.14] - 2026-06-08

### Fixed

- **CI: pin Zig to 0.13.0 for `aarch64-unknown-linux-musl` builds** —
  `mlugg/setup-zig@v2` was pulling Zig 0.16.0 which dropped support for
  `--fix-cortex-a53-843419`. `cargo-zigbuild` does not yet filter this flag.
  Pinning to `0.13.0` restores the previous working behaviour until
  `cargo-zigbuild` adds the filter upstream.

## [0.20.13] - 2026-06-08

### Fixed

- **CI: `aarch64-unknown-linux-musl` builds now work with Zig 0.14+** —
  `mlugg/setup-zig@v2` pulls the latest Zig which dropped support for the
  `--fix-cortex-a53-843419` linker flag. Rust emits this flag unconditionally
  for all `aarch64` targets. Added `[target.aarch64-unknown-linux-musl]`
  to `.cargo/config.toml` with `target-cpu=generic`, which uses a baseline
  aarch64 profile and avoids emitting the errata workaround flag.

## [0.20.12] - 2026-06-01

### Fixed

- **HTTP proxy mode: upstream always connects to backend Service, not external
  hostname** — when `--with-http-response` is set in `fault inject kubernetes`,
  the injected proxy pod previously derived the upstream address from the
  request's `Host` header. Inside a Kubernetes cluster this resolves to the
  external hostname, which routes outside the cluster — hitting Cloudflare or
  other CDN/proxies that issue 301 redirects. Fault then modified the 301 into
  the configured HTTP error, masking the real problem.

  The proxy Job now receives `--http-upstream-override {service}-backend:{port}`
  in HTTP mode, which forces all connections to the in-cluster backend Service
  regardless of the request's `Host`. The `Host` header is still forwarded
  correctly so the backend pod accepts the request.

### Added

- **`--http-upstream-override [scheme://]host:port` flag** (`fault run`) —
  forces the HTTP CONNECT proxy to connect to the specified address for every
  request, ignoring the request's Host/authority. Scheme is inferred from port
  (443 → https, else http) when not provided. The original `Host` header is
  preserved so the backend accepts the request normally. Env:
  `FAULT_HTTP_UPSTREAM_OVERRIDE`.

## [0.20.11] - 2026-06-01

### Fixed

- **HTTP forward proxy: Host header now always set to upstream host** —
  previously the client's original `Host` header (pointing at the proxy
  address, e.g. `fault-proxy-myapi:3180`) was forwarded verbatim to the
  upstream server, which would reject the request with a `400` or a connection
  reset. Firefox reports this as `NS_ERROR_INTERCEPTION_FAILED` for CORS
  requests. `curl` users working around it by passing `-H "Host: real-host"`
  masked the bug. The proxy now always overwrites `Host` with the upstream
  hostname derived from the resolved URL, regardless of what the client sent.

### Added

- **Stream summary log in HTTP forward path** — the `info!` stream summary
  line (`src / dst / status / fault / bypassed`) was previously only emitted
  for TCP and HTTP CONNECT (tunnel) paths. It is now also emitted for plain
  HTTP requests handled by the forward proxy, completing the logging story
  for all three proxy paths.

## [0.20.10] - 2026-06-01

### Fixed

- **HTTP proxy mode: faults were always bypassed** — when no `--upstream` flag
  is passed, `upstream_hosts` is empty, so every host fails the membership
  check and `passthrough=true`. No faults were ever applied. The injected
  proxy Job now passes `--upstream "*"` in HTTP mode, which is the wildcard
  meaning "fault all hosts". This is correct for the injected case since the
  proxy only receives traffic already routed to it by the Service selector
  patch.

## [0.20.9] - 2026-06-01

### Fixed

- **HTTP proxy mode not reachable in Kubernetes** — when `--with-http-response`
  was set, the injected proxy Job started the HTTP CONNECT proxy on
  `127.0.0.1:3180` (the default). Inside a pod, Kubernetes Service traffic
  arrives on the pod's non-loopback interface, so connections were silently
  dropped. The HTTP mode args now pass `--proxy-address 0.0.0.0:{proxy_port}`
  so the HTTP CONNECT proxy binds to all interfaces and is reachable from the
  Service.

## [0.20.8] - 2026-06-01

### Changed

- **Stream summary log is now `info` level with a readable one-liner** —
  previously a structured `trace!` event with key=value fields, now a plain
  `info!` message in the format:

  ```
  src: 10.0.1.5:43210  dst: my-api-backend[10.0.2.3:5432]  fault: latency(mean=200ms)  bypassed: no
  src: 10.0.1.5:43211  dst: prod-db.example.com[10.0.2.4:5432]  fault: none  bypassed: no
  ```

  Both hostname and resolved IP:port are shown in the `dst` field so you
  don't need to memorise IP addresses. Emitted from both the TCP proxy
  and HTTP CONNECT tunnel paths.

## [0.20.7] - 2026-06-01

### Added

- **`--verbose` flag for `fault inject kubernetes`** — the injected proxy Job
  now runs at `info` log level by default (previously `debug`). Pass
  `--verbose` to get `debug`-level logs from the proxy container, or set
  `FAULT_INJECTION_K8S_VERBOSE=true`.

- **Lean `trace`-level stream summary log** — after each stream completes, a
  single structured `trace` event is emitted with the following fields:
  - `src` — client socket address (IP:port)
  - `dst` — upstream socket address (IP:port)
  - `host` — upstream hostname (HTTP CONNECT path only)
  - `bypassed` — whether fault injection was skipped for this stream
  - `fault` — comma-separated list of active fault injectors, or `"none"`
  - `c2s_bytes` / `s2c_bytes` — bytes transferred in each direction

  Emitted from both the TCP proxy path (`tcp/mod.rs`) and the HTTP CONNECT
  tunnel path (`http/proxy/tunnel.rs`). To see these lines set the proxy
  log level to `trace` (e.g. via `FAULT_LOG_LEVEL=trace` or
  `--log-level trace` when running `fault run` locally).

## [0.20.6] - 2026-06-01

### Added

- **`--dry-run` for `fault inject kubernetes`** — prints the full injection
  plan without making any changes to the cluster.

  Inbound mode (`--service`) shows: target service name/namespace, current
  selector and ports, resources that would be created (ServiceAccount,
  ConfigMap, Job, backend Service), and the Service patch that would be
  applied.

  Standalone outbound mode (`--env-override`) shows: proxy name/namespace/
  upstream/listen port, resources that would be created, each env var key
  with its resolved value (`{host}` and `{port}` substituted), and active
  fault settings.

- **Clear rollback failure output** — if `plt.rollback()` fails, a prominent
  `ERROR:` message is printed to stderr with the error, the likely leftover
  resources to clean up manually, and guidance on restoring the original
  Service selector. The process exits with a non-zero status.

## [0.20.5] - 2026-06-01

### Fixed

- **Ctrl-C now always triggers rollback** — previously, when no `--duration`
  was set, the confirmation prompt (`Press 'y' to finish and rollback`) blocked
  the async runtime synchronously. A SIGINT at that point killed the process
  before `plt.rollback()` could run, leaving injected Service selectors and
  proxy resources in place. The prompt is now run on a thread-pool thread via
  `spawn_blocking` so the async runtime stays live; a `tokio::select!` races
  the prompt completion against `ctrl_c()`, and rollback always executes
  afterward.

### Added

- **System service protection** — the Kubernetes API server service
  (`kubernetes` in `default`) and all services in system namespaces
  (`kube-system`, `kube-public`, `kube-node-lease`) are now excluded from the
  interactive service selection list and blocked at the `set_service` call when
  passed via `--service`. Attempting to inject into a protected service returns
  a clear error message suggesting `--ns` if the wrong namespace was used.

## [0.20.4] - 2026-06-01

### Changed

- **`fault inject kubernetes`: HTTP error fault now forces HTTP proxy mode** —
  when `--with-http-response` is set, the injected proxy Job runs as an HTTP
  CONNECT proxy (omitting `--disable-http-proxy` and `--proxy`). This is the
  only mode that can inspect and rewrite HTTP responses at L7. All other faults
  continue to use TCP proxy mode (transparent, L4 only).

- **`--with-http-response` help text** clarifies that HTTP error injection
  requires inbound proxy mode (`--service`). Standalone outbound mode
  (`--env-override` without `--service`) cannot use HTTP error faults because
  the TCP proxy has no L7 visibility.

## [0.20.3] - 2026-06-01

### Fixed

- **`--env-override` upstream resolution with split host/port keys** — when
  separate `DB_HOST={host}` and `DB_PORT={port}` overrides are used, the proxy
  upstream was assembled from only the first key's current value, producing a
  portless address (e.g. `prod-db.example.com` instead of
  `prod-db.example.com:5432`) which caused the proxy to fail to connect.
  `resolve_upstream` now reads both keys and combines them into `host:port`.

## [0.20.2] - 2026-06-01

### Changed

- **`--env-override` template substitution** — the value now supports
  `{host}` and `{port}` placeholders that fault replaces with the proxy's
  in-cluster name and port (`3180`) at inject time. Any combination works:

  ```
  --env-override configmap/my-config:DB_HOST={host}
  --env-override configmap/my-config:DB_PORT={port}
  --env-override configmap/my-config:DATABASE_URL=postgres://{host}:{port}/mydb
  --env-override configmap/my-config:API_URL=https://{host}:{port}/v1
  ```

  Values without `{host}` or `{port}` are treated as literals (unchanged
  from before).

### Removed

- **Bare `KEY` without `=VALUE`** — previously accepted as an auto-inject
  shorthand, now a parse error. Use `KEY={host}:{port}` instead.

## [0.20.1] - 2026-06-01

### Changed

- **`--env-override` auto proxy address injection** — the value side is now
  optional. `kind/name:KEY` (no `=VALUE`) instructs fault to automatically
  fill in the proxy's own in-cluster address (`proxy-name:3180`) at inject
  time, so you no longer need to know the proxy name ahead of time when using
  a generated suffix.

- **`--env-override` value is now `Explicit | Auto`** — internally the value
  field is now a typed enum; the parser accepts both `KEY=VALUE` and bare
  `KEY`.

### Removed

- **`--env-override-ns`** — dropped before it shipped. The `--ns` flag already
  scopes everything; a separate override namespace would require cross-namespace
  RBAC which is out of scope.

- **Port derivation from `--env-override` value** — the standalone proxy
  always listens on port `3180`, consistent with the inbound proxy. The
  `:PORT` suffix in an explicit value is the *upstream* port, not the proxy's
  listen port; parsing it as the proxy port was wrong.

## [0.20.0] - 2026-05-29

### Added

- **Kubernetes injection: outbound (standalone) proxy mode** — inject faults on
  traffic a pod sends *to* a downstream dependency (e.g. a cloud DB), not just
  on inbound traffic arriving at the pod.

  Triggered by passing one or more `--env-override` flags without `--service`.
  A standalone fault proxy Job + ClusterIP Service is created; env vars in the
  named ConfigMaps, Deployments, or StatefulSets are patched to redirect the
  downstream address through the proxy. On rollback, original values are
  restored and the proxy resources are deleted.

  ```
  fault inject kubernetes \
    --env-override configmap/my-app-config:DB_HOST=fault-proxy-db:5432 \
    --with-latency --latency-mean 200
  ```

- **`--env-override kind/name:KEY=VALUE`** — new repeatable flag for the
  Kubernetes injector. Patches a specific key in a ConfigMap, Deployment, or
  StatefulSet (aliases: `cm`, `deploy`, `sts`). For Deployment/StatefulSet a
  rolling restart annotation is added; for ConfigMap only the data key is
  patched (rollout is left to the operator). Original values are stored in the
  rollback snapshot and restored automatically.

- **`--name`** — optional name for the standalone proxy resources. When omitted
  a short random suffix is generated (`fault-proxy-<6 chars>`). Useful in
  scripts where the proxy address must be known ahead of time and embedded in
  the `--env-override` value.

### Fixed

- `BandwidthUnit::from_str`: match arms used mixed case (`"Bps"`, `"KBps"`)
  after `.to_lowercase()`, making them unreachable. Arms are now all lowercase.

## [0.19.1] - 2026-05-29

### Fixed

- **Kubernetes injection**: handle named target ports in Service resources —
  `targetPort` can be a string (e.g. `"http"`) not only a number. Both
  `inject::k8s::run` and `inject::k8s::scenario` now fall back to
  `IntOrString::String` when the numeric parse fails, instead of panicking on
  `unwrap()`.

## [0.19.0] - 2026-05-28

### Changed

- **Agent vector database**: replaced Qdrant (external server) with embedded LanceDB
  - Removed `qdrant-client` crate dependency; no Docker or network server needed
  - LanceDB stores data locally in `.fault/lancedb` — tables created implicitly on first write
  - Sparse vector generation removed from retrieval (LanceDB uses Tantivy for FTS)
  - Removed `create_index_if_not_exists()` calls from all query pipelines
  - All batch sizes updated to `usize` literals to match LanceDB builder API
  - Custom `OpIdRetriever` struct in `suggestion.rs` replaced with `SimilaritySingleEmbedding<String>` using LanceDB native filter syntax (`operation_id = '{opid}'`)
  - `HybridSearch<Filter>` replaced with `SimilaritySingleEmbedding<String>` across all query pipelines
  - All Qdrant builder calls replaced with LanceDB equivalents (`.uri()`, `.table_name()`)

## [0.18.0] - 2026-05-28

### Added

- Agent: Anthropic/Claude LLM client support — `--llm-client claude` (alias: `claude`, `anthropic`)
  - Uses Claude's native Messages API via the `async-anthropic` crate
  - Reads `ANTHROPIC_API_KEY` from the environment
  - Embedding support via local FastEmbed (Anthropic doesn't provide native embeddings)

## [0.17.1] - 2026-02-27

## Fixed

- ci: set `aarch64-linux-gnu-gcc` as linker for `aarch64-unknown-linux-gnu` cross-compilation to fix x86_64/aarch64 ELF incompatibility error

## [0.17.0] - 2026-02-27

## Added

- eBPF stealth mode: new `--capture-pid` flag to target a specific process by PID,
  bypassing the `/proc` name scan — essential when multiple instances of the same
  process are running (e.g. multiple opencode sessions)
- eBPF stealth mode: match intercepted processes by TGID instead of thread comm, fixing
  capture of multi-threaded runtimes (Bun/Node) where the HTTP thread has a different
  comm than the process name (e.g. `HTTP Client` vs `opencode`)
- eBPF stealth mode: skip interception of connections to `127.0.0.0/8` (loopback IPC)
  to avoid forwarding intra-process connections that would reset
- eBPF stealth mode: treat `ConnectionReset` from client as a normal teardown (not an
  error) — Happy Eyeballs causes the losing IP-family connection to be RST'd by the
  client once the winning family completes

- eBPF stealth mode: IPv6 interception support via a new `cg_connect6` cgroup program
  - Extended `ProxyConfig` and `Socket` BPF maps to carry IPv6 addresses
  - Added dual-listener proxy (separate ports for IPv4/IPv6 to avoid dual-stack bind conflicts)
  - BPF redirects IPv6 connections to the machine's global IPv6 address; retrieves the original destination via `getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST)`
  - All aya crates (`aya`, `aya-log`, `aya-ebpf`, `aya-log-ebpf`, `aya-build`) pinned to the same git rev (`c42157f0`) so the BPF log ring-buffer transport is consistent between kernel and userspace

## Fixed

- bpf-linker: set `LLVM_PREFIX=/usr/lib/llvm-21` when installing to fix "could not find dynamic libLLVM" error
- eBPF build: fixed memcpy symbol multiply defined error by aligning aya-ebpf version (using git version to match aya-log-ebpf)
- fault-ebpf-programs: fixed reference error in MAP_SOCKS.get() call

## Changed

- Renamed `fault/llm/openai.rs` to `fault/llm/inject.rs` and updated types:
  `OpenAiSettings` → `LlmSettings`, `OpenAiInjector` → `LlmInjector` — the
  module already handles both OpenAI-compatible and Anthropic/Claude APIs so the
  OpenAI-specific naming was misleading
- Add proper DNS fault support
