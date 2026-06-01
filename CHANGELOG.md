# Changes

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
