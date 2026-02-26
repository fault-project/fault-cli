# Changes

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

- Add proper DNS fault support
