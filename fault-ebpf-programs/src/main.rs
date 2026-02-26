#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::mem;

use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_ebpf::bindings::TC_ACT_RECLASSIFY;
use aya_ebpf::bindings::bpf_sock_addr;
use aya_ebpf::bindings::bpf_sockopt;
use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::macros::cgroup_sockopt;
use aya_ebpf::macros::map;
use aya_ebpf::macros::sock_ops;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::programs::SockOpsContext;
use aya_ebpf::programs::SockoptContext;
use network_types::ip::IpProto;

// ---------------------------------------------------------------------
// Data Structures and Maps
// ---------------------------------------------------------------------

/// Proxy configuration supporting both IPv4 and IPv6.
/// All IP addresses and ports are stored in network byte order.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProxyConfig {
    /// Target process name (null-terminated in 16 bytes).
    /// Used as fallback when target_tgid is 0.
    pub target_proc_name: [u8; 16],
    /// If non-zero, only intercept connections from this TGID.
    /// Takes precedence over target_proc_name. This correctly matches all
    /// threads of a process, even those with a different thread comm.
    pub target_tgid: u32,
    /// If a connection originates from this TGID (the proxy), skip
    /// redirection.
    pub proxy_pid: u32,
    /// IPv4 proxy address (network byte order)
    pub proxy_ip4: u32,
    /// IPv4 proxy port (network byte order)
    pub proxy_port4: u16,
    /// IPv6 proxy address (network byte order, 16 bytes)
    pub proxy_ip6: [u8; 16],
    /// IPv6 proxy port (network byte order)
    pub proxy_port6: u16,
}

#[map(name = "PROXY_CONFIG")]
static mut PROXY_CONFIG: HashMap<u32, ProxyConfig> =
    HashMap::<u32, ProxyConfig>::with_max_entries(1, 0);

/// Structure to hold the original destination for a connection.
/// Supports both IPv4 (dst_addr populated) and IPv6 (dst_addr6 populated).
/// The `is_v6` field distinguishes which is in use.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Socket {
    pub dst_addr: u32, // IPv4 original destination IP (network byte order)
    pub dst_addr6: [u8; 16], /* IPv6 original destination IP (network byte
                        * order) */
    pub dst_port: u16, // original destination port (network byte order)
    pub is_v6: u8,     // 0 = IPv4, 1 = IPv6
}

/// Map to store the original destination for each connection,
/// keyed by a unique socket cookie (a 64-bit value).
#[map(name = "MAP_SOCKS")]
static mut MAP_SOCKS: HashMap<u64, Socket> =
    HashMap::<u64, Socket>::with_max_entries(20000, 0);

/// Map to store a mapping from the client's source port to the socket cookie.
/// This helps the getsockopt program find the correct connection.
#[map(name = "MAP_PORTS")]
static mut MAP_PORTS: HashMap<u16, u64> =
    HashMap::<u16, u64>::with_max_entries(20000, 0);

/// IPv4 socket address structure (aya doesn't expose this directly).
#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

const SOCKADDR_IN_SIZE: usize = 16;

/// IPv6 socket address structure.
#[repr(C)]
pub struct In6Addr {
    pub in6_u: [u8; 16],
}

#[repr(C)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

const SOCKADDR_IN6_SIZE: usize = 28;

// AF_INET = 2, AF_INET6 = 10
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

// getsockopt levels
const SOL_IP: i32 = 0;
const SOL_IPV6: i32 = 41;

// ---------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------

/// Returns `true` if this connection should be intercepted, based on:
/// 1. If config.target_tgid is non-zero: match on TGID (upper 32 bits of
///    bpf_get_current_pid_tgid). This correctly handles multi-threaded
///    processes where individual threads have a different comm than the process
///    (e.g. "HTTP Client" vs "opencode").
/// 2. Otherwise: fall back to matching the current thread's comm against
///    config.target_proc_name (prefix match, for single-threaded processes or
///    when the target is not yet running at fault startup).
#[inline(always)]
fn should_intercept(config: &ProxyConfig, ctx: &SockAddrContext) -> bool {
    if config.target_tgid != 0 {
        let tgid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() }
            >> 32) as u32;
        return tgid == config.target_tgid;
    }

    // Fallback: match on the current thread's comm (prefix match).
    let comm = match ctx.command() {
        Ok(c) => c,
        Err(_) => return false,
    };
    starts_with_comm(&comm, &config.target_proc_name)
}

#[inline(always)]
fn starts_with_comm(comm_arr: &[u8; 16], prefix_arr: &[u8; 16]) -> bool {
    let comm_end =
        comm_arr.iter().position(|&b| b == 0).unwrap_or(comm_arr.len());
    let prefix_end =
        prefix_arr.iter().position(|&b| b == 0).unwrap_or(prefix_arr.len());
    if prefix_end > comm_end {
        return false;
    }
    comm_arr[0..prefix_end] == prefix_arr[0..prefix_end]
}

// ---------------------------------------------------------------------
// cgroup_sock_addr Program for IPv4 (Redirect on connect)
// ---------------------------------------------------------------------

/// This program runs when a process calls connect(2) on an IPv4 socket.
/// It filters by IPv4/TCP and by process name, then stores the original
/// destination (from sock->user_ip4 and user_port) in MAP_SOCKS and rewrites
/// the socket's destination to the proxy address/port. The kernel will preserve
/// the original destination so that the proxy can later retrieve it via
/// getsockopt(SO_ORIGINAL_DST).
#[cgroup_sock_addr(connect4)]
pub fn cg_connect4(ctx: SockAddrContext) -> i32 {
    let sock = unsafe { &*ctx.sock_addr };
    // Process only IPv4 TCP connections.
    if sock.user_family != AF_INET || sock.protocol != IpProto::Tcp as u32 {
        return TC_ACT_RECLASSIFY;
    }
    let config = match unsafe { PROXY_CONFIG.get(&0) } {
        Some(c) => c,
        None => return TC_ACT_RECLASSIFY,
    };

    // Exclude the proxy's own connections first (cheap check).
    let tgid =
        (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    if tgid == config.proxy_pid {
        return TC_ACT_RECLASSIFY;
    }

    if !should_intercept(config, &ctx) {
        return 1;
    }

    let orig_ip = sock.user_ip4;

    // Skip connections to 127.0.0.0/8 — loopback IPC that should never be
    // proxied. Note: user_ip4 is NBO; on LE 127.0.0.1 = 0x0100007f, so the
    // first byte (low byte of the u32) is 0x7f.
    if orig_ip.to_ne_bytes()[0] == 0x7f {
        return TC_ACT_RECLASSIFY;
    }

    let orig_port = sock.user_port as u16;

    // Obtain a unique socket cookie.
    let cookie =
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };

    // Store the original destination in MAP_SOCKS, keyed by the cookie.
    let orig = Socket {
        dst_addr: orig_ip,
        dst_addr6: [0u8; 16],
        dst_port: orig_port,
        is_v6: 0,
    };
    unsafe {
        let _ = MAP_SOCKS.insert(&cookie, &orig, 0);
    }

    // Rewrite the socket's destination so that the connection is redirected to
    // the proxy.
    let sock_mut = ctx.sock_addr as *mut bpf_sock_addr;
    unsafe {
        (*sock_mut).user_ip4 = config.proxy_ip4.to_be();
        (*sock_mut).user_port = u32::from(config.proxy_port4);
    }

    TC_ACT_RECLASSIFY
}

// ---------------------------------------------------------------------
// cgroup_sock_addr Program for IPv6 (Redirect on connect)
// ---------------------------------------------------------------------

/// This program runs when a process calls connect(2) on an IPv6 socket.
/// The connect6 hook is only invoked for AF_INET6 sockets, so no family check
/// is needed. It filters by process name, stores the original destination, and
/// rewrites the socket's destination to the IPv6 proxy address/port.
#[cgroup_sock_addr(connect6)]
pub fn cg_connect6(ctx: SockAddrContext) -> i32 {
    let sock = unsafe { &*ctx.sock_addr };

    let config = match unsafe { PROXY_CONFIG.get(&0) } {
        Some(c) => c,
        None => return TC_ACT_RECLASSIFY,
    };

    // Exclude the proxy's own connections first (cheap check).
    let tgid =
        (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    if tgid == config.proxy_pid {
        return TC_ACT_RECLASSIFY;
    }

    if !should_intercept(config, &ctx) {
        return 1;
    }

    let orig_ip6_u32 = sock.user_ip6;
    let orig_port = sock.user_port as u16;

    // user_ip6 is [u32; 4] in network byte order (big-endian) in memory.
    // to_ne_bytes() copies the memory bytes as-is, preserving the NBO layout.
    let mut orig_ip6 = [0u8; 16];
    orig_ip6[0..4].copy_from_slice(&orig_ip6_u32[0].to_ne_bytes());
    orig_ip6[4..8].copy_from_slice(&orig_ip6_u32[1].to_ne_bytes());
    orig_ip6[8..12].copy_from_slice(&orig_ip6_u32[2].to_ne_bytes());
    orig_ip6[12..16].copy_from_slice(&orig_ip6_u32[3].to_ne_bytes());

    // Obtain a unique socket cookie.
    let cookie =
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };

    // Store the original destination in MAP_SOCKS, keyed by the cookie.
    let orig = Socket {
        dst_addr: 0,
        dst_addr6: orig_ip6,
        dst_port: orig_port,
        is_v6: 1,
    };
    unsafe {
        let _ = MAP_SOCKS.insert(&cookie, &orig, 0);
    }

    // Rewrite the socket's destination to the IPv6 proxy address/port.
    // user_ip6 is [u32; 4] stored in network byte order (big-endian) in
    // memory. proxy_ip6 is already [u8; 16] in network byte order (from
    // Ipv6Addr::octets()). We use from_ne_bytes so the 4 bytes are placed
    // into memory exactly as they appear in proxy_ip6 without any byte swap.
    let sock_mut = ctx.sock_addr as *mut bpf_sock_addr;
    unsafe {
        let p = config.proxy_ip6;
        (*sock_mut).user_ip6[0] = u32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
        (*sock_mut).user_ip6[1] = u32::from_ne_bytes([p[4], p[5], p[6], p[7]]);
        (*sock_mut).user_ip6[2] =
            u32::from_ne_bytes([p[8], p[9], p[10], p[11]]);
        (*sock_mut).user_ip6[3] =
            u32::from_ne_bytes([p[12], p[13], p[14], p[15]]);
        (*sock_mut).user_port = u32::from(config.proxy_port6);
    }

    TC_ACT_RECLASSIFY
}

// ---------------------------------------------------------------------
// sock_ops Program: Map client's source port to socket cookie
// ---------------------------------------------------------------------

/// This program fires on ACTIVE_ESTABLISHED events
/// (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB). It retrieves the unique socket cookie
/// and the client's ephemeral local port, then updates MAP_PORTS to map that
/// port to the cookie.
#[sock_ops]
pub fn cg_sock_ops(ctx: SockOpsContext) -> u32 {
    // Only handle ACTIVE_ESTABLISHED events. (op code 3 is typical.)
    if ctx.op() != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        return 0;
    }
    let cookie =
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    // Retrieve the local (client) port.
    let local_port = ctx.local_port() as u16;
    unsafe {
        let _ = MAP_PORTS.insert(&local_port, &cookie, 0);
    }
    // TC_ACT_OK
    0
}

// ---------------------------------------------------------------------
// cgroup_sockopt Program: Respond to SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST
// ---------------------------------------------------------------------

/// This program is triggered when the proxy calls getsockopt(SO_ORIGINAL_DST)
/// or getsockopt(IP6T_SO_ORIGINAL_DST). It uses the client's source port (from
/// the socket) to retrieve the corresponding cookie from MAP_PORTS, then uses
/// that cookie to get the original destination from MAP_SOCKS. Finally, it
/// writes the original destination (sockaddr_in or sockaddr_in6) into the
/// optval.
#[cgroup_sockopt(getsockopt)]
pub fn cg_sock_opt(ctx: SockoptContext) -> i32 {
    let sockopt = unsafe { &mut *(ctx.sockopt as *mut bpf_sockopt) };

    // Only handle SO_ORIGINAL_DST (optname 80), on the correct level per
    // family.
    if sockopt.optname != 80 {
        return TC_ACT_RECLASSIFY;
    }

    let sk = unsafe { &*sockopt.__bindgen_anon_1.sk };

    // must be TCP
    if sk.protocol != 6 {
        return TC_ACT_RECLASSIFY;
    }

    let family = sk.family;

    // Only handle the level that matches the socket family.
    // SOL_IP (0) for AF_INET, SOL_IPV6 (41) for AF_INET6.
    // This prevents trying to write a 28-byte sockaddr_in6 into the
    // 16-byte buffer the caller allocated for the SOL_IP probe.
    if family == AF_INET && sockopt.level != SOL_IP {
        return TC_ACT_RECLASSIFY;
    }
    if family == AF_INET6 && sockopt.level != SOL_IPV6 {
        return TC_ACT_RECLASSIFY;
    }
    if family != AF_INET && family != AF_INET6 {
        return TC_ACT_RECLASSIFY;
    }

    // Get the client's source port.
    let src_port = u16::from_be(sk.dst_port as u16);

    // Look up the cookie using the client's source port.
    let cookie = match unsafe { MAP_PORTS.get(&src_port) } {
        Some(c) => c,
        None => return TC_ACT_RECLASSIFY,
    };

    // Look up the original destination using the cookie.
    let orig = match unsafe { MAP_SOCKS.get(cookie) } {
        Some(o) => o,
        None => return TC_ACT_RECLASSIFY,
    };

    let optval = unsafe { sockopt.__bindgen_anon_2.optval };
    let optval_end = unsafe { sockopt.__bindgen_anon_3.optval_end };

    if orig.is_v6 == 0 {
        // IPv4: write a sockaddr_in
        let sa: *mut SockaddrIn = optval as *mut SockaddrIn;
        if sa.is_null() {
            return TC_ACT_RECLASSIFY;
        }
        if (optval as usize + SOCKADDR_IN_SIZE) > optval_end as usize {
            return TC_ACT_RECLASSIFY;
        }

        sockopt.optlen = mem::size_of::<SockaddrIn>() as i32;
        unsafe {
            (*sa).sin_family = AF_INET as u16;
            (*sa).sin_addr.s_addr = orig.dst_addr;
            (*sa).sin_port = orig.dst_port;
            (*sa).sin_zero = [0u8; 8];
        }
    } else {
        // IPv6: write a sockaddr_in6
        let sa6: *mut SockaddrIn6 = optval as *mut SockaddrIn6;
        if sa6.is_null() {
            return TC_ACT_RECLASSIFY;
        }
        if (optval as usize + SOCKADDR_IN6_SIZE) > optval_end as usize {
            return TC_ACT_RECLASSIFY;
        }

        sockopt.optlen = mem::size_of::<SockaddrIn6>() as i32;
        unsafe {
            (*sa6).sin6_family = AF_INET6 as u16;
            (*sa6).sin6_port = orig.dst_port;
            (*sa6).sin6_flowinfo = 0;
            (*sa6).sin6_addr.in6_u = orig.dst_addr6;
            (*sa6).sin6_scope_id = 0;
        }
    }

    sockopt.retval = 0;

    TC_ACT_RECLASSIFY
}

//
// ==================== Panic Handler and License ====================
//
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
