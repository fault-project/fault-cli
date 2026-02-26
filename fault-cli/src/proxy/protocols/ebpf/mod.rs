use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use ::oneshot::Sender;
use anyhow::Result;
use libc::SO_ORIGINAL_DST;
use libc::SOL_IP;
use libc::getsockopt;
use libc::sockaddr_in;
use libc::sockaddr_in6;
use libc::socklen_t;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::errors::ProxyError;
use crate::event::TaskManager;
use crate::proxy::ProxyState;
use crate::proxy::protocols::tcp::stream::handle_stream;

pub mod init;

// SOL_IPV6 and IP6T_SO_ORIGINAL_DST — libc exposes SOL_IPV6 but not the
// iptables-specific sockopt constant, so we define it here.
const SOL_IPV6: libc::c_int = 41;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(all(
    target_os = "linux",
    any(feature = "stealth", feature = "stealth-auto-build")
))]
pub async fn run_ebpf_proxy(
    proxy_address_v4: String,
    proxy_address_v6: String,
    state: Arc<ProxyState>,
    shutdown_rx: kanal::AsyncReceiver<()>,
    readiness_tx: Sender<()>,
    task_manager: Arc<TaskManager>,
) -> Result<(), ProxyError> {
    let addr_v4: SocketAddr = proxy_address_v4.parse().map_err(|e| {
        ProxyError::Internal(format!(
            "Failed to parse eBPF IPv4 proxy address {}: {}",
            proxy_address_v4, e
        ))
    })?;
    let addr_v6: SocketAddr = proxy_address_v6.parse().map_err(|e| {
        ProxyError::Internal(format!(
            "Failed to parse eBPF IPv6 proxy address {}: {}",
            proxy_address_v6, e
        ))
    })?;

    let listener_v4 = TcpListener::bind(addr_v4).await.map_err(|e| {
        ProxyError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to bind eBPF IPv4 proxy to address {}: {}",
                addr_v4, e
            ),
        ))
    })?;
    let listener_v6 = TcpListener::bind(addr_v6).await.map_err(|e| {
        ProxyError::IoError(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to bind eBPF IPv6 proxy to address {}: {}",
                addr_v6, e
            ),
        ))
    })?;

    let _ = readiness_tx.send(()).map_err(|e| {
        ProxyError::Internal(format!("Failed to send readiness signal: {}", e))
    });

    tracing::debug!(
        "Listening for eBPF-redirected connections on {} and {}",
        addr_v4,
        addr_v6
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal received. Stopping eBPF listeners.");
                break;
            },
            accept_result = listener_v4.accept() => {
                handle_accept(accept_result, state.clone(), task_manager.clone());
            },
            accept_result = listener_v6.accept() => {
                handle_accept(accept_result, state.clone(), task_manager.clone());
            },
        }
    }

    tracing::debug!("eBPF proxy finished");
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(feature = "stealth", feature = "stealth-auto-build")
))]
fn handle_accept(
    accept_result: std::io::Result<(TcpStream, SocketAddr)>,
    state: Arc<ProxyState>,
    task_manager: Arc<TaskManager>,
) {
    match accept_result {
        Ok((stream, peer_addr)) => {
            tracing::debug!("Accepted eBPF connection from {}", peer_addr);
            tokio::spawn(async move {
                let start = Instant::now();

                let event =
                    task_manager.new_fault_event("".to_string()).await.unwrap();

                let _ = event
                    .on_started(peer_addr.to_string(), peer_addr.to_string());
                let _ = event.on_resolved(peer_addr.ip().to_string(), 0.0);

                match get_connect_addr(&stream).await {
                    Ok(Some(connect_to)) => {
                        tracing::debug!(
                            "eBPF: {} -> {}",
                            peer_addr,
                            connect_to
                        );
                        match handle_stream(
                            stream,
                            connect_to,
                            &state,
                            false,
                            event.clone(),
                            None,
                        )
                        .await
                        {
                            Ok((bytes_from_client, bytes_to_server)) => {
                                let _ = event.on_response(0);
                                let _ = event.on_completed(
                                    start.elapsed(),
                                    bytes_from_client,
                                    bytes_to_server,
                                );
                            }
                            Err(e) if is_unexpected_eof(&e) => {
                                tracing::debug!("EOF reached on stream: {}", e);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Error handling eBPF stream from {}: {:?}",
                                    peer_addr,
                                    e
                                );
                                let _ = event.on_error(Box::new(e));
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::error!(
                            "No original destination found for connection from {}",
                            peer_addr
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to get original destination for {}: {}",
                            peer_addr,
                            e
                        );
                    }
                }
            });
        }
        Err(e) => {
            tracing::error!("Failed to accept eBPF connection: {}", e);
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(feature = "stealth", feature = "stealth-auto-build")
))]
async fn get_connect_addr(
    stream: &TcpStream,
) -> Result<Option<SocketAddr>, ProxyError> {
    let fd = stream.as_raw_fd();
    get_original_dst(fd).await
}

#[cfg(all(
    target_os = "linux",
    any(feature = "stealth", feature = "stealth-auto-build")
))]
/// Retrieve the original destination using getsockopt.
///
/// For connections arriving on the IPv4 listener: SOL_IP / SO_ORIGINAL_DST.
/// For connections arriving on the IPv6 listener: SOL_IPV6 /
/// IP6T_SO_ORIGINAL_DST. We try IPv4 first; if that fails (ENOPROTOOPT /
/// ENOENT), we try IPv6.
async fn get_original_dst(fd: i32) -> Result<Option<SocketAddr>, ProxyError> {
    // --- Try IPv4 first ---
    let mut orig_dst_v4 = MaybeUninit::<sockaddr_in>::uninit();
    let mut orig_len_v4 = std::mem::size_of::<sockaddr_in>() as socklen_t;
    let ret_v4 = unsafe {
        getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            orig_dst_v4.as_mut_ptr() as *mut _,
            &mut orig_len_v4 as *mut socklen_t,
        )
    };

    if ret_v4 == 0 {
        let sa = unsafe { orig_dst_v4.assume_init() };
        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        let port = u16::from_be(sa.sin_port);
        return Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)));
    }

    // --- Fall back to IPv6 ---
    let mut orig_dst_v6 = MaybeUninit::<sockaddr_in6>::uninit();
    let mut orig_len_v6 = std::mem::size_of::<sockaddr_in6>() as socklen_t;
    let ret_v6 = unsafe {
        getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            orig_dst_v6.as_mut_ptr() as *mut _,
            &mut orig_len_v6 as *mut socklen_t,
        )
    };

    if ret_v6 == 0 {
        let sa6 = unsafe { orig_dst_v6.assume_init() };
        let ip = Ipv6Addr::from(sa6.sin6_addr.s6_addr);
        let port = u16::from_be(sa6.sin6_port);
        return Ok(Some(SocketAddr::new(IpAddr::V6(ip), port)));
    }

    Err(ProxyError::IoError(std::io::Error::last_os_error()))
}

fn is_unexpected_eof(err: &ProxyError) -> bool {
    match err {
        ProxyError::IoError(ioerr) => ioerr.kind() == ErrorKind::UnexpectedEof,
        _ => false,
    }
}
