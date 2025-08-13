use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::errors::ProxyError;
use crate::event::TaskManager;
use crate::fault::DatagramAction;
use crate::plugin::ProxyPlugin;
use crate::proxy::ProxyState;
use crate::types::Direction;
use crate::types::ProxyMap;

pub mod init;

#[tracing::instrument(skip_all)]
pub async fn run_udp_proxy(
    proxied_proto: ProxyMap,
    state: Arc<ProxyState>,
    shutdown_rx: kanal::AsyncReceiver<()>,
    readiness_tx: Sender<()>,
    task_manager: Arc<TaskManager>,
) -> Result<(), ProxyError> {
    let addr: SocketAddr = SocketAddr::new(
        IpAddr::V4(proxied_proto.proxy.proxy_ip),
        proxied_proto.proxy.proxy_port,
    );

    let sock = Arc::new(UdpSocket::bind(addr).await.map_err(ProxyError::from)?);
    let _ = readiness_tx.send(()).await;

    let state_cloned = state.clone();

    let mut buf = vec![0u8; 4096];

    let remote_host = proxied_proto.remote.remote_host.clone();
    let upstream_addr: SocketAddr = {
        SocketAddr::new(
            proxied_proto.remote.remote_host.parse().map_err(|_| {
                ProxyError::Other(
                    "failed to parse remote UDP address".to_string(),
                )
            })?,
            proxied_proto.remote.remote_port,
        )
    };

    loop {
        select! {
            // let's make sure we prioritize the shutdown branch
            biased;

            _ = shutdown_rx.recv() => {
                tracing::debug!("UDP proxy shutdown");
                break;
            }

            Ok((n, peer)) = sock.recv_from(&mut buf) => {
                let start = Instant::now();

                let proto = proxied_proto.clone();
                let plugins = state_cloned.faults_plugin.load();
                let host = format!("{}:{}", remote_host, proto.remote.remote_port);

                let packet = (&buf[..n]).to_vec();
                let plugins = plugins.clone();
                let tm = task_manager.clone();
                let sock_tx = Arc::clone(&sock);

                tokio::spawn(async move {
                    let res = async {
                        let event = tm.new_fault_event(host.clone()).await.unwrap();
                        let _ = event.on_started(host, peer.to_string());

                        let action = plugins
                            .inject_datagram(Direction::Ingress, bytes::Bytes::from(packet), peer, event.clone())
                            .await?;

                        match action {
                            DatagramAction::Drop => {
                                let _ = event.on_response(0);
                                let _ = event.on_completed(start.elapsed(), 0, 0);
                                return Ok::<(), ProxyError>(());
                            }
                            DatagramAction::Respond(p) => {
                                let _ = sock_tx.send_to(&p, peer).await;
                                let _ = event.on_response(0);
                                let _ = event.on_completed(start.elapsed(), 0, p.len() as u64);
                                return Ok(());
                            }
                            DatagramAction::Pass(p) => {
                                let up = UdpSocket::bind("0.0.0.0:0").await.map_err(ProxyError::from)?;
                                up.connect(upstream_addr).await.map_err(ProxyError::from)?;
                                let req_bytes = p.len() as u64;

                                up.send(&p).await.map_err(ProxyError::from)?;

                                let mut rbuf = vec![0u8; 4096];
                                let n = up.recv(&mut rbuf)
                                    .await
                                    .map_err(ProxyError::from)?;
                                let reply = bytes::Bytes::copy_from_slice(&rbuf[..n]);

                                let _ = sock_tx.send_to(&reply, peer).await;
                                let _ = event.on_response(0);
                                let _ = event.on_completed(start.elapsed(), req_bytes, reply.len() as u64);
                                return Ok(());
                            }
                        }
                    }.await;

                    if let Err(e) = res {
                        tracing::error!("udp task error: {e}");
                    }
                });
            }
        }
    }

    tracing::info!("finished {}", remote_host);
    Ok(())
}
