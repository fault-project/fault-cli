use std::sync::Arc;

use anyhow::Result;
use rand;
use tokio::sync::mpsc;
use tokio::task;

use crate::errors::ProxyError;
use crate::event::TaskManager;
use crate::proxy::ProxyState;
use crate::proxy::protocols::udp::run_udp_proxy;
use crate::types::ProxyMap;

pub async fn initialize_udp_proxies(
    proxied_protos: Vec<ProxyMap>,
    state: Arc<ProxyState>,
    shutdown_rx: kanal::AsyncReceiver<()>,
    task_manager: Arc<TaskManager>,
) -> Result<Vec<task::JoinHandle<std::result::Result<(), ProxyError>>>> {
    let count = proxied_protos.len();
    if count == 0 {
        return Ok(Vec::new());
    }

    let (readiness_tx, mut readiness_rx) = mpsc::channel::<()>(count);
    let mut handles = Vec::with_capacity(count);

    for proto in proxied_protos {
        let h = tokio::spawn(run_udp_proxy(
            proto,
            state.clone(),
            shutdown_rx.clone(),
            readiness_tx.clone(),
            task_manager.clone(),
        ));
        handles.push(h);
    }

    let mut pending = count;
    while readiness_rx.recv().await.is_some() {
        pending -= 1;
        if pending == 0 {
            break;
        }
    }

    Ok(handles)
}
