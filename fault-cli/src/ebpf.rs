#[cfg(all(
    target_os = "linux",
    any(feature = "stealth", feature = "stealth-auto-build")
))]
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process;

use aya::Ebpf;
use aya::Pod;
use aya::maps::HashMap;
use aya::programs::CgroupAttachMode;
use aya::programs::CgroupSockAddr;
use aya::programs::CgroupSockopt;
use aya::programs::SockOps;
use aya::programs::tc;
use local_ip_address::list_afinet_netifas;
use rand::Rng;

use crate::cli::StealthCommandCommon;
use crate::types::EbpfProxyAddrConfig;
use crate::types::ProxyAddrConfig;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfConfig {
    pub proxy_ip: u32,      // IPv4 address in network byte order
    pub proxy_ifindex: u32, // Network interface index for redirection
    pub proxy_port: u16,    // Proxy port in network byte order
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfProxyConfig {
    pub target_proc_name: [u8; 16], /* Fallback: match by comm prefix */
    pub target_tgid: u32,           /* Primary: match by TGID (0 = use comm
                                     * fallback) */
    pub proxy_pid: u32, // Exclude the proxy's own TGID

    // IPv4 proxy fields:
    pub proxy_ip4: u32,   // Proxy IPv4 in network byte order
    pub proxy_port4: u16, // Proxy IPv4 port (network byte order)

    // IPv6 proxy fields:
    pub proxy_ip6: [u8; 16], // Proxy IPv6 address (network byte order)
    pub proxy_port6: u16,    // Proxy IPv6 port (network byte order)
}

unsafe impl Pod for EbpfConfig {}
unsafe impl Pod for EbpfProxyConfig {}

pub fn get_ebpf_proxy(
    proxy_nic_config: &ProxyAddrConfig,
    ebpf_proxy_iface: Option<String>,
    ebpf_proxy_ip: Option<String>,
    ebpf_proxy_port: Option<u16>,
) -> anyhow::Result<Option<EbpfProxyAddrConfig>> {
    let interfaces = get_all_interfaces()?;
    if interfaces.is_empty() {
        tracing::warn!(
            "Could not find any suitable interfaces to bind our ebpf program to"
        );
        return Ok(None);
    }

    let iface_name: String;
    let iface_ip: IpAddr;

    if let Some(iface) = ebpf_proxy_iface {
        let proxy_iface = match find_ip_by_interface(&interfaces, iface) {
            Some(it) => it,
            None => return Ok(None),
        };
        iface_ip = proxy_iface.1;
        iface_name = proxy_iface.0.clone();
    } else if let Some(ebpf_ip) = ebpf_proxy_ip {
        let parsed: IpAddr = ebpf_ip.parse()?;
        let proxy_iface = match find_interface_by_ip(&interfaces, parsed) {
            Some(it) => it,
            None => return Ok(None),
        };
        iface_ip = proxy_iface.1;
        iface_name = proxy_iface.0.clone();
    } else {
        let proxy_ip4: u32 = proxy_nic_config.proxy_ip.into();

        if Ipv4Addr::from(proxy_ip4) == Ipv4Addr::new(0, 0, 0, 0) {
            let proxy_iface = find_non_loopback_interface(&interfaces).unwrap();
            iface_ip = proxy_iface.1;
            iface_name = proxy_iface.0.clone();
        } else {
            let proxy_iface = match find_interface_by_ip(
                &interfaces,
                IpAddr::V4(proxy_ip4.into()),
            ) {
                Some(it) => it,
                None => return Ok(None),
            };
            iface_ip = proxy_iface.1;
            iface_name = proxy_iface.0.clone();
        }
    }

    let port: u16 = match ebpf_proxy_port {
        Some(p) => p,
        None => rand::rng().random_range(1024..=65535),
    };
    // Use a separate port for IPv6 to avoid dual-stack bind conflicts:
    // binding [::]:port when 127.0.0.1:port already exists fails on systems
    // with IPV6_V6ONLY=0 because [::] also claims 0.0.0.0:port.
    let port6: u16 = rand::rng().random_range(1024..=65535);

    tracing::debug!(
        "eBPF proxy detected address {}:{} (IPv6 port: {})",
        iface_ip,
        port,
        port6
    );

    // Find the machine's global (non-loopback, non-link-local) IPv6 address
    // to use as the BPF redirect target. The kernel rejects connect6 rewrites
    // to loopback (::1) for non-loopback sockets.
    let ip6_redirect = interfaces.iter().find_map(|(_, addr)| {
        if let IpAddr::V6(v6) = addr {
            if !v6.is_loopback() && !is_ipv6_link_local(v6) {
                return Some(*v6);
            }
        }
        None
    });

    Ok(Some(EbpfProxyAddrConfig {
        ip: iface_ip,
        ip6_redirect,
        port,
        port6,
        ifname: iface_name,
    }))
}

pub fn install_and_run(
    ebpf: &mut aya::Ebpf,
    ebpf_proxy_config: &EbpfProxyAddrConfig,
    ebpf_process: String,
    ebpf_process_pid: Option<u32>,
) -> anyhow::Result<()> {
    let iface = ebpf_proxy_config.ifname.as_str();

    tracing::debug!(
        "Using interface {} {} (IPv6 redirect target: {:?})",
        ebpf_proxy_config.ip,
        iface,
        ebpf_proxy_config.ip6_redirect
    );

    for (name, ..) in ebpf.maps() {
        tracing::info!("found map `{}`", name,);
    }

    let proxy_ip4: u32 = std::net::Ipv4Addr::LOCALHOST.into();
    let proxy_port4 = u16::to_be(ebpf_proxy_config.port);
    // Use the machine's global IPv6 address as the redirect target.
    // The kernel rejects connect6 rewrites to ::1 (loopback) for sockets
    // that aren't already bound to a loopback source.
    let proxy_ip6 = ebpf_proxy_config
        .ip6_redirect
        .map(|v6| v6.octets())
        .unwrap_or([0u8; 16]);
    let proxy_port6 = u16::to_be(ebpf_proxy_config.port6);

    // Initialize the shared map for proxy configuration.
    let ebpf_map: &mut aya::maps::Map = ebpf
        .map_mut("PROXY_CONFIG")
        .expect("Failed to create PROXY_CONFIG ebpf map");
    let mut proxy_config_map: HashMap<_, u32, EbpfProxyConfig> =
        HashMap::try_from(ebpf_map).unwrap();

    // Determine the target TGID:
    // 1. --capture-pid takes precedence (explicit, unambiguous)
    // 2. Otherwise scan /proc for the first process matching the name
    // 3. Fall back to 0 (comm-prefix matching at the BPF layer)
    let target_tgid = if let Some(pid) = ebpf_process_pid {
        tracing::info!("Using explicit PID {} for eBPF interception", pid);
        pid
    } else {
        let tgid = find_tgid_by_name(&ebpf_process).unwrap_or(0);
        if tgid != 0 {
            tracing::info!(
                "Resolved '{}' to TGID {} for eBPF interception",
                ebpf_process,
                tgid
            );
        } else {
            tracing::info!(
                "'{}' not yet running; will match by process name when it starts",
                ebpf_process
            );
        }
        tgid
    };

    let mut config = EbpfProxyConfig {
        target_proc_name: [0; 16],
        target_tgid,
        proxy_pid: process::id(),
        proxy_ip4,
        proxy_port4,
        proxy_ip6,
        proxy_port6,
    };

    let proc_name = ebpf_process.as_bytes();
    for (i, b) in proc_name.iter().enumerate() {
        config.target_proc_name[i] = *b;
    }

    proxy_config_map.insert(0, config, 0)?;

    tracing::info!(
        "Shared map PROXY_CONFIG initialized {}:{} [PID: {}]",
        ebpf_proxy_config.ip,
        ebpf_proxy_config.port,
        config.proxy_pid
    );

    let _ = tc::qdisc_add_clsact(iface);

    // Attach the cgroup_sock programs to the cgroup.
    let cgroup_path = "/sys/fs/cgroup/"; // Adjust as needed.
    let cgroup = std::fs::File::open(cgroup_path).unwrap();

    let _ = tc::qdisc_add_clsact(iface);

    let cgroup_prog_v4: &mut CgroupSockAddr =
        ebpf.program_mut("cg_connect4").unwrap().try_into()?;
    match cgroup_prog_v4.load() {
        Ok(_) => tracing::debug!("cg_connect4 program loaded"),
        Err(e) => tracing::error!("cg_connect4 program failed to load {:?}", e),
    };
    cgroup_prog_v4.attach(&cgroup, CgroupAttachMode::Single).unwrap();

    let cgroup_prog_v6: &mut CgroupSockAddr =
        ebpf.program_mut("cg_connect6").unwrap().try_into()?;
    match cgroup_prog_v6.load() {
        Ok(_) => tracing::debug!("cg_connect6 program loaded"),
        Err(e) => tracing::error!("cg_connect6 program failed to load {:?}", e),
    };
    cgroup_prog_v6.attach(&cgroup, CgroupAttachMode::Single).unwrap();

    // Attach the sock_ops program.
    let sock_ops: &mut SockOps =
        ebpf.program_mut("cg_sock_ops").unwrap().try_into()?;
    match sock_ops.load() {
        Ok(_) => tracing::debug!("cg_sock_ops program loaded"),
        Err(e) => tracing::error!("cg_sock_ops program failed to load {:?}", e),
    };
    sock_ops.attach(&cgroup, CgroupAttachMode::Single).unwrap();

    let opt_prog: &mut CgroupSockopt =
        ebpf.program_mut("cg_sock_opt").unwrap().try_into()?;
    match opt_prog.load() {
        Ok(_) => tracing::debug!("cg_sock_opt program loaded"),
        Err(e) => tracing::error!("cg_sock_opt program failed to load {:?}", e),
    };
    opt_prog.attach(&cgroup, CgroupAttachMode::Single).unwrap();

    tracing::debug!("ebpf programs installed");

    Ok(())
}

//
// -------------------- Private functions -----------------------------------
//

// Function to find interface by IP (supports both IPv4 and IPv6).
fn find_interface_by_ip(
    interfaces: &[(String, IpAddr)],
    ip: IpAddr,
) -> Option<&(String, IpAddr)> {
    interfaces.iter().find(|iface| iface.1 == ip)
}

// Function to find a non-loopback interface (prefer IPv4, fall back to IPv6).
fn find_non_loopback_interface(
    interfaces: &[(String, IpAddr)],
) -> Option<&(String, IpAddr)> {
    // Prefer a non-loopback IPv4 first.
    interfaces
        .iter()
        .find(|iface| matches!(iface.1, IpAddr::V4(v4) if !v4.is_loopback()))
        .or_else(|| {
            interfaces.iter().find(
                |iface| matches!(iface.1, IpAddr::V6(v6) if !v6.is_loopback()),
            )
        })
}

// Function to find the IP attached to a named interface.
fn find_ip_by_interface(
    interfaces: &[(String, IpAddr)],
    iface_name: String,
) -> Option<&(String, IpAddr)> {
    interfaces.iter().find(|iface| iface.0 == iface_name)
}

/// Scan /proc to find the TGID of a running process whose comm matches
/// `name`. Returns the first match found, or None if not running.
fn find_tgid_by_name(name: &str) -> Option<u32> {
    let dir = std::fs::read_dir("/proc").ok()?;
    for entry in dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        // Only look at numeric entries (PIDs)
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let mut comm_path = entry.path();
        comm_path.push("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == name {
                if let Ok(tgid) = fname_str.parse::<u32>() {
                    return Some(tgid);
                }
            }
        }
    }
    None
}

fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    // fe80::/10
    let octets = addr.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

fn get_all_interfaces() -> anyhow::Result<Vec<(String, IpAddr)>> {
    let interfaces: Vec<(String, IpAddr)> = list_afinet_netifas()
        .map_err(|e| tracing::error!("Failed to get network interfaces: {}", e))
        .unwrap();

    Ok(interfaces)
}

#[cfg(all(target_os = "linux", feature = "stealth-auto-build"))]
pub fn initialize_stealth(
    cli: &StealthCommandCommon,
    ebpf_proxy_config: &EbpfProxyAddrConfig,
) -> Option<Ebpf> {
    let proc_name = cli.ebpf_process_name.clone().unwrap_or_default();
    let proc_pid = cli.ebpf_process_pid;

    #[allow(unused_variables)]
    let ebpf_guard = match cli.ebpf {
        true => {
            let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(
                concat!(env!("OUT_DIR"), "/fault-ebpf")
            ))
            .unwrap();

            if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
                tracing::warn!("failed to initialize eBPF logger: {}", e);
            }

            let _ = install_and_run(
                &mut bpf,
                &ebpf_proxy_config,
                proc_name,
                proc_pid,
            );

            tracing::info!("Ebpf has been loaded");

            Some(bpf)
        }
        false => None,
    };

    ebpf_guard
}

#[cfg(all(target_os = "linux", feature = "stealth"))]
pub fn initialize_stealth(
    stealth_options: &StealthCommandCommon,
    ebpf_proxy_config: &EbpfProxyAddrConfig,
) -> Option<Ebpf> {
    let proc_name =
        stealth_options.ebpf_process_name.clone().unwrap_or_default();
    let proc_pid = stealth_options.ebpf_process_pid;

    #[allow(unused_variables)]
    let ebpf_guard = match stealth_options.ebpf {
        true => {
            let cargo_bin_dir = get_programs_bin_dir(stealth_options);
            if cargo_bin_dir.is_none() {
                tracing::warn!(
                    "No cargo bin directory could be detected, please set CARGO_HOME"
                );
                return None;
            }
            tracing::info!(
                "Loading ebpf programs from bin directory {:?}",
                cargo_bin_dir
            );

            let bin_dir = cargo_bin_dir.unwrap();
            let programs_path = bin_dir.join("fault-ebpf");
            if !programs_path.exists() {
                tracing::error!(
                    "Missing the fault ebpf programs. Please install them."
                );
                return None;
            }

            tracing::info!("Loading ebpf programs from {:?}", programs_path);

            let mut bpf = aya::Ebpf::load_file(programs_path).unwrap();

            if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
                tracing::warn!("failed to initialize eBPF logger: {}", e);
            }

            let _ = install_and_run(
                &mut bpf,
                ebpf_proxy_config,
                proc_name,
                proc_pid,
            );

            tracing::info!("Ebpf has been loaded");

            Some(bpf)
        }
        false => None,
    };

    ebpf_guard
}

#[cfg(all(target_os = "linux", feature = "stealth"))]
fn get_programs_bin_dir(cli: &StealthCommandCommon) -> Option<PathBuf> {
    if let Some(programs_dir) = &cli.ebpf_programs_dir {
        let path = PathBuf::from(programs_dir);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        let mut path = PathBuf::from(cargo_home);
        path.push("bin");

        if path.exists() {
            return Some(path);
        }
    }

    // Fallback for Unix-like systems: use HOME/.cargo/bin
    #[cfg(unix)]
    {
        match env::home_dir() {
            Some(mut path) => {
                path.push(".cargo/bin");
                Some(path)
            }
            None => None,
        }
    }
}
