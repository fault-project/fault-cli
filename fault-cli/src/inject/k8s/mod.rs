use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use anyhow::anyhow;
use async_trait::async_trait;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::Api;
use kube::Client;
use kube::api::ListParams;
use tokio::time::sleep;

pub(crate) mod env_override;
pub(crate) mod run;
pub(crate) mod scenario;

use crate::discovery::k8s::discover_kubernetes_resources;
use crate::discovery::types::K8sSpecSnapshot;
use crate::discovery::types::Resource;
use crate::inject::InjectionHandle;
use crate::inject::Platform;
use crate::inject::ServiceResource;
use crate::inject::k8s::env_override::EnvOverride;

// ---------------------------------------------------------------------------
// System service protection
// ---------------------------------------------------------------------------

/// Namespaces that are exclusively for Kubernetes infrastructure.
/// Services in these namespaces must never be injected into.
const SYSTEM_NAMESPACES: &[&str] =
    &["kube-system", "kube-public", "kube-node-lease"];

/// Well-known infrastructure service names that are dangerous to inject into
/// regardless of namespace (e.g. the `kubernetes` API server service lives in
/// `default`).
const SYSTEM_SERVICE_NAMES: &[&str] = &["kubernetes"];

/// Returns true if the given service should be blocked from injection.
fn is_system_service(name: &str, namespace: &str) -> bool {
    SYSTEM_NAMESPACES.contains(&namespace)
        || SYSTEM_SERVICE_NAMES.contains(&name)
}

/// Kubernetes implementation of `Platform`.
///
/// Two modes:
///
/// **Inbound** (`standalone_proxy_name` is `None`):
///   A proxy Job is inserted in front of an existing Service so traffic
///   arriving *at* the target pod passes through the fault proxy.
///
/// **Standalone outbound** (`standalone_proxy_name` is `Some`):
///   A standalone proxy Job + ClusterIP Service is created.  `--env-override`
///   patches ConfigMaps / Deployments / StatefulSets so pods redirect a
///   downstream dependency through the proxy.  No existing Service is touched.
#[derive(Clone)]
pub struct KubernetesPlatform {
    client: Client,
    namespace: String,
    scenario: Option<String>,
    fault_settings: Option<BTreeMap<String, String>>,
    /// Targeted env var overrides (kind/name:KEY[=VALUE]).
    env_overrides: Vec<EnvOverride>,
    /// `Some(proxy_name)` → standalone outbound mode.
    /// `None`             → inbound service-based mode.
    standalone_proxy_name: Option<String>,
    /// Only used in standalone mode: the real upstream address ("host:port").
    standalone_upstream: Option<String>,
    /// Port the standalone proxy Job listens on (and the frontend Service
    /// exposes).
    standalone_proxy_port: i32,
    service_name: String,
    container_image: String,
    api_address: String,
    resources: Vec<Resource>,
    injection_handle: Option<InjectionHandle>,
    verbose: bool,
}

impl KubernetesPlatform {
    /// Inbound proxy mode: insert proxy in front of `service`.
    pub async fn new_proxy(
        namespace: &str,
        service: &str,
        container_image: &str,
        api_address: &str,
        fault_settings: BTreeMap<String, String>,
        env_overrides: Vec<EnvOverride>,
        verbose: bool,
    ) -> Result<Self> {
        let client = Client::try_default().await?;
        let resources = discover_kubernetes_resources(namespace).await?;
        Ok(Self {
            client,
            fault_settings: Some(fault_settings),
            env_overrides,
            standalone_proxy_name: None,
            standalone_upstream: None,
            standalone_proxy_port: 3180,
            scenario: None,
            namespace: namespace.to_string(),
            service_name: service.to_string(),
            container_image: container_image.to_string(),
            api_address: api_address.to_string(),
            resources,
            injection_handle: None,
            verbose,
        })
    }

    /// Standalone outbound proxy mode: create a named proxy + ClusterIP
    /// Service, patch env vars so workloads redirect a downstream
    /// dependency through it.
    pub async fn new_standalone(
        namespace: &str,
        proxy_name: &str,
        upstream: &str,
        proxy_port: i32,
        container_image: &str,
        api_address: &str,
        fault_settings: BTreeMap<String, String>,
        env_overrides: Vec<EnvOverride>,
        verbose: bool,
    ) -> Result<Self> {
        let client = Client::try_default().await?;
        let resources = discover_kubernetes_resources(namespace).await?;
        Ok(Self {
            client,
            fault_settings: Some(fault_settings),
            env_overrides,
            standalone_proxy_name: Some(proxy_name.to_string()),
            standalone_upstream: Some(upstream.to_string()),
            standalone_proxy_port: proxy_port,
            scenario: None,
            namespace: namespace.to_string(),
            service_name: String::new(),
            container_image: container_image.to_string(),
            api_address: api_address.to_string(),
            resources,
            injection_handle: None,
            verbose,
        })
    }

    pub async fn new_scenario(
        namespace: &str,
        service: &str,
        container_image: &str,
        api_address: &str,
        scenario: String,
    ) -> Result<Self> {
        let client = Client::try_default().await?;
        let resources = discover_kubernetes_resources(namespace).await?;
        Ok(Self {
            client,
            fault_settings: None,
            env_overrides: Vec::new(),
            standalone_proxy_name: None,
            standalone_upstream: None,
            standalone_proxy_port: 3180,
            scenario: Some(scenario),
            namespace: namespace.to_string(),
            service_name: service.to_string(),
            container_image: container_image.to_string(),
            api_address: api_address.to_string(),
            resources,
            injection_handle: None,
            verbose: false,
        })
    }

    fn is_scenario(&self) -> bool {
        self.scenario.is_some()
    }

    fn is_standalone(&self) -> bool {
        self.standalone_proxy_name.is_some()
    }

    /// Helper: get only the Service‐kind entries (with address),
    /// excluding known system/infrastructure services that must never
    /// be injected into.
    fn cached_services(&self) -> Vec<ServiceResource> {
        self.resources
            .iter()
            .filter(|r| r.meta.kind == "Service")
            .filter(|r| !is_system_service(&r.meta.name, &r.meta.ns))
            .map(|r| {
                let addr = r.content["spec"]["clusterIP"]
                    .as_str()
                    .unwrap_or(&r.meta.name)
                    .to_string();
                ServiceResource { name: r.meta.name.clone(), address: addr }
            })
            .collect()
    }

    /// Helper: find the full Resource for a given name
    fn find_resource(&self, name: &str) -> &Resource {
        self.resources
            .iter()
            .find(|r| r.meta.name == name)
            .expect("service must exist in cache")
    }
}

#[async_trait]
impl Platform for KubernetesPlatform {
    async fn discover(&self) -> Result<Vec<ServiceResource>> {
        Ok(self.cached_services())
    }

    async fn get_service(&self) -> Result<ServiceResource> {
        let svcs = self.discover().await?;
        match svcs.into_iter().find(|s| s.name == self.service_name) {
            Some(m) => Ok(m),
            None => Err(anyhow!(
                "service '{}' could not be found",
                self.service_name
            )),
        }
    }

    fn set_service(&mut self, service: &str) -> Result<()> {
        if is_system_service(service, &self.namespace) {
            anyhow::bail!(
                "Service '{}' in namespace '{}' is a protected system service \
                 and cannot be injected into. If you intended a different \
                 service, use --ns to set the correct namespace.",
                service,
                self.namespace
            );
        }
        self.service_name = service.to_string();
        Ok(())
    }

    async fn inject(&mut self) -> Result<()> {
        let snapshot = if self.is_standalone() {
            let proxy_name = self.standalone_proxy_name.clone().unwrap();
            let upstream = self.standalone_upstream.clone().unwrap();
            let fault_vars =
                &mut self.fault_settings.clone().unwrap_or_default();
            run::inject_fault_proxy_standalone(
                self.client.clone(),
                &self.namespace,
                &proxy_name,
                &upstream,
                self.standalone_proxy_port,
                &self.container_image,
                fault_vars,
                &self.env_overrides,
                self.verbose,
            )
            .await?
        } else if self.is_scenario() {
            let svc = self.get_service().await?;
            let full = self.find_resource(&svc.name);
            scenario::inject_fault_scenario(
                self.client.clone(),
                full,
                self.scenario.clone().unwrap(),
                self.container_image.clone(),
                self.api_address.clone(),
            )
            .await?
        } else {
            let svc = self.get_service().await?;
            let full = self.find_resource(&svc.name);
            let fault_vars = &mut self.fault_settings.clone().unwrap();
            run::inject_fault_proxy(
                self.client.clone(),
                full,
                fault_vars,
                self.container_image.clone(),
                self.api_address.clone(),
                &self.env_overrides,
                self.verbose,
            )
            .await?
        };

        let token = serde_json::to_string(&snapshot)?;
        self.injection_handle =
            Some(InjectionHandle::Kubernetes { rollback_token: token });
        Ok(())
    }

    async fn rollback(&mut self) -> Result<()> {
        if self.injection_handle.is_none() {
            return Ok(());
        }
        if let Some(InjectionHandle::Kubernetes { rollback_token }) =
            self.injection_handle.take()
        {
            let snapshot: K8sSpecSnapshot =
                serde_json::from_str(&rollback_token)?;
            if self.is_standalone() {
                let proxy_name = self.standalone_proxy_name.clone().unwrap();
                run::rollback_fault_proxy_standalone(
                    self.client.clone(),
                    &self.namespace,
                    &proxy_name,
                    snapshot,
                )
                .await?;
            } else {
                let svc = self.get_service().await?;
                let full = self.find_resource(&svc.name);
                if self.is_scenario() {
                    scenario::rollback_fault_injection(
                        self.client.clone(),
                        full,
                        snapshot,
                    )
                    .await?;
                } else {
                    run::rollback_fault_injection(
                        self.client.clone(),
                        full,
                        snapshot,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn update_fault_settings(
        &mut self,
        fault_settings: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        if let Some(ref mut settings) = self.fault_settings {
            settings.clear();
            settings.append(fault_settings);
        }
        Ok(())
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let ns = &self.namespace.clone();
        let proxy_name = if self.is_standalone() {
            self.standalone_proxy_name.clone().unwrap()
        } else {
            format!("{}-proxy", self.get_service().await?.name)
        };

        let pods_api: Api<Pod> = Api::namespaced(self.client.clone(), ns);
        let start = Instant::now();
        let timeout = Duration::from_secs(60);
        let interval = Duration::from_millis(300);

        loop {
            let lp =
                ListParams::default().labels(&format!("app={}", proxy_name));
            let pod_list = pods_api.list(&lp).await?;

            for pod in pod_list.items.iter() {
                if let Some(status) = pod.status.as_ref() {
                    if status.phase.as_deref() == Some("Running") {
                        if let Some(conds) = status.conditions.as_ref() {
                            if conds.iter().any(|c| {
                                c.type_ == "Ready" && c.status == "True"
                            }) {
                                return Ok(());
                            }
                        }
                    }
                }
            }

            if start.elapsed() > timeout {
                anyhow::bail!(
                    "Timed out waiting for proxy pod `{}` to become Ready",
                    proxy_name
                );
            }
            sleep(interval).await;
        }
    }

    async fn wait_cleanup(&mut self) -> Result<()> {
        let ns = self.namespace.clone();
        let proxy_name = if self.is_standalone() {
            self.standalone_proxy_name.clone().unwrap()
        } else {
            format!("{}-proxy", self.get_service().await?.name)
        };
        let backend_name = format!("{}-backend", proxy_name);

        let deadline = Duration::from_secs(30);
        let interval = Duration::from_secs(2);
        let start = Instant::now();

        let jobs: Api<Job> = Api::namespaced(self.client.clone(), &ns);
        let services: Api<Service> = Api::namespaced(self.client.clone(), &ns);
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), &ns);
        let sas: Api<ServiceAccount> =
            Api::namespaced(self.client.clone(), &ns);
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &ns);

        loop {
            let j_exist = jobs.get_opt(&proxy_name).await?.is_some();
            let s_exist = services.get_opt(&proxy_name).await?.is_some()
                || services.get_opt(&backend_name).await?.is_some();
            let cm_exist =
                cms.get_opt(&format!("{}-config", proxy_name)).await?.is_some();
            let sa_exist = sas.get_opt(&proxy_name).await?.is_some();
            let lp =
                ListParams::default().labels(&format!("app={}", proxy_name));
            let pods_exist = !pods.list(&lp).await?.items.is_empty();

            if !(j_exist || s_exist || cm_exist || sa_exist || pods_exist) {
                return Ok(());
            }

            if start.elapsed() > deadline {
                anyhow::bail!(
                    "timed out waiting for cleanup of `{}`",
                    proxy_name
                );
            }
            sleep(interval).await;
        }
    }

    fn get_concrete_resources(&self) -> &Vec<Resource> {
        &self.resources
    }

    fn get_concrete_service(&self) -> &Resource {
        self.resources
            .iter()
            .find(|r| {
                r.meta.kind == "Service" && r.meta.name == self.service_name
            })
            .unwrap()
    }
}
