use std::collections::BTreeMap;

use anyhow::Result;
use json_patch::Patch as JsonPatch;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::batch::v1::JobSpec;
use k8s_openapi::api::core::v1::Capabilities;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::api::core::v1::ConfigMapEnvSource;
use k8s_openapi::api::core::v1::Container;
use k8s_openapi::api::core::v1::ContainerPort;
use k8s_openapi::api::core::v1::EnvFromSource;
use k8s_openapi::api::core::v1::PodSecurityContext;
use k8s_openapi::api::core::v1::PodSpec;
use k8s_openapi::api::core::v1::PodTemplateSpec;
use k8s_openapi::api::core::v1::Probe;
use k8s_openapi::api::core::v1::SecurityContext;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::core::v1::TCPSocketAction;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Api;
use kube::Client;
use kube::api::DeleteParams;
use kube::api::Patch;
use kube::api::PatchParams;
use kube::api::PostParams;
use kube::api::PropagationPolicy;
use serde_json::from_value;
use serde_json::json;

use crate::discovery::types::EnvVarRollbackEntry;
use crate::discovery::types::K8sSpecSnapshot;
use crate::discovery::types::Resource;
use crate::inject::k8s::env_override;
use crate::inject::k8s::env_override::EnvOverride;

fn build_service_account(
    ns: &str,
    name: &str,
    labels: &BTreeMap<String, String>,
) -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        automount_service_account_token: Some(false),
        ..Default::default()
    }
}

fn build_config_map(
    ns: &str,
    name: &str,
    labels: &BTreeMap<String, String>,
    data: BTreeMap<String, String>,
) -> ConfigMap {
    ConfigMap {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

fn build_backend_service(original: &Resource, backend_name: &str) -> Service {
    // Pull the original ports & selector out of the Resource’s `content`
    let spec = &original.content["spec"];
    let selector = spec["selector"].clone(); // assume it's an object
    let ports = spec["ports"].clone(); // assume array of {port, targetPort,…}

    Service {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            namespace: Some(original.meta.ns.clone()),
            name: Some(backend_name.to_string()),
            labels: Some(BTreeMap::from([
                ("app".into(), backend_name.into()),
                // prevent external clients accidentally using it:
                ("fault-proxy-backend".into(), "true".into()),
            ])),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
            selector: selector.as_object().map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            }),
            ports: Some(
                ports
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        let port = p["port"].as_i64().unwrap() as i32;
                        let svc_port = match p["targetPort"].as_i64() {
                            Some(port) => IntOrString::Int(port as i32),
                            None => IntOrString::String(
                                p["targetPort"].as_str().unwrap().to_string(),
                            ),
                        };
                        k8s_openapi::api::core::v1::ServicePort {
                            protocol: Some("TCP".into()),
                            port,
                            target_port: Some(svc_port),
                            ..Default::default()
                        }
                    })
                    .collect(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_proxy_job(
    ns: &str,
    name: &str,
    labels: &BTreeMap<String, String>,
    config_map_name: &str,
    image: &str,
    api_adress: String,
    proxy_port: i32,
    proxy_arg: String,
) -> Job {
    let readiness_probe = Probe {
        tcp_socket: Some(TCPSocketAction {
            port:
                k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                    proxy_port,
                ),
            ..Default::default()
        }),
        initial_delay_seconds: Some(2),
        period_seconds: Some(2),
        timeout_seconds: Some(1),
        ..Default::default()
    };

    // fault proxy container
    let container = Container {
        name: name.into(),
        image: Some(image.into()),
        image_pull_policy: Some("Always".into()),
        tty: Some(false),
        args: Some(vec![
            "--log-stdout".into(),
            "--log-level".into(),
            "debug".into(),
            //"--api-address".into(),
            //api_adress,
            "run".into(),
            "--no-ui".into(),
            "--disable-http-proxy".into(),
            "--proxy".into(),
            proxy_arg,
        ]),
        ports: Some(vec![ContainerPort {
            container_port: proxy_port,
            name: Some("proxy".into()),
            ..Default::default()
        }]),
        env_from: Some(vec![EnvFromSource {
            config_map_ref: Some(ConfigMapEnvSource {
                name: config_map_name.into(),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        readiness_probe: Some(readiness_probe),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            privileged: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    Job {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    annotations: Some(BTreeMap::from([(
                        // when istio is available, we ignore it
                        "sidecar.istio.io/inject".into(),
                        "false".into(),
                    )])),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(name.into()),
                    security_context: Some(PodSecurityContext {
                        run_as_user: Some(65532),
                        run_as_group: Some(65532),
                        fs_group: Some(65532),
                        ..Default::default()
                    }),
                    containers: vec![container],
                    restart_policy: Some("Never".into()),
                    ..Default::default()
                }),
            },
            backoff_limit: Some(0),
            // automatically delete pods after 5mn
            ttl_seconds_after_finished: Some(300),
            ..Default::default()
        }),
        status: None,
    }
}

pub async fn inject_fault_proxy(
    client: Client,
    svc: &Resource,
    fault_settings: &mut BTreeMap<String, String>,
    container_image: String,
    api_address: String,
    env_overrides: &[EnvOverride],
) -> Result<K8sSpecSnapshot> {
    let ns = &svc.meta.ns;
    let orig_name = &svc.meta.name;
    let backend_name = format!("{}-backend", orig_name);
    let proxy_name = format!("{}-proxy", orig_name);
    let proxy_port = 3180;

    // Create the backend Service
    let backend_svc = build_backend_service(svc, &backend_name);
    Api::<Service>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &backend_svc)
        .await?;

    // Prepare labels & config for the proxy
    let mut labels = BTreeMap::new();
    labels.insert("app".into(), proxy_name.clone());

    let mut cm_data = BTreeMap::new();
    cm_data.append(fault_settings);

    // Determine the original service's first port
    let orig_port =
        svc.content["spec"]["ports"][0]["port"].as_i64().unwrap() as i32;

    // Build each proxy object
    let sa = build_service_account(ns, &proxy_name, &labels);
    let cm = build_config_map(
        ns,
        &format!("{}-config", proxy_name),
        &labels,
        cm_data,
    );
    let proxy_arg = format!("{}={}:{}", proxy_port, backend_name, orig_port);
    let proxy_job = build_proxy_job(
        ns,
        &proxy_name,
        &labels,
        &cm.metadata.name.clone().unwrap(),
        &container_image,
        api_address,
        proxy_port,
        proxy_arg,
    );

    // Create the proxy
    let pp = PostParams::default();
    Api::<ServiceAccount>::namespaced(client.clone(), ns)
        .create(&pp, &sa)
        .await?;
    Api::<ConfigMap>::namespaced(client.clone(), ns).create(&pp, &cm).await?;
    Api::<Job>::namespaced(client.clone(), ns).create(&pp, &proxy_job).await?;

    // Patch the original Service's selector to point at our proxy
    let svc_api: Api<Service> = Api::namespaced(client.clone(), ns);
    let orig_svc = svc_api.get(orig_name).await?;
    let original_selector =
        orig_svc.spec.and_then(|s| s.selector).unwrap_or_default();

    let orig_ports = svc.content["spec"]["ports"]
        .as_array()
        .expect("service must have ports");

    let patched_ports: Vec<_> = orig_ports
        .iter()
        .map(|p| {
            json!({
                "port": p["port"].as_i64().unwrap(),
                "protocol": p.get("protocol").cloned().unwrap_or(json!("TCP")),
                "targetPort": proxy_port,
                "name": p.get("name").cloned().unwrap_or_default(),
            })
        })
        .collect();

    let patch: JsonPatch = from_value(json!([
        {
          "op": "replace",
          "path": "/spec/selector",
          "value":  labels
        },
        {
          "op": "replace",
          "path": "/spec/ports",
          "value": patched_ports
        }
    ]))
    .unwrap();

    svc_api
        .patch(orig_name, &PatchParams::default(), &Patch::Json::<()>(patch))
        .await?;

    // Apply env var overrides. Inbound mode: pass empty strings for host/port
    // — templates would be a user error and are caught inside the function.
    let env_var_rollback: Vec<EnvVarRollbackEntry> =
        env_override::apply_env_overrides(
            client.clone(),
            ns,
            env_overrides,
            "",
            "",
        )
        .await?;

    let snapshot = K8sSpecSnapshot {
        selector: original_selector,
        ports: orig_ports.to_vec(),
        env_var_rollback,
    };

    Ok(snapshot)
}

pub async fn rollback_fault_injection(
    client: Client,
    svc: &Resource,
    original_snapshot: K8sSpecSnapshot,
) -> Result<()> {
    let ns = &svc.meta.ns;
    let orig_name = &svc.meta.name;
    let backend_name = format!("{}-backend", orig_name);
    let proxy_name = format!("{}-proxy", orig_name);

    // Restore any env var overrides first, before tearing down the proxy,
    // so that workloads start their rolling restart while the proxy is still
    // alive and traffic continues to flow.
    env_override::rollback_env_overrides(
        client.clone(),
        ns,
        &original_snapshot.env_var_rollback,
    )
    .await?;

    // Patch the original Service back
    let svc_api: Api<Service> = Api::namespaced(client.clone(), ns);
    let pp = PatchParams::apply("fault-injector");

    let patch: JsonPatch = from_value(json!([
        {
          "op": "replace",
          "path": "/spec/selector",
          "value":  original_snapshot.selector
        },
        {
          "op": "replace",
          "path": "/spec/ports",
          "value": original_snapshot.ports
        }
    ]))
    .unwrap();

    svc_api.patch(orig_name, &pp, &Patch::Json::<()>(patch)).await?;

    //Delete all injected artifacts
    let sa_api = Api::<ServiceAccount>::namespaced(client.clone(), ns);
    let cm_api = Api::<ConfigMap>::namespaced(client.clone(), ns);
    let job_api = Api::<Job>::namespaced(client.clone(), ns);
    let backend_api = Api::<Service>::namespaced(client.clone(), ns);

    let dp = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..Default::default()
    };

    // best‐effort deletes, ignoring "not found"
    let _ = sa_api.delete(&proxy_name, &dp).await;
    let _ = cm_api.delete(&format!("{}-config", proxy_name), &dp).await;
    let _ = job_api.delete(&proxy_name, &dp).await;
    let _ = backend_api.delete(&backend_name, &dp).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone outbound proxy
// ---------------------------------------------------------------------------
//
// Diagram:
//
//   pod
//    | (env var e.g. DB_HOST now points at fault-proxy-<name>:<port>)
//    v
//   fault-proxy-<name> Service  (ClusterIP, port -> 3180)
//    |
//    v
//   fault-proxy-<name> Job pod  (fault proxy 3180=<real-upstream>)
//    |
//    v
//   real upstream  (e.g. prod-db.rds.amazonaws.com:5432)
//
// No existing Service is touched.  The proxy name and the in-cluster Service
// name are both derived from `proxy_name` (caller supplies it, usually
// something like "fault-proxy-db").

/// Launch a standalone outbound proxy and apply env-var overrides so workloads
/// start talking to it instead of the real upstream.
///
/// `proxy_name`     — name used for all created resources (Job, Service, …)
/// `upstream`       — real destination the proxy should forward to
/// ("host:port") `proxy_port`     — port the in-cluster Service exposes (and
/// the proxy listens on) `fault_settings` — fault env vars injected via
/// ConfigMap into the proxy Job `env_overrides`  — list of
/// ConfigMap/Deployment/StatefulSet keys to patch
pub async fn inject_fault_proxy_standalone(
    client: Client,
    ns: &str,
    proxy_name: &str,
    upstream: &str,
    proxy_port: i32,
    container_image: &str,
    fault_settings: &mut BTreeMap<String, String>,
    env_overrides: &[EnvOverride],
) -> Result<K8sSpecSnapshot> {
    let mut labels = BTreeMap::new();
    labels.insert("app".into(), proxy_name.to_string());
    labels.insert("fault-proxy-standalone".into(), "true".into());

    // ConfigMap carrying fault settings for the proxy Job
    let mut cm_data = BTreeMap::new();
    cm_data.append(fault_settings);
    let cm = build_config_map(
        ns,
        &format!("{}-config", proxy_name),
        &labels,
        cm_data,
    );

    // ServiceAccount
    let sa = build_service_account(ns, proxy_name, &labels);

    // proxy_arg: "<listen_port>=<real_upstream>"
    let proxy_arg = format!("{}={}", proxy_port, upstream);
    let proxy_job = build_proxy_job(
        ns,
        proxy_name,
        &labels,
        &cm.metadata.name.clone().unwrap(),
        container_image,
        String::new(),
        proxy_port,
        proxy_arg,
    );

    // Frontend ClusterIP Service — pods reach the proxy through this
    let frontend_svc =
        build_proxy_frontend_service(ns, proxy_name, &labels, proxy_port);

    let pp = PostParams::default();
    Api::<ServiceAccount>::namespaced(client.clone(), ns)
        .create(&pp, &sa)
        .await?;
    Api::<ConfigMap>::namespaced(client.clone(), ns).create(&pp, &cm).await?;
    Api::<Job>::namespaced(client.clone(), ns).create(&pp, &proxy_job).await?;
    Api::<Service>::namespaced(client.clone(), ns)
        .create(&pp, &frontend_svc)
        .await?;

    // Patch env vars so workloads point at the in-cluster proxy Service.
    // Substitute {host} → proxy_name, {port} → proxy_port in templates.
    let env_var_rollback = env_override::apply_env_overrides(
        client.clone(),
        ns,
        env_overrides,
        proxy_name,
        &proxy_port.to_string(),
    )
    .await?;

    Ok(K8sSpecSnapshot {
        // No selector/ports snapshot needed — we never touched an existing
        // Service
        selector: BTreeMap::new(),
        ports: Vec::new(),
        env_var_rollback,
    })
}

/// Roll back a standalone proxy injection.
pub async fn rollback_fault_proxy_standalone(
    client: Client,
    ns: &str,
    proxy_name: &str,
    snapshot: K8sSpecSnapshot,
) -> Result<()> {
    // Restore env vars first so workloads get their real upstream back while
    // the proxy is still alive to serve any in-flight connections.
    env_override::rollback_env_overrides(
        client.clone(),
        ns,
        &snapshot.env_var_rollback,
    )
    .await?;

    let dp = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..Default::default()
    };

    let _ = Api::<ServiceAccount>::namespaced(client.clone(), ns)
        .delete(proxy_name, &dp)
        .await;
    let _ = Api::<ConfigMap>::namespaced(client.clone(), ns)
        .delete(&format!("{}-config", proxy_name), &dp)
        .await;
    let _ = Api::<Job>::namespaced(client.clone(), ns)
        .delete(proxy_name, &dp)
        .await;
    let _ = Api::<Service>::namespaced(client.clone(), ns)
        .delete(proxy_name, &dp)
        .await;

    Ok(())
}

fn build_proxy_frontend_service(
    ns: &str,
    name: &str,
    labels: &BTreeMap<String, String>,
    port: i32,
) -> Service {
    use k8s_openapi::api::core::v1::ServicePort;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    Service {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels.clone()),
            ports: Some(vec![ServicePort {
                protocol: Some("TCP".into()),
                port,
                target_port: Some(IntOrString::Int(port)),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}
