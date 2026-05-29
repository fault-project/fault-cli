/// Targeted env-var / ConfigMap override injection.
///
/// Each `--env-override` flag takes the form:
///
///   kind/name:KEY=VALUE
///
/// Supported kinds:
///   deployment/name   — patches container env vars in-place, triggers
/// rolling restart   statefulset/name  — same
///   configmap/name    — patches the ConfigMap data key directly; no
/// restart is                       triggered (the caller is expected to
/// do a manual rollout,                       or the app picks up the
/// change live)
///
/// Examples:
///   --env-override deployment/my-api:DB_HOST=proxy-svc:5432
///   --env-override statefulset/my-db:DB_HOST=proxy-svc:5432
///   --env-override configmap/my-app-config:DB_HOST=proxy-svc:5432
///
/// Only the named resource is touched — no namespace-wide scanning.
///
/// For Deployment/StatefulSet: containers that hold the env var via
/// `valueFrom` (ConfigMapKeyRef, SecretKeyRef, etc.) are skipped with a
/// warning — we cannot safely overwrite references without chasing the
/// source object.
///
/// On rollback: original values are restored.  For Deployment/StatefulSet
/// a rolling restart is triggered.  For ConfigMap the data is patched
/// back; the caller is again responsible for the rollout if needed.
use std::collections::BTreeMap;

use anyhow::Result;
use anyhow::bail;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::api::core::v1::EnvVar;
use kube::Api;
use kube::Client;
use kube::api::Patch;
use kube::api::PatchParams;
use serde_json::json;

use crate::discovery::types::EnvVarRollbackEntry;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single parsed `--env-override` entry.
#[derive(Clone, Debug)]
pub struct EnvOverride {
    pub kind: WorkloadKind,
    pub name: String,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadKind {
    Deployment,
    StatefulSet,
    ConfigMap,
}

impl WorkloadKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkloadKind::Deployment => "Deployment",
            WorkloadKind::StatefulSet => "StatefulSet",
            WorkloadKind::ConfigMap => "ConfigMap",
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a list of raw `kind/name:KEY=VALUE` strings into `EnvOverride`s.
/// Returns an error immediately if any entry is malformed.
pub fn parse_env_overrides(raw: &[String]) -> Result<Vec<EnvOverride>> {
    let mut out = Vec::new();

    for s in raw {
        // Split at the FIRST ':' to get "kind/name" and "KEY=VALUE".
        // Note: VALUE itself may contain ':', e.g. "DB_HOST=host:5432" — fine
        // because we only split_once here.
        let (target_part, kv_part) = match s.split_once(':') {
            Some(pair) => pair,
            None => bail!(
                "--env-override '{}': expected format 'kind/name:KEY=VALUE' \
                 (missing ':')",
                s
            ),
        };

        let (kind_str, workload_name) = match target_part.split_once('/') {
            Some(pair) => pair,
            None => bail!(
                "--env-override '{}': target '{}' must be 'kind/name' \
                 e.g. 'deployment/my-app', 'statefulset/my-db', \
                 or 'configmap/my-config'",
                s,
                target_part
            ),
        };

        let kind = match kind_str.to_lowercase().as_str() {
            "deployment" | "deploy" => WorkloadKind::Deployment,
            "statefulset" | "sts" => WorkloadKind::StatefulSet,
            "configmap" | "cm" => WorkloadKind::ConfigMap,
            other => bail!(
                "--env-override '{}': unsupported kind '{}'. \
                 Use 'deployment', 'statefulset', or 'configmap'.",
                s,
                other
            ),
        };

        let (key, value) = match kv_part.split_once('=') {
            Some(pair) => pair,
            None => bail!(
                "--env-override '{}': env var part '{}' must be 'KEY=VALUE'",
                s,
                kv_part
            ),
        };

        if key.trim().is_empty() {
            bail!("--env-override '{}': key must not be empty", s);
        }

        out.push(EnvOverride {
            kind,
            name: workload_name.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Upstream resolution
// ---------------------------------------------------------------------------

/// Read the **current** value of the first override's key from the named
/// resource.  This is used in standalone proxy mode to discover the real
/// upstream address (e.g. the current `DB_HOST` value) before we overwrite it.
///
/// Returns `None` if the key doesn't exist or the resource has no relevant
/// data (e.g. a Deployment container that doesn't carry the key at all).
pub async fn resolve_current_value(
    client: Client,
    ns: &str,
    ov: &EnvOverride,
) -> Result<Option<String>> {
    match &ov.kind {
        WorkloadKind::ConfigMap => {
            let api: Api<ConfigMap> = Api::namespaced(client, ns);
            let cm = api.get(&ov.name).await?;
            Ok(cm.data.and_then(|d| d.get(&ov.key).cloned()))
        }
        WorkloadKind::Deployment => {
            let api: Api<Deployment> = Api::namespaced(client, ns);
            let d = api.get(&ov.name).await?;
            let containers = d
                .spec
                .as_ref()
                .and_then(|s| s.template.spec.as_ref())
                .map(|ps| ps.containers.as_slice())
                .unwrap_or(&[]);
            for c in containers {
                if let Some(ev) = c
                    .env
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .find(|e| e.name == ov.key)
                {
                    return Ok(ev.value.clone());
                }
            }
            Ok(None)
        }
        WorkloadKind::StatefulSet => {
            let api: Api<StatefulSet> = Api::namespaced(client, ns);
            let ss = api.get(&ov.name).await?;
            let containers = ss
                .spec
                .as_ref()
                .and_then(|s| s.template.spec.as_ref())
                .map(|ps| ps.containers.as_slice())
                .unwrap_or(&[]);
            for c in containers {
                if let Some(ev) = c
                    .env
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .find(|e| e.name == ov.key)
                {
                    return Ok(ev.value.clone());
                }
            }
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// Apply env-var overrides to the explicitly named workloads / ConfigMaps.
/// Returns rollback entries for everything that was actually changed.
pub async fn apply_env_overrides(
    client: Client,
    ns: &str,
    overrides: &[EnvOverride],
) -> Result<Vec<EnvVarRollbackEntry>> {
    if overrides.is_empty() {
        return Ok(vec![]);
    }

    // Group by (kind, name) so we make one patch per resource.
    let mut by_resource: BTreeMap<
        (WorkloadKind, String),
        BTreeMap<String, String>,
    > = BTreeMap::new();
    for ov in overrides {
        by_resource
            .entry((ov.kind.clone(), ov.name.clone()))
            .or_default()
            .insert(ov.key.clone(), ov.value.clone());
    }

    let deploys: Api<Deployment> = Api::namespaced(client.clone(), ns);
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), ns);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), ns);

    let mut rollback = Vec::new();

    for ((kind, name), kv_map) in &by_resource {
        match kind {
            WorkloadKind::Deployment => {
                let d = deploys.get(name).await?;
                let entries =
                    patch_deployment_env(&deploys, name, &d, kv_map).await?;
                rollback.extend(entries);
            }
            WorkloadKind::StatefulSet => {
                let ss = statefulsets.get(name).await?;
                let entries =
                    patch_statefulset_env(&statefulsets, name, &ss, kv_map)
                        .await?;
                rollback.extend(entries);
            }
            WorkloadKind::ConfigMap => {
                let cm = configmaps.get(name).await?;
                let entry =
                    patch_configmap_data(&configmaps, name, &cm, kv_map)
                        .await?;
                if let Some(e) = entry {
                    rollback.push(e);
                }
            }
        }
    }

    Ok(rollback)
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/// Restore all resources from the rollback entries produced by
/// `apply_env_overrides`.
pub async fn rollback_env_overrides(
    client: Client,
    ns: &str,
    entries: &[EnvVarRollbackEntry],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let deploys: Api<Deployment> = Api::namespaced(client.clone(), ns);
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), ns);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), ns);

    for entry in entries {
        match entry.workload_kind.as_str() {
            "Deployment" => restore_deployment_env(&deploys, entry).await?,
            "StatefulSet" => {
                restore_statefulset_env(&statefulsets, entry).await?
            }
            "ConfigMap" => restore_configmap_data(&configmaps, entry).await?,
            other => {
                tracing::warn!(
                    "Unknown workload kind '{}' in rollback entry, skipping",
                    other
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Deployment helpers
// ---------------------------------------------------------------------------

async fn patch_deployment_env(
    api: &Api<Deployment>,
    name: &str,
    deploy: &Deployment,
    overrides: &BTreeMap<String, String>,
) -> Result<Vec<EnvVarRollbackEntry>> {
    let containers = deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|ps| ps.containers.as_slice())
        .unwrap_or(&[]);

    let mut rollback_entries = Vec::new();
    let mut patch_containers: Vec<serde_json::Value> = Vec::new();

    for container in containers {
        let (patched_env, originals) = compute_env_patch(
            container.env.as_deref().unwrap_or(&[]),
            overrides,
            name,
            "Deployment",
            &container.name,
        );
        if !originals.is_empty() {
            rollback_entries.push(EnvVarRollbackEntry {
                workload_kind: "Deployment".into(),
                workload_name: name.into(),
                container_name: Some(container.name.clone()),
                original_values: originals,
            });
            patch_containers.push(
                json!({ "name": container.name, "env": env_to_json(&patched_env) }),
            );
        } else {
            patch_containers.push(json!({ "name": container.name }));
        }
    }

    if rollback_entries.is_empty() {
        return Ok(vec![]);
    }

    apply_workload_patch(api, name, patch_containers).await?;
    tracing::info!("Patched env vars in Deployment '{}'", name);
    Ok(rollback_entries)
}

async fn restore_deployment_env(
    api: &Api<Deployment>,
    entry: &EnvVarRollbackEntry,
) -> Result<()> {
    let deploy = api.get(&entry.workload_name).await?;
    let containers = deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|ps| ps.containers.as_slice())
        .unwrap_or(&[]);

    let patch_containers = build_restore_patch(containers, entry);
    apply_workload_patch(api, &entry.workload_name, patch_containers).await?;
    tracing::info!("Restored env vars in Deployment '{}'", entry.workload_name);
    Ok(())
}

// ---------------------------------------------------------------------------
// StatefulSet helpers
// ---------------------------------------------------------------------------

async fn patch_statefulset_env(
    api: &Api<StatefulSet>,
    name: &str,
    ss: &StatefulSet,
    overrides: &BTreeMap<String, String>,
) -> Result<Vec<EnvVarRollbackEntry>> {
    let containers = ss
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|ps| ps.containers.as_slice())
        .unwrap_or(&[]);

    let mut rollback_entries = Vec::new();
    let mut patch_containers: Vec<serde_json::Value> = Vec::new();

    for container in containers {
        let (patched_env, originals) = compute_env_patch(
            container.env.as_deref().unwrap_or(&[]),
            overrides,
            name,
            "StatefulSet",
            &container.name,
        );
        if !originals.is_empty() {
            rollback_entries.push(EnvVarRollbackEntry {
                workload_kind: "StatefulSet".into(),
                workload_name: name.into(),
                container_name: Some(container.name.clone()),
                original_values: originals,
            });
            patch_containers.push(
                json!({ "name": container.name, "env": env_to_json(&patched_env) }),
            );
        } else {
            patch_containers.push(json!({ "name": container.name }));
        }
    }

    if rollback_entries.is_empty() {
        return Ok(vec![]);
    }

    apply_workload_patch(api, name, patch_containers).await?;
    tracing::info!("Patched env vars in StatefulSet '{}'", name);
    Ok(rollback_entries)
}

async fn restore_statefulset_env(
    api: &Api<StatefulSet>,
    entry: &EnvVarRollbackEntry,
) -> Result<()> {
    let ss = api.get(&entry.workload_name).await?;
    let containers = ss
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|ps| ps.containers.as_slice())
        .unwrap_or(&[]);

    let patch_containers = build_restore_patch(containers, entry);
    apply_workload_patch(api, &entry.workload_name, patch_containers).await?;
    tracing::info!(
        "Restored env vars in StatefulSet '{}'",
        entry.workload_name
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ConfigMap helpers
// ---------------------------------------------------------------------------

/// Patch specific keys in a ConfigMap's `data` map.
/// No rollout restart is triggered — the caller manages that.
async fn patch_configmap_data(
    api: &Api<ConfigMap>,
    name: &str,
    cm: &ConfigMap,
    overrides: &BTreeMap<String, String>,
) -> Result<Option<EnvVarRollbackEntry>> {
    let current_data = cm.data.clone().unwrap_or_default();
    let mut originals: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut patched_data = current_data.clone();

    for (key, new_val) in overrides {
        let original = current_data.get(key).cloned();
        originals.insert(key.clone(), original);
        patched_data.insert(key.clone(), new_val.clone());
    }

    if originals.is_empty() {
        return Ok(None);
    }

    // Merge-patch just the data field
    let patch_body = json!({ "data": patched_data });
    let pp = PatchParams::default();
    api.patch(name, &pp, &Patch::Merge::<serde_json::Value>(patch_body))
        .await?;

    tracing::info!(
        "Patched ConfigMap '{}' keys: {}",
        name,
        overrides.keys().cloned().collect::<Vec<_>>().join(", ")
    );

    Ok(Some(EnvVarRollbackEntry {
        workload_kind: "ConfigMap".into(),
        workload_name: name.into(),
        container_name: None,
        original_values: originals,
    }))
}

/// Restore ConfigMap data keys from rollback entry.
/// No rollout restart is triggered — the caller manages that.
async fn restore_configmap_data(
    api: &Api<ConfigMap>,
    entry: &EnvVarRollbackEntry,
) -> Result<()> {
    let cm = api.get(&entry.workload_name).await?;
    let mut data = cm.data.clone().unwrap_or_default();

    for (key, original_value) in &entry.original_values {
        match original_value {
            Some(orig) => {
                data.insert(key.clone(), orig.clone());
            }
            None => {
                data.remove(key);
            }
        }
    }

    let patch_body = json!({ "data": data });
    let pp = PatchParams::default();
    api.patch(
        &entry.workload_name,
        &pp,
        &Patch::Merge::<serde_json::Value>(patch_body),
    )
    .await?;

    tracing::info!(
        "Restored ConfigMap '{}' keys: {}",
        entry.workload_name,
        entry.original_values.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared workload patch helpers (Deployment / StatefulSet)
// ---------------------------------------------------------------------------

/// Apply a server-side-apply patch to a Deployment or StatefulSet that updates
/// container env vars and bumps the restart annotation.
async fn apply_workload_patch<K>(
    api: &Api<K>,
    name: &str,
    containers: Vec<serde_json::Value>,
) -> Result<()>
where
    K: kube::Resource
        + serde::de::DeserializeOwned
        + serde::Serialize
        + Clone
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let patch_body = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "fault-inject/restartedAt": chrono::Utc::now().to_rfc3339()
                    }
                },
                "spec": { "containers": containers }
            }
        }
    });

    let pp = PatchParams::apply("fault-injector").force();
    api.patch(name, &pp, &Patch::Apply::<serde_json::Value>(patch_body))
        .await?;
    Ok(())
}

fn build_restore_patch(
    containers: &[k8s_openapi::api::core::v1::Container],
    entry: &EnvVarRollbackEntry,
) -> Vec<serde_json::Value> {
    let target_container = entry.container_name.as_deref().unwrap_or("");
    containers
        .iter()
        .map(|c| {
            if c.name != target_container {
                return json!({ "name": c.name });
            }
            let restored = restore_env(
                c.env.as_deref().unwrap_or(&[]),
                &entry.original_values,
            );
            json!({ "name": c.name, "env": env_to_json(&restored) })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pure helpers (no I/O)
// ---------------------------------------------------------------------------

fn compute_env_patch(
    current_env: &[EnvVar],
    overrides: &BTreeMap<String, String>,
    workload_name: &str,
    workload_kind: &str,
    container_name: &str,
) -> (Vec<EnvVar>, BTreeMap<String, Option<String>>) {
    let mut originals: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut result: Vec<EnvVar> = current_env.to_vec();

    for (key, new_val) in overrides {
        if let Some(existing) = result.iter().find(|e| &e.name == key) {
            if existing.value_from.is_some() {
                tracing::warn!(
                    "{}/{} container '{}': env var '{}' uses valueFrom — \
                     cannot patch a reference directly, skipping.",
                    workload_kind,
                    workload_name,
                    container_name,
                    key
                );
                continue;
            }
            originals.insert(key.clone(), existing.value.clone());
        } else {
            originals.insert(key.clone(), None);
        }

        if let Some(ev) = result.iter_mut().find(|e| &e.name == key) {
            ev.value = Some(new_val.clone());
            ev.value_from = None;
        } else {
            result.push(EnvVar {
                name: key.clone(),
                value: Some(new_val.clone()),
                value_from: None,
            });
        }
    }

    (result, originals)
}

fn restore_env(
    current_env: &[EnvVar],
    originals: &BTreeMap<String, Option<String>>,
) -> Vec<EnvVar> {
    let mut result: Vec<EnvVar> = current_env.to_vec();
    for (key, original_value) in originals {
        match original_value {
            Some(orig) => {
                if let Some(ev) = result.iter_mut().find(|e| &e.name == key) {
                    ev.value = Some(orig.clone());
                    ev.value_from = None;
                }
            }
            None => result.retain(|e| &e.name != key),
        }
    }
    result
}

fn env_to_json(env: &[EnvVar]) -> Vec<serde_json::Value> {
    env.iter().map(|e| json!({ "name": e.name, "value": e.value })).collect()
}
