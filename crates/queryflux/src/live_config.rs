//! Building and hot-reloading `LiveConfig`: the config generation every query runs against.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::registered_engines;
use anyhow::{Context, Result};
use queryflux_auth::{AllowAllAuthorization, NoneAuthProvider};
use queryflux_cluster_manager::cluster_state::ClusterState;
use queryflux_core::query::{ClusterGroupName, ClusterName, EngineType};
use queryflux_frontend::{access_control_guard::OpaAccessGuard, state::LiveConfig};
use queryflux_guardrails::GuardChain;
use queryflux_metrics::MetricsStore;
use queryflux_persistence::{AdminStore, BackendStore};
use queryflux_routing::{chain::RouterChain, RouterTrait};

use crate::guards::{
    apply_stored_access_control, build_auth_provider, build_authorization,
    build_guard_chains_from_db_value, load_guard_script_bodies, operators_from_auth,
    validate_group_translation_scripts,
};

pub(crate) type GroupStatesMap = HashMap<
    ClusterGroupName,
    (
        Vec<Arc<ClusterState>>,
        Arc<dyn queryflux_cluster_manager::strategy::ClusterSelectionStrategy>,
    ),
>;

/// Parses the `variants` JSONB column into `ClusterVariant`s. Shared by every
/// startup/reload path that expands a persisted cluster record into runtime
/// clusters, so the parsing behavior (and its `unwrap_or_default` on malformed
/// JSON) stays identical everywhere instead of drifting across call sites.
pub(crate) fn parse_cluster_variants(
    variants_json: &serde_json::Value,
) -> Vec<queryflux_core::config::ClusterVariant> {
    serde_json::from_value(variants_json.clone()).unwrap_or_default()
}

/// Extracts the base `healthCheckQuery` / `reconcileQuery` overrides from a
/// cluster's persisted `config` JSONB blob, ahead of variant expansion (which
/// applies driver defaults and `{{sub_resource}}` substitution on top). Shared
/// by every call site that needs these two fields before calling
/// `expand_cluster_variants`.
pub(crate) fn extract_base_probe_queries(
    config_json: &serde_json::Value,
) -> (Option<String>, Option<String>) {
    let health_check_query = config_json
        .get("healthCheckQuery")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let reconcile_query = config_json
        .get("reconcileQuery")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (health_check_query, reconcile_query)
}

/// Convert optional Postgres `BIGINT` (`max_running_queries`) to `Option<u64>`.
/// Negative values fail fast (invalid row).
pub(crate) fn max_running_queries_u64_from_db(
    cluster: &str,
    v: Option<i64>,
) -> Result<Option<u64>> {
    match v {
        None => Ok(None),
        Some(n) => u64::try_from(n).map(Some).map_err(|_| {
            anyhow::anyhow!(
                "cluster '{cluster}': max_running_queries must be non-negative (got {n})"
            )
        }),
    }
}

/// Holds adapter instances between DB reloads. Adapters are recreated when the
/// reload fingerprint changes (`engine_key` + config JSON), so engine switches and
/// endpoint/credential updates rebuild adapters.
#[derive(Clone)]
pub(crate) struct AdapterReloadCache {
    pub(crate) adapters: HashMap<String, queryflux_engine_adapters::AdapterKind>,
    pub(crate) config_json: HashMap<String, String>,
    /// Previous-generation cluster states keyed by (group, cluster).
    /// Preserved across reloads so that health status and running-query counters
    /// are not reset to their initial values every time the config is reloaded.
    pub(crate) cluster_states: HashMap<(String, String), Arc<ClusterState>>,
    /// Last-known routing from DB (or YAML at startup). Used when `load_routing_config` returns
    /// `Ok(None)` so periodic reload does not wipe routing.
    pub(crate) routing_fallback: String,
    pub(crate) routers_cfg: Vec<queryflux_core::config::RouterConfig>,
    /// Last-successfully-built cluster-selection strategy per group, keyed by group name.
    /// Consulted when a reload's `strategy_from_config` fails (e.g. a `pythonScript` group's
    /// `scriptFile` becomes transiently unreadable) so that group keeps its real strategy
    /// (weighting, engine affinity, …) instead of silently degrading to round robin. Only
    /// updated on a successful build, so it always reflects the last *good* strategy, not
    /// whatever fallback got substituted on a prior failed reload.
    pub(crate) strategies:
        HashMap<String, Arc<dyn queryflux_cluster_manager::strategy::ClusterSelectionStrategy>>,
}

pub(crate) fn health_targets_from_groups(
    group_states: &GroupStatesMap,
    adapters: &HashMap<String, queryflux_engine_adapters::AdapterKind>,
) -> Vec<(queryflux_engine_adapters::AdapterKind, Arc<ClusterState>)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (states, _) in group_states.values() {
        for state in states {
            let name = state.cluster_name.0.clone();
            // The same backend may be a member of several groups, each with an
            // independent breaker that needs its own half-open probe.
            if seen.insert((state.group_name.0.clone(), name.clone())) {
                if let Some(adapter) = adapters.get(&name) {
                    out.push((adapter.clone(), state.clone()));
                }
            }
        }
    }
    out
}

/// Validate referential integrity of a config that is about to go live.
///
/// Returns a list of human-readable issue strings (empty = valid). Callers should
/// treat any non-empty return as a fatal config error and keep the previous LiveConfig.
///
/// Checks:
///  - `routing_fallback` names a group that exists in `group_members`.
///  - Every static `target_group` reference in `routers_cfg` names a group in `group_members`.
///    (PythonScript routers are skipped — their target group is computed at runtime.)
///  - Every cluster name listed in `group_members` has a built adapter in `adapters`.
pub(crate) fn validate_live_config_refs(
    routers_cfg: &[queryflux_core::config::RouterConfig],
    routing_fallback: &str,
    group_members: &HashMap<String, Vec<String>>,
    adapters: &HashMap<String, queryflux_engine_adapters::AdapterKind>,
) -> Vec<String> {
    use queryflux_core::config::RouterConfig;

    let mut issues: Vec<String> = Vec::new();

    if !group_members.contains_key(routing_fallback) {
        issues.push(format!(
            "routing_fallback references unknown group '{routing_fallback}'"
        ));
    }

    for router in routers_cfg {
        let mut refs: Vec<&str> = Vec::new();
        match router {
            RouterConfig::ProtocolBased {
                trino_http,
                postgres_wire,
                mysql_wire,
                clickhouse_http,
                flight_sql,
                snowflake_http,
                snowflake_sql_api,
                mcp,
            } => {
                let opts: [Option<&str>; 8] = [
                    trino_http.as_deref(),
                    postgres_wire.as_deref(),
                    mysql_wire.as_deref(),
                    clickhouse_http.as_deref(),
                    flight_sql.as_deref(),
                    snowflake_http.as_deref(),
                    snowflake_sql_api.as_deref(),
                    mcp.as_deref(),
                ];
                refs.extend(opts.into_iter().flatten());
            }
            RouterConfig::Header {
                header_value_to_group,
                ..
            } => {
                refs.extend(header_value_to_group.values().map(String::as_str));
            }
            RouterConfig::UserGroup { user_to_group } => {
                refs.extend(user_to_group.values().map(String::as_str));
            }
            RouterConfig::QueryRegex { rules } => {
                for rule in rules {
                    if matches!(rule.action, queryflux_core::config::RegexRouteAction::Route) {
                        if let Some(group) = rule.target_group.as_deref() {
                            refs.push(group);
                        } else {
                            issues.push("queryRegex route rule requires targetGroup".to_string());
                        }
                    }
                }
            }
            RouterConfig::Tags { rules } => {
                refs.extend(rules.iter().map(|r| r.target_group.as_str()));
            }
            RouterConfig::Compound { target_group, .. } => {
                refs.push(target_group.as_str());
            }
            RouterConfig::PythonScript { .. } => {}
        }
        for group in refs {
            if !group_members.contains_key(group) {
                issues.push(format!("router references unknown group '{group}'"));
            }
        }
    }

    for (group, members) in group_members {
        for member in members {
            if !adapters.contains_key(member.as_str()) {
                issues.push(format!(
                    "group '{group}' member '{member}' has no built adapter"
                ));
            }
        }
    }

    issues
}

/// Where a cluster definition came from.
///
/// `Persisted` is the engine-specific JSON stored in Postgres (and, later, carried by the
/// worker config snapshot). `Yaml` keeps the typed `ClusterConfig` from the YAML file,
/// because converting it to JSON is lossy: `UpsertClusterConfig::from_core` drops
/// key-pair private keys, `driver` and `maxWaitSecs`. YAML clusters therefore build their
/// adapter from `ClusterConfig` exactly as before and are not variant-expanded.
#[derive(Clone)]
pub(crate) enum ClusterSource {
    Persisted {
        engine_key: String,
        max_running_queries: Option<i64>,
        config: serde_json::Value,
        variants: serde_json::Value,
    },
    Yaml(Box<queryflux_core::config::ClusterConfig>),
}

/// One cluster definition, in the plain form every config source produces.
#[derive(Clone)]
pub(crate) struct ClusterSpec {
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) source: ClusterSource,
}

impl ClusterSpec {
    pub(crate) fn from_record(
        r: &queryflux_persistence::cluster_config::ClusterConfigRecord,
    ) -> Self {
        Self {
            name: r.name.clone(),
            enabled: r.enabled,
            source: ClusterSource::Persisted {
                engine_key: r.engine_key.clone(),
                max_running_queries: r.max_running_queries,
                config: r.config.clone(),
                variants: r.variants.clone(),
            },
        }
    }

    pub(crate) fn from_yaml(name: &str, cfg: &queryflux_core::config::ClusterConfig) -> Self {
        Self {
            name: name.to_string(),
            enabled: cfg.enabled,
            source: ClusterSource::Yaml(Box::new(cfg.clone())),
        }
    }
}

/// Everything `compile_live_config` needs, as plain values: no database handles and no
/// persistence record types. YAML startup, Postgres startup and Postgres reload all
/// produce this; the worker config snapshot will too.
#[derive(Clone, Default)]
pub(crate) struct LiveConfigInputs {
    pub(crate) clusters: Vec<ClusterSpec>,
    pub(crate) groups: HashMap<String, queryflux_core::config::ClusterGroupConfig>,
    pub(crate) routers: Vec<queryflux_core::config::RouterConfig>,
    pub(crate) routing_fallback: String,
    pub(crate) group_translation_scripts: HashMap<String, Vec<String>>,
}

impl LiveConfigInputs {
    /// Inputs from Postgres rows. Group rows that fail to convert reject the whole load.
    pub(crate) fn from_records(
        clusters: &[queryflux_persistence::cluster_config::ClusterConfigRecord],
        groups: HashMap<String, queryflux_core::config::ClusterGroupConfig>,
        routers: Vec<queryflux_core::config::RouterConfig>,
        routing_fallback: String,
        group_translation_scripts: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            clusters: clusters.iter().map(ClusterSpec::from_record).collect(),
            groups,
            routers,
            routing_fallback,
            group_translation_scripts,
        }
    }
}

/// Postgres row ids, used only for `query_history` foreign keys on `ClusterState`.
/// Empty for YAML-only startup (and for workers).
#[derive(Clone, Default)]
pub(crate) struct ConfigIds {
    pub(crate) clusters: HashMap<String, i64>,
    pub(crate) groups: HashMap<String, i64>,
}

impl ConfigIds {
    pub(crate) fn from_records(
        clusters: &[queryflux_persistence::cluster_config::ClusterConfigRecord],
        groups: &[queryflux_persistence::cluster_config::ClusterGroupConfigRecord],
    ) -> Self {
        Self {
            clusters: clusters.iter().map(|r| (r.name.clone(), r.id)).collect(),
            groups: groups.iter().map(|r| (r.name.clone(), r.id)).collect(),
        }
    }
}

/// How `compile_live_config` treats a part that fails to build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompileMode {
    /// Startup: an unknown group member, a strategy that fails to build or an unreadable
    /// routing script rejects the whole config.
    Strict,
    /// Hot reload: log and degrade (skip the member, keep the group's previous strategy,
    /// skip the router) so one bad row doesn't block every other change.
    Lenient,
}

/// How to build one runtime cluster's adapter.
enum AdapterRecipe {
    Json {
        engine_key: String,
        config: serde_json::Value,
    },
    Yaml(Box<queryflux_core::config::ClusterConfig>),
}

/// One runtime cluster: a spec, or one expanded variant of a persisted spec.
struct RuntimeCluster {
    name: String,
    /// The spec it came from (differs from `name` for variants).
    parent: String,
    enabled: bool,
    /// `None` when the engine key does not parse; the cluster then gets no adapter.
    engine_type: Option<EngineType>,
    endpoint: Option<String>,
    /// Cluster-level concurrency override; falls back to the group's limit.
    max_running_queries: Option<u64>,
    /// Adapter cache key: rebuild when this changes.
    fingerprint: String,
    recipe: AdapterRecipe,
    /// `None` when the engine key does not parse (excluded from `cluster_configs`).
    cluster_config: Option<queryflux_core::config::ClusterConfig>,
}

/// Expand specs into runtime clusters (variants become their own clusters).
fn runtime_clusters(specs: &[ClusterSpec]) -> Result<Vec<RuntimeCluster>> {
    use queryflux_core::config::apply_default_probe_queries;
    use queryflux_core::engine_registry::{
        cluster_config_from_persisted_json, json_str, parse_auth_from_config_json,
        parse_engine_key, parse_query_auth_from_config_json,
    };

    let mut out = Vec::new();
    for spec in specs {
        match &spec.source {
            ClusterSource::Yaml(cfg) => {
                let engine_key = cfg
                    .engine
                    .as_ref()
                    .map(queryflux_core::engine_registry::engine_key)
                    .unwrap_or("");
                out.push(RuntimeCluster {
                    name: spec.name.clone(),
                    parent: spec.name.clone(),
                    enabled: spec.enabled,
                    engine_type: cfg.engine.as_ref().map(EngineType::from),
                    endpoint: cfg.endpoint.clone(),
                    max_running_queries: cfg.max_running_queries,
                    fingerprint: serde_json::to_string(&(engine_key, cfg.as_ref()))
                        .unwrap_or_default(),
                    recipe: AdapterRecipe::Yaml(cfg.clone()),
                    cluster_config: Some(cfg.as_ref().clone()),
                });
            }
            ClusterSource::Persisted {
                engine_key,
                max_running_queries,
                config,
                variants,
            } => {
                let max_running =
                    max_running_queries_u64_from_db(&spec.name, *max_running_queries)?;
                let engine = match parse_engine_key(engine_key) {
                    Ok(e) => Some(e),
                    Err(err) => {
                        tracing::warn!(cluster = %spec.name, "skipping cluster: {err}");
                        None
                    }
                };
                // Only parsed when the engine key is valid, as before.
                let base_cfg = match &engine {
                    Some(engine) => {
                        let query_auth =
                            parse_query_auth_from_config_json(config).map_err(|e| {
                                anyhow::anyhow!(
                                    "cluster '{}': invalid queryAuth in JSONB: {e}",
                                    spec.name
                                )
                            })?;
                        let auth = match parse_auth_from_config_json(config) {
                            Ok(a) => a,
                            Err(e) => {
                                tracing::warn!(
                                    cluster = %spec.name,
                                    "invalid auth in cluster config JSON: {e}"
                                );
                                None
                            }
                        };
                        Some(cluster_config_from_persisted_json(
                            engine.clone(),
                            spec.enabled,
                            max_running,
                            config,
                            auth,
                            query_auth,
                        ))
                    }
                    None => None,
                };
                let engine_type = engine.as_ref().map(EngineType::from);

                let parsed_variants = parse_cluster_variants(variants);
                if parsed_variants.is_empty() {
                    let cluster_config = base_cfg.map(|mut c| {
                        apply_default_probe_queries(&mut c, engine_key, config);
                        c
                    });
                    out.push(RuntimeCluster {
                        name: spec.name.clone(),
                        parent: spec.name.clone(),
                        enabled: spec.enabled,
                        engine_type,
                        endpoint: json_str(config, "endpoint"),
                        max_running_queries: max_running,
                        fingerprint: serde_json::to_string(&(engine_key.as_str(), config))
                            .unwrap_or_default(),
                        recipe: AdapterRecipe::Json {
                            engine_key: engine_key.clone(),
                            config: config.clone(),
                        },
                        cluster_config,
                    });
                    continue;
                }

                let (health_check_query, reconcile_query) = extract_base_probe_queries(config);
                let expanded = match queryflux_core::config::expand_cluster_variants(
                    &spec.name,
                    config,
                    engine_key,
                    &parsed_variants,
                    health_check_query.as_deref(),
                    reconcile_query.as_deref(),
                ) {
                    Ok(expanded) => expanded,
                    Err(err) => {
                        tracing::error!(cluster = %spec.name, error = %err, "variant expansion failed — cluster omitted");
                        continue;
                    }
                };
                for exp in expanded {
                    let cluster_config = base_cfg.as_ref().map(|base| {
                        let mut c = base.clone();
                        c.max_running_queries = exp.max_running_queries.or(max_running);
                        c.health_check_query = exp.health_check_query.clone();
                        c.reconcile_query = exp.reconcile_query.clone();
                        c
                    });
                    out.push(RuntimeCluster {
                        name: exp.expanded_name.clone(),
                        parent: spec.name.clone(),
                        enabled: spec.enabled,
                        engine_type: engine_type.clone(),
                        endpoint: json_str(&exp.merged_config, "endpoint"),
                        max_running_queries: exp.max_running_queries.or(max_running),
                        fingerprint: serde_json::to_string(&(
                            engine_key.as_str(),
                            &exp.merged_config,
                        ))
                        .unwrap_or_default(),
                        recipe: AdapterRecipe::Json {
                            engine_key: engine_key.clone(),
                            config: exp.merged_config,
                        },
                        cluster_config,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// The `ClusterConfig` per runtime cluster, as `LiveConfig::cluster_configs` exposes them
/// (credential resolution, validation and startup warnings read these).
pub(crate) fn cluster_configs_from_specs(
    specs: &[ClusterSpec],
) -> Result<HashMap<String, queryflux_core::config::ClusterConfig>> {
    Ok(runtime_clusters(specs)?
        .into_iter()
        .filter_map(|rc| rc.cluster_config.map(|c| (rc.name, c)))
        .collect())
}

async fn build_adapter(
    name: &str,
    recipe: &AdapterRecipe,
) -> Result<queryflux_engine_adapters::AdapterKind> {
    let cluster_name = ClusterName(name.to_string());
    let placeholder_group = ClusterGroupName("_".to_string());
    match recipe {
        AdapterRecipe::Json { engine_key, config } => {
            registered_engines::build_adapter_from_record(
                cluster_name,
                placeholder_group,
                engine_key,
                config,
            )
            .await
        }
        AdapterRecipe::Yaml(cfg) => {
            registered_engines::build_adapter(cluster_name, placeholder_group, cfg, name).await
        }
    }
}

/// Compile plain config inputs into a `LiveConfig`.
///
/// `cache` carries state from the previous generation: adapters are reused while a
/// cluster's fingerprint is unchanged, cluster load counters are shared, health and
/// (for unchanged clusters) breaker state carry over, and each group's last good
/// strategy is kept. Settings that `LiveConfig` gets from outside this function
/// (auth, authorization, guard chains, access control, catalog) are set to
/// placeholders; callers fill them in.
pub(crate) async fn compile_live_config(
    inputs: &LiveConfigInputs,
    ids: &ConfigIds,
    cache: &mut AdapterReloadCache,
    mode: CompileMode,
) -> Result<LiveConfig> {
    use queryflux_cluster_manager::{
        cluster_state::ClusterState,
        simple::SimpleClusterGroupManager,
        strategy::{strategy_from_config, RoundRobinStrategy},
    };
    use queryflux_core::tags::QueryTags;

    let clusters = runtime_clusters(&inputs.clusters)?;
    let by_name: HashMap<&str, &RuntimeCluster> =
        clusters.iter().map(|c| (c.name.as_str(), c)).collect();

    let prev_config_json = cache.config_json.clone();

    // Build adapters, reusing them while the fingerprint is unchanged.
    for rc in &clusters {
        if !rc.enabled || rc.engine_type.is_none() {
            cache.adapters.remove(rc.name.as_str());
            cache.config_json.remove(rc.name.as_str());
            continue;
        }
        let reuse = cache.adapters.contains_key(rc.name.as_str())
            && prev_config_json.get(rc.name.as_str()).map(String::as_str)
                == Some(rc.fingerprint.as_str());
        if reuse {
            continue;
        }
        cache.adapters.remove(rc.name.as_str());
        cache.config_json.remove(rc.name.as_str());
        match build_adapter(&rc.name, &rc.recipe).await {
            Ok(adapter) => {
                cache.adapters.insert(rc.name.clone(), adapter);
                cache
                    .config_json
                    .insert(rc.name.clone(), rc.fingerprint.clone());
            }
            Err(e) => {
                tracing::error!(
                    cluster = %rc.name,
                    error = %e,
                    "Failed to build engine adapter — cluster omitted from routing until config or environment is fixed"
                );
            }
        }
    }
    cache
        .adapters
        .retain(|name, _| by_name.contains_key(name.as_str()));
    cache
        .config_json
        .retain(|name, _| by_name.contains_key(name.as_str()));

    // Build group states.
    let mut group_states: GroupStatesMap = HashMap::new();
    let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_order: Vec<String> = Vec::new();

    for (group_name, group_config) in &inputs.groups {
        if !group_config.enabled {
            continue;
        }
        if let Some(breaker) = &group_config.circuit_breaker {
            breaker
                .validate()
                .map_err(|e| anyhow::anyhow!("group '{group_name}': {e}"))?;
        }
        let group_key = ClusterGroupName(group_name.clone());
        let mut states: Vec<Arc<ClusterState>> = Vec::new();
        let mut seen_members: HashSet<&str> = HashSet::new();

        for member_name in &group_config.members {
            if !seen_members.insert(member_name.as_str()) {
                tracing::warn!(
                    group = %group_name,
                    cluster = %member_name,
                    "Duplicate cluster in group members — ignoring extra entry"
                );
                continue;
            }
            let Some(rc) = by_name.get(member_name.as_str()) else {
                if mode == CompileMode::Strict {
                    anyhow::bail!(
                        "group '{group_name}' references unknown cluster '{member_name}'"
                    );
                }
                tracing::warn!(group = %group_name, cluster = %member_name, "Group references unknown cluster");
                continue;
            };
            if !cache.adapters.contains_key(member_name.as_str()) {
                tracing::warn!(
                    group = %group_name,
                    cluster = %member_name,
                    "Skipping cluster in group: disabled, or its adapter failed to build"
                );
                continue;
            }
            let Some(engine_type) = rc.engine_type.clone() else {
                continue;
            };
            let max_q = rc
                .max_running_queries
                .unwrap_or(group_config.max_running_queries);
            let cluster_cid = ids
                .clusters
                .get(member_name.as_str())
                .or_else(|| ids.clusters.get(rc.parent.as_str()))
                .copied();
            let group_cid = ids.groups.get(group_name.as_str()).copied();

            let config_unchanged = prev_config_json
                .get(member_name.as_str())
                .map(String::as_str)
                == Some(rc.fingerprint.as_str());
            let previous = cache
                .cluster_states
                .get(&(group_name.clone(), member_name.clone()));
            let previous_unchanged = if config_unchanged {
                previous.map(Arc::as_ref)
            } else {
                None
            };
            // Load counters are shared (not copied) with the previous generation, whether or not
            // the config changed. Queries admitted before this reload are still running on this
            // member and release through either generation: sync dispatch through the manager
            // that admitted them (a copied count would leak, #299), async terminals through the
            // current one (a fresh counter would miss them and over-admit, #301).
            let state = Arc::new(
                ClusterState::new(
                    ClusterName(member_name.clone()),
                    group_key.clone(),
                    cluster_cid,
                    group_cid,
                    engine_type,
                    rc.endpoint.clone(),
                    max_q,
                    rc.enabled,
                )
                .with_circuit_breaker(group_config.circuit_breaker.clone(), previous_unchanged)
                .with_shared_load_counters(previous.map(Arc::as_ref)),
            );
            if let Some(prev) = previous {
                state.set_healthy(prev.is_healthy());
            }
            states.push(state);
        }

        let strategy = match strategy_from_config(group_config.strategy.as_ref()) {
            Ok(s) => {
                cache.strategies.insert(group_name.clone(), s.clone());
                s
            }
            Err(e) if mode == CompileMode::Strict => {
                return Err(anyhow::Error::from(e)
                    .context(format!("group '{group_name}' cluster-selection strategy")));
            }
            Err(e) => {
                if let Some(prev) = cache.strategies.get(group_name.as_str()) {
                    tracing::warn!(
                        group = %group_name,
                        error = %e,
                        "Failed to build cluster-selection strategy; keeping this group's previous strategy"
                    );
                    prev.clone()
                } else {
                    tracing::warn!(
                        group = %group_name,
                        error = %e,
                        "Failed to build cluster-selection strategy; no previous strategy cached, falling back to round robin"
                    );
                    Arc::new(RoundRobinStrategy::new())
                }
            }
        };
        group_members.insert(group_name.clone(), group_config.members.clone());
        group_order.push(group_name.clone());
        group_states.insert(group_key, (states, strategy));
    }
    group_order.sort();
    // Drop cached strategies for groups that no longer exist, so a deleted-then-recreated
    // group name can't inherit the old group's strategy if the new one's build ever fails.
    cache
        .strategies
        .retain(|name, _| inputs.groups.contains_key(name.as_str()));

    let health_check_targets = health_targets_from_groups(&group_states, &cache.adapters);
    let rebuilt_cluster_states = health_check_targets
        .iter()
        .map(|(_, s)| {
            (
                (s.group_name.0.clone(), s.cluster_name.0.clone()),
                s.clone(),
            )
        })
        .collect();
    let cluster_manager = Arc::new(SimpleClusterGroupManager::new(group_states));

    let cluster_configs: HashMap<String, queryflux_core::config::ClusterConfig> = clusters
        .iter()
        .filter_map(|rc| rc.cluster_config.clone().map(|c| (rc.name.clone(), c)))
        .collect();

    let router_chain = build_router_chain(&inputs.routers, &inputs.routing_fallback, mode)?;

    let group_default_tags: HashMap<String, QueryTags> = inputs
        .groups
        .iter()
        .filter(|(_, g)| !g.default_tags.is_empty())
        .map(|(name, g)| (name.clone(), g.default_tags.clone()))
        .collect();

    let group_max_queued_queries: HashMap<String, Option<u64>> = inputs
        .groups
        .iter()
        .filter(|(_, g)| g.max_queued_queries.is_some())
        .map(|(name, g)| (name.clone(), g.max_queued_queries))
        .collect();

    let group_capacity_wait_timeout_secs: HashMap<String, u64> = inputs
        .groups
        .iter()
        .map(|(name, g)| (name.clone(), g.capacity_wait_timeout_secs_or_default()))
        .collect();

    let group_cache_settings: HashMap<String, queryflux_core::config::GroupCacheConfig> = inputs
        .groups
        .iter()
        .filter_map(|(name, g)| {
            g.cache
                .as_ref()
                .filter(|c| c.enabled)
                .map(|c| (name.clone(), c.clone()))
        })
        .collect();

    // Referential integrity: routers must target groups that exist in this config, and
    // every declared group member must have a built adapter. A stale read (e.g. a group
    // deleted between the cluster read and the group read) would otherwise produce a live
    // config where dispatch returns NoClusterGroupAvailable with no explanation.
    let issues = validate_live_config_refs(
        &inputs.routers,
        &inputs.routing_fallback,
        &group_members,
        &cache.adapters,
    );
    if !issues.is_empty() {
        for issue in &issues {
            tracing::error!("Config validation: {issue}");
        }
        return Err(anyhow::anyhow!(
            "Config has {} referential integrity error(s)",
            issues.len()
        ));
    }

    // Build custom health/reconcile query maps from cluster configs.
    let mut custom_health_queries: HashMap<String, String> = HashMap::new();
    let mut custom_reconcile_queries: HashMap<String, String> = HashMap::new();
    for (name, cfg) in &cluster_configs {
        if let Some(q) = &cfg.health_check_query {
            custom_health_queries.insert(name.clone(), q.clone());
        }
        if let Some(q) = &cfg.reconcile_query {
            custom_reconcile_queries.insert(name.clone(), q.clone());
        }
    }

    cache.cluster_states = rebuilt_cluster_states;
    Ok(LiveConfig {
        router_chain,
        // Placeholders: callers fill these in (startup from YAML/DB settings, reload by
        // carrying forward the previous value or rebuilding from DB settings).
        guard_chain: None,
        group_guard_chains: HashMap::new(),
        access_control_guard: None,
        cluster_manager,
        adapters: cache.adapters.clone(),
        health_check_targets,
        custom_health_queries,
        custom_reconcile_queries,
        cluster_configs,
        group_members,
        group_order,
        group_translation_scripts: inputs.group_translation_scripts.clone(),
        group_default_tags,
        group_max_queued_queries,
        group_capacity_wait_timeout_secs,
        group_cache_settings,
        auth_provider: Arc::new(NoneAuthProvider::new(false)),
        authorization: Arc::new(AllowAllAuthorization::default()),
        catalog: Arc::new(queryflux_core::catalog::NullCatalogProvider),
    })
}

fn build_router_chain(
    routers_cfg: &[queryflux_core::config::RouterConfig],
    routing_fallback: &str,
    mode: CompileMode,
) -> Result<RouterChain> {
    use queryflux_core::config::RouterConfig;
    use queryflux_routing::implementations::{
        compound::CompoundRouter, header::HeaderRouter, protocol_based::ProtocolBasedRouter,
        python_script::PythonScriptRouter, query_regex::QueryRegexRouter, tags::TagsRouter,
        user_group::UserGroupRouter,
    };

    let fallback = ClusterGroupName(routing_fallback.to_string());
    let mut routers: Vec<Box<dyn RouterTrait>> = Vec::new();
    for router_cfg in routers_cfg {
        match router_cfg {
            RouterConfig::ProtocolBased {
                trino_http,
                postgres_wire,
                mysql_wire,
                clickhouse_http,
                flight_sql,
                snowflake_http,
                snowflake_sql_api,
                mcp,
            } => {
                routers.push(Box::new(ProtocolBasedRouter {
                    trino_http: trino_http.as_ref().map(|s| ClusterGroupName(s.clone())),
                    postgres_wire: postgres_wire.as_ref().map(|s| ClusterGroupName(s.clone())),
                    mysql_wire: mysql_wire.as_ref().map(|s| ClusterGroupName(s.clone())),
                    clickhouse_http: clickhouse_http
                        .as_ref()
                        .map(|s| ClusterGroupName(s.clone())),
                    flight_sql: flight_sql.as_ref().map(|s| ClusterGroupName(s.clone())),
                    snowflake_http: snowflake_http.as_ref().map(|s| ClusterGroupName(s.clone())),
                    snowflake_sql_api: snowflake_sql_api
                        .as_ref()
                        .map(|s| ClusterGroupName(s.clone())),
                    mcp: mcp.as_ref().map(|s| ClusterGroupName(s.clone())),
                }));
            }
            RouterConfig::Header {
                header_name,
                header_value_to_group,
            } => {
                let mapping = header_value_to_group
                    .iter()
                    .map(|(k, v)| (k.clone(), ClusterGroupName(v.clone())))
                    .collect();
                routers.push(Box::new(HeaderRouter::new(header_name.clone(), mapping)));
            }
            RouterConfig::UserGroup { user_to_group } => {
                let mapping = user_to_group
                    .iter()
                    .map(|(k, v)| (k.clone(), ClusterGroupName(v.clone())))
                    .collect();
                routers.push(Box::new(UserGroupRouter::new(mapping)));
            }
            RouterConfig::QueryRegex { rules } => {
                routers.push(Box::new(QueryRegexRouter::from_rules(rules.clone())));
            }
            RouterConfig::Tags { rules } => {
                routers.push(Box::new(TagsRouter::new(rules.clone())));
            }
            RouterConfig::PythonScript {
                script,
                script_file,
            } => {
                let router = match script_file {
                    Some(path) => match PythonScriptRouter::from_file(path) {
                        Ok(r) => r,
                        Err(e) if mode == CompileMode::Strict => {
                            return Err(anyhow::Error::from(e)
                                .context(format!("Failed to load routing script from {path}")));
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load routing script from {path}: {e}");
                            continue;
                        }
                    },
                    None => PythonScriptRouter::new(script.clone()),
                };
                routers.push(Box::new(router));
            }
            RouterConfig::Compound {
                combine,
                conditions,
                target_group,
            } => {
                routers.push(Box::new(CompoundRouter::new(
                    *combine,
                    conditions.clone(),
                    target_group.clone(),
                )));
            }
        }
    }
    Ok(RouterChain::new(routers, fallback))
}

/// Load cluster/group configs + routing config from Postgres and build a fresh `LiveConfig`.
/// Existing adapter instances are reused for clusters that haven't changed.
///
/// Cluster records are passed directly to `build_live_config` — no `to_core()` conversion.
/// Hot pieces carried over from the previous `LiveConfig` when their backing
/// rows are absent from the backend (never configured via admin) or fail to
/// parse. A reload must never revert auth to permissive defaults or drop
/// YAML-configured guard chains just because no row was ever written.
pub(crate) struct PreservedLive {
    pub(crate) auth_provider: Arc<dyn queryflux_auth::AuthProvider>,
    pub(crate) authorization: Arc<dyn queryflux_auth::AuthorizationChecker>,
    pub(crate) guard_chain: Option<Arc<GuardChain>>,
    pub(crate) group_guard_chains: HashMap<String, Arc<GuardChain>>,
    pub(crate) access_control_guard: Option<Arc<OpaAccessGuard>>,
    pub(crate) catalog: Arc<dyn queryflux_core::catalog::CatalogProvider>,
}

pub(crate) async fn reload_live_config(
    pg: &Arc<dyn BackendStore>,
    cache: &mut AdapterReloadCache,
    prev: &PreservedLive,
    metrics: &Arc<dyn MetricsStore>,
) -> Result<LiveConfig> {
    let cluster_records = pg
        .list_cluster_configs()
        .await
        .context("reload: list_cluster_configs")?;
    let group_records = pg
        .list_group_configs()
        .await
        .context("reload: list_group_configs")?;
    let ids = ConfigIds::from_records(&cluster_records, &group_records);
    let cluster_groups: std::collections::HashMap<
        String,
        queryflux_core::config::ClusterGroupConfig,
    > = group_records
        .into_iter()
        .map(|r| Ok((r.name.clone(), r.to_core().map_err(anyhow::Error::msg)?)))
        .collect::<Result<_>>()?;

    // Load routing from DB if present; otherwise keep last-known routing (startup YAML or previous DB load).
    let (routing_fallback, routers_cfg) = match pg.load_routing_config().await {
        Ok(Some(loaded)) => {
            let mut routers = Vec::new();
            for v in loaded.routers {
                match serde_json::from_value::<queryflux_core::config::RouterConfig>(v) {
                    Ok(r) => routers.push(r),
                    Err(e) => {
                        tracing::warn!(error = %e, "Reload: skipping invalid routing_rules row")
                    }
                }
            }
            cache.routing_fallback = loaded.routing_fallback.clone();
            cache.routers_cfg.clone_from(&routers);
            (loaded.routing_fallback, routers)
        }
        Ok(None) => (cache.routing_fallback.clone(), cache.routers_cfg.clone()),
        Err(e) => {
            return Err(anyhow::anyhow!("reload: load_routing_config: {e}"));
        }
    };

    let group_translation_scripts = pg
        .load_group_translation_bodies()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "reload: load_group_translation_bodies failed");
            HashMap::new()
        });
    let group_translation_scripts = validate_group_translation_scripts(group_translation_scripts);
    let guard_script_bodies = load_guard_script_bodies(Some(pg.as_ref() as &dyn AdminStore)).await;

    let inputs = LiveConfigInputs::from_records(
        &cluster_records,
        cluster_groups,
        routers_cfg,
        routing_fallback,
        group_translation_scripts,
    );
    let mut live = compile_live_config(&inputs, &ids, cache, CompileMode::Lenient).await?;

    // Carry forward the pieces build_live_config seeds with placeholders. The
    // DB reads below only *override* these on success — a missing row or a
    // parse failure keeps the previous (startup-YAML or last-good) values.
    live.auth_provider = prev.auth_provider.clone();
    live.authorization = prev.authorization.clone();
    live.guard_chain = prev.guard_chain.clone();
    live.group_guard_chains = prev.group_guard_chains.clone();
    // Startup already applied any stored `access_control_config` over the YAML; reload
    // re-reads it below and overrides on success (same contract as catalog / guardrails).
    live.access_control_guard = prev.access_control_guard.clone();
    live.catalog = prev.catalog.clone();

    // Guardrails from DB (UI-managed) override carried-over chains. An admin
    // "clear" still writes an empty `global` row, so Ok(None) can only mean
    // "never configured via admin" — keep the previous (e.g. YAML) chains.
    match pg.get_proxy_setting("guardrails_config").await {
        Ok(Some(v)) => {
            let (global, groups) = build_guard_chains_from_db_value(&v, &guard_script_bodies);
            live.guard_chain = global;
            live.group_guard_chains = groups;
        }
        Ok(None) => {}
        Err(e) => {
            metrics.on_config_reload_failure("guard_reload");
            tracing::warn!("Reload: guardrails_config read failed; keeping previous chains: {e}")
        }
    }

    // Rebuild auth/authz from persisted security config. On a missing row or
    // any parse/build failure keep the carried-over providers — a reload must
    // never fall back to permissive defaults.
    match pg.get_proxy_setting("security_config").await {
        Ok(Some(v)) if queryflux_core::security_setting::is_blank_security_setting(&v) => {}
        Ok(Some(v)) => {
            let (auth_cfg, authz_cfg) =
                queryflux_core::security_setting::parse_security_setting(&v);
            match auth_cfg.as_ref().map(|cfg| build_auth_provider(cfg)) {
                Some(Ok(provider)) => live.auth_provider = provider,
                Some(Err(e)) => {
                    metrics.on_config_reload_failure("auth_rebuild");
                    tracing::warn!("Reload: failed to rebuild auth provider; keeping previous: {e}")
                }
                None => {
                    metrics.on_config_reload_failure("auth_rebuild");
                    tracing::warn!(
                        "Reload: security_config has no recognizable auth section; keeping previous"
                    );
                }
            }
            match auth_cfg {
                Some(auth) => {
                    let operators = operators_from_auth(&auth);
                    match authz_cfg.map(|cfg| build_authorization(&cfg, &inputs.groups, operators))
                    {
                        Some(Ok(checker)) => live.authorization = checker,
                        Some(Err(e)) => {
                            metrics.on_config_reload_failure("authz_rebuild");
                            tracing::warn!(
                                "Reload: failed to rebuild authorization; keeping previous: {e}"
                            )
                        }
                        None => {
                            metrics.on_config_reload_failure("authz_rebuild");
                            tracing::warn!(
                            "Reload: security_config has no recognizable authorization section; keeping previous"
                        );
                        }
                    }
                }
                None if authz_cfg.is_some() => {
                    metrics.on_config_reload_failure("authz_rebuild");
                    tracing::warn!(
                        "Reload: security_config has authorization but no auth section; keeping previous authorization (operator policy unchanged)"
                    );
                }
                None => {}
            }
        }
        Ok(None) => {}
        Err(e) => {
            metrics.on_config_reload_failure("auth_rebuild");
            tracing::warn!("Reload: security_config read failed; keeping previous auth: {e}")
        }
    }

    // Rebuild the catalog provider from persisted config. A missing row means
    // "never configured via admin" (keep the carried-over, e.g. startup-YAML,
    // provider); a parse failure keeps the previous provider too — a reload must
    // never silently fall back to `NullCatalogProvider` and quietly stop
    // discovering schema for already-working translation.
    match pg.get_proxy_setting("catalog_config").await {
        Ok(Some(v)) => {
            match serde_json::from_value::<queryflux_core::config::CatalogProviderConfig>(v) {
                Ok(cfg) => live.catalog = queryflux_catalog::build_catalog_provider(&cfg).await,
                Err(e) => {
                    metrics.on_config_reload_failure("catalog_reload");
                    tracing::warn!(
                        "Reload: catalog_config parse failed; keeping previous catalog: {e}"
                    )
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            metrics.on_config_reload_failure("catalog_reload");
            tracing::warn!("Reload: catalog_config read failed; keeping previous catalog: {e}")
        }
    }

    match pg.get_proxy_setting("access_control_config").await {
        Ok(Some(v)) => match apply_stored_access_control(&v) {
            Ok(guard) => live.access_control_guard = guard,
            Err(e) => {
                metrics.on_config_reload_failure("access_control_reload");
                tracing::warn!(
                    "Reload: access_control_config parse/build failed; keeping previous: {e}"
                )
            }
        },
        Ok(None) => {}
        Err(e) => {
            metrics.on_config_reload_failure("access_control_reload");
            tracing::warn!(
                "Reload: access_control_config read failed; keeping previous access control: {e}"
            )
        }
    }

    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use queryflux_core::config::{ClusterConfig, ClusterGroupConfig};

    fn group(mut json: serde_json::Value) -> ClusterGroupConfig {
        if json.get("maxRunningQueries").is_none() {
            json["maxRunningQueries"] = serde_json::json!(10);
        }
        serde_json::from_value(json).expect("valid group fixture")
    }

    fn empty_cache() -> AdapterReloadCache {
        AdapterReloadCache {
            adapters: HashMap::new(),
            config_json: HashMap::new(),
            cluster_states: HashMap::new(),
            routing_fallback: String::new(),
            routers_cfg: Vec::new(),
            strategies: HashMap::new(),
        }
    }

    fn persisted(
        name: &str,
        config: serde_json::Value,
        variants: serde_json::Value,
    ) -> ClusterSpec {
        ClusterSpec {
            name: name.to_string(),
            enabled: true,
            source: ClusterSource::Persisted {
                engine_key: "duckDb".to_string(),
                max_running_queries: Some(3),
                config,
                variants,
            },
        }
    }

    fn inputs(
        clusters: Vec<ClusterSpec>,
        groups: Vec<(&str, ClusterGroupConfig)>,
    ) -> LiveConfigInputs {
        LiveConfigInputs {
            clusters,
            groups: groups
                .into_iter()
                .map(|(n, g)| (n.to_string(), g))
                .collect(),
            routing_fallback: "g".to_string(),
            ..LiveConfigInputs::default()
        }
    }

    async fn compile(
        i: &LiveConfigInputs,
        ids: &ConfigIds,
        mode: CompileMode,
    ) -> Result<LiveConfig> {
        compile_live_config(i, ids, &mut empty_cache(), mode).await
    }

    /// A YAML cluster and the same cluster as Postgres stores it (via the YAML seed
    /// conversion) compile to the same groups, members, limits and adapters.
    #[tokio::test]
    async fn yaml_and_persisted_specs_compile_to_the_same_live_config() {
        let yaml: ClusterConfig = serde_json::from_value(serde_json::json!({
            "engine": "duckDb",
            "maxRunningQueries": 3
        }))
        .expect("valid cluster fixture");
        let upsert = queryflux_persistence::cluster_config::UpsertClusterConfig::from_core(&yaml)
            .expect("serializes")
            .expect("has an engine");
        let as_persisted = ClusterSpec {
            name: "duck".to_string(),
            enabled: upsert.enabled,
            source: ClusterSource::Persisted {
                engine_key: upsert.engine_key,
                max_running_queries: upsert.max_running_queries,
                config: upsert.config,
                variants: upsert.variants,
            },
        };
        let g = || group(serde_json::json!({ "members": ["duck"], "maxRunningQueries": 10 }));

        let from_yaml = compile(
            &inputs(
                vec![ClusterSpec::from_yaml("duck", &yaml)],
                vec![("g", g())],
            ),
            &ConfigIds::default(),
            CompileMode::Strict,
        )
        .await
        .expect("YAML compiles");
        let from_db = compile(
            &inputs(vec![as_persisted], vec![("g", g())]),
            &ConfigIds::default(),
            CompileMode::Strict,
        )
        .await
        .expect("persisted compiles");

        for live in [&from_yaml, &from_db] {
            assert_eq!(live.group_members.get("g"), Some(&vec!["duck".to_string()]));
            assert!(live.adapters.contains_key("duck"));
            let states = live.cluster_manager.all_cluster_states().await.unwrap();
            assert_eq!(states.len(), 1);
            assert_eq!(states[0].max_running_queries, 3);
            assert_eq!(
                live.cluster_configs
                    .get("duck")
                    .and_then(|c| c.max_running_queries),
                Some(3)
            );
        }
    }

    #[tokio::test]
    async fn strict_mode_rejects_an_unknown_group_member() {
        let i = inputs(
            vec![],
            vec![("g", group(serde_json::json!({ "members": ["missing"] })))],
        );
        let err = compile(&i, &ConfigIds::default(), CompileMode::Strict)
            .await
            .err()
            .expect("strict rejects");
        assert!(
            err.to_string()
                .contains("references unknown cluster 'missing'"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn strict_mode_rejects_a_strategy_that_fails_to_build_lenient_falls_back() {
        let i = inputs(
            vec![persisted(
                "duck",
                serde_json::json!({}),
                serde_json::json!([]),
            )],
            vec![(
                "g",
                group(serde_json::json!({
                    "members": ["duck"],
                    "strategy": { "type": "pythonScript" }
                })),
            )],
        );
        assert!(compile(&i, &ConfigIds::default(), CompileMode::Strict)
            .await
            .is_err());
        assert!(compile(&i, &ConfigIds::default(), CompileMode::Lenient)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn strict_mode_rejects_an_unreadable_routing_script_lenient_skips_it() {
        let mut i = inputs(
            vec![persisted(
                "duck",
                serde_json::json!({}),
                serde_json::json!([]),
            )],
            vec![("g", group(serde_json::json!({ "members": ["duck"] })))],
        );
        i.routers = vec![serde_json::from_value(serde_json::json!({
            "type": "pythonScript",
            "script": "",
            "scriptFile": "/nonexistent/queryflux-router.py"
        }))
        .expect("valid router fixture")];
        let err = compile(&i, &ConfigIds::default(), CompileMode::Strict)
            .await
            .err()
            .expect("strict rejects");
        assert!(
            err.to_string().contains("Failed to load routing script"),
            "{err}"
        );
        assert!(compile(&i, &ConfigIds::default(), CompileMode::Lenient)
            .await
            .is_ok());
    }

    /// Variant clusters have no row of their own; they get their parent's id.
    #[tokio::test]
    async fn variant_clusters_get_their_parents_database_id() {
        let i = inputs(
            vec![persisted(
                "duck",
                serde_json::json!({}),
                serde_json::json!([{ "name": "a" }]),
            )],
            vec![("g", group(serde_json::json!({ "members": ["duck::a"] })))],
        );
        let ids = ConfigIds {
            clusters: HashMap::from([("duck".to_string(), 7)]),
            groups: HashMap::from([("g".to_string(), 9)]),
        };
        let live = compile(&i, &ids, CompileMode::Strict)
            .await
            .expect("compiles");
        let (_, state) = live
            .health_check_targets
            .iter()
            .find(|(_, s)| s.cluster_name.0 == "duck::a")
            .expect("variant is a group member");
        assert_eq!(state.cluster_config_id, Some(7));
        assert_eq!(state.cluster_group_config_id, Some(9));
    }
}
