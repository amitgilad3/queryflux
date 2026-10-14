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

/// Per expanded variant: merged JSON config, optional max concurrency, optional probe SQL.
pub(crate) type ExpandedVariantConfig = (
    serde_json::Value,
    Option<u64>,
    Option<String>,
    Option<String>,
);

/// Build a `LiveConfig` from DB cluster records, group maps, and router chain components.
///
/// This is the DB load path: adapters are built directly from the JSONB config blob
/// in each `ClusterConfigRecord`, bypassing the `ClusterConfig` god struct.
///
/// `cache` holds adapter instances from the previous generation. Adapters are reused
/// only when the fingerprint of `engine_key` + JSONB config matches the previous reload;
/// otherwise they are rebuilt (e.g. engine switch, endpoint, or password changed).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_live_config(
    cluster_records: &[queryflux_persistence::cluster_config::ClusterConfigRecord],
    cluster_groups: &std::collections::HashMap<String, queryflux_core::config::ClusterGroupConfig>,
    cluster_ids_by_name: &HashMap<String, i64>,
    group_ids_by_name: &HashMap<String, i64>,
    routers_cfg: &[queryflux_core::config::RouterConfig],
    routing_fallback: &str,
    group_translation_scripts: HashMap<String, Vec<String>>,
    cache: &mut AdapterReloadCache,
) -> Result<LiveConfig> {
    use queryflux_cluster_manager::{
        cluster_state::ClusterState,
        simple::SimpleClusterGroupManager,
        strategy::{strategy_from_config, RoundRobinStrategy},
    };
    use queryflux_core::config::apply_default_probe_queries;
    use queryflux_core::engine_registry::{
        cluster_config_from_persisted_json, json_str, parse_auth_from_config_json,
        parse_engine_key, parse_query_auth_from_config_json,
    };
    use queryflux_core::tags::QueryTags;

    // Build a lookup map from records for group member resolution.
    // This includes both base record names and expanded variant names.
    let records_by_name: HashMap<
        &str,
        &queryflux_persistence::cluster_config::ClusterConfigRecord,
    > = cluster_records
        .iter()
        .map(|r| (r.name.as_str(), r))
        .collect();

    // Expand variants: build a map of all valid cluster names (base + expanded).
    let mut all_cluster_names: HashSet<String> = HashSet::new();
    // Track which expanded names map to which parent record (for records_by_name resolution).
    let mut expanded_to_parent: HashMap<
        String,
        &queryflux_persistence::cluster_config::ClusterConfigRecord,
    > = HashMap::new();
    // Track expanded cluster configs for each variant.
    let mut expanded_configs: HashMap<String, ExpandedVariantConfig> = HashMap::new();

    for record in cluster_records {
        let variants = parse_cluster_variants(&record.variants);

        if variants.is_empty() {
            all_cluster_names.insert(record.name.clone());
        } else {
            let (health_check_query, reconcile_query) = extract_base_probe_queries(&record.config);
            match queryflux_core::config::expand_cluster_variants(
                &record.name,
                &record.config,
                &record.engine_key,
                &variants,
                health_check_query.as_deref(),
                reconcile_query.as_deref(),
            ) {
                Ok(expanded) => {
                    for exp in expanded {
                        all_cluster_names.insert(exp.expanded_name.clone());
                        expanded_to_parent.insert(exp.expanded_name.clone(), record);
                        expanded_configs.insert(
                            exp.expanded_name,
                            (
                                exp.merged_config,
                                exp.max_running_queries,
                                exp.health_check_query,
                                exp.reconcile_query,
                            ),
                        );
                    }
                }
                Err(err) => {
                    tracing::error!(cluster = %record.name, error = %err, "Reload: variant expansion failed — cluster omitted");
                }
            }
        }
    }

    let prev_config_json = cache.config_json.clone();

    // Build adapters — reuse when serialized cluster config is unchanged.
    // First handle base (non-variant) records.
    for record in cluster_records {
        if !parse_cluster_variants(&record.variants).is_empty() {
            continue; // has variants — handled below
        }

        let cluster_name_str = &record.name;
        if !record.enabled {
            cache.adapters.remove(cluster_name_str.as_str());
            cache.config_json.remove(cluster_name_str.as_str());
            continue;
        }
        let cfg_json = serde_json::to_string(&(record.engine_key.as_str(), &record.config))
            .unwrap_or_default();
        let reuse = cache.adapters.contains_key(cluster_name_str.as_str())
            && prev_config_json
                .get(cluster_name_str.as_str())
                .map(String::as_str)
                == Some(cfg_json.as_str());
        if reuse {
            continue;
        }
        cache.adapters.remove(cluster_name_str.as_str());
        cache.config_json.remove(cluster_name_str.as_str());

        let cluster_name = ClusterName(cluster_name_str.clone());
        let placeholder_group = ClusterGroupName("_".to_string());
        let adapter = match registered_engines::build_adapter_from_record(
            cluster_name,
            placeholder_group,
            &record.engine_key,
            &record.config,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(
                    cluster = %cluster_name_str,
                    error = %e,
                    "Reload: failed to build engine adapter — cluster omitted until fixed"
                );
                continue;
            }
        };
        cache.adapters.insert(cluster_name_str.clone(), adapter);
        cache.config_json.insert(cluster_name_str.clone(), cfg_json);
    }

    // Build adapters for expanded variant clusters.
    for (expanded_name, (merged_config, _, _, _)) in &expanded_configs {
        let parent = match expanded_to_parent.get(expanded_name) {
            Some(p) => p,
            None => continue,
        };
        if !parent.enabled {
            cache.adapters.remove(expanded_name.as_str());
            cache.config_json.remove(expanded_name.as_str());
            continue;
        }
        let cfg_json =
            serde_json::to_string(&(parent.engine_key.as_str(), merged_config)).unwrap_or_default();
        let reuse = cache.adapters.contains_key(expanded_name.as_str())
            && prev_config_json
                .get(expanded_name.as_str())
                .map(String::as_str)
                == Some(cfg_json.as_str());
        if reuse {
            continue;
        }
        cache.adapters.remove(expanded_name.as_str());
        cache.config_json.remove(expanded_name.as_str());

        let cluster_name = ClusterName(expanded_name.clone());
        let placeholder_group = ClusterGroupName("_".to_string());
        let adapter = match registered_engines::build_adapter_from_record(
            cluster_name,
            placeholder_group,
            &parent.engine_key,
            merged_config,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(
                    cluster = %expanded_name,
                    error = %e,
                    "Reload: failed to build engine adapter for variant — omitted"
                );
                continue;
            }
        };
        cache.adapters.insert(expanded_name.clone(), adapter);
        cache.config_json.insert(expanded_name.clone(), cfg_json);
    }

    cache
        .adapters
        .retain(|name, _| all_cluster_names.contains(name));
    cache
        .config_json
        .retain(|name, _| all_cluster_names.contains(name));

    // Build group states.
    let mut group_states: GroupStatesMap = HashMap::new();
    let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_order: Vec<String> = Vec::new();

    for (group_name, group_config) in cluster_groups {
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
                    "Reload: duplicate cluster in group members — ignoring extra entry"
                );
                continue;
            }
            // Resolve member: check base records first, then expanded variant names.
            let record = match records_by_name.get(member_name.as_str()) {
                Some(r) => *r,
                None => match expanded_to_parent.get(member_name.as_str()) {
                    Some(r) => *r,
                    None => {
                        tracing::warn!(group = %group_name, cluster = %member_name, "Reload: group references unknown cluster");
                        continue;
                    }
                },
            };
            if !cache.adapters.contains_key(member_name.as_str()) {
                tracing::info!(group = %group_name, cluster = %member_name, "Reload: skipping disabled/missing cluster in group");
                continue;
            }
            let engine = match parse_engine_key(&record.engine_key) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let engine_type = EngineType::from(&engine);
            // For expanded variants, use the variant-specific max_running_queries if set.
            // `?` (not `.unwrap_or_else` — a closure can't propagate `?` out of this
            // function) so an invalid `max_running_queries` on the base record rejects
            // the reload here exactly like the non-variant fallback, instead of
            // silently falling back to the group default.
            let variant_max_override = expanded_configs
                .get(member_name.as_str())
                .and_then(|(_, variant_max, _, _)| *variant_max);
            let max_q = match variant_max_override {
                Some(v) => v,
                None => max_running_queries_u64_from_db(member_name, record.max_running_queries)?
                    .unwrap_or(group_config.max_running_queries),
            };
            // For expanded variants, use merged config for endpoint resolution.
            let effective_config = expanded_configs
                .get(member_name.as_str())
                .map(|(cfg, _, _, _)| cfg)
                .unwrap_or(&record.config);
            let endpoint = json_str(effective_config, "endpoint");
            let cluster_cid = cluster_ids_by_name
                .get(member_name.as_str())
                .copied()
                .or_else(|| expanded_to_parent.get(member_name.as_str()).map(|r| r.id));
            let group_cid = group_ids_by_name.get(group_name.as_str()).copied();

            // When the JSONB + engine_key fingerprint is unchanged, rebuild `ClusterState` from
            // the current record anyway (group membership, IDs, endpoint, max_q may still change)
            // but copy health and queue counters from the previous generation.
            let cfg_json = serde_json::to_string(&(record.engine_key.as_str(), effective_config))
                .unwrap_or_default();
            let config_unchanged = prev_config_json
                .get(member_name.as_str())
                .map(String::as_str)
                == Some(cfg_json.as_str());

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
                    endpoint,
                    max_q,
                    record.enabled,
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
            Err(e) => {
                if let Some(prev) = cache.strategies.get(group_name.as_str()) {
                    tracing::warn!(
                        group = %group_name,
                        error = %e,
                        "Reload: failed to build cluster-selection strategy; keeping this group's previous strategy"
                    );
                    prev.clone()
                } else {
                    tracing::warn!(
                        group = %group_name,
                        error = %e,
                        "Reload: failed to build cluster-selection strategy; no previous strategy cached, falling back to round robin"
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
        .retain(|name, _| cluster_groups.contains_key(name.as_str()));

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

    // Build minimal ClusterConfig values for BackendIdentityResolver (`queryAuth` from JSONB).
    let mut cluster_configs: HashMap<String, queryflux_core::config::ClusterConfig> =
        HashMap::new();
    for r in cluster_records {
        let engine = match parse_engine_key(&r.engine_key) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(cluster = %r.name, "reload: {err}");
                continue;
            }
        };
        let query_auth = parse_query_auth_from_config_json(&r.config).map_err(|e| {
            anyhow::anyhow!("cluster '{}': invalid queryAuth in JSONB: {e}", r.name)
        })?;
        let auth = match parse_auth_from_config_json(&r.config) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    cluster = %r.name,
                    "reload: invalid auth in cluster config JSON: {e}"
                );
                None
            }
        };
        let max_running = max_running_queries_u64_from_db(&r.name, r.max_running_queries)?;
        let base_cfg = cluster_config_from_persisted_json(
            engine.clone(),
            r.enabled,
            max_running,
            &r.config,
            auth.clone(),
            query_auth.clone(),
        );

        let variants = parse_cluster_variants(&r.variants);
        if variants.is_empty() {
            let mut base_cfg = base_cfg;
            apply_default_probe_queries(&mut base_cfg, &r.engine_key, &r.config);
            cluster_configs.insert(r.name.clone(), base_cfg);
        } else {
            // Insert a ClusterConfig entry for each expanded variant name.
            for (expanded_name, (_, variant_max, hcq, rq)) in &expanded_configs {
                if expanded_name.starts_with(&format!("{}::", r.name)) {
                    let mut variant_cfg = base_cfg.clone();
                    variant_cfg.max_running_queries = variant_max.or(max_running);
                    variant_cfg.health_check_query = hcq.clone();
                    variant_cfg.reconcile_query = rq.clone();
                    cluster_configs.insert(expanded_name.clone(), variant_cfg);
                }
            }
        }
    }

    // Build router chain.
    let fallback = ClusterGroupName(routing_fallback.to_string());
    let mut routers: Vec<Box<dyn RouterTrait>> = Vec::new();
    for router_cfg in routers_cfg {
        use queryflux_core::config::RouterConfig;
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
                routers.push(Box::new(
                    queryflux_routing::implementations::protocol_based::ProtocolBasedRouter {
                        trino_http: trino_http.as_ref().map(|s| ClusterGroupName(s.clone())),
                        postgres_wire: postgres_wire.as_ref().map(|s| ClusterGroupName(s.clone())),
                        mysql_wire: mysql_wire.as_ref().map(|s| ClusterGroupName(s.clone())),
                        clickhouse_http: clickhouse_http
                            .as_ref()
                            .map(|s| ClusterGroupName(s.clone())),
                        flight_sql: flight_sql.as_ref().map(|s| ClusterGroupName(s.clone())),
                        snowflake_http: snowflake_http
                            .as_ref()
                            .map(|s| ClusterGroupName(s.clone())),
                        snowflake_sql_api: snowflake_sql_api
                            .as_ref()
                            .map(|s| ClusterGroupName(s.clone())),
                        mcp: mcp.as_ref().map(|s| ClusterGroupName(s.clone())),
                    },
                ));
            }
            RouterConfig::Header {
                header_name,
                header_value_to_group,
            } => {
                let mapping = header_value_to_group
                    .iter()
                    .map(|(k, v)| (k.clone(), ClusterGroupName(v.clone())))
                    .collect();
                routers.push(Box::new(
                    queryflux_routing::implementations::header::HeaderRouter::new(
                        header_name.clone(),
                        mapping,
                    ),
                ));
            }
            RouterConfig::UserGroup { user_to_group } => {
                let mapping = user_to_group
                    .iter()
                    .map(|(k, v)| (k.clone(), ClusterGroupName(v.clone())))
                    .collect();
                routers.push(Box::new(
                    queryflux_routing::implementations::user_group::UserGroupRouter::new(mapping),
                ));
            }
            RouterConfig::QueryRegex { rules } => {
                routers.push(Box::new(
                    queryflux_routing::implementations::query_regex::QueryRegexRouter::from_rules(
                        rules.clone(),
                    ),
                ));
            }
            RouterConfig::Tags { rules } => {
                routers.push(Box::new(
                    queryflux_routing::implementations::tags::TagsRouter::new(rules.clone()),
                ));
            }
            RouterConfig::PythonScript {
                script,
                script_file,
            } => {
                let router = if let Some(path) = script_file {
                    match queryflux_routing::implementations::python_script::PythonScriptRouter::from_file(path) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Reload: failed to load routing script from {path}: {e}");
                            continue;
                        }
                    }
                } else {
                    queryflux_routing::implementations::python_script::PythonScriptRouter::new(
                        script.clone(),
                    )
                };
                routers.push(Box::new(router));
            }
            RouterConfig::Compound {
                combine,
                conditions,
                target_group,
            } => {
                routers.push(Box::new(
                    queryflux_routing::implementations::compound::CompoundRouter::new(
                        *combine,
                        conditions.clone(),
                        target_group.clone(),
                    ),
                ));
            }
        }
    }
    let router_chain = RouterChain::new(routers, fallback);

    let group_default_tags: HashMap<String, QueryTags> = cluster_groups
        .iter()
        .filter(|(_, g)| !g.default_tags.is_empty())
        .map(|(name, g)| (name.clone(), g.default_tags.clone()))
        .collect();

    let group_max_queued_queries: HashMap<String, Option<u64>> = cluster_groups
        .iter()
        .filter(|(_, g)| g.max_queued_queries.is_some())
        .map(|(name, g)| (name.clone(), g.max_queued_queries))
        .collect();

    let group_capacity_wait_timeout_secs: HashMap<String, u64> = cluster_groups
        .iter()
        .map(|(name, g)| (name.clone(), g.capacity_wait_timeout_secs_or_default()))
        .collect();

    let group_cache_settings: HashMap<String, queryflux_core::config::GroupCacheConfig> =
        cluster_groups
            .iter()
            .filter_map(|(name, g)| {
                g.cache
                    .as_ref()
                    .filter(|c| c.enabled)
                    .map(|c| (name.clone(), c.clone()))
            })
            .collect();

    // Referential integrity: routers must target groups that exist in this reload cycle,
    // and every declared group member must have a built adapter. A stale read (e.g. a
    // group deleted between the cluster read and the group read) would produce a live
    // config where dispatch returns NoClusterGroupAvailable with no explanation.
    // On any inconsistency, bail out so the caller keeps the previous LiveConfig.
    let issues = validate_live_config_refs(
        routers_cfg,
        routing_fallback,
        &group_members,
        &cache.adapters,
    );
    if !issues.is_empty() {
        for issue in &issues {
            tracing::warn!("Live config validation: {issue}");
        }
        return Err(anyhow::anyhow!(
            "Live config is internally inconsistent ({} issue(s)); keeping previous config",
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
        guard_chain: None,
        group_guard_chains: HashMap::new(),
        // Placeholder — `reload_live_config` immediately carries forward the previous
        // value, same as `guard_chain`/`group_guard_chains` above.
        access_control_guard: None,
        cluster_manager,
        adapters: cache.adapters.clone(),
        health_check_targets,
        custom_health_queries,
        custom_reconcile_queries,
        cluster_configs,
        group_members,
        group_order,
        group_translation_scripts,
        group_default_tags,
        group_max_queued_queries,
        group_capacity_wait_timeout_secs,
        group_cache_settings,
        auth_provider: Arc::new(NoneAuthProvider::new(false)),
        authorization: Arc::new(AllowAllAuthorization::default()),
        // Placeholder — `reload_live_config` immediately overwrites this with the
        // carried-forward previous value (and possibly a fresh one from
        // `catalog_config`), same as `auth_provider`/`authorization` above.
        catalog: Arc::new(queryflux_core::catalog::NullCatalogProvider),
    })
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
    let mut cluster_ids_by_name: HashMap<String, i64> = cluster_records
        .iter()
        .map(|r| (r.name.clone(), r.id))
        .collect();
    // Also map expanded variant names to their parent's DB ID.
    for r in &cluster_records {
        for v in &parse_cluster_variants(&r.variants) {
            cluster_ids_by_name.insert(format!("{}::{}", r.name, v.name), r.id);
        }
    }

    let group_records = pg
        .list_group_configs()
        .await
        .context("reload: list_group_configs")?;
    let group_ids_by_name: HashMap<String, i64> = group_records
        .iter()
        .map(|r| (r.name.clone(), r.id))
        .collect();
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

    let mut live = build_live_config(
        &cluster_records,
        &cluster_groups,
        &cluster_ids_by_name,
        &group_ids_by_name,
        &routers_cfg,
        &routing_fallback,
        group_translation_scripts,
        cache,
    )
    .await?;

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
                    match authz_cfg.map(|cfg| build_authorization(&cfg, &cluster_groups, operators))
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
