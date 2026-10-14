use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use queryflux_auth::BackendIdentityResolver;
use queryflux_cluster_manager::cluster_state::ClusterState;
use queryflux_config::{yaml::YamlFileConfigProvider, ConfigProvider};
use queryflux_core::query::{ClusterGroupName, ClusterName};
use queryflux_frontend::{
    admin::{
        build_frontends_status, AdminFrontend, RoutingConfigDto as AdminRoutingConfigDto,
        SecurityConfigDto as AdminSecurityConfigDto, TestCatalogProviderFn, TestClusterFn,
    },
    flight_sql::FlightSqlFrontend,
    mcp::McpFrontend,
    mysql_wire::MysqlWireFrontend,
    postgres_wire::PostgresWireFrontend,
    snowflake::SnowflakeFrontend,
    state::LiveConfig,
    trino_http::{state::AppState, TrinoHttpFrontend},
    FrontendListenerTrait,
};
use queryflux_metrics::{
    buffered_store::BufferedMetricsStore, prometheus_store::PrometheusMetrics, MetricsStore,
    MultiMetricsStore,
};
use queryflux_persistence::{
    in_memory::InMemoryPersistence, postgres::PostgresStore, AdminStore, BackendStore,
    DistributedBackendStore,
};
use queryflux_translation::TranslationService;
use tracing::info;

mod guards;
mod live_config;
mod registered_engines;

use crate::guards::{
    apply_stored_access_control, build_access_control_guard, build_auth_provider,
    build_authorization, build_guard_chains, build_guard_chains_from_db_value,
    load_guard_script_bodies, load_guard_script_bodies_from_admin, operators_from_auth,
    validate_group_translation_scripts,
};
use crate::live_config::{
    cluster_configs_from_specs, compile_live_config, reload_live_config, AdapterReloadCache,
    ClusterSpec, CompileMode, ConfigIds, LiveConfigInputs, PreservedLive,
};

type FrontendTaskResult = queryflux_core::error::Result<()>;

/// Owns only the frontend listeners that are actually running.
///
/// Keeping disabled frontends out of the task set is important for graceful
/// shutdown: a placeholder future that never completes would make the drain
/// timeout the only way to leave the process.
#[derive(Default)]
struct FrontendTasks {
    tasks: tokio::task::JoinSet<FrontendTaskResult>,
    names: HashMap<tokio::task::Id, &'static str>,
}

struct FrontendTaskExit {
    name: &'static str,
    result: std::result::Result<FrontendTaskResult, tokio::task::JoinError>,
}

impl FrontendTasks {
    fn spawn<F>(&mut self, name: &'static str, task: F)
    where
        F: std::future::Future<Output = FrontendTaskResult> + Send + 'static,
    {
        let handle = self.tasks.spawn(task);
        self.names.insert(handle.id(), name);
    }

    fn spawn_if_enabled<F, Fut>(&mut self, name: &'static str, enabled: bool, task: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = FrontendTaskResult> + Send + 'static,
    {
        if enabled {
            self.spawn(name, task());
        }
    }

    async fn join_next(&mut self) -> Option<FrontendTaskExit> {
        let result = self.tasks.join_next_with_id().await?;
        Some(match result {
            Ok((id, result)) => FrontendTaskExit {
                name: self.names.remove(&id).unwrap_or("unknown frontend"),
                result: Ok(result),
            },
            Err(error) => FrontendTaskExit {
                name: self.names.remove(&error.id()).unwrap_or("unknown frontend"),
                result: Err(error),
            },
        })
    }

    async fn drain(&mut self) {
        while let Some(exit) = self.join_next().await {
            match exit.result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        frontend = exit.name,
                        "Frontend failed while draining: {error}"
                    )
                }
                Err(error) => tracing::warn!(
                    frontend = exit.name,
                    "Frontend task failed while draining: {error}"
                ),
            }
        }
    }

    fn outstanding_names(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.names.values().copied().collect();
        names.sort_unstable();
        names
    }
}

/// Returns `true` when the interval fired (continue work), `false` on shutdown.
async fn tick_or_shutdown(
    interval: &mut tokio::time::Interval,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = shutdown.wait_for(|v| *v) => false,
        _ = interval.tick() => true,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = match queryflux_cli::run_cli().await? {
        queryflux_cli::CliAction::Exit => return Ok(()),
        queryflux_cli::CliAction::Migrate { config } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "queryflux=info".into()),
                )
                .init();
            let config = YamlFileConfigProvider::new(&config)
                .load()
                .await
                .context("Failed to load config")?;
            queryflux_persistence::run_persistence_migrations(&config.queryflux.persistence)
                .await
                .context("Migration failed")?;
            tracing::info!("Migrations applied successfully");
            return Ok(());
        }
        queryflux_cli::CliAction::Serve { config } => config,
    };

    // Load config before initializing the tracing subscriber so that
    // `otlpEndpoint` from the config file can feed the OTel layer.
    let mut config = YamlFileConfigProvider::new(&config_path)
        .load()
        .await
        .context("Failed to load config")?;

    // Initialize tracing subscriber — with OTel if configured.
    {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "queryflux=info,queryflux_frontend=info".into());

        #[cfg(feature = "otlp")]
        {
            if let Some(endpoint) = &config.queryflux.otlp_endpoint {
                use opentelemetry::trace::TracerProvider;
                use opentelemetry_otlp::WithExportConfig;
                use tracing_subscriber::layer::SubscriberExt;
                use tracing_subscriber::util::SubscriberInitExt;

                let exporter = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint)
                    .build()
                    .expect("Failed to create OTLP exporter");
                let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(
                        opentelemetry_sdk::Resource::builder()
                            .with_service_name("queryflux")
                            .build(),
                    )
                    .build();
                let telemetry =
                    tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("queryflux"));
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer())
                    .with(telemetry)
                    .init();
                tracing::info!(endpoint = %endpoint, "OpenTelemetry OTLP tracing enabled");
            } else {
                tracing_subscriber::fmt().with_env_filter(env_filter).init();
            }
        }

        #[cfg(not(feature = "otlp"))]
        {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    info!("QueryFlux starting — loaded config from: {}", config_path);

    let external_address = config
        .queryflux
        .external_address
        .clone()
        .unwrap_or_else(|| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string();

    // --- Build persistence + metrics stores (must happen before cluster building) ---
    // When Postgres is configured we seed cluster/group config on first run and read
    // from the DB on subsequent starts, so persistence must be ready before the
    // two-pass cluster/adapter construction below.
    let prometheus = Arc::new(
        PrometheusMetrics::new_with_deny_list(config.queryflux.metrics.tags_deny_list.clone())
            .context("Failed to init Prometheus metrics")?,
    );
    let mut pg_store: Option<Arc<PostgresStore>> = None;
    let mut mem_store: Option<Arc<InMemoryPersistence>> = None;

    let (persistence, metrics): (
        Arc<dyn queryflux_persistence::Persistence>,
        Arc<dyn MetricsStore>,
    ) = match &config.queryflux.persistence {
        queryflux_core::config::PersistenceConfig::Postgres { conn } => {
            let url = conn
                .connection_url()
                .map_err(|m| anyhow::anyhow!("Invalid postgres persistence config: {m}"))?;
            let pg = Arc::new(
                PostgresStore::connect_from_config(&url, conn)
                    .await
                    .context("Failed to connect to Postgres")?,
            );
            if conn.auto_migrate {
                pg.migrate().await.context("Migration failed")?;
            } else {
                info!(
                    "persistence.autoMigrate=false — skipping startup migrations \
                     (apply with `queryflux migrate` or a Job)"
                );
            }
            let buffered = Arc::new(BufferedMetricsStore::new(
                pg.clone() as Arc<dyn MetricsStore>,
                100,
                std::time::Duration::from_secs(5),
            ));
            let metrics = Arc::new(MultiMetricsStore::new(vec![
                prometheus.clone() as Arc<dyn MetricsStore>,
                buffered as Arc<dyn MetricsStore>,
            ]));
            pg_store = Some(pg.clone());
            (
                pg as Arc<dyn queryflux_persistence::Persistence>,
                metrics as Arc<dyn MetricsStore>,
            )
        }
        queryflux_core::config::PersistenceConfig::Redis { url } => {
            anyhow::bail!(
                "persistence.type = redis is not implemented (configured url: {url}). \
                 Use type: postgres or type: inMemory."
            );
        }
        queryflux_core::config::PersistenceConfig::InMemory => {
            let mem = Arc::new(InMemoryPersistence::new());
            mem_store = Some(mem.clone());
            (
                mem.clone() as Arc<dyn queryflux_persistence::Persistence>,
                in_memory_metrics(prometheus.clone(), mem),
            )
        }
    };

    // The durable backend behind the proxy, type-erased so that everything south
    // of this point is wired against traits. Redis is intentionally rejected above
    // until a real `BackendStore` implementation exists (no silent in-memory fallback).
    // `None` in in-memory mode, which intentionally has no durable config source.
    let backend: Option<Arc<dyn BackendStore>> = pg_store.clone().map(|pg| pg as _);
    // Multi-replica coordination is optional: only backends that also implement
    // `DistributedBackendStore` (Postgres today) are stored here.
    let distributed_backend: Option<Arc<dyn DistributedBackendStore>> = pg_store.map(|pg| pg as _);

    // Filled when Postgres loads cluster/group rows — used for query_history FKs on ClusterState.
    let mut cluster_ids_by_name: HashMap<String, i64> = HashMap::new();
    let mut group_ids_by_name: HashMap<String, i64> = HashMap::new();
    // Cluster specs loaded from Postgres; `None` for YAML-only startup.
    let mut startup_cluster_specs: Option<Vec<ClusterSpec>> = None;

    // --- When Postgres is active, load cluster/group config from DB ---
    // Seed YAML `clusters` / `clusterGroups` only for names that are not already in
    // Postgres. Existing DB rows (Studio/admin edits) win and are never overwritten
    // by a ConfigMap/Helm values restart. First boot with an empty DB still seeds
    // from YAML. Omit those maps (or leave them empty) for Studio-only setups.
    if let Some(pg) = &backend {
        if !config.clusters.is_empty() {
            let report = queryflux_persistence::yaml_seed::seed_clusters_from_yaml_if_missing(
                pg.as_ref(),
                &config.clusters,
            )
            .await
            .context("Seed clusters from YAML")?;
            if report.seeded > 0 {
                info!(
                    "Seeded {} cluster definition(s) from YAML into Postgres",
                    report.seeded
                );
            } else if report.existing_before > 0 {
                info!(
                    existing = report.existing_before,
                    "Skipping YAML cluster upsert — Postgres already has these cluster names"
                );
            }
        }
        if !config.cluster_groups.is_empty() {
            let report = queryflux_persistence::yaml_seed::seed_groups_from_yaml_if_missing(
                pg.as_ref(),
                &config.cluster_groups,
            )
            .await
            .context("Seed cluster groups from YAML")?;
            if report.seeded > 0 {
                info!(
                    "Seeded {} cluster group definition(s) from YAML into Postgres",
                    report.seeded
                );
            } else if report.existing_before > 0 {
                info!(
                    existing = report.existing_before,
                    "Skipping YAML group upsert — Postgres already has these group names"
                );
            }
        }

        // Effective config comes from Postgres (YAML above only seeds missing names).
        info!("Loading cluster and group configs from Postgres");
        let db_cluster_records = pg
            .list_cluster_configs()
            .await
            .context("Load cluster configs from DB")?;
        cluster_ids_by_name = db_cluster_records
            .iter()
            .map(|r| (r.name.clone(), r.id))
            .collect();
        // `ClusterConfig` values for validation, startup warnings and credential resolution.
        // Adapters are built from the persisted JSON by `compile_live_config` below.
        let specs: Vec<ClusterSpec> = db_cluster_records
            .iter()
            .map(ClusterSpec::from_record)
            .collect();
        config.clusters = cluster_configs_from_specs(&specs)?;
        startup_cluster_specs = Some(specs);

        let group_records = pg
            .list_group_configs()
            .await
            .context("Load group configs from DB")?;
        group_ids_by_name = group_records
            .iter()
            .map(|r| (r.name.clone(), r.id))
            .collect();
        config.cluster_groups = group_records
            .into_iter()
            .map(|r| Ok((r.name.clone(), r.to_core().map_err(anyhow::Error::msg)?)))
            .collect::<Result<_>>()?;

        // Apply persisted security overrides (`security_settings` / `security_config` key).
        // The migration seeds `{}`; that is not an override — keep YAML.
        if let Ok(Some(v)) = pg.get_proxy_setting("security_config").await {
            if !queryflux_core::security_setting::is_blank_security_setting(&v) {
                let (auth_cfg, authz_cfg) =
                    queryflux_core::security_setting::parse_security_setting(&v);
                if let Some(auth_cfg) = auth_cfg {
                    config.auth = auth_cfg;
                }
                if let Some(authz_cfg) = authz_cfg {
                    config.authorization = authz_cfg;
                }
            }
        }
        let mut routing_from_db = false;
        match pg.load_routing_config().await {
            Ok(Some(loaded)) => {
                config.routing_fallback = loaded.routing_fallback;
                let mut routers = Vec::new();
                for v in loaded.routers {
                    match serde_json::from_value::<queryflux_core::config::RouterConfig>(v) {
                        Ok(r) => routers.push(r),
                        Err(e) => {
                            tracing::warn!(error = %e, "Skipping invalid routing_rules row from Postgres")
                        }
                    }
                }
                config.routers = routers;
                routing_from_db = true;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "load_routing_config failed; keeping YAML routing")
            }
        }
        if !routing_from_db {
            if let Ok(Some(v)) = pg.get_proxy_setting("routing_config").await {
                if let Ok(fallback) = serde_json::from_value::<String>(
                    v.get("routingFallback")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                ) {
                    config.routing_fallback = fallback;
                }
                if let Ok(routers) =
                    serde_json::from_value::<Vec<queryflux_core::config::RouterConfig>>(
                        v.get("routers").cloned().unwrap_or(serde_json::Value::Null),
                    )
                {
                    config.routers = routers;
                }
            }
        }
    }

    // Build the engine registry up front so it can be used for validation and AppState.
    let engine_registry = Arc::new(queryflux_core::engine_registry::EngineRegistry::new(
        registered_engines::all_descriptors(),
    ));

    // --- Validate cluster configs against the engine registry ---
    {
        use queryflux_core::engine_registry::validate_cluster_config;
        let mut all_errors: Vec<String> = Vec::new();
        for (name, cfg) in &config.clusters {
            all_errors.extend(validate_cluster_config(&engine_registry, name, cfg));
        }
        if !all_errors.is_empty() {
            for e in &all_errors {
                tracing::error!("{e}");
            }
            anyhow::bail!(
                "Config validation failed with {} error(s)",
                all_errors.len()
            );
        }
    }

    // --- Build translation service ---
    let translation = Arc::new(
        TranslationService::new_sqlglot(config.translation.python_scripts.clone())
            .unwrap_or_else(|e| {
                tracing::warn!(mode = ?config.translation.mode, "sqlglot unavailable ({e}); required translation will follow the configured policy");
                TranslationService::unavailable(config.translation.python_scripts.clone())
            })
            .with_policy(
                config.translation.mode,
                config.translation.error_on_unsupported,
            )
            .with_schema_resolution_timeout(std::time::Duration::from_millis(
                config.translation.schema_resolution_timeout_ms,
            )),
    );

    // --- Build catalog provider ---
    // Feeds `translation.resolve_schema_context` so sqlglot's optimizer can qualify
    // columns/types instead of falling back to dialect-only translation. Never fails
    // startup: an unimplemented or misconfigured integration degrades to a no-op
    // (see `queryflux_catalog::build_catalog_provider`), same philosophy as `translation` above.
    let catalog: Arc<dyn queryflux_core::catalog::CatalogProvider> =
        queryflux_catalog::build_catalog_provider(&config.catalog_provider).await;

    config
        .validate_startup_security()
        .map_err(|e| anyhow::anyhow!("Startup security validation failed: {e}"))?;

    let auth_provider = build_auth_provider(&config.auth)?;
    let authorization = build_authorization(
        &config.authorization,
        &config.cluster_groups,
        operators_from_auth(&config.auth),
    )?;

    // --- Production safety warnings ---
    if matches!(
        config.auth.provider,
        queryflux_core::config::AuthProviderConfig::None
    ) {
        tracing::warn!(
            "SECURITY: auth.provider is 'none' — all query frontends accept unauthenticated traffic. \
             Set auth.provider to 'oidc', 'ldap', or 'static' and auth.required = true for production."
        );
    }
    if !config.auth.required {
        tracing::warn!(
            "SECURITY: auth.required is false — unauthenticated requests are allowed even when \
             an auth provider is configured. Set auth.required = true for production."
        );
    }
    {
        let effective_user = std::env::var("QUERYFLUX_ADMIN_USER")
            .unwrap_or_else(|_| config.queryflux.admin_api.username.clone());
        let effective_pass = std::env::var("QUERYFLUX_ADMIN_PASSWORD")
            .unwrap_or_else(|_| config.queryflux.admin_api.password.clone());
        if effective_user == "admin" && effective_pass == "admin" {
            tracing::warn!(
                "SECURITY: admin API is using default credentials (admin/admin). \
                 Change via QUERYFLUX_ADMIN_USER / QUERYFLUX_ADMIN_PASSWORD or the Studio UI."
            );
        }
    }

    // --- Startup validation: engine × queryAuth support matrix ---
    // Centralized in `query_auth_supported` so YAML load, Studio PUT, and this check can't
    // drift apart. `passthrough`/`impersonate` are Trino-only; `tokenExchange` is Trino or
    // ADBC-with-an-OAuth-capable-driver (`cfg.driver`, only ever set for admin-API-created
    // ADBC clusters — see `ClusterConfig::driver`).
    for (name, cfg) in &config.clusters {
        if let Some(mode) = &cfg.query_auth {
            if let Err(msg) = queryflux_core::config::query_auth_supported(
                cfg.engine.as_ref(),
                cfg.driver.as_deref(),
                mode,
            ) {
                anyhow::bail!("cluster '{name}': {msg}");
            }
        }
    }

    // Deprecation warning: a cluster with no explicit `queryAuth` (or `serviceAccount`) and
    // no HTTP-setting cluster auth still implicitly forwards the client's own Authorization
    // header today, for backward compatibility. Operators should migrate to an explicit
    // `queryAuth: passthrough` — this fallback may be removed in a future release.
    for (name, cfg) in &config.clusters {
        let is_implicit_passthrough_eligible = matches!(
            cfg.query_auth,
            None | Some(queryflux_core::config::QueryAuthConfig::ServiceAccount)
        ) && matches!(
            cfg.engine,
            Some(queryflux_core::config::EngineConfig::Trino)
        ) && !cfg
            .auth
            .as_ref()
            .is_some_and(|a| a.sets_http_authorization());
        if is_implicit_passthrough_eligible {
            tracing::warn!(
                "DEPRECATED: cluster '{name}' has no HTTP cluster auth and no explicit \
                 queryAuth — it still implicitly forwards the client's Authorization header \
                 (legacy behavior). Set queryAuth.type: passthrough explicitly; the implicit \
                 fallback may be removed in a future release."
            );
        }
    }

    // Startup warning: with no gateway-level authorization policy, `passthrough` forwards
    // whatever the client sent straight to the backend. The gap exists regardless of how
    // many cluster groups there are — a single-group deployment is the common default, so
    // gating on `cluster_groups.len() > 1` hid the warning for exactly the most likely
    // misconfiguration. Group count only changes the blast radius, not whether the gap
    // exists, so it's now informational in the message rather than a gate.
    let passthrough_clusters = unauthenticated_passthrough_clusters(&config);
    if !passthrough_clusters.is_empty() {
        tracing::warn!(
            clusters = ?passthrough_clusters,
            "SECURITY: authorization.provider is 'none' and queryAuth: passthrough is set \
             on {} cluster(s) across {} cluster group(s) — QueryFlux is not enforcing any \
             access policy, so a client's own credential decides what it can reach on \
             every group it can route to. Configure authorization or narrow routing.",
            passthrough_clusters.len(),
            config.cluster_groups.len()
        );
    }

    let identity_resolver = Arc::new(BackendIdentityResolver::new());

    let group_translation_scripts: HashMap<String, Vec<String>> = if let Some(pg) = &backend {
        let loaded = pg
            .load_group_translation_bodies()
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to load group translation scripts from Postgres: {e}");
                HashMap::new()
            });
        validate_group_translation_scripts(loaded)
    } else {
        HashMap::new()
    };
    let guard_script_bodies =
        load_guard_script_bodies(backend.as_deref().map(|b| b as &dyn AdminStore)).await;

    // --- Build the data access-control guard (OPA row filtering / column masking /
    // table-column allow-deny), if configured. Runs on the source SQL, before
    // dialect translation — see `queryflux_frontend::access_control_guard`.
    let access_control_guard = build_access_control_guard(&config, backend.as_deref()).await?;

    // --- Build guard chains: DB-stored config (UI-managed) takes precedence over YAML ---
    // When a persisted config exists in Postgres it is authoritative, even if it
    // resolves to an empty chain (the user may have intentionally cleared guards).
    let (guard_chain, group_guard_chains) = if let Some(pg) = &backend {
        match pg.get_proxy_setting("guardrails_config").await {
            Ok(Some(v)) => build_guard_chains_from_db_value(&v, &guard_script_bodies),
            _ => build_guard_chains(&config, &guard_script_bodies),
        }
    } else {
        build_guard_chains(&config, &guard_script_bodies)
    };

    // --- Compile the config into a LiveConfig (adapters, groups, routing, validation) ---
    // Same compiler as hot reload, in strict mode: an unknown group member, a strategy
    // that fails to build, an unreadable routing script or a dangling reference aborts
    // startup.
    let inputs = LiveConfigInputs {
        clusters: startup_cluster_specs.unwrap_or_else(|| {
            config
                .clusters
                .iter()
                .map(|(name, cfg)| ClusterSpec::from_yaml(name, cfg))
                .collect()
        }),
        groups: config.cluster_groups.clone(),
        routers: config.routers.clone(),
        routing_fallback: config.routing_fallback.clone(),
        group_translation_scripts,
        // Startup applies settings itself (YAML with DB overrides, below and above).
        settings: Default::default(),
    };
    let ids = ConfigIds {
        clusters: cluster_ids_by_name,
        groups: group_ids_by_name,
    };
    let mut reload_cache = AdapterReloadCache {
        adapters: HashMap::new(),
        config_json: HashMap::new(),
        cluster_states: HashMap::new(),
        routing_fallback: config.routing_fallback.clone(),
        routers_cfg: config.routers.clone(),
        strategies: HashMap::new(),
    };
    let mut live_config =
        compile_live_config(&inputs, &ids, &mut reload_cache, CompileMode::Strict)
            .await
            .context("Startup config is invalid — aborting")?;
    live_config.guard_chain = guard_chain;
    live_config.group_guard_chains = group_guard_chains;
    live_config.access_control_guard = access_control_guard;
    live_config.auth_provider = auth_provider;
    live_config.authorization = authorization;
    live_config.catalog = catalog;
    let adapter_reload_cache = Arc::new(tokio::sync::Mutex::new(reload_cache));
    let live = Arc::new(tokio::sync::RwLock::new(live_config));

    // Replica identity for capacity leases and queue claims. Must be unique per
    // *process incarnation*: PIDs collide across containers (the main process is
    // PID 1 in most pods), and a bare hostname survives container restarts —
    // either would make this replica's heartbeat renew leases that belong to a
    // dead instance, so they would never expire. Hostname (= pod name in
    // Kubernetes) is included purely for debuggability; the random nonce is what
    // guarantees uniqueness.
    let instance_id = std::env::var("QUERYFLUX_INSTANCE_ID").unwrap_or_else(|_| {
        let host =
            std::env::var("HOSTNAME").unwrap_or_else(|_| format!("pid{}", std::process::id()));
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        format!("qf-{host}-{}", &nonce[..8])
    });
    tracing::info!(instance_id = %instance_id, "Replica instance ID");

    // Distributed mode detection and validation. Resolved before AppState is
    // built so the flag actually gates coordination: with `distributed: false`
    // no capacity leases are taken, no queue claims are made, and the
    // heartbeat/expiry/reconcile tasks (all keyed on `capacity_store`) stay off.
    let distributed = config
        .queryflux
        .resolve_distributed(
            distributed_backend
                .as_ref()
                .is_some_and(|b| b.supports_distributed_coordination()),
        )
        .map_err(|e| anyhow::anyhow!(e))?;

    if distributed {
        tracing::warn!(
            "Distributed coordination is enabled. \
             This requires HA Postgres — during a Postgres outage the fleet reverts to \
             per-replica capacity limits (group_limit × replicas worst case). \
             Alert on queryflux_coordination_failures_total > 0."
        );
    }

    let capacity_store: Option<Arc<dyn queryflux_persistence::CapacityStore>> = distributed
        .then(|| {
            distributed_backend
                .clone()
                .map(|b| b as Arc<dyn queryflux_persistence::CapacityStore>)
        })
        .flatten();
    let queue_coordinator: Option<Arc<dyn queryflux_persistence::QueueCoordinator>> = distributed
        .then(|| {
            distributed_backend
                .clone()
                .map(|b| b as Arc<dyn queryflux_persistence::QueueCoordinator>)
        })
        .flatten();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Initialize the query result cache (startup-only, not hot-reloadable).
    let result_cache: Arc<dyn queryflux_cache::QueryResultCache> = match &config
        .queryflux
        .cache_backend
    {
        Some(cache_cfg) => {
            let cache_store: Arc<dyn queryflux_persistence::CacheStore> =
                if let Some(b) = backend.clone() {
                    b as Arc<dyn queryflux_persistence::CacheStore>
                } else {
                    mem_store
                        .clone()
                        .expect("mem_store must exist when no backend")
                        as Arc<dyn queryflux_persistence::CacheStore>
                };
            match queryflux_cache::opendal_cache::OpenDalResultCache::new(cache_cfg, cache_store) {
                Ok(c) => {
                    tracing::info!("Query result cache enabled (scheme={})", cache_cfg.scheme);
                    Arc::new(c)
                }
                Err(e) => {
                    tracing::error!("Failed to initialize result cache: {e}; caching disabled");
                    Arc::new(queryflux_cache::noop::NoopResultCache)
                }
            }
        }
        None => Arc::new(queryflux_cache::noop::NoopResultCache),
    };

    let app_state = Arc::new(AppState {
        external_address: external_address.clone(),
        live: live.clone(),
        persistence,
        translation,
        metrics,
        identity_resolver,
        capacity_store,
        queue_coordinator,
        instance_id,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("build shared http client"),
        result_cache,
    });

    // --- Start admin server (Prometheus /metrics + future /admin/* endpoints) ---
    let admin_port = config.queryflux.admin_api.port;
    let admin_store: Option<Arc<dyn AdminStore>> = backend
        .clone()
        .map(|b| b as Arc<dyn AdminStore>)
        .or_else(|| mem_store.clone().map(|m| m as Arc<dyn AdminStore>));
    let security_config = Arc::new(AdminSecurityConfigDto::from_config(
        &config.auth,
        &config.authorization,
        &config.cluster_groups,
    ));
    let routing_config = Arc::new(AdminRoutingConfigDto::from_config(
        &config.routing_fallback,
        &config.routers,
    ));
    let catalog_provider_config = Arc::new(config.catalog_provider.clone());
    let access_control_config = Arc::new(config.access_control.clone());
    let config_reload_notify = Arc::new(tokio::sync::Notify::new());

    let frontends_status = build_frontends_status(
        &config.queryflux.frontends,
        admin_port,
        config.queryflux.external_address.clone(),
    );

    // Build admin credentials — env vars take precedence over YAML.
    // Bootstrap lives on `queryflux.adminApi`, not the unused top-level `adminApi`.
    let admin_username = std::env::var("QUERYFLUX_ADMIN_USER")
        .unwrap_or_else(|_| config.queryflux.admin_api.username.clone());
    let admin_password = std::env::var("QUERYFLUX_ADMIN_PASSWORD")
        .unwrap_or_else(|_| config.queryflux.admin_api.password.clone());
    let settings_store = backend
        .clone()
        .map(|b| b as Arc<dyn queryflux_persistence::ProxySettingsStore>)
        .or_else(|| {
            mem_store
                .clone()
                .map(|m| m as Arc<dyn queryflux_persistence::ProxySettingsStore>)
        });
    let admin_creds = Arc::new(queryflux_auth::AdminCredentialsManager::new(
        admin_username,
        admin_password,
        settings_store,
        backend.is_some(),
    ));

    let test_cluster_fn: TestClusterFn = Arc::new(|engine_key, config_json| {
        Box::pin(async move {
            let adapter = registered_engines::build_adapter_from_record(
                ClusterName("__test__".to_string()),
                ClusterGroupName("__test__".to_string()),
                &engine_key,
                &config_json,
            )
            .await?;
            Ok(adapter.health_check().await)
        })
    });

    let test_catalog_provider_fn: TestCatalogProviderFn = Arc::new(|config_json| {
        Box::pin(async move {
            let cfg = serde_json::from_value::<queryflux_core::config::CatalogProviderConfig>(
                config_json,
            )?;
            if matches!(cfg, queryflux_core::config::CatalogProviderConfig::Null) {
                return Ok((true, "No catalog configured (type: null).".to_string()));
            }
            // Uses the fallible builder, not `build_catalog_provider` — this
            // needs the real construction error, not a silent degrade to a
            // no-op. Every real provider ignores its `catalog` argument (Glue/
            // HiveMetastore/IcebergRest each expose exactly one synthetic
            // catalog), so any string works here.
            let provider = match queryflux_catalog::try_build_catalog_provider(&cfg).await {
                Ok(provider) => provider,
                Err(e) => return Ok((false, format!("Failed to build provider: {e}"))),
            };
            if matches!(
                cfg,
                queryflux_core::config::CatalogProviderConfig::Static { .. }
            ) {
                return match provider.list_tables("", "").await {
                    Ok(tables) => Ok((
                        true,
                        format!("Static catalog — {} table(s) configured", tables.len()),
                    )),
                    Err(e) => Ok((
                        false,
                        format!("Built static catalog, but listing tables failed: {e}"),
                    )),
                };
            }
            // `list_catalogs()` is a hardcoded synthetic single-entry result for
            // every real provider (Glue/HMS/Iceberg REST have no native "list
            // catalogs" call) — it makes no network call at all, so it can't
            // prove connectivity. `list_databases` does: it's the cheapest call
            // that actually round-trips to the backing service for all three.
            match provider.list_databases("").await {
                Ok(databases) => Ok((
                    true,
                    format!("Connected — {} database(s) visible", databases.len()),
                )),
                Err(e) => Ok((
                    false,
                    format!("Built provider, but listing databases failed: {e}"),
                )),
            }
        })
    });

    let admin_store_for_reload = admin_store.clone();
    let cors_origins = config.queryflux.admin_api.cors_allowed_origins.clone();
    if cors_origins.is_empty() {
        tracing::warn!(
            "Admin API CORS allows any origin (corsAllowedOrigins is empty). \
             Set queryflux.adminApi.corsAllowedOrigins to restrict cross-origin access in production."
        );
    }
    let admin = AdminFrontend::new(
        prometheus.clone(),
        live.clone(),
        admin_store,
        admin_port,
        security_config,
        routing_config,
        catalog_provider_config,
        access_control_config,
        engine_registry,
        config_reload_notify.clone(),
        frontends_status,
        admin_creds,
        test_cluster_fn,
        test_catalog_provider_fn,
        cors_origins,
        app_state.result_cache.clone(),
        app_state.clone(),
    );

    // --- Start Trino HTTP frontend (honors frontends.trinoHttp.enabled) ---
    let trino_cfg = config.queryflux.frontends.trino_http.clone();
    let trino_port = trino_cfg.port;

    if trino_cfg.enabled {
        info!(
            "QueryFlux ready — Trino HTTP on :{trino_port}, admin/metrics on :{admin_port}, external address: {external_address}"
        );
    } else {
        info!(
            "QueryFlux ready — Trino HTTP disabled, admin/metrics on :{admin_port}, external address: {external_address}"
        );
    }

    if distributed {
        if config
            .queryflux
            .periodic_config_reload_interval_secs()
            .is_none()
        {
            tracing::warn!(
                "Distributed mode with configReloadIntervalSecs: 0 — periodic config polling \
                 is disabled. Config propagation relies solely on LISTEN/NOTIFY; if the \
                 notification channel drops, replicas may become stale."
            );
        }
        tracing::info!(
            instance_id = %app_state.instance_id,
            "Distributed mode enabled — global capacity, config revision, and queue \
             coordination are active via the persistence backend"
        );
    }

    if backend.is_some() {
        match config.queryflux.periodic_config_reload_interval_secs() {
            None => tracing::info!(
                "Postgres persistence: routing rules and cluster/group config are cached in memory; periodic DB refresh is disabled (configReloadIntervalSecs: 0). Reloads still run after Studio/admin API writes."
            ),
            Some(secs) => tracing::info!(
                secs,
                "Postgres persistence: routing rules and cluster/group config are cached in memory and reloaded from the DB on this interval (seconds), or immediately after Studio/admin writes"
            ),
        }
    }

    // Background task: push cluster utilization snapshots every 5s.
    // In distributed mode, overlay the last published engine reconcile counts so
    // every replica's metrics reflect the same backend ground truth.
    //
    // Every replica refreshes its *local* Prometheus gauges (each replica's
    // /metrics is scraped independently), but only the replica holding the
    // sweep lock persists history rows to the backend — otherwise R replicas
    // write R duplicate rows per cluster per tick and Studio's history tables
    // grow R times faster.
    tokio::spawn({
        let state = app_state.clone();
        let prometheus = prometheus.clone();
        let backend = backend.clone();
        let distributed_backend = distributed_backend.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }
                let cluster_manager = state.live.read().await.cluster_manager.clone();
                let Ok(snapshots) = cluster_manager.all_cluster_states().await else {
                    continue;
                };
                let breaker_states: Vec<_> = snapshots
                    .iter()
                    .map(|snap| {
                        let state = snap.breaker_state.map(|state| match state {
                            queryflux_cluster_manager::circuit_breaker::CircuitState::Closed => 0,
                            queryflux_cluster_manager::circuit_breaker::CircuitState::Open => 1,
                            queryflux_cluster_manager::circuit_breaker::CircuitState::HalfOpen => 2,
                        });
                        (
                            snap.group_name.0.clone(),
                            snap.cluster_name.0.clone(),
                            state,
                        )
                    })
                    .collect();
                prometheus.sync_circuit_breaker_states(&breaker_states);
                let mut records = Vec::with_capacity(snapshots.len());
                for snap in snapshots {
                    let global_running = if let Some(db) = &distributed_backend {
                        let store = db.clone() as Arc<dyn queryflux_persistence::CapacityStore>;
                        store
                            .active_count(&snap.cluster_name.0)
                            .await
                            .unwrap_or(snap.running_queries)
                    } else {
                        snap.running_queries
                    };
                    records.push(queryflux_metrics::ClusterSnapshot {
                        cluster_name: snap.cluster_name,
                        group_name: snap.group_name,
                        engine_type: snap.engine_type,
                        running_queries: global_running,
                        queued_queries: snap.queued_queries,
                        max_running_queries: snap.max_running_queries,
                        recorded_at: chrono::Utc::now(),
                    });
                }
                for record in &records {
                    let _ = prometheus.record_cluster_snapshot(record.clone()).await;
                }
                // History rows go to the durable backend. When the backend can
                // coordinate, only the sweep-lock owner persists this cycle; a
                // coordination failure fails open (duplicate rows beat no rows).
                // A non-coordinating backend persists unconditionally — it
                // cannot dedup across replicas anyway.
                let lock = match &distributed_backend {
                    Some(db) => match db.try_sweep_lock("cluster-snapshots").await {
                        Ok(Some(lock)) => Some(Some(lock)),
                        Ok(None) => None, // another replica persists this cycle
                        Err(e) => {
                            tracing::debug!("Snapshot sweep lock failed: {e}");
                            Some(None)
                        }
                    },
                    None => Some(None),
                };
                if let Some(lock) = lock {
                    if let Some(backend) = &backend {
                        for record in records {
                            let _ = backend.record_cluster_snapshot(record).await;
                        }
                    }
                    if let Some(lock) = lock {
                        lock.release().await;
                    }
                }
            }
        }
    });

    // Background task: renew capacity lease heartbeats for this replica every 60s so that
    // long-running queries on a live instance are never reclaimed by `expire_stale` (cutoff
    // is 300s — five missed beats). Leases of crashed replicas stop heartbeating and expire.
    if let Some(cap) = app_state.capacity_store.clone() {
        let state = app_state.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }
                if let Err(e) = cap.heartbeat(&state.instance_id).await {
                    state.metrics.on_coordination_failure("capacity_heartbeat");
                    tracing::warn!("Capacity lease heartbeat failed: {e}");
                }
            }
        });
    }

    // Background task: release capacity for zombie executing queries (client disconnected
    // before polling to completion). Runs every 120s; evicts entries not polled for > 5 min.
    //
    // Uses `last_accessed` from persistence — updated by any proxy instance that handles
    // a poll, throttled to at most one write per 120s. Safe across multiple instances.
    // Also expires stale capacity leases from crashed replicas.
    tokio::spawn({
        let state = app_state.clone();
        let distributed_backend = distributed_backend.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        async move {
            const CLIENT_TIMEOUT_SECS: i64 = 300; // matches Trino's query.client.timeout default
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }

                // Single-owner sweep: the eviction and lease expiry below are global
                // (idempotent, but redundant on every replica), so only the replica
                // holding the advisory lock runs them this cycle. A crashed owner's
                // lock is released with its connection, so another replica takes
                // over on its next tick. On lock errors, fail open and sweep anyway.
                let sweep_lock = match &distributed_backend {
                    Some(backend) => match backend.try_sweep_lock("zombie-eviction").await {
                        Ok(Some(lock)) => Some(lock),
                        Ok(None) => continue, // another replica owns this cycle
                        Err(e) => {
                            state.metrics.on_coordination_failure("sweep_lock");
                            tracing::warn!("Sweep lock failed, sweeping anyway: {e}");
                            None
                        }
                    },
                    None => None,
                };

                let cutoff = chrono::Utc::now() - chrono::Duration::seconds(CLIENT_TIMEOUT_SECS);

                // Expire stale capacity leases (crashed replicas).
                if let Some(cap) = &state.capacity_store {
                    match cap.expire_stale(cutoff).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!("Expired {n} stale capacity leases"),
                        Err(e) => {
                            state.metrics.on_coordination_failure("capacity_expire");
                            tracing::warn!("Capacity lease expiry failed: {e}");
                        }
                    }
                }

                let Ok(all) = state.persistence.list_all().await else {
                    continue;
                };
                for q in all {
                    if q.last_accessed < cutoff {
                        tracing::warn!(
                            id = %q.backend_query_id,
                            cluster = %q.cluster_name,
                            group = %q.cluster_group,
                            last_accessed = %q.last_accessed,
                            "Evicting zombie executing query — not polled for >5 min"
                        );

                        // Best-effort cancel on the backend with cluster credentials
                        // (same path as client/admin cancel). The previous unauthenticated
                        // DELETE on `/v1/statement/executing/...` did not stop secured Trino.
                        let backend_id = q.backend_query_id.clone();
                        let wire_auth = q.wire_auth.clone();
                        let cluster = q.cluster_name.0.clone();
                        let (engine_type, tgt_dialect) =
                            if let Some(adapter) = state.adapter(&cluster).await {
                                (adapter.engine_type(), adapter.translation_target_dialect())
                            } else {
                                state.engine_type_for_cluster(&cluster).await
                            };
                        state.record_executing_cancelled(
                            &q,
                            queryflux_core::query::FrontendProtocol::TrinoHttp,
                            engine_type,
                            tgt_dialect,
                            "zombie_evicted: not polled for >5 min",
                        );
                        if let Some(adapter) = state.adapter(&cluster).await {
                            tokio::spawn(async move {
                                if let Err(e) =
                                    adapter.cancel_query(&backend_id, wire_auth.as_ref()).await
                                {
                                    tracing::debug!(
                                        "Zombie cancel request failed (best-effort): {e}"
                                    );
                                }
                            });
                        } else {
                            tracing::debug!(
                                cluster = %cluster,
                                id = %q.backend_query_id,
                                "No adapter available for zombie cancel"
                            );
                        }

                        state
                            .release_query_slot(&q.cluster_group, &q.cluster_name, &q.id.0)
                            .await;
                        let _ = state.persistence.delete(&q.backend_query_id).await;
                    }
                }

                if let Some(lock) = sweep_lock {
                    lock.release().await;
                }
            }
        }
    });

    // Background task: clean up stale queued queries (client disconnected before getting
    // cluster capacity). Runs every 120s;
    // deletes queued entries not accessed for > 5 minutes.
    tokio::spawn({
        let state = app_state.clone();
        let distributed_backend = distributed_backend.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        async move {
            const CLIENT_TIMEOUT_SECS: i64 = 300;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }

                let sweep_lock = match &distributed_backend {
                    Some(backend) => match backend.try_sweep_lock("stale-queued-eviction").await {
                        Ok(Some(lock)) => Some(lock),
                        Ok(None) => continue,
                        Err(e) => {
                            state.metrics.on_coordination_failure("sweep_lock");
                            tracing::warn!("Stale queued sweep lock failed, sweeping anyway: {e}");
                            None
                        }
                    },
                    None => None,
                };

                let cutoff = chrono::Utc::now() - chrono::Duration::seconds(CLIENT_TIMEOUT_SECS);
                let Ok(queued) = state.persistence.list_queued().await else {
                    if let Some(lock) = sweep_lock {
                        lock.release().await;
                    }
                    continue;
                };
                let mut cleaned = 0u64;
                for q in queued {
                    if q.last_accessed < cutoff {
                        if let Ok(Some(taken)) = state.persistence.take_queued(&q.id).await {
                            state.record_queued_terminal(
                                &taken,
                                queryflux_core::query::QueryStatus::Failed,
                                "stale_queued_evicted: client disconnected before dispatch",
                            );
                            cleaned += 1;
                        }
                    }
                }
                if cleaned > 0 {
                    tracing::info!("Cleaned up {cleaned} stale queued queries");
                }

                if let Some(lock) = sweep_lock {
                    lock.release().await;
                }
            }
        }
    });

    // Background task: periodically clean up expired cache entries.
    {
        let cache = app_state.result_cache.clone();
        let interval_secs = config
            .queryflux
            .cache_backend
            .as_ref()
            .map(|c| c.cleanup_interval_secs)
            .unwrap_or(300);
        if interval_secs > 0 {
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    return;
                }
                loop {
                    if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                        break;
                    }
                    match cache.cleanup_expired().await {
                        Ok(0) => {}
                        Ok(n) => {
                            tracing::info!(deleted = n, "Cache cleanup: removed expired entries")
                        }
                        Err(e) => tracing::warn!(error = %e, "Cache cleanup failed"),
                    }
                }
            });
        }
    }

    // Background task: enforce query_history_retention_days — runs hourly and deletes
    // query_records, query_digest_stats, and cluster_snapshots older than the window.
    // Only active when Postgres is configured and retention_days is set.
    if let (Some(backend), Some(retention_days)) = (
        backend.clone(),
        config.queryflux.query_history_retention_days,
    ) {
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                return;
            }
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }
                let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
                match backend.purge_old_query_records(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!("Purged {n} history rows older than {retention_days} days")
                    }
                    Err(e) => tracing::warn!("Query history purge failed: {e}"),
                }
            }
        });
    }

    // Background task: hot-reload routing rules + cluster configs from the DB when:
    //   1. Another replica bumps the config revision (distributed LISTEN/NOTIFY via ConfigRevisionStore)
    //   2. This replica's admin API writes config (local tokio::sync::Notify fast-path)
    //   3. A periodic timer fires (safety-net polling, configurable via configReloadIntervalSecs)
    //
    // When no durable backend is configured, only local Notify triggers guard-chain reloads.
    tokio::spawn({
        let live = live.clone();
        let backend = backend.clone();
        let cache = adapter_reload_cache.clone();
        let notify = config_reload_notify.clone();
        let admin_for_reload = admin_store_for_reload;
        let metrics = app_state.metrics.clone();
        let periodic_secs = config.queryflux.periodic_config_reload_interval_secs();
        let mut shutdown_rx = shutdown_rx.clone();

        // Subscribe to distributed config revision changes (push where the
        // backend supports it, e.g. Postgres LISTEN/NOTIFY).
        let revision_rx = if let Some(backend) = &backend {
            match backend.subscribe_revisions().await {
                Ok(Some(rx)) => {
                    tracing::info!("Subscribed to backend config revision notifications");
                    Some(rx)
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!("Failed to subscribe to config revision notifications: {e}");
                    None
                }
            }
        } else {
            None
        };

        async move {
            async fn do_reload(
                backend: &Arc<dyn BackendStore>,
                cache: &tokio::sync::Mutex<AdapterReloadCache>,
                live: &Arc<tokio::sync::RwLock<LiveConfig>>,
                metrics: &Arc<dyn MetricsStore>,
            ) {
                let mut cache_guard = cache.lock().await;
                // Snapshot the pieces a reload must never silently weaken; the
                // read guard is dropped before the write below.
                let prev = {
                    let l = live.read().await;
                    PreservedLive {
                        auth_provider: l.auth_provider.clone(),
                        authorization: l.authorization.clone(),
                        guard_chain: l.guard_chain.clone(),
                        group_guard_chains: l.group_guard_chains.clone(),
                        access_control_guard: l.access_control_guard.clone(),
                        catalog: l.catalog.clone(),
                    }
                };
                // A rejected reload must not change the adapter/state cache that
                // the next attempt uses to preserve the currently live breakers.
                let mut candidate_cache = cache_guard.clone();
                match reload_live_config(backend, &mut candidate_cache, &prev, metrics).await {
                    Ok(new_live) => {
                        let mut live_guard = live.write().await;
                        *cache_guard = candidate_cache;
                        *live_guard = new_live;
                        tracing::info!("Live config reloaded from backend");
                    }
                    Err(e) => {
                        metrics.on_config_reload_failure("reload");
                        tracing::warn!("Config reload failed: {e}");
                    }
                }
            }

            async fn reload_guard_chain_from_admin(
                admin: &Option<Arc<dyn AdminStore>>,
                live: &Arc<tokio::sync::RwLock<LiveConfig>>,
                metrics: &Arc<dyn MetricsStore>,
            ) {
                if let Some(store) = admin {
                    let guard_script_bodies =
                        load_guard_script_bodies_from_admin(store.as_ref()).await;
                    match store.get_proxy_setting("guardrails_config").await {
                        Ok(Some(v)) => {
                            let (global, groups) =
                                build_guard_chains_from_db_value(&v, &guard_script_bodies);
                            let mut w = live.write().await;
                            w.guard_chain = global;
                            w.group_guard_chains = groups;
                        }
                        Ok(None) => {
                            let mut w = live.write().await;
                            w.guard_chain = None;
                            w.group_guard_chains = HashMap::new();
                        }
                        Err(e) => {
                            metrics.on_config_reload_failure("guard_reload");
                            tracing::warn!("Guard chain reload failed: {e}");
                        }
                    }
                    // Catalog provider: same admin-store-only reload contract as guard
                    // chains above — a `Null` provider is always a safe fallback (schema-aware
                    // translation just degrades to dialect-only), unlike auth/authz.
                    match store.get_proxy_setting("catalog_config").await {
                        Ok(Some(v)) => {
                            match serde_json::from_value::<
                                queryflux_core::config::CatalogProviderConfig,
                            >(v)
                            {
                                Ok(cfg) => {
                                    let provider =
                                        queryflux_catalog::build_catalog_provider(&cfg).await;
                                    live.write().await.catalog = provider;
                                }
                                Err(e) => {
                                    metrics.on_config_reload_failure("catalog_reload");
                                    tracing::warn!("Catalog config parse failed: {e}");
                                }
                            }
                        }
                        Ok(None) => {
                            live.write().await.catalog =
                                Arc::new(queryflux_core::catalog::NullCatalogProvider);
                        }
                        Err(e) => {
                            metrics.on_config_reload_failure("catalog_reload");
                            tracing::warn!("Catalog config reload failed: {e}");
                        }
                    }
                    match store.get_proxy_setting("access_control_config").await {
                        Ok(Some(v)) => match apply_stored_access_control(&v) {
                            Ok(guard) => {
                                live.write().await.access_control_guard = guard;
                            }
                            Err(e) => {
                                metrics.on_config_reload_failure("access_control_reload");
                                tracing::warn!("Access control config parse/build failed: {e}");
                            }
                        },
                        Ok(None) => {}
                        Err(e) => {
                            metrics.on_config_reload_failure("access_control_reload");
                            tracing::warn!("Access control config reload failed: {e}");
                        }
                    }
                }
            }

            async fn do_reload_or_guard(
                backend: &Option<Arc<dyn BackendStore>>,
                cache: &tokio::sync::Mutex<AdapterReloadCache>,
                live: &Arc<tokio::sync::RwLock<LiveConfig>>,
                admin: &Option<Arc<dyn AdminStore>>,
                metrics: &Arc<dyn MetricsStore>,
            ) {
                if let Some(backend) = backend {
                    do_reload(backend, cache, live, metrics).await;
                } else {
                    // YAML-mode reload contract: without a Postgres backend, routing rules,
                    // cluster configs, and adapters are fixed at startup from the YAML file
                    // and cannot change at runtime. Only guard chains (stored in the admin
                    // store) can be hot-reloaded via the admin API. Routing or cluster
                    // changes in YAML require a process restart.
                    reload_guard_chain_from_admin(admin, live, metrics).await;
                }
            }

            // Wrap the optional receiver so we can always select on it.
            let mut revision_rx = revision_rx;

            // Coalesce notification bursts: a bulk admin save bumps the revision
            // once per write, and each bump is one channel message — without
            // draining, N rapid writes would trigger N full reloads (adapter
            // rebuilds included) on every replica. A short settle window lets
            // writes a few hundred ms apart collapse into one reload too.
            async fn coalesce_revisions(rx: &mut Option<tokio::sync::mpsc::Receiver<u64>>) {
                if let Some(rx) = rx.as_mut() {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    while rx.try_recv().is_ok() {}
                }
            }

            // A future that resolves when the revision receiver gets a message,
            // or pends forever if there is no receiver. A closed channel (the
            // LISTEN/NOTIFY task died) drops the receiver so we don't spin on
            // an immediately-ready `recv()`; periodic polling remains the
            // safety net for config propagation.
            async fn recv_revision(rx: &mut Option<tokio::sync::mpsc::Receiver<u64>>) -> u64 {
                match rx {
                    Some(r) => match r.recv().await {
                        Some(rev) => rev,
                        None => {
                            tracing::warn!(
                                "Config revision channel closed — falling back to periodic polling"
                            );
                            *rx = None;
                            std::future::pending().await
                        }
                    },
                    None => std::future::pending().await,
                }
            }

            match periodic_secs {
                None => loop {
                    tokio::select! {
                        _ = shutdown_rx.wait_for(|v| *v) => break,
                        _ = notify.notified() => {
                            tracing::debug!("Config reload triggered by local admin write");
                        }
                        rev = recv_revision(&mut revision_rx) => {
                            tracing::debug!(revision = rev, "Config reload triggered by distributed revision change");
                        }
                    }
                    coalesce_revisions(&mut revision_rx).await;
                    do_reload_or_guard(&backend, &cache, &live, &admin_for_reload, &metrics).await;
                },
                Some(interval_secs) => {
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                    interval.tick().await; // skip the first immediate tick — startup already loaded
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.wait_for(|v| *v) => break,
                            _ = interval.tick() => {}
                            _ = notify.notified() => {
                                tracing::debug!("Config reload triggered by local admin write");
                            }
                            rev = recv_revision(&mut revision_rx) => {
                                tracing::debug!(revision = rev, "Config reload triggered by distributed revision change");
                            }
                        }
                        coalesce_revisions(&mut revision_rx).await;
                        do_reload_or_guard(&backend, &cache, &live, &admin_for_reload, &metrics)
                            .await;
                    }
                }
            }
        }
    });

    // Background task: health-check each cluster every 30s via its adapter.
    // Clusters with a custom `healthCheckQuery` use that SQL instead of `SELECT 1`.
    // ADBC SaaS backends without a custom query skip health checks (always healthy).
    tokio::spawn({
        let state = app_state.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }
                let (targets, custom_health) = {
                    let live = state.live.read().await;
                    (
                        live.health_check_targets.clone(),
                        live.custom_health_queries.clone(),
                    )
                };
                for (adapter, cstate) in &targets {
                    let cluster_name = &cstate.cluster_name.0;
                    let breaker_probe = BreakerProbeGuard::reserve(cstate);
                    let healthy = if let Some(custom_sql) = custom_health.get(cluster_name) {
                        adapter.execute_custom_health_check(custom_sql).await
                    } else {
                        adapter.health_check().await
                    };
                    if let Some(probe) = breaker_probe {
                        let state = probe.finish(healthy);
                        tracing::info!(
                            cluster = %cluster_name,
                            group = %cstate.group_name.0,
                            breaker_state = ?state,
                            "Circuit breaker health probe completed"
                        );
                    }
                    if !healthy {
                        tracing::warn!(
                            cluster = %cluster_name,
                            group = %cstate.group_name.0,
                            "Health check failed — marking cluster unhealthy"
                        );
                    } else if !cstate.is_healthy() {
                        tracing::info!(
                            cluster = %cluster_name,
                            group = %cstate.group_name.0,
                            "Health check recovered — marking cluster healthy"
                        );
                    }
                    cstate.set_healthy(healthy);
                }
            }
        }
    });

    // Background task: reconcile in-memory running_queries counters with ground truth
    // from each engine (engines that implement fetch_running_query_count). Runs every 30s.
    // Corrects drift caused by proxy crashes, client disconnects, or any other leak.
    // In distributed mode, only the replica holding the `engine-reconcile` sweep lock
    // queries backends; it publishes counts to Postgres and other replicas sync locally.
    tokio::spawn({
        let state = app_state.clone();
        let distributed_backend = distributed_backend.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                if !tick_or_shutdown(&mut interval, &mut shutdown_rx).await {
                    break;
                }
                let (targets, custom_reconcile) = {
                    let live = state.live.read().await;
                    (
                        live.health_check_targets.clone(),
                        live.custom_reconcile_queries.clone(),
                    )
                };
                let targets = reconcile_targets_from_health_targets(&targets);

                if let Some(ref db) = distributed_backend {
                    let capacity_store =
                        db.clone() as Arc<dyn queryflux_persistence::CapacityStore>;
                    match db.try_sweep_lock("engine-reconcile").await {
                        Ok(Some(lock)) => {
                            for (adapter, states) in &targets {
                                let cluster_name = &states[0].cluster_name.0;
                                let tracked = observe_running(states);
                                let actual = fetch_engine_running_count(
                                    adapter,
                                    cluster_name,
                                    &custom_reconcile,
                                )
                                .await;
                                if let Some(count) = actual {
                                    if let Err(e) = capacity_store
                                        .publish_running_count(cluster_name, count)
                                        .await
                                    {
                                        state
                                            .metrics
                                            .on_coordination_failure("engine_reconcile_publish");
                                        tracing::warn!(
                                            cluster = %cluster_name,
                                            "Failed to publish engine running count: {e}"
                                        );
                                    }
                                }
                                for (cstate, tracked) in states.iter().zip(tracked) {
                                    apply_reconcile_to_cluster_state(cstate, tracked, actual);
                                }
                            }
                            let _ = lock.release().await;
                        }
                        Ok(None) => {
                            for (_, states) in &targets {
                                let cluster_name = &states[0].cluster_name.0;
                                let tracked = observe_running(states);
                                match capacity_store.active_count(cluster_name).await {
                                    Ok(count) => {
                                        for (cstate, tracked) in states.iter().zip(tracked) {
                                            apply_reconcile_to_cluster_state(
                                                cstate,
                                                tracked,
                                                Some(count),
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        state
                                            .metrics
                                            .on_coordination_failure("engine_reconcile_read");
                                        tracing::warn!(
                                            cluster = %cluster_name,
                                            "Failed to read engine running count: {e}"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            state
                                .metrics
                                .on_coordination_failure("engine_reconcile_sweep_lock");
                            tracing::warn!("Engine reconcile sweep lock failed: {e}");
                        }
                    }
                } else {
                    for (adapter, states) in &targets {
                        let cluster_name = &states[0].cluster_name.0;
                        let tracked = observe_running(states);
                        let actual =
                            fetch_engine_running_count(adapter, cluster_name, &custom_reconcile)
                                .await;
                        for (cstate, tracked) in states.iter().zip(tracked) {
                            apply_reconcile_to_cluster_state(cstate, tracked, actual);
                        }
                    }
                }
            }
        }
    });

    // Spawn all enabled frontends as tasks. Each frontend observes `shutdown_rx`
    // internally: axum-based frontends use `with_graceful_shutdown` (stop accepting,
    // finish in-flight requests), wire-based frontends break their accept loop, and
    // tonic (Flight SQL) uses `serve_with_shutdown`.
    let mut frontend_tasks = FrontendTasks::default();

    frontend_tasks.spawn_if_enabled("Trino HTTP", trino_cfg.enabled, || {
        let state = app_state.clone();
        let rx = shutdown_rx.clone();
        let cfg = trino_cfg;
        async move {
            TrinoHttpFrontend::new(state, cfg.port, cfg.max_connections)
                .listen(rx)
                .await
        }
    });
    frontend_tasks.spawn("Admin", {
        let rx = shutdown_rx.clone();
        async move { admin.listen(rx).await }
    });
    if let Some(cfg) = config.queryflux.frontends.mysql_wire.clone() {
        frontend_tasks.spawn_if_enabled("MySQL wire", cfg.enabled, || {
            let state = app_state.clone();
            let rx = shutdown_rx.clone();
            async move {
                MysqlWireFrontend::new(state, cfg.port, cfg.max_connections)
                    .listen(rx)
                    .await
            }
        });
    }
    if let Some(cfg) = config.queryflux.frontends.postgres_wire.clone() {
        frontend_tasks.spawn_if_enabled("Postgres wire", cfg.enabled, || {
            let state = app_state.clone();
            let rx = shutdown_rx.clone();
            async move {
                PostgresWireFrontend::new(state, cfg.port, cfg.max_connections)
                    .listen(rx)
                    .await
            }
        });
    }
    if let Some(cfg) = config.queryflux.frontends.flight_sql.clone() {
        frontend_tasks.spawn_if_enabled("Flight SQL", cfg.enabled, || {
            let state = app_state.clone();
            let rx = shutdown_rx.clone();
            async move {
                FlightSqlFrontend::new(state, cfg.port, cfg.max_connections)
                    .listen(rx)
                    .await
            }
        });
    }
    if let Some(cfg) = config.queryflux.frontends.snowflake_http.clone() {
        frontend_tasks.spawn_if_enabled("Snowflake", cfg.enabled, || {
            let state = app_state.clone();
            let rx = shutdown_rx.clone();
            async move { SnowflakeFrontend::new(state, cfg).listen(rx).await }
        });
    }
    if let Some(cfg) = config.queryflux.frontends.mcp.clone() {
        frontend_tasks.spawn_if_enabled("MCP", cfg.enabled, || {
            let state = app_state.clone();
            let rx = shutdown_rx.clone();
            async move {
                McpFrontend::new(state, cfg.port, cfg.max_connections)
                    .listen(rx)
                    .await
            }
        });
    }

    // Wait for either a shutdown signal or an unexpected frontend exit.
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => tracing::info!("Received SIGINT — initiating graceful shutdown"),
                _ = sigterm.recv() => tracing::info!("Received SIGTERM — initiating graceful shutdown"),
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            tracing::info!("Received Ctrl-C — initiating graceful shutdown");
        }
    };

    tokio::select! {
        _ = shutdown_signal => {},
        exit = frontend_tasks.join_next() => {
            if let Some(exit) = exit {
                match exit.result {
                    Ok(Ok(())) => tracing::warn!(frontend = exit.name, "Frontend exited unexpectedly"),
                    Ok(Err(error)) => tracing::error!(frontend = exit.name, "Frontend exited unexpectedly: {error}"),
                    Err(error) => tracing::error!(frontend = exit.name, "Frontend task failed: {error}"),
                }
            }
        },
    }

    // --- Phase 1: signal all frontends to stop accepting new connections ---
    let _ = shutdown_tx.send(true);

    // --- Phase 2: drain in-flight requests ---
    let drain_timeout_secs = config.queryflux.shutdown_drain_timeout_secs();
    let drain_timeout = std::time::Duration::from_secs(drain_timeout_secs);
    tracing::info!("Draining in-flight requests (timeout: {drain_timeout_secs}s)...");

    let drain_future = async {
        // Wait for enabled frontends to finish processing in-flight requests.
        // Axum frontends complete when all connections are done; wire frontends
        // return immediately from their accept loop but spawned connection tasks
        // continue running.
        frontend_tasks.drain().await;

        // Poll persistence until no executing or queued queries remain (or until
        // the outer timeout fires). This covers spawned wire-protocol connection
        // handlers that are still mid-query after the accept loop exited.
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            interval.tick().await;
            let executing = app_state
                .persistence
                .list_all()
                .await
                .map(|v| v.len())
                .unwrap_or(0);
            let queued = app_state
                .persistence
                .list_queued()
                .await
                .map(|v| v.len())
                .unwrap_or(0);
            if executing == 0 && queued == 0 {
                tracing::info!("All in-flight queries drained");
                break;
            }
            tracing::info!(executing, queued, "Waiting for queries to drain...");
        }
    };

    if tokio::time::timeout(drain_timeout, drain_future)
        .await
        .is_err()
    {
        let outstanding_frontends = frontend_tasks.outstanding_names();
        let executing = app_state
            .persistence
            .list_all()
            .await
            .map(|v| v.len())
            .unwrap_or(0);
        let queued = app_state
            .persistence
            .list_queued()
            .await
            .map(|v| v.len())
            .unwrap_or(0);
        tracing::warn!(
            executing,
            queued,
            ?outstanding_frontends,
            "Drain timeout reached after {drain_timeout_secs}s — forcing shutdown"
        );
    }

    // --- Phase 3: release capacity leases owned by this replica ---
    tracing::info!("Releasing capacity leases for this replica...");
    if let Some(cap) = &app_state.capacity_store {
        if let Err(e) = cap.release_all_for_instance(&app_state.instance_id).await {
            tracing::warn!("Failed to release capacity leases on shutdown: {e}");
        } else {
            tracing::info!("Capacity leases released");
        }
    }

    tracing::info!("QueryFlux shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Hot-reload helpers
// ---------------------------------------------------------------------------

/// Clusters with `queryAuth: passthrough` when `authorization.provider` is `none` — the
/// gateway enforces no access policy, so a client's own credential decides what it can
/// reach. Returned regardless of `cluster_groups.len()`: a single-group deployment (the
/// common default) has this gap just as much as a multi-group one, it's just narrower in
/// blast radius, which is why the caller reports the group count rather than gating on it.
fn unauthenticated_passthrough_clusters(
    config: &queryflux_core::config::ProxyConfig,
) -> Vec<&String> {
    if !matches!(
        config.authorization.provider,
        queryflux_core::config::AuthorizationProviderConfig::None
    ) {
        return Vec::new();
    }
    // `build_authorization` still enforces a per-group SimpleAuthorizationPolicy when
    // provider is `none` but any group declares an allow-list — mirror that check so this
    // warning only fires on the genuinely allow-all case, not one that already has policy.
    let has_any_policy = config.cluster_groups.values().any(|cfg| {
        !cfg.authorization.allow_groups.is_empty() || !cfg.authorization.allow_users.is_empty()
    });
    if has_any_policy {
        return Vec::new();
    }
    config
        .clusters
        .iter()
        .filter(|(_, cfg)| {
            matches!(
                cfg.query_auth,
                Some(queryflux_core::config::QueryAuthConfig::Passthrough)
            )
        })
        .map(|(name, _)| name)
        .collect()
}

/// A cancelled health-check future must not leave its member HalfOpen forever.
struct BreakerProbeGuard {
    state: Arc<ClusterState>,
    completed: bool,
}

impl BreakerProbeGuard {
    fn reserve(state: &Arc<ClusterState>) -> Option<Self> {
        state.begin_breaker_probe().then(|| Self {
            state: state.clone(),
            completed: false,
        })
    }

    fn finish(
        mut self,
        healthy: bool,
    ) -> Option<queryflux_cluster_manager::circuit_breaker::CircuitState> {
        let result = self.state.finish_breaker_probe(healthy);
        self.completed = true;
        result
    }
}

impl Drop for BreakerProbeGuard {
    fn drop(&mut self) {
        if !self.completed {
            // The probe did not finish (for example, its task was cancelled).
            // Treat it as a failed check and retry after the usual backoff.
            self.state.finish_breaker_probe(false);
        }
    }
}

/// Health probes are per group/member; engine reconciliation is per backend.
/// Keep every member state so the single fetched count reaches all groups.
fn reconcile_targets_from_health_targets<A: Clone>(
    targets: &[(A, Arc<ClusterState>)],
) -> Vec<(A, Vec<Arc<ClusterState>>)> {
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut grouped: Vec<(_, Vec<Arc<ClusterState>>)> = Vec::new();
    for (adapter, state) in targets {
        let name = &state.cluster_name.0;
        if let Some(&index) = positions.get(name) {
            grouped[index].1.push(state.clone());
        } else {
            positions.insert(name.clone(), grouped.len());
            grouped.push((adapter.clone(), vec![state.clone()]));
        }
    }
    grouped
}

async fn fetch_engine_running_count(
    adapter: &queryflux_engine_adapters::AdapterKind,
    cluster_name: &str,
    custom_reconcile: &HashMap<String, String>,
) -> Option<u64> {
    if let Some(custom_sql) = custom_reconcile.get(cluster_name) {
        adapter.execute_custom_reconcile_query(custom_sql).await
    } else {
        adapter.fetch_running_query_count().await
    }
}

/// Read every state's running counter before the (slow) engine fetch, so the correction can
/// be applied relative to what was observed — see [`apply_reconcile_to_cluster_state`].
fn observe_running(
    states: &[Arc<queryflux_cluster_manager::cluster_state::ClusterState>],
) -> Vec<u64> {
    states.iter().map(|s| s.running_queries()).collect()
}

/// `tracked` is the counter value observed *before* the engine count was fetched. The fix is
/// applied as a relative correction (`ClusterState::reconcile_running`), so queries admitted or
/// released while the fetch was in flight — including through a newer config generation that
/// shares this counter after a reload — are not overwritten by a stale count.
fn apply_reconcile_to_cluster_state(
    cstate: &queryflux_cluster_manager::cluster_state::ClusterState,
    tracked: u64,
    actual: Option<u64>,
) {
    let cluster_name = &cstate.cluster_name.0;
    let max = cstate.max_running_queries();
    if tracked > max {
        let fix = actual.unwrap_or(0);
        tracing::warn!(
            cluster = %cluster_name,
            group = %cstate.group_name.0,
            tracked,
            max,
            fix,
            "running_queries above group capacity; resetting from engine count"
        );
        cstate.reconcile_running(tracked, fix);
        return;
    }
    if let Some(actual) = actual {
        if actual != tracked {
            tracing::info!(
                cluster = %cluster_name,
                group = %cstate.group_name.0,
                tracked,
                actual,
                "Reconciling running_queries counter with engine ground truth"
            );
            cstate.reconcile_running(tracked, actual);
        }
    }
}

/// Metrics chain for in-memory persistence: Prometheus plus the in-memory store
/// itself. The in-memory store must be part of the chain — the admin API serves
/// `/admin/queries` and `/admin/stats` from it, so recording only to Prometheus
/// leaves query history and the Studio dashboard permanently empty.
fn in_memory_metrics(
    prometheus: Arc<PrometheusMetrics>,
    mem: Arc<InMemoryPersistence>,
) -> Arc<dyn MetricsStore> {
    Arc::new(MultiMetricsStore::new(vec![
        prometheus as Arc<dyn MetricsStore>,
        mem as Arc<dyn MetricsStore>,
    ]))
}

#[cfg(test)]
mod tests {
    mod circuit_breaker_reload {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        use queryflux_cluster_manager::circuit_breaker::{BackendOutcome, CircuitState};
        use queryflux_cluster_manager::cluster_state::ClusterState;
        use queryflux_core::config::{CircuitBreakerConfig, ClusterGroupConfig};
        use queryflux_core::query::{ClusterGroupName, ClusterName, EngineType};

        use super::super::{
            reconcile_targets_from_health_targets, AdapterReloadCache, BreakerProbeGuard,
        };
        use crate::live_config::{compile_live_config, CompileMode, ConfigIds, LiveConfigInputs};

        fn state(group: &str, name: &str, breaker: bool) -> Arc<ClusterState> {
            let state = ClusterState::new(
                ClusterName(name.to_string()),
                ClusterGroupName(group.to_string()),
                None,
                None,
                EngineType::ClickHouse,
                None,
                10,
                true,
            );
            Arc::new(if breaker {
                state.with_circuit_breaker(
                    Some(CircuitBreakerConfig {
                        min_requests: 1,
                        failure_rate_percent: 100,
                        initial_backoff_secs: 1,
                        max_backoff_secs: 2,
                        ..CircuitBreakerConfig::default()
                    }),
                    None,
                )
            } else {
                state
            })
        }

        #[test]
        fn shared_backend_is_reconciled_once_but_updates_each_group() {
            let first = state("group-a", "shared", false);
            let second = state("group-b", "shared", false);
            let other = state("group-a", "other", false);
            let targets = vec![
                ("adapter-a", first.clone()),
                ("adapter-a", second.clone()),
                ("adapter-b", other.clone()),
            ];
            let grouped = reconcile_targets_from_health_targets(&targets);
            assert_eq!(grouped.len(), 2);
            assert_eq!(grouped[0].1.len(), 2);
            assert_eq!(grouped[1].1.len(), 1);
            for member in &grouped[0].1 {
                member.set_running_queries(3);
            }
            assert_eq!(first.running_queries(), 3);
            assert_eq!(second.running_queries(), 3);
            assert_eq!(other.running_queries(), 0);
        }

        #[tokio::test]
        async fn invalid_reload_does_not_replace_cached_breaker_states() {
            let old = state("group", "old", true);
            let key = ("group".to_string(), "old".to_string());
            let mut cache = AdapterReloadCache {
                adapters: HashMap::new(),
                config_json: HashMap::new(),
                cluster_states: HashMap::from([(key.clone(), old.clone())]),
                routing_fallback: "group".to_string(),
                routers_cfg: Vec::new(),
                strategies: HashMap::new(),
            };
            let group: ClusterGroupConfig = serde_json::from_value(serde_json::json!({
                "members": ["missing"],
                "maxRunningQueries": 10
            }))
            .expect("valid group fixture");
            let inputs = LiveConfigInputs {
                groups: HashMap::from([("group".to_string(), group)]),
                routing_fallback: "group".to_string(),
                ..LiveConfigInputs::default()
            };
            let result = compile_live_config(
                &inputs,
                &ConfigIds::default(),
                &mut cache,
                CompileMode::Lenient,
            )
            .await;
            assert!(result.is_err(), "unknown member must reject reload");
            assert!(Arc::ptr_eq(
                cache.cluster_states.get(&key).expect("old state retained"),
                &old
            ));
        }

        fn duck_record(
            config: serde_json::Value,
        ) -> queryflux_persistence::cluster_config::ClusterConfigRecord {
            queryflux_persistence::cluster_config::ClusterConfigRecord {
                id: 1,
                name: "duck".to_string(),
                engine_key: "duckDb".to_string(),
                enabled: true,
                max_running_queries: None,
                config,
                variants: serde_json::json!([]),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }
        }

        async fn reload(
            record: &queryflux_persistence::cluster_config::ClusterConfigRecord,
            cache: &mut AdapterReloadCache,
        ) -> crate::LiveConfig {
            let group: ClusterGroupConfig = serde_json::from_value(serde_json::json!({
                "members": ["duck"],
                "maxRunningQueries": 10
            }))
            .expect("valid group fixture");
            let inputs = LiveConfigInputs::from_records(
                std::slice::from_ref(record),
                HashMap::from([("g".to_string(), group)]),
                Vec::new(),
                "g".to_string(),
                HashMap::new(),
            );
            compile_live_config(&inputs, &ConfigIds::default(), cache, CompileMode::Lenient)
                .await
                .expect("reload succeeds")
        }

        async fn running(live: &crate::LiveConfig) -> u64 {
            live.cluster_manager.all_cluster_states().await.unwrap()[0].running_queries
        }

        fn empty_cache() -> AdapterReloadCache {
            AdapterReloadCache {
                adapters: HashMap::new(),
                config_json: HashMap::new(),
                cluster_states: HashMap::new(),
                routing_fallback: "g".to_string(),
                routers_cfg: Vec::new(),
                strategies: HashMap::new(),
            }
        }

        /// Regression for #299: a query in flight across a reload releases through the
        /// generation that admitted it; the new generation must not keep its slot.
        #[tokio::test]
        async fn reload_does_not_leak_in_flight_running_count() {
            let record = duck_record(serde_json::json!({}));
            let mut cache = empty_cache();
            let group = ClusterGroupName("g".to_string());

            let gen1 = reload(&record, &mut cache).await;
            let cluster = gen1
                .cluster_manager
                .acquire_cluster(&group)
                .await
                .unwrap()
                .unwrap();
            let gen2 = reload(&record, &mut cache).await;
            assert_eq!(
                running(&gen2).await,
                1,
                "in-flight query still counts after reload"
            );

            gen1.cluster_manager
                .release_cluster(&group, &cluster)
                .await
                .unwrap();
            assert_eq!(running(&gen2).await, 0);
            let gen3 = reload(&record, &mut cache).await;
            assert_eq!(running(&gen3).await, 0);
        }

        /// A reconcile pass that captured the previous generation must not overwrite an
        /// admission made through the new generation while the engine fetch was in flight.
        #[tokio::test]
        async fn stale_generation_reconcile_keeps_new_generation_admissions() {
            let record = duck_record(serde_json::json!({}));
            let mut cache = empty_cache();
            let group = ClusterGroupName("g".to_string());

            let gen1 = reload(&record, &mut cache).await;
            // One leaked slot: the counter says 1, the engine runs nothing.
            gen1.cluster_manager
                .acquire_cluster(&group)
                .await
                .unwrap()
                .unwrap();
            let gen1_state = cache
                .cluster_states
                .get(&("g".to_string(), "duck".to_string()))
                .cloned()
                .expect("gen1 state cached");
            let tracked = gen1_state.running_queries(); // reconcile observes 1, starts the fetch

            // A reload shares the counter; the new generation admits a real query.
            let gen2 = reload(&record, &mut cache).await;
            gen2.cluster_manager
                .acquire_cluster(&group)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(running(&gen2).await, 2);

            // The engine count (0, taken before the admission) lands through the stale state:
            // only the leaked slot is removed, the new admission survives.
            super::super::apply_reconcile_to_cluster_state(&gen1_state, tracked, Some(0));
            assert_eq!(running(&gen2).await, 1);
        }

        /// A query admitted before a config-changing reload still counts against the member,
        /// and is released correctly through either generation (#301).
        #[tokio::test]
        async fn changed_config_reload_keeps_counting_in_flight_queries() {
            let mut cache = empty_cache();
            let group = ClusterGroupName("g".to_string());

            let gen1 = reload(&duck_record(serde_json::json!({})), &mut cache).await;
            let sync_slot = gen1
                .cluster_manager
                .acquire_cluster(&group)
                .await
                .unwrap()
                .unwrap();
            let async_slot = gen1
                .cluster_manager
                .acquire_cluster(&group)
                .await
                .unwrap()
                .unwrap();
            let gen2 = reload(&duck_record(serde_json::json!({"poolSize": 2})), &mut cache).await;
            assert_eq!(
                running(&gen2).await,
                2,
                "in-flight queries still occupy the member"
            );

            // Sync dispatch releases through the manager that admitted the query.
            gen1.cluster_manager
                .release_cluster(&group, &sync_slot)
                .await
                .unwrap();
            assert_eq!(running(&gen2).await, 1);
            // Async terminals (poll, cancel) release through the current manager.
            gen2.cluster_manager
                .release_cluster(&group, &async_slot)
                .await
                .unwrap();
            assert_eq!(running(&gen2).await, 0);
            assert_eq!(running(&gen1).await, 0);
        }

        #[test]
        fn dropped_probe_reopens_breaker_instead_of_stranding_half_open() {
            let member = state("group", "backend", true);
            assert_eq!(
                member.record_backend_outcome(BackendOutcome::Failure),
                Some(CircuitState::Open)
            );
            std::thread::sleep(Duration::from_secs(1));
            let probe = BreakerProbeGuard::reserve(&member).expect("probe should be ready");
            assert_eq!(member.breaker_state(), Some(CircuitState::HalfOpen));
            drop(probe);
            assert_eq!(member.breaker_state(), Some(CircuitState::Open));
        }

        #[test]
        fn completed_probe_is_not_reopened_on_drop() {
            let member = state("group", "backend", true);
            member.record_backend_outcome(BackendOutcome::Failure);
            std::thread::sleep(Duration::from_secs(1));
            let probe = BreakerProbeGuard::reserve(&member).expect("probe should be ready");
            assert_eq!(probe.finish(true), Some(CircuitState::Closed));
            assert_eq!(member.breaker_state(), Some(CircuitState::Closed));
        }
    }

    mod group_translation_scripts {
        use std::collections::HashMap;

        use super::super::validate_group_translation_scripts;

        #[test]
        fn drops_only_the_group_whose_script_fails_validation() {
            let scripts = HashMap::from([
                (
                    "good-group".to_string(),
                    vec!["def transform(sql, src, dst):\n    return sql\n".to_string()],
                ),
                (
                    "legacy-group".to_string(),
                    vec!["def transform(ast, src, dst):\n    return None\n".to_string()],
                ),
            ]);
            let valid = validate_group_translation_scripts(scripts);
            assert_eq!(valid.get("good-group").map(Vec::len), Some(1));
            assert_eq!(valid.get("legacy-group").map(Vec::len), Some(0));
        }
    }

    mod frontend_tasks {
        use std::time::Duration;

        use super::super::FrontendTasks;

        #[tokio::test]
        async fn disabled_frontend_does_not_block_shutdown_drain() {
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
            let mut frontends = FrontendTasks::default();
            let mut disabled_task_constructed = false;

            frontends.spawn("enabled", async move {
                shutdown_rx
                    .wait_for(|shutdown| *shutdown)
                    .await
                    .expect("shutdown sender should remain available");
                Ok(())
            });
            frontends.spawn_if_enabled("disabled", false, || {
                disabled_task_constructed = true;
                std::future::pending()
            });

            assert!(!disabled_task_constructed);

            shutdown_tx
                .send(true)
                .expect("enabled frontend is listening");
            tokio::time::timeout(Duration::from_secs(1), frontends.drain())
                .await
                .expect("disabled frontend must not hold the drain open");

            assert!(frontends.outstanding_names().is_empty());
        }
    }

    mod unauthenticated_passthrough_warning {
        use super::super::unauthenticated_passthrough_clusters;
        use queryflux_core::config::ProxyConfig;
        use serde_json::json;

        fn config(authorization_provider: &str, clusters: serde_json::Value) -> ProxyConfig {
            config_with_groups(authorization_provider, clusters, json!({}))
        }

        fn config_with_groups(
            authorization_provider: &str,
            clusters: serde_json::Value,
            cluster_groups: serde_json::Value,
        ) -> ProxyConfig {
            serde_json::from_value(json!({
                "queryflux": { "externalAddress": null },
                "clusters": clusters,
                "clusterGroups": cluster_groups,
                "authorization": { "provider": authorization_provider },
            }))
            .expect("valid minimal ProxyConfig fixture")
        }

        fn passthrough_cluster() -> serde_json::Value {
            json!({
                "trino-1": {
                    "engine": "trino",
                    "endpoint": "http://trino:8080",
                    "queryAuth": { "type": "passthrough" },
                }
            })
        }

        #[test]
        fn warns_even_with_a_single_cluster_group() {
            // Regression: this used to be gated on `cluster_groups.len() > 1`, hiding the
            // warning for the common single-group default — exactly the most likely
            // deployment to have this gap.
            let cfg = config("none", passthrough_cluster());
            assert_eq!(cfg.cluster_groups.len(), 0);
            let flagged = unauthenticated_passthrough_clusters(&cfg);
            assert_eq!(flagged, vec!["trino-1"]);
        }

        #[test]
        fn no_warning_when_authorization_is_configured() {
            let cfg = config("openfga", passthrough_cluster());
            assert!(unauthenticated_passthrough_clusters(&cfg).is_empty());
        }

        #[test]
        fn no_warning_without_any_passthrough_cluster() {
            let cfg = config(
                "none",
                json!({
                    "trino-1": {
                        "engine": "trino",
                        "endpoint": "http://trino:8080",
                    }
                }),
            );
            assert!(unauthenticated_passthrough_clusters(&cfg).is_empty());
        }

        #[test]
        fn no_warning_when_a_group_allow_list_already_enforces_policy() {
            // build_authorization treats provider:none + any group allow-list as an
            // enforced SimpleAuthorizationPolicy, not allow-all — this check must agree,
            // or the warning fires for deployments that already have the gap closed.
            let cfg = config_with_groups(
                "none",
                passthrough_cluster(),
                json!({
                    "trino": {
                        "members": ["trino-1"],
                        "maxRunningQueries": 10,
                        "authorization": { "allowGroups": ["data-team"] },
                    }
                }),
            );
            assert!(unauthenticated_passthrough_clusters(&cfg).is_empty());
        }

        #[test]
        fn warns_when_groups_exist_but_none_declare_an_allow_list() {
            let cfg = config_with_groups(
                "none",
                passthrough_cluster(),
                json!({
                    "trino": {
                        "members": ["trino-1"],
                        "maxRunningQueries": 10,
                    }
                }),
            );
            assert_eq!(unauthenticated_passthrough_clusters(&cfg), vec!["trino-1"]);
        }
    }

    mod guard_chains {
        use std::collections::{BTreeMap, HashMap};

        use queryflux_core::config::{GuardKindConfig, GuardSpecConfig, GuardrailsConfig};
        use queryflux_core::query::{ClusterGroupName, EngineType, SqlDialect};
        use queryflux_core::tags::QueryTags;
        use queryflux_guardrails::context::{GuardChainOutcome, GuardContext, GuardLayer};

        use crate::guards::{build_chain_from_db_specs, build_chain_from_yaml_specs};

        fn is_blocked(o: &GuardChainOutcome) -> bool {
            matches!(o, GuardChainOutcome::Blocked { .. })
        }

        static EMPTY_S: Vec<String> = Vec::new();
        static GENERIC_DIALECT: SqlDialect = SqlDialect::Generic;
        static EMPTY_ATTRS: std::sync::LazyLock<BTreeMap<String, serde_json::Value>> =
            std::sync::LazyLock::new(BTreeMap::new);
        static EMPTY_EXTRA: std::sync::LazyLock<HashMap<String, String>> =
            std::sync::LazyLock::new(HashMap::new);

        fn plan_ctx<'a>(
            engine: &'a EngineType,
            group: &'a ClusterGroupName,
            tags: &'a QueryTags,
        ) -> GuardContext<'a> {
            GuardContext {
                sql: "SELECT 1",
                original_sql: None,
                dialect: &GENERIC_DIALECT,
                engine_type: engine,
                cluster_group: group,
                user: Some("alice"),
                groups: &EMPTY_S,
                roles: &EMPTY_S,
                attributes: &EMPTY_ATTRS,
                agent_context: None,
                query_tags: tags,
                session_extra: &EMPTY_EXTRA,
                schema: None,
                sql_parse: None,
            }
        }

        #[tokio::test]
        async fn yaml_unknown_built_in_denies_at_runtime() {
            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = vec![GuardSpecConfig {
                kind: GuardKindConfig::BuiltIn,
                name: Some("does_not_exist".to_string()),
                script_id: None,
                script: None,
                url: None,
                timeout_ms: None,
                retry_count: None,
                fail_behavior: None,
                headers: None,
                max_rows: None,
                applies_to: None,
            }];
            let chain = build_chain_from_yaml_specs(&specs, &HashMap::new())
                .expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (actions, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(is_blocked(&outcome));
            assert_eq!(actions.len(), 1);
            assert_eq!(actions[0].guard, "built_in");
            assert_eq!(actions[0].action, "deny");
        }

        #[tokio::test]
        async fn yaml_python_script_without_body_denies_at_runtime() {
            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = vec![GuardSpecConfig {
                kind: GuardKindConfig::PythonScript,
                name: None,
                script_id: None,
                script: None,
                url: None,
                timeout_ms: None,
                retry_count: None,
                fail_behavior: None,
                headers: None,
                max_rows: None,
                applies_to: None,
            }];
            let err = GuardrailsConfig {
                global: specs.clone(),
                groups: HashMap::new(),
            }
            .validate()
            .expect_err("startup validation must reject");
            assert!(err.contains("script"), "{err}");

            // Misconfigured guards still deny if validation is bypassed (e.g. DB reload).
            let chain = build_chain_from_yaml_specs(&specs, &HashMap::new())
                .expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (_, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(is_blocked(&outcome));
        }

        #[tokio::test]
        async fn db_unknown_kind_denies_at_runtime() {
            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = serde_json::json!([{ "kind": "future_kind" }]);
            let chain =
                build_chain_from_db_specs(&specs, &HashMap::new()).expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (actions, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(is_blocked(&outcome));
            assert_eq!(actions[0].guard, "guard");
            assert!(actions[0]
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("future_kind"));
        }

        #[tokio::test]
        async fn inline_python_script_guard_allows() {
            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = vec![GuardSpecConfig {
                kind: GuardKindConfig::PythonScript,
                name: None,
                script_id: None,
                script: Some("def check(ctx):\n    return {'action': 'allow'}".to_string()),
                url: None,
                timeout_ms: Some(500),
                retry_count: None,
                fail_behavior: None,
                headers: None,
                max_rows: None,
                applies_to: None,
            }];
            let chain = build_chain_from_yaml_specs(&specs, &HashMap::new())
                .expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (_, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(!is_blocked(&outcome));
        }

        #[tokio::test]
        async fn non_http_webhook_url_denies_even_when_fail_open() {
            use queryflux_core::config::GuardFailBehaviorConfig;

            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = vec![GuardSpecConfig {
                kind: GuardKindConfig::HttpWebhook,
                name: None,
                script_id: None,
                script: None,
                url: Some("file:///tmp/policy".to_string()),
                timeout_ms: Some(100),
                retry_count: None,
                fail_behavior: Some(GuardFailBehaviorConfig::Allow),
                headers: None,
                max_rows: None,
                applies_to: None,
            }];
            let chain = build_chain_from_yaml_specs(&specs, &HashMap::new())
                .expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (actions, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(
                is_blocked(&outcome),
                "non-http(s) webhook URL must deny at construction"
            );
            assert_eq!(actions[0].guard, "http_webhook");
            assert!(actions[0]
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("http or https"));
        }

        #[tokio::test]
        async fn http_webhook_url_is_accepted_and_can_fail_open() {
            use queryflux_core::config::GuardFailBehaviorConfig;

            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = vec![GuardSpecConfig {
                kind: GuardKindConfig::HttpWebhook,
                name: None,
                script_id: None,
                script: None,
                url: Some("http://127.0.0.1:1/unreachable".to_string()),
                timeout_ms: Some(100),
                retry_count: Some(0),
                fail_behavior: Some(GuardFailBehaviorConfig::Allow),
                headers: None,
                max_rows: None,
                applies_to: None,
            }];
            let chain = build_chain_from_yaml_specs(&specs, &HashMap::new())
                .expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (_, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(
                !is_blocked(&outcome),
                "valid http(s) webhook with fail_open must allow when unreachable"
            );
        }

        #[tokio::test]
        async fn db_non_http_webhook_url_denies_at_runtime() {
            let engine = EngineType::DuckDb;
            let group = ClusterGroupName("default".to_string());
            let tags = QueryTags::new();
            let specs = serde_json::json!([{
                "kind": "http_webhook",
                "url": "ftp://evil.example/guard",
                "fail_behavior": "allow"
            }]);
            let chain =
                build_chain_from_db_specs(&specs, &HashMap::new()).expect("chain should be built");
            let ctx = plan_ctx(&engine, &group, &tags);
            let (actions, outcome) = chain.run(&ctx, GuardLayer::Plan).await;
            assert!(is_blocked(&outcome));
            assert_eq!(actions[0].guard, "http_webhook");
            assert!(actions[0]
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("http or https"));
        }
    }

    mod in_memory_metrics {
        use std::sync::Arc;

        use queryflux_core::query::{
            ClusterGroupName, ClusterName, EngineType, FrontendProtocol, QueryStatus, SqlDialect,
        };
        use queryflux_metrics::{prometheus_store::PrometheusMetrics, QueryRecord};
        use queryflux_persistence::{
            in_memory::InMemoryPersistence, query_history::QueryFilters, QueryHistoryStore,
        };

        fn sample_record() -> QueryRecord {
            QueryRecord {
                proxy_query_id: "q-1".into(),
                backend_query_id: None,
                cluster_group: ClusterGroupName("duckdb-local".to_string()),
                cluster_name: ClusterName("duckdb-1".to_string()),
                cluster_group_config_id: None,
                cluster_config_id: None,
                engine_type: EngineType::DuckDb,
                frontend_protocol: FrontendProtocol::TrinoHttp,
                source_dialect: SqlDialect::Trino,
                target_dialect: SqlDialect::DuckDb,
                was_rewritten: false,
                rewritten_sql: None,
                was_translated: false,
                translation: None,
                translated_sql: None,
                user: None,
                catalog: None,
                database: None,
                sql_preview: "SELECT 1".into(),
                status: QueryStatus::Success,
                routing_trace: None,
                queue_duration_ms: 0,
                execution_duration_ms: 1,
                rows_returned: Some(1),
                error_message: None,
                created_at: chrono::Utc::now(),
                engine_stats: None,
                query_tags: Default::default(),
                query_hash: None,
                query_parameterized_hash: None,
                translated_query_hash: None,
                digest_text: None,
                translated_digest_text: None,
                agent_id: None,
                conversation_id: None,
                step_index: None,
                tool_call_id: None,
                query_intent: None,
                guard_actions: Vec::new(),
                was_guard_blocked: false,
                cache_hit: false,
            }
        }

        /// Regression test: with in-memory persistence, queries recorded through
        /// the metrics chain must land in the same store the admin API reads
        /// (`/admin/queries`, `/admin/stats`). Wiring Prometheus alone leaves the
        /// dashboard and query history permanently empty.
        #[tokio::test]
        async fn records_query_history_in_backing_store() {
            let prometheus = Arc::new(PrometheusMetrics::new().expect("prometheus init"));
            let mem = Arc::new(InMemoryPersistence::new());
            let metrics = super::super::in_memory_metrics(prometheus, mem.clone());

            metrics
                .record_query(sample_record())
                .await
                .expect("record_query");

            // `limit: 0` is the `Default` value and returns nothing; the HTTP
            // layer fills it via serde's `default_limit` (50) instead.
            let filters = QueryFilters {
                limit: 50,
                ..Default::default()
            };
            let rows = mem.list_queries(&filters).await.expect("list_queries");
            assert_eq!(rows.len(), 1, "query must be visible to the admin API");
            assert_eq!(rows[0].sql_preview, "SELECT 1");
        }
    }
}
