//! OPA wire format: `{"input": {...}}` request, `{"result": {...}}` response, and the
//! mapping to/from `queryflux_core::access_model`.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use queryflux_core::access_model::{
    AccessDecision, AccessRequest, ColumnMask, Columns, ResourceDecision, ResourceKind, RowFilter,
};

// ---- request ----

#[derive(Serialize)]
pub(super) struct OpaRequest<'a> {
    pub input: OpaInput<'a>,
}

#[derive(Serialize)]
pub(super) struct OpaInput<'a> {
    pub identity: WireIdentity<'a>,
    pub action: WireAction<'a>,
    pub context: WireContext<'a>,
}

#[derive(Serialize)]
pub(super) struct WireIdentity<'a> {
    pub user: &'a str,
    pub groups: &'a [String],
    pub roles: &'a [String],
    pub attributes: &'a BTreeMap<String, Value>,
}

#[derive(Serialize)]
pub(super) struct WireAction<'a> {
    pub operation: &'a str,
    pub resources: Vec<WireResource<'a>>,
    /// What a `GRANT`/`REVOKE` hands out. Only present for `grant.*` and `role.grant/revoke`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<WireGrant<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WireGrant<'a> {
    pub privileges: &'a [String],
    pub grantees: &'a [String],
    pub with_grant_option: bool,
}

fn is_empty_str(s: &&str) -> bool {
    s.is_empty()
}

#[derive(Serialize)]
pub(super) struct WireResource<'a> {
    /// `table`, `view`, `schema` or `catalog` — reads are always tables; DDL can target the rest.
    pub kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<&'a str>,
    /// Only `table` and `view` resources have one; every other kind is identified by `name`.
    #[serde(skip_serializing_if = "is_empty_str")]
    pub table: &'a str,
    /// The value a `SET` assigns to a session setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<&'a str>,
    /// The object's own name (table/view, schema, or catalog) — echo it back in the response.
    pub name: &'a str,
    /// `null` = all columns (schema unresolved / `SELECT *`).
    pub columns: Option<&'a [String]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WireContext<'a> {
    pub cluster_group: &'a str,
    pub engine: &'a str,
    pub query_id: &'a str,
    pub session_params: &'a BTreeMap<String, String>,
}

pub(super) fn to_request(req: &AccessRequest) -> OpaRequest<'_> {
    OpaRequest {
        input: OpaInput {
            identity: WireIdentity {
                user: &req.identity.user,
                groups: &req.identity.groups,
                roles: &req.identity.roles,
                attributes: &req.identity.attributes,
            },
            action: WireAction {
                operation: req.operation.as_str(),
                resources: req
                    .resources
                    .iter()
                    .map(|r| WireResource {
                        kind: r.kind.as_str(),
                        catalog: r.catalog.as_deref(),
                        schema: r.schema.as_deref(),
                        table: if matches!(r.kind, ResourceKind::Table | ResourceKind::View) {
                            &r.table
                        } else {
                            ""
                        },
                        value: r.value.as_deref(),
                        name: r.name(),
                        columns: match &r.columns {
                            Columns::All => None,
                            Columns::Named(c) => Some(c.as_slice()),
                        },
                    })
                    .collect(),
                grant: req.grant.as_ref().map(|g| WireGrant {
                    privileges: &g.privileges,
                    grantees: &g.grantees,
                    with_grant_option: g.with_grant_option,
                }),
            },
            context: WireContext {
                cluster_group: &req.context.cluster_group,
                engine: &req.context.engine,
                query_id: &req.context.query_id,
                session_params: &req.context.session_params,
            },
        },
    }
}

// ---- response ----

#[derive(Deserialize)]
pub(super) struct OpaResponse {
    #[serde(default)]
    pub result: Option<OpaResult>,
}

#[derive(Deserialize)]
pub(super) struct OpaResult {
    #[serde(default)]
    pub resources: Vec<WireResourceDecision>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WireResourceDecision {
    /// Echo of the resource's `table` (table resources) or `name` (any kind); `name` wins if
    /// both are present. Neither → the decision can't be matched and the resource is denied.
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub allow: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub row_filters: Vec<RowFilter>,
    #[serde(default)]
    pub column_masks: Vec<ColumnMask>,
}

/// Map an OPA `{"result": {...}}` body to a neutral [`AccessDecision`].
///
/// A missing `result` (OPA returns `{}` for "undefined") is treated as **deny-all** — the
/// policy must explicitly produce a per-resource verdict. A `result` that omits a verdict
/// for one of the *requested* resources (e.g. a policy bug that only matches some of the
/// tables in a join) is treated as a denial for that resource specifically — `is_allowed()`
/// is a vacuous `all()` over whatever's present, so a silently-missing entry must not be
/// allowed to mean "allowed".
pub(super) fn from_response(resp: OpaResponse, requested: &AccessRequest) -> AccessDecision {
    let Some(result) = resp.result.filter(|r| !r.resources.is_empty()) else {
        return AccessDecision::deny_all(format!(
            "policy returned no decision for {} resource(s)",
            requested.resources.len()
        ));
    };

    let mut resources: Vec<ResourceDecision> = result
        .resources
        .into_iter()
        .map(|r| ResourceDecision {
            table: r.name.or(r.table).unwrap_or_default(),
            allow: r.allow,
            reason: r.reason,
            row_filters: r.row_filters,
            column_masks: r.column_masks,
        })
        .collect();

    let decided: HashSet<String> = resources.iter().map(|r| r.table.clone()).collect();
    for req in &requested.resources {
        if !decided.contains(req.name()) {
            resources.push(ResourceDecision {
                table: req.name().to_string(),
                allow: false,
                reason: Some("policy returned no decision for this resource".to_string()),
                row_filters: Vec::new(),
                column_masks: Vec::new(),
            });
        }
    }

    AccessDecision { resources }
}

#[cfg(test)]
mod tests {
    use super::*;
    use queryflux_core::access_model::{
        AccessResource, Identity, Operation, RequestContext, ResourceKind,
    };

    fn requested(tables: &[&str]) -> AccessRequest {
        AccessRequest {
            grant: None,
            identity: Identity::default(),
            operation: Operation::table_select(),
            resources: tables
                .iter()
                .map(|t| AccessResource {
                    kind: ResourceKind::Table,
                    value: None,
                    catalog: None,
                    schema: None,
                    table: t.to_string(),
                    columns: Columns::All,
                })
                .collect(),
            context: RequestContext::default(),
        }
    }

    /// Regression: a response that only decides some of the requested resources (e.g. a
    /// policy bug that matches one table in a join but not another) must not let the
    /// unmentioned table's vacuous absence read as "allowed" — `is_allowed()` is an
    /// `all()` over whatever's present, so a missing entry has to become an explicit deny.
    #[test]
    fn missing_resource_in_response_is_denied_not_vacuously_allowed() {
        let resp: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"table": "orders", "allow": true}]}}"#,
        )
        .unwrap();
        let decision = from_response(resp, &requested(&["orders", "customers"]));
        assert!(!decision.is_allowed());
        assert_eq!(decision.first_denied().map(|(t, _)| t), Some("customers"));
    }

    fn schema_request(schema: &str) -> AccessRequest {
        let mut req = requested(&[]);
        req.operation = Operation("schema.drop".to_string());
        req.resources = vec![AccessResource {
            kind: ResourceKind::Schema,
            value: None,
            catalog: Some("prod".to_string()),
            schema: Some(schema.to_string()),
            table: String::new(),
            columns: Columns::All,
        }];
        req
    }

    /// DDL targets go out with their `kind` and `name`; a schema has no `table`.
    #[test]
    fn schema_resource_is_sent_with_kind_and_name_and_no_table() {
        let req = schema_request("analytics");
        let json = serde_json::to_value(to_request(&req)).unwrap();
        let r = &json["input"]["action"]["resources"][0];
        assert_eq!(r["kind"], "schema");
        assert_eq!(r["name"], "analytics");
        assert_eq!(r["schema"], "analytics");
        assert_eq!(r["catalog"], "prod");
        assert!(r.get("table").is_none(), "{r}");
        assert_eq!(json["input"]["action"]["operation"], "schema.drop");

        let table = serde_json::to_value(to_request(&requested(&["orders"]))).unwrap();
        let t = &table["input"]["action"]["resources"][0];
        assert_eq!(
            (t["kind"].as_str(), t["table"].as_str(), t["name"].as_str()),
            (Some("table"), Some("orders"), Some("orders"))
        );
    }

    /// Administrative resources are identified by `kind` + `name` (no `table`); a session
    /// setting carries its `value`, and a grant its privileges and grantees.
    #[test]
    fn admin_resources_and_grant_detail_are_sent() {
        use queryflux_core::access_model::GrantDetail;
        let mut req = requested(&[]);
        req.operation = Operation("grant.grant".to_string());
        req.grant = Some(GrantDetail {
            privileges: vec!["SELECT".to_string()],
            grantees: vec!["alice".to_string()],
            with_grant_option: true,
        });
        req.resources = vec![
            AccessResource {
                kind: ResourceKind::Role,
                catalog: None,
                schema: None,
                table: "analyst".to_string(),
                columns: Columns::All,
                value: None,
            },
            AccessResource {
                kind: ResourceKind::Session,
                catalog: None,
                schema: None,
                table: "search_path".to_string(),
                columns: Columns::All,
                value: Some("analytics".to_string()),
            },
        ];
        let json = serde_json::to_value(to_request(&req)).unwrap();
        let a = &json["input"]["action"];
        assert_eq!(a["grant"]["privileges"], serde_json::json!(["SELECT"]));
        assert_eq!(a["grant"]["grantees"], serde_json::json!(["alice"]));
        assert_eq!(a["grant"]["withGrantOption"], true);
        let (role, session) = (&a["resources"][0], &a["resources"][1]);
        assert_eq!(
            (role["kind"].as_str(), role["name"].as_str()),
            (Some("role"), Some("analyst"))
        );
        assert!(
            role.get("table").is_none() && role.get("value").is_none(),
            "{role}"
        );
        assert_eq!(
            (session["kind"].as_str(), session["value"].as_str()),
            (Some("session"), Some("analytics"))
        );

        // A plain read carries neither.
        let plain = serde_json::to_value(to_request(&requested(&["orders"]))).unwrap();
        assert!(plain["input"]["action"].get("grant").is_none());
    }

    /// A policy may echo `name` (any kind) or `table` (table resources); `name` wins.
    #[test]
    fn response_is_matched_on_name_or_table() {
        let by_name: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"name": "analytics", "allow": true}]}}"#,
        )
        .unwrap();
        assert!(from_response(by_name, &schema_request("analytics")).is_allowed());

        let by_table: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"table": "orders", "allow": true}]}}"#,
        )
        .unwrap();
        assert!(from_response(by_table, &requested(&["orders"])).is_allowed());

        let both: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"table": "x", "name": "analytics", "allow": true}]}}"#,
        )
        .unwrap();
        assert!(from_response(both, &schema_request("analytics")).is_allowed());

        // An echo that matches nothing is a missing decision, not an implicit allow.
        let wrong: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"name": "other", "allow": true}]}}"#,
        )
        .unwrap();
        assert!(!from_response(wrong, &schema_request("analytics")).is_allowed());
    }

    #[test]
    fn fully_decided_response_is_allowed() {
        let resp: OpaResponse = serde_json::from_str(
            r#"{"result": {"resources": [{"table": "orders", "allow": true}]}}"#,
        )
        .unwrap();
        let decision = from_response(resp, &requested(&["orders"]));
        assert!(decision.is_allowed());
    }

    #[test]
    fn empty_result_is_deny_all() {
        let resp: OpaResponse = serde_json::from_str(r#"{}"#).unwrap();
        let decision = from_response(resp, &requested(&["orders"]));
        assert!(!decision.is_allowed());
    }
}
