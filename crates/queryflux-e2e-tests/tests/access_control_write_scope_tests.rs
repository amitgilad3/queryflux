//! Row scoping on writes: the policy's row filter is ANDed into an `UPDATE`/`DELETE`'s
//! `WHERE`, so a principal can only modify rows the policy lets them target. `INSERT`,
//! `MERGE` and `TRUNCATE` have no such `WHERE`, so a filter (and any column mask) returned
//! for a write is denied instead.
//!
//! Run with: `cargo test -p queryflux-e2e-tests --test access_control_write_scope_tests`

use queryflux_core::access_model::MaskType;
use queryflux_e2e_tests::access_control::{
    build_guard_with_operations, customers_schema, mask, orders_schema, payroll_schema, pg_connect,
    pg_run, seed_customers, seed_orders, start_opa_stub, MapCatalog, StubState,
};
use queryflux_e2e_tests::harness::ProtocolWireHarness;
use std::sync::{Arc, Mutex};

async fn harness(opa_url: &str, ops: &[&str]) -> ProtocolWireHarness {
    let catalog = MapCatalog::new(vec![customers_schema(), orders_schema(), payroll_schema()]);
    ProtocolWireHarness::new_with_access_control_and_catalog(
        Some(build_guard_with_operations(opa_url, ops)),
        catalog,
    )
    .await
    .expect("harness")
}

/// `id:amount` of every order, read with the policy's filters removed. Seed data:
/// 10:50 EU, 11:150 EU, 12:200 US, 13:80 EU.
async fn orders(client: &tokio_postgres::Client, stub: &Arc<Mutex<StubState>>) -> Vec<String> {
    stub.lock().unwrap().clear_filters();
    pg_run(client, "SELECT id, amount FROM orders ORDER BY id")
        .await
        .expect("read orders")
        .into_iter()
        .map(|r| format!("{}:{}", r[0], r[1]))
        .collect()
}

#[tokio::test]
async fn update_only_touches_rows_the_filter_allows() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.update"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock().unwrap().filter("orders", "region = 'EU'");

    pg_run(&client, "UPDATE orders SET amount = 0")
        .await
        .expect("update");

    assert_eq!(
        orders(&client, &stub).await,
        ["10:0", "11:0", "12:200", "13:0"],
        "the US row is outside the caller's scope and must be untouched"
    );
    let record = h
        .wait_for_record(|r| r.sql_preview.to_lowercase().contains("update orders"))
        .await
        .expect("update recorded");
    assert!(
        record
            .guard_actions
            .iter()
            .any(|a| a.guard == "opa_access" && a.action == "rewrite"),
        "the scoping must be audited as a rewrite: {:?}",
        record.guard_actions
    );
}

#[tokio::test]
async fn delete_only_removes_rows_the_filter_allows() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.delete"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock().unwrap().filter("orders", "region = 'EU'");

    pg_run(&client, "DELETE FROM orders").await.expect("delete");

    assert_eq!(orders(&client, &stub).await, ["12:200"]);
}

/// The policy must constrain the caller's whole `WHERE`, including an `OR`.
#[tokio::test]
async fn filter_constrains_the_statements_own_or() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.delete"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock().unwrap().filter("orders", "region = 'EU'");

    pg_run(&client, "DELETE FROM orders WHERE id = 10 OR id = 12")
        .await
        .expect("delete");

    assert_eq!(
        orders(&client, &stub).await,
        ["11:150", "12:200", "13:80"],
        "12 matches the caller's WHERE but is US, so it must survive"
    );
}

#[tokio::test]
async fn aliased_target_is_scoped() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.update"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock().unwrap().filter("orders", "region = 'EU'");

    pg_run(&client, "UPDATE orders o SET amount = 1 WHERE o.id > 0")
        .await
        .expect("update");

    assert_eq!(
        orders(&client, &stub).await,
        ["10:1", "11:1", "12:200", "13:1"]
    );
}

/// `customers` also has a `region` column: an unqualified filter would be ambiguous.
#[tokio::test]
async fn filter_is_not_ambiguous_against_a_joined_table() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.delete"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_customers(&client).await;
    seed_orders(&client).await;
    stub.lock()
        .unwrap()
        .filter_for("table.delete", "orders", "region = 'EU'");

    pg_run(
        &client,
        "DELETE FROM orders USING customers c WHERE orders.customer_id = c.id",
    )
    .await
    .expect("delete using");

    assert_eq!(orders(&client, &stub).await, ["12:200"]);
}

/// The same table read and written in one statement gets each operation's own filter.
#[tokio::test]
async fn read_and_write_filters_on_the_same_table_are_independent() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.delete"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    {
        let mut st = stub.lock().unwrap();
        st.filter_for("table.select", "orders", "amount > 100");
        st.filter_for("table.delete", "orders", "region = 'EU'");
    }

    // The subquery reads only amount > 100 (11, 12); the delete only reaches EU (10, 11, 13).
    pg_run(
        &client,
        "DELETE FROM orders WHERE id IN (SELECT id FROM orders)",
    )
    .await
    .expect("delete");

    assert_eq!(orders(&client, &stub).await, ["10:50", "12:200", "13:80"]);
}

/// INSERT/MERGE/TRUNCATE have no WHERE to scope, so a returned filter is denied rather than
/// silently dropped.
#[tokio::test]
async fn filters_on_insert_and_truncate_fail_closed() {
    for (op, sql) in [
        (
            "table.insert",
            "INSERT INTO orders VALUES (99, 1, 10, 'EU')",
        ),
        ("table.truncate", "TRUNCATE TABLE orders"),
    ] {
        let (opa_url, stub) = start_opa_stub().await;
        let h = harness(&opa_url, &["table.select", op]).await;
        let client = pg_connect(h.postgres_port).await;
        seed_orders(&client).await;
        stub.lock().unwrap().filter("orders", "region = 'EU'");

        let err = pg_run(&client, sql)
            .await
            .expect_err("filter on a write with no WHERE");
        assert!(
            err.contains("only supported for table.select, table.update and table.delete"),
            "{op}: unexpected error: {err}"
        );
        assert_eq!(
            orders(&client, &stub).await.len(),
            4,
            "{op}: nothing may have changed"
        );
    }
}

#[tokio::test]
async fn column_masks_on_a_write_fail_closed() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.update"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock()
        .unwrap()
        .mask("orders", mask("amount", MaskType::Null));

    let err = pg_run(&client, "UPDATE orders SET amount = 1")
        .await
        .expect_err("a mask on a write must fail closed");
    assert!(
        err.contains("apply to reads only"),
        "unexpected error: {err}"
    );
    // The verification read would be masked too — drop the mask first.
    stub.lock().unwrap().column_masks.clear();
    assert_eq!(
        orders(&client, &stub).await,
        ["10:50", "11:150", "12:200", "13:80"]
    );
}

/// Scoping decides which rows a write may *target*, not what it may write, so an UPDATE that
/// assigns a column the filter depends on could move a row out of the caller's scope. It is
/// refused; updating other columns is unaffected.
#[tokio::test]
async fn update_that_would_move_a_row_out_of_scope_is_refused() {
    let (opa_url, stub) = start_opa_stub().await;
    let h = harness(&opa_url, &["table.select", "table.update"]).await;
    let client = pg_connect(h.postgres_port).await;
    seed_orders(&client).await;
    stub.lock().unwrap().filter("orders", "region = 'EU'");

    let err = pg_run(&client, "UPDATE orders SET region = 'US' WHERE id = 10")
        .await
        .expect_err("moving a row out of scope");
    assert!(err.contains("region"), "unexpected error: {err}");
    assert_eq!(
        orders(&client, &stub).await,
        ["10:50", "11:150", "12:200", "13:80"],
        "nothing may have changed"
    );

    // Other columns are still updatable within scope.
    stub.lock().unwrap().filter("orders", "region = 'EU'");
    pg_run(&client, "UPDATE orders SET amount = 1 WHERE id = 10")
        .await
        .expect("in-scope update of another column");
}
