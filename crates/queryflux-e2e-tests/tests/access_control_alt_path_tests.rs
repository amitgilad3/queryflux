//! Other routes to the same data: a table function (`read_csv('f.csv')`) and a bare path
//! (`FROM 'f.csv'`) read a file the way a table reads its rows. They are evaluated under
//! `function.execute` and `location.read` when those operations are enabled.
//!
//! Run with: `cargo test -p queryflux-e2e-tests --test access_control_alt_path_tests`

use queryflux_e2e_tests::access_control::{
    build_guard, build_guard_with_operations, customers_schema, orders_schema, payroll_schema,
    pg_connect, pg_run, seed_customers, start_opa_stub, MapCatalog, StubState,
};
use queryflux_e2e_tests::harness::ProtocolWireHarness;
use serde_json::Value;
use std::sync::{Arc, Mutex};

async fn harness(
    opa_url: &str,
    ops: Option<&[&str]>,
) -> (ProtocolWireHarness, tokio_postgres::Client, String) {
    let catalog = MapCatalog::new(vec![customers_schema(), orders_schema(), payroll_schema()]);
    let guard = match ops {
        Some(ops) => build_guard_with_operations(opa_url, ops),
        None => build_guard(opa_url),
    };
    let h = ProtocolWireHarness::new_with_access_control_and_catalog(Some(guard), catalog)
        .await
        .expect("harness");
    let client = pg_connect(h.postgres_port).await;
    seed_customers(&client).await;
    // The protected table's rows, sitting in a file the backend can read.
    let file = std::env::temp_dir()
        .join(format!(
            "qf_alt_{}_{}.csv",
            std::process::id(),
            opa_url.len() + rand_suffix()
        ))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&file);
    pg_run(&client, &format!("COPY customers TO '{file}'"))
        .await
        .expect("export");
    (h, client, file)
}

fn rand_suffix() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn action(stub: &Arc<Mutex<StubState>>, op: &str) -> Vec<Value> {
    stub.lock().unwrap().actions_for(op)
}

#[tokio::test]
async fn a_table_function_is_evaluated_as_function_execute() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, Some(&["table.select", "function.execute"])).await;
    stub.lock().unwrap().deny("customers");
    stub.lock().unwrap().requests.clear();

    // With the function denied by name, the file's rows are not returned.
    stub.lock().unwrap().deny("read_csv");
    let err = pg_run(&client, &format!("SELECT * FROM read_csv('{file}')"))
        .await
        .expect_err("denied function");
    assert!(err.contains("read_csv"), "unexpected error: {err}");
    let req = &action(&stub, "function.execute")[0];
    let r = &req["resources"][0];
    assert_eq!(
        (r["kind"].as_str(), r["name"].as_str(), r["value"].as_str()),
        (Some("function"), Some("read_csv"), Some(file.as_str()))
    );

    // Allowed, the same query goes through — and is a separate call from any table read.
    stub.lock().unwrap().deny_tables.remove("read_csv");
    let rows = pg_run(&client, &format!("SELECT * FROM read_csv('{file}')"))
        .await
        .expect("allowed function");
    assert_eq!(rows.len(), 3);
    let _ = std::fs::remove_file(&file);
}

#[tokio::test]
async fn a_bare_path_is_evaluated_as_location_read() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, Some(&["table.select", "location.read"])).await;
    stub.lock().unwrap().requests.clear();
    stub.lock().unwrap().deny(file.clone());

    let err = pg_run(&client, &format!("SELECT * FROM '{file}'"))
        .await
        .expect_err("denied location");
    assert!(err.contains("qf_alt_"), "unexpected error: {err}");
    let r = &action(&stub, "location.read")[0]["resources"][0];
    assert_eq!(
        (r["kind"].as_str(), r["name"].as_str()),
        (Some("location"), Some(file.as_str()))
    );
    assert!(
        action(&stub, "table.select").is_empty(),
        "a location is not a table read"
    );
    let _ = std::fs::remove_file(&file);
}

/// Without `location.read` a bare path stays visible exactly as before: a `table.select` on the
/// path-named "table", so an existing policy that denies it keeps working.
#[tokio::test]
async fn a_bare_path_falls_back_to_a_table_read_when_location_read_is_off() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, None).await;
    stub.lock().unwrap().requests.clear();
    stub.lock().unwrap().deny(file.clone());

    pg_run(&client, &format!("SELECT * FROM '{file}'"))
        .await
        .expect_err("denied as a table");
    let r = &action(&stub, "table.select")[0]["resources"][0];
    assert_eq!(
        (r["kind"].as_str(), r["name"].as_str()),
        (Some("table"), Some(file.as_str()))
    );
    let _ = std::fs::remove_file(&file);
}

#[tokio::test]
async fn a_table_function_is_not_evaluated_unless_enabled() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, None).await;
    stub.lock().unwrap().requests.clear();
    stub.lock().unwrap().deny("read_csv");

    pg_run(&client, &format!("SELECT * FROM read_csv('{file}')"))
        .await
        .expect("not evaluated by default");
    assert!(
        stub.lock().unwrap().requests.is_empty(),
        "no provider call by default"
    );
    let _ = std::fs::remove_file(&file);
}

/// A function read and a table read in one statement are separate calls.
#[tokio::test]
async fn function_and_table_reads_are_separate_calls() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, Some(&["table.select", "function.execute"])).await;
    stub.lock().unwrap().requests.clear();

    pg_run(
        &client,
        &format!("SELECT c.name FROM customers c JOIN read_csv('{file}') f ON c.id = f.id"),
    )
    .await
    .expect("join");
    assert_eq!(action(&stub, "function.execute").len(), 1);
    assert_eq!(action(&stub, "table.select").len(), 1);
    let _ = std::fs::remove_file(&file);
}

/// Set-returning helpers read no data, so there is nothing to authorize.
#[tokio::test]
async fn generators_are_not_function_reads() {
    let (opa_url, stub) = start_opa_stub().await;
    let (_h, client, file) = harness(&opa_url, Some(&["table.select", "function.execute"])).await;
    stub.lock().unwrap().requests.clear();

    pg_run(&client, "SELECT * FROM generate_series(1, 3)")
        .await
        .expect("generate_series");
    assert!(action(&stub, "function.execute").is_empty());
    let _ = std::fs::remove_file(&file);
}
