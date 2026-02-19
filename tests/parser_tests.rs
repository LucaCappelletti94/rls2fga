use rls2fga::parser::sql_parser;
use sql_traits::prelude::*;

#[test]
fn parse_emi_schema_tables() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    assert_eq!(db.number_of_tables(), 5, "Expected 5 tables");
    assert!(db.table(None, "users").is_some());
    assert!(db.table(None, "teams").is_some());
    assert!(db.table(None, "team_members").is_some());
    assert!(db.table(None, "ownables").is_some());
    assert!(db.table(None, "owner_grants").is_some());
}

#[test]
fn parse_emi_schema_columns() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let ownables = db.table(None, "ownables").expect("ownables table");
    let cols: Vec<String> = ownables
        .columns(&db)
        .map(|c| c.column_name().to_string())
        .collect();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0], "id");
    assert_eq!(cols[1], "owner_id");

    let team_members = db.table(None, "team_members").expect("team_members table");
    let tm_col_count = team_members.columns(&db).count();
    assert_eq!(tm_col_count, 2);
}

#[test]
fn parse_emi_schema_foreign_keys() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let team_members = db.table(None, "team_members").expect("team_members table");
    let fk_count = team_members.foreign_keys(&db).count();
    assert!(
        fk_count >= 2,
        "team_members should have at least 2 foreign keys, got {fk_count}",
    );
}

#[test]
fn parse_emi_functions() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    // sql-traits tracks all function references, not just CREATE FUNCTION statements.
    // Verify the two user-defined functions are present.
    assert!(db.function("auth_current_user_id").is_some());
    assert!(db.function("get_owner_role").is_some());
}

#[test]
fn parse_emi_policies() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let policies: Vec<_> = db.policies().collect();
    assert_eq!(policies.len(), 4, "Expected 4 policies");

    let select_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_select_policy")
        .unwrap();
    assert_eq!(select_policy.table_name.to_string(), "ownables");
    assert!(matches!(
        select_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Select)
    ));
    assert!(select_policy.using.is_some());
    assert!(select_policy.with_check.is_none());

    let insert_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_insert_policy")
        .unwrap();
    assert!(matches!(
        insert_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Insert)
    ));
    assert!(insert_policy.using.is_none());
    assert!(insert_policy.with_check.is_some());

    let update_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_update_policy")
        .unwrap();
    assert!(matches!(
        update_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Update)
    ));
    assert!(update_policy.using.is_some());
    assert!(update_policy.with_check.is_some());

    let delete_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_delete_policy")
        .unwrap();
    assert!(matches!(
        delete_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Delete)
    ));
    assert!(delete_policy.using.is_some());
}

#[test]
fn parse_emi_rls_enabled() {
    let sql = std::fs::read_to_string("tests/fixtures/earth_metabolome/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).unwrap();

    let rls_tables: Vec<_> = db.rls_tables().collect();
    assert_eq!(rls_tables.len(), 1);
    assert_eq!(rls_tables[0].table_name(), "ownables");
}
