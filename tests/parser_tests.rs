use rls2fga::parser::sql_parser::parse_schema;
use sql_traits::prelude::*;

mod support;

#[test]
fn parse_emi_schema_tables() {
    let db = support::parse_fixture_db("earth_metabolome");

    assert_eq!(db.number_of_tables(), 5, "Expected 5 tables");
    assert!(db.table(None, "users").is_some());
    assert!(db.table(None, "teams").is_some());
    assert!(db.table(None, "team_members").is_some());
    assert!(db.table(None, "ownables").is_some());
    assert!(db.table(None, "owner_grants").is_some());
}

#[test]
fn parse_emi_schema_columns() {
    let db = support::parse_fixture_db("earth_metabolome");

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
    let db = support::parse_fixture_db("earth_metabolome");

    let team_members = db.table(None, "team_members").expect("team_members table");
    let fk_count = team_members.foreign_keys(&db).count();
    assert!(
        fk_count >= 2,
        "team_members should have at least 2 foreign keys, got {fk_count}",
    );
}

#[test]
fn parse_emi_functions() {
    let db = support::parse_fixture_db("earth_metabolome");

    // sql-traits tracks all function references, not just CREATE FUNCTION statements.
    // Verify the two user-defined functions are present.
    assert!(db.function("auth_current_user_id").is_some());
    assert!(db.function("get_owner_role").is_some());
}

#[test]
fn parse_emi_policies() {
    let db = support::parse_fixture_db("earth_metabolome");

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
    let db = support::parse_fixture_db("earth_metabolome");

    let rls_tables: Vec<_> = db.rls_tables().collect();
    assert_eq!(rls_tables.len(), 1);
    assert_eq!(rls_tables[0].table_name(), "ownables");
}

/// `ALTER POLICY ... USING` supersedes the expression the policy was created
/// with. The parser keeps the original, so translating the schema would model a
/// policy `PostgreSQL` no longer has.
#[test]
fn a_policy_expression_the_parser_cannot_apply_is_refused() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
ALTER POLICY docs_sel ON docs USING (TRUE);
";
    let error = parse_schema(sql).expect_err("a superseded policy expression must be refused");
    let rendered = error.to_string();
    assert!(
        rendered.contains("docs_sel"),
        "the operator needs to know which policy was altered, got: {rendered}"
    );
}

/// Renaming a policy leaves its expression alone, so the schema still describes
/// what `PostgreSQL` enforces.
#[test]
fn renaming_a_policy_is_still_accepted() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
ALTER POLICY docs_sel ON docs RENAME TO docs_select;
";
    parse_schema(sql).expect("a rename does not change the expression");
}
