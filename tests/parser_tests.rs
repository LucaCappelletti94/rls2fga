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
        .expect("ownables columns")
        .map(|c| c.column_name().to_string())
        .collect();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0], "id");
    assert_eq!(cols[1], "owner_id");

    let team_members = db.table(None, "team_members").expect("team_members table");
    let tm_col_count = team_members
        .columns(&db)
        .expect("team_members columns")
        .count();
    assert_eq!(tm_col_count, 2);
}

#[test]
fn parse_emi_schema_foreign_keys() {
    let db = support::parse_fixture_db("earth_metabolome");

    let team_members = db.table(None, "team_members").expect("team_members table");
    let fk_count = team_members
        .foreign_keys(&db)
        .expect("team_members foreign keys")
        .count();
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

    let rls_tables: Vec<_> = db.rls_tables().expect("rls tables").collect();
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

/// Every schema accessor rls2fga calls is fallible upstream, and rls2fga reads an error
/// as "the schema does not say" so the decision falls closed. That is only safe because
/// the error cannot occur: every object is fetched from the same database it is then
/// queried against, which is exactly what `LookupError::ObjectNotInDatabase` reports.
/// Nothing in the type system enforces that, so assert it over the whole corpus. A
/// failure here means a fail-closed default has started hiding a real diagnosis.
#[test]
fn no_schema_lookup_fails_on_any_fixture() {
    let mut dirs: Vec<_> = std::fs::read_dir("tests/fixtures")
        .expect("fixtures directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.join("input.sql").is_file())
        .collect();
    dirs.sort();
    assert!(dirs.len() > 20, "the corpus should not have shrunk");

    let mut failures: Vec<String> = Vec::new();
    let mut visited = 0usize;

    for dir in dirs {
        let name = dir.file_name().expect("fixture name").to_string_lossy();
        let sql = std::fs::read_to_string(dir.join("input.sql")).expect("fixture SQL");
        let Ok(db) = parse_schema(&sql) else {
            continue;
        };

        if db.rls_tables().map(Iterator::count).is_err() {
            failures.push(format!("{name}: rls_tables"));
        }
        for table in db.tables() {
            let table_name = table.table_name();
            visited += 1;
            let mut note = |what: &str| failures.push(format!("{name}: {table_name} {what}"));

            if table.has_row_level_security(&db).is_err() {
                note("has_row_level_security");
            }
            if table.has_composite_primary_key(&db).is_err() {
                note("has_composite_primary_key");
            }
            if table.primary_key_column(&db).is_err() {
                note("primary_key_column");
            }
            if table.primary_key_columns(&db).map(Iterator::count).is_err() {
                note("primary_key_columns");
            }
            if table.policies(&db).map(Iterator::count).is_err() {
                note("policies");
            }

            match table.columns(&db) {
                Ok(columns) => {
                    for column in columns {
                        if column.is_nullable(&db).is_err() {
                            note("column is_nullable");
                        }
                    }
                }
                Err(_) => note("columns"),
            }
            match table.unique_indices(&db) {
                Ok(indices) => {
                    for index in indices {
                        if index.columns(&db).map(Iterator::count).is_err() {
                            note("unique index columns");
                        }
                    }
                }
                Err(_) => note("unique_indices"),
            }
            match table.foreign_keys(&db) {
                Ok(foreign_keys) => {
                    for foreign_key in foreign_keys {
                        if foreign_key.host_column(&db).is_err() {
                            note("fk host_column");
                        }
                        if foreign_key.host_columns(&db).map(Iterator::count).is_err() {
                            note("fk host_columns");
                        }
                        if foreign_key.referenced_table(&db).is_err() {
                            note("fk referenced_table");
                        }
                    }
                }
                Err(_) => note("foreign_keys"),
            }
        }
    }

    assert!(
        visited > 20,
        "only {visited} tables checked, so the corpus is not being walked"
    );
    assert!(
        failures.is_empty(),
        "a fail-closed default is hiding a real diagnosis:\n{}",
        failures.join("\n")
    );
}

/// The invariant above is worth asserting only because violating it is reported rather
/// than ignored. Querying a table against a database that does not hold it is exactly
/// the mistake `LookupError::ObjectNotInDatabase` exists for, and upstream used to abort
/// on it. This pins that it now returns an error, so the fail-closed defaults in
/// `db_lookup` and the generator are covering a condition that can genuinely arise.
#[test]
fn a_table_queried_against_another_database_is_reported() {
    let owning = parse_schema("CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);")
        .expect("schema should parse");
    let other = parse_schema("CREATE TABLE notes(id UUID PRIMARY KEY);").expect("schema parses");

    let docs = owning.table(None, "docs").expect("docs table");
    assert!(
        docs.columns(&owning).is_ok(),
        "its own database resolves it"
    );
    assert!(
        docs.columns(&other).is_err(),
        "a database without the table must report rather than answer"
    );
}
