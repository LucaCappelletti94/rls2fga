//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! How an identifier is spelled, and the name `PostgreSQL` stores it under.

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::notes::TranslationNote;
use rls2fga::generator::tuple_generator::format_tuples;

mod support;

use support::footgun::{db_of, relation_definition, translator, type_names};

/// A quoted identifier may contain a dot. Treating it as a schema separator names
/// the type after a fragment of the table name.
#[test]
fn quoted_dot_in_a_table_name_is_not_read_as_a_schema_separator() {
    let db = db_of(
        "CREATE TABLE \"we.ird\"(id UUID PRIMARY KEY);\n\
         ALTER TABLE \"we.ird\" ENABLE ROW LEVEL SECURITY;\n",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert!(
        type_names(&dsl).iter().any(|name| name == "we_ird"),
        "the type must derive from the whole quoted name, got: {:?}\n{dsl}",
        type_names(&dsl)
    );
}

/// A policy may spell the parent table quoted. Matching that spelling against the
/// declared foreign key as raw text loses the inheritance and tells the operator to
/// declare a foreign key the schema already has.
#[test]
fn a_quoted_parent_reference_still_inherits() {
    let schema = |parent_ref: &str| {
        format!(
            "CREATE TABLE parents(id UUID PRIMARY KEY, owner_id UUID);\n\
             ALTER TABLE parents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY parents_sel ON parents FOR SELECT USING (owner_id = current_user);\n\
             CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES parents(id));\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM {parent_ref} p\n\
               WHERE p.id = docs.parent_id AND p.owner_id = current_user));\n"
        )
    };
    let read_of = |parent_ref: &str| {
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db_of(&schema(parent_ref)))
            .outputs_accepting_gaps()
            .model();
        relation_definition(&dsl, "docs", "can_select")
    };

    assert_eq!(
        read_of("parents").as_deref(),
        Some("owner from parents"),
        "the bare spelling must inherit, or this comparison proves nothing"
    );
    assert_eq!(
        read_of("\"parents\"").as_deref(),
        Some("owner from parents"),
        "quoting the parent table in the policy must not lose the inheritance"
    );
}

/// `PostgreSQL` folds an unquoted identifier to lowercase, so a table declared
/// `Docs` with a column `ID` is stored as `docs` and `id`. Emitting the source
/// spelling quoted asks for a relation and a column that do not exist.
#[test]
fn generated_sql_names_identifiers_the_way_postgres_stores_them() {
    let db = db_of(
        r"
CREATE TABLE Docs(ID UUID PRIMARY KEY, Owner_Id TEXT);
ALTER TABLE Docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON Docs FOR SELECT USING (owner_id = current_user);
",
    );
    let rendered = format_tuples(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"FROM "docs""#),
        "the stored relation name is docs:\n{rendered}"
    );
    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "the stored column name is id:\n{rendered}"
    );
    assert!(
        rendered.contains(r#""owner_id""#),
        "the stored column name is owner_id:\n{rendered}"
    );
}

/// A quoted declaration keeps its case, and both spellings may name distinct
/// columns of one table, so folding must follow the quoting.
#[test]
fn a_quoted_column_keeps_the_case_postgres_stores_it_under() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, "Owner_Id" TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING ("Owner_Id" = current_user);
"#,
    );
    let rendered = format_tuples(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#""Owner_Id""#),
        "a quoted column is stored verbatim:\n{rendered}"
    );
}

/// The policy and the declaration may spell one column in different cases, and
/// unquoted they still name the same stored column.
#[test]
fn a_policy_reaches_a_column_the_declaration_spells_in_another_case() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (Owner_Id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the relation name follows the stored column, not the policy's spelling:\n{dsl}"
    );
    assert!(
        rendered.contains(r#""owner_id""#) && !rendered.contains(r#""Owner_Id""#),
        "the stored column name is owner_id:\n{rendered}"
    );
}

/// A membership join whose columns are declared in mixed case still resolves,
/// since `PostgreSQL` reads the policy's folded spelling as the same column.
#[test]
fn mixed_case_membership_columns_still_infer_the_join() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(Doc_Id UUID REFERENCES docs(id), User_Id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user)
);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert_ne!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the membership join resolves, so reads are granted:\n{dsl}"
    );

    // The other direction: the declaration is lowercase and the policy spells
    // the same columns in another case.
    let policy_side = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.Doc_Id = docs.ID AND m.User_Id = current_user)
);
",
    );
    let policy_side_dsl = translator(ConfidenceLevel::B)
        .translate(&policy_side)
        .outputs_accepting_gaps()
        .model();
    assert_ne!(
        relation_definition(&policy_side_dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the policy's spelling folds to the declared columns:\n{policy_side_dsl}"
    );
}

/// A foreign key declared in mixed case still carries parent inheritance.
#[test]
fn a_mixed_case_foreign_key_still_inherits_the_parent_rule() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, Project_Id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    assert_eq!(
        relation_definition(&dsl, "tasks", "can_select").as_deref(),
        Some("owner from projects"),
        "the parent link resolves through the stored column name:\n{dsl}"
    );
    assert!(
        format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries()
        )
        .contains(r#"'projects:' || CASE WHEN "project_id"::text"#),
        "the bridge query reads the stored column name"
    );

    // The other direction: the declaration is lowercase and the policy spells
    // the join columns in another case.
    let policy_side = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.ID = tasks.Project_Id AND p.Owner_Id = current_user));
",
    );
    assert_eq!(
        relation_definition(
            &translator
                .translate(&policy_side)
                .outputs_accepting_gaps()
                .model(),
            "tasks",
            "can_select"
        )
        .as_deref(),
        Some("owner from projects"),
        "the policy's spelling folds to the declared columns"
    );
}

/// The `id` fallback for a row identifier answers for a column declared `ID`.
#[test]
fn a_mixed_case_unique_id_column_identifies_a_row() {
    let db = db_of(
        r"
CREATE TABLE docs(ID UUID UNIQUE NOT NULL, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let rendered = format_tuples(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "the unique NOT NULL id column identifies the row:\n{rendered}"
    );
}

/// A quoted `"current_user"` names a real role, not the keyword, and the `Owner` enum
/// tells them apart, so the role keeps its ordinary scope.
#[test]
fn a_quoted_current_user_role_is_a_role() {
    let db = db_of(
        r#"
CREATE ROLE "current_user";
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO "current_user" USING (owner_id = current_user);
"#,
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from scope_"),
        "a quoted role scopes like any other:\n{dsl}"
    );
    assert!(
        outputs
            .tuple_queries()
            .iter()
            .any(|q| q.sql.contains("'pg_role:current_user'")),
        "the real role's scope tuples are wanted, got: {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|q| &q.sql)
            .collect::<Vec<_>>()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyBoundToDdlTimeRole { .. })),
        "a real role is not the keyword, got: {:#?}",
        outputs.notes()
    );
}
