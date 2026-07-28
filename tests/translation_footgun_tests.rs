//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.

use rls2fga::classifier::patterns::{ConfidenceLevel, PatternClass};
use rls2fga::generator::tuple_generator::{format_tuples, TupleQuery};
use rls2fga::output::report::build_report;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translator, TranslatorBuilder};

fn db_of(sql: &str) -> ParserDB {
    parse_schema(sql).expect("schema should parse")
}

fn translator(min_confidence: ConfidenceLevel) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .build()
}

/// Return the right-hand side of `define <relation>:` inside `type <type_name>`.
fn relation_definition(dsl: &str, type_name: &str, relation: &str) -> Option<String> {
    let mut in_type = false;
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            in_type = name.trim() == type_name;
            continue;
        }
        if in_type {
            if let Some(rest) = trimmed.strip_prefix(&format!("define {relation}:")) {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

fn type_names(dsl: &str) -> Vec<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("type "))
        .map(|name| name.trim().to_string())
        .collect()
}

fn tuples_reading_from(tuples: &[TupleQuery], from_clause: &str) -> Vec<String> {
    tuples
        .iter()
        .filter(|q| q.sql.contains(from_clause))
        .map(|q| q.sql.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Two source tables canonicalising to the same OpenFGA type name.
// ---------------------------------------------------------------------------

const COLLIDING_SCHEMAS: &str = r"
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_docs_sel ON app.docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY public_docs_sel ON public.docs FOR SELECT USING (owner_id = current_user);
";

/// `app.docs` and `public.docs` both canonicalize to `docs`, so the second type
/// is renamed. Emitting its rows as `docs:<id>` would grant a `public.docs` owner
/// access to the `app.docs` row with the same key.
#[test]
fn disambiguated_type_receives_tuples_under_its_own_type_name() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("collision should produce a renamed second type");

    let tuples = translator.generate_tuple_queries(&db);
    assert_eq!(
        tuples.len(),
        2,
        "each colliding table needs its own ownership query, got: {tuples:#?}"
    );

    for (from_clause, expected_type) in [
        (r#"FROM "app"."docs""#, "docs"),
        (r#"FROM "public"."docs""#, renamed.as_str()),
    ] {
        let matching = tuples_reading_from(&tuples, from_clause);
        let [sql] = matching.as_slice() else {
            panic!("expected exactly one query reading {from_clause}, got: {matching:#?}");
        };
        assert!(
            sql.contains(&format!("'{expected_type}:'")),
            "query reading {from_clause} must emit '{expected_type}:' objects, got:\n{sql}"
        );
    }
}

/// A type without tuples can never be satisfied, so its policy is never enforced.
#[test]
fn disambiguated_type_is_not_left_without_tuples() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;
    let tuples = translator.generate_tuple_queries(&db);
    let rendered = format_tuples(&tuples);

    for type_name in type_names(&dsl) {
        if type_name == "user" {
            continue;
        }
        assert!(
            rendered.contains(&format!("'{type_name}:'")),
            "type '{type_name}' has no tuple query, so its relations can never be populated:\n{rendered}"
        );
    }
}

/// A parent table also has to be resolved through the disambiguated names: a
/// child that inherits from the renamed table must not be wired to, or populate,
/// the table that kept the canonical name.
#[test]
fn parent_inheritance_resolves_the_disambiguated_parent_type() {
    let db = db_of(
        r"
CREATE TABLE aaa.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE zzz.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES zzz.projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM zzz.projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "projects" && name.starts_with("projects"))
        .expect("the second projects table should be renamed");

    let can_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    assert!(
        can_select.contains(&renamed),
        "tasks inherits from zzz.projects, so can_select must reference '{renamed}', got 'define can_select: {can_select}'\n{dsl}"
    );

    for query in translator.generate_tuple_queries(&db) {
        if !query.sql.contains(r#"FROM "zzz"."projects""#) {
            continue;
        }
        assert!(
            query.sql.contains(&format!("'{renamed}:'")),
            "rows of zzz.projects must not be filed under another table's type:\n{}",
            query.sql
        );
    }
}

/// A parent without RLS gets no type of its own, so its name is derived on
/// demand. That derivation must still avoid a name another table already owns.
#[test]
fn untyped_parent_does_not_borrow_another_tables_type() {
    let db = db_of(
        r"
CREATE TABLE aaa.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE zzz.projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES zzz.projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM zzz.projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::A);

    for query in translator.generate_tuple_queries(&db) {
        assert!(
            !(query.sql.contains(r#"FROM "zzz"."projects""#) && query.sql.contains("'projects:'")),
            "zzz.projects has no RLS, so its rows must not be filed under aaa.projects' type:\n{}",
            query.sql
        );
    }
}

/// A quoted identifier may contain a dot. Treating it as a schema separator names
/// the type after a fragment of the table name.
#[test]
fn quoted_dot_in_a_table_name_is_not_read_as_a_schema_separator() {
    let db = db_of(
        "CREATE TABLE \"we.ird\"(id UUID PRIMARY KEY);\n\
         ALTER TABLE \"we.ird\" ENABLE ROW LEVEL SECURITY;\n",
    );
    let dsl = translator(ConfidenceLevel::A).generate_model(&db).dsl;

    assert!(
        type_names(&dsl).iter().any(|name| name == "we_ird"),
        "the type must derive from the whole quoted name, got: {:?}\n{dsl}",
        type_names(&dsl)
    );
}

/// A table that only appears as a deny-all must not take the canonical name from
/// a table with real policies: enabling RLS on an unrelated empty table would
/// otherwise rename a type whose tuples are already loaded.
#[test]
fn deny_only_table_does_not_take_the_name_of_a_table_with_policies() {
    let db = db_of(
        r"
CREATE TABLE aaa.docs(id UUID PRIMARY KEY);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the table with policies keeps the canonical name:\n{dsl}"
    );
    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("the deny-all table should be the renamed one");
    assert_eq!(
        relation_definition(&dsl, &renamed, "can_select").as_deref(),
        Some("no_access"),
        "the deny-all table is the one that gets renamed:\n{dsl}"
    );
}

/// A policy that inherits from a parent only *reads* the parent, so `PostgreSQL`
/// applies the parent's SELECT policy to every command the child covers. Pointing
/// an inherited command at the parent's relation of the same name denies work the
/// database allows.
#[test]
fn inherited_commands_consult_the_parents_select_policy() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_all ON tasks FOR ALL USING (
  EXISTS (SELECT 1 FROM projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::A).generate_model(&db).dsl;

    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "tasks", relation).as_deref(),
            Some("can_select from projects"),
            "projects only has a SELECT policy, so inherited {relation} must read it:\n{dsl}"
        );
    }
}

// ---------------------------------------------------------------------------
// Composite primary keys.
// ---------------------------------------------------------------------------

/// `PRIMARY KEY (tenant_id, id)` says `id` alone is not unique, so using it as
/// the object identifier merges rows across tenants.
#[test]
fn composite_primary_key_does_not_produce_truncated_object_ids() {
    let db = db_of(
        r"
CREATE TABLE docs(tenant_id UUID, id UUID, owner_id UUID, PRIMARY KEY (tenant_id, id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(&translator.generate_tuple_queries(&db));

    assert!(
        !rendered.contains(r#"'docs:' || "id""#),
        "a single column of a composite primary key must not identify objects:\n{rendered}"
    );
    assert!(
        rendered.contains("composite primary key"),
        "the operator must be told why no ownership tuples were emitted:\n{rendered}"
    );
}

// ---------------------------------------------------------------------------
// RESTRICTIVE policies dropped by confidence filtering.
// ---------------------------------------------------------------------------

/// RLS is `(permissive OR ...) AND restrictive AND ...`, so dropping a
/// RESTRICTIVE policy grants access it forbids.
#[test]
fn untranslatable_restrictive_policy_denies_instead_of_widening_access() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs AS RESTRICTIVE FOR SELECT
  USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);

    let can_select = relation_definition(&model.dsl, "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains("no_access"),
        "an untranslatable RESTRICTIVE policy must gate can_select, got 'define can_select: {can_select}'\n{}",
        model.dsl
    );
    assert!(
        model
            .todos
            .iter()
            .any(|todo| todo.policy_name == "docs_tenant"),
        "the dropped RESTRICTIVE policy must be reported, got: {:#?}",
        model.todos
    );
}

// ---------------------------------------------------------------------------
// Generated SQL comments.
// ---------------------------------------------------------------------------

/// `PostgreSQL` identifiers may contain newlines, which end a `--` comment early
/// and turn the rest of the identifier into an executable statement.
#[test]
fn generated_comments_cannot_escape_into_executable_sql() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
         CREATE TABLE \"doc_mem\nSELECT 1; --\"(doc_id UUID, user_id UUID);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
           SELECT 1 FROM \"doc_mem\nSELECT 1; --\" m\n\
           WHERE m.doc_id = docs.id AND m.user_id = current_user));\n",
    );
    let tuples = translator(ConfidenceLevel::A).generate_tuple_queries(&db);

    assert!(!tuples.is_empty(), "expected membership tuple queries");
    for query in &tuples {
        assert!(
            query.comment.starts_with("--"),
            "a query comment must be a comment: {:?}",
            query.comment
        );
        assert!(
            !query.comment.contains('\n') && !query.comment.contains('\r'),
            "comment spans multiple lines, so its tail executes as SQL: {:?}",
            query.comment
        );
        assert!(
            !query.comment.chars().any(char::is_control),
            "control characters in a comment can terminate it: {:?}",
            query.comment
        );
    }
    assert!(
        tuples
            .iter()
            .any(|query| query.comment.contains("doc_mem SELECT 1; --")),
        "the comment must still name the source table, collapsed onto one line: {tuples:#?}"
    );
}

// ---------------------------------------------------------------------------
// RLS enabled without a usable policy.
// ---------------------------------------------------------------------------

/// Enabling RLS without any policy denies every row. Omitting the table from the
/// model instead implies unrestricted access.
#[test]
fn rls_enabled_table_without_policies_denies_every_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
",
    );
    let model = translator(ConfidenceLevel::A).generate_model(&db);

    assert!(
        type_names(&model.dsl).iter().any(|name| name == "docs"),
        "an RLS-enabled table must appear in the model:\n{}",
        model.dsl
    );
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.dsl, "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.dsl));
        assert!(
            definition.contains("no_access"),
            "RLS with no policy denies {relation}, got 'define {relation}: {definition}'"
        );
    }
}

/// `FOR INSERT`-only RLS makes the table unreadable.
#[test]
fn command_without_permissive_policy_is_denied() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A).generate_model(&db);

    assert_eq!(
        relation_definition(&model.dsl, "docs", "can_insert").as_deref(),
        Some("owner"),
        "the INSERT policy must still translate:\n{}",
        model.dsl
    );
    for relation in ["can_select", "can_update", "can_delete"] {
        let definition = relation_definition(&model.dsl, "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.dsl));
        assert!(
            definition.contains("no_access"),
            "no policy covers {relation}, so RLS denies it, got 'define {relation}: {definition}'"
        );
    }
}

/// A table whose only policy is dropped must still be denied, not omitted.
#[test]
fn table_whose_only_policy_is_filtered_denies_every_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tenant ON docs FOR ALL USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);

    let can_select = relation_definition(&model.dsl, "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.dsl));
    assert!(
        can_select.contains("no_access"),
        "filtered-out policies leave the table denied, got 'define can_select: {can_select}'"
    );
}

/// A dropped PERMISSIVE clause narrows the model rather than widening it, but the
/// operator still loses a policy they wrote.
#[test]
fn report_names_dropped_permissive_policies_and_their_reason() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs FOR SELECT USING (tenant = current_setting('app.tenant'));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let classified = translator.classify(&db);
    let model = translator.generate_model(&db);

    let report = build_report(&model, &classified, ConfidenceLevel::B);
    assert!(
        report.contains("docs_tenant"),
        "a dropped permissive policy must still be named:\n{report}"
    );
    assert!(
        report.contains('D'),
        "the report must state the confidence that caused the drop:\n{report}"
    );
}

// ---------------------------------------------------------------------------
// Report disclosure.
// ---------------------------------------------------------------------------

/// A dropped clause appears in neither the model nor the tuples, so the report is
/// the only place its loss is visible.
#[test]
fn report_enumerates_policies_dropped_by_confidence_filtering() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs AS RESTRICTIVE FOR SELECT
  USING (tenant = current_setting('app.tenant'));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let classified = translator.classify(&db);
    let model = translator.generate_model(&db);

    let report = build_report(&model, &classified, ConfidenceLevel::B);
    assert!(
        report.contains("docs_owner"),
        "translated policies stay in the report:\n{report}"
    );
    assert!(
        report.contains("docs_tenant"),
        "a policy dropped below the confidence threshold must still be listed:\n{report}"
    );
}

// ---------------------------------------------------------------------------
// Missing translations.
// ---------------------------------------------------------------------------

/// The missing-key-tolerant `current_setting(key, true)` identifies the current
/// user exactly like the single-argument form.
#[test]
fn current_setting_with_missing_ok_infers_a_current_user_accessor() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION app_user_id() RETURNS UUID
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'', true)::uuid';
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = app_user_id());
",
    );
    let classified = translator(ConfidenceLevel::A).classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected exactly one classified policy");
    };
    let using = policy
        .using_classification
        .as_ref()
        .expect("USING should classify");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "missing_ok current_setting should still yield P3 ownership, got: {:?}",
        using.pattern
    );
}

/// `x = ANY (SELECT ...)` is another spelling of `x IN (SELECT ...)`.
#[test]
fn equals_any_subquery_classifies_as_exists_membership() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT
  USING (id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user));
",
    );
    let classified = translator(ConfidenceLevel::A).classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected exactly one classified policy");
    };
    let using = policy
        .using_classification
        .as_ref()
        .expect("USING should classify");
    assert!(
        matches!(
            &using.pattern,
            PatternClass::P4ExistsMembership { join_table, fk_column, user_column, .. }
                if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
        ),
        "= ANY (subquery) should match IN (subquery) membership, got: {:?}",
        using.pattern
    );
}

// ---------------------------------------------------------------------------
// Identifier rewriting.
// ---------------------------------------------------------------------------

/// Canonicalizing a quoted role can map it onto a different existing role, which
/// changes who the policy admits.
#[test]
fn pg_role_identifier_rewrite_is_reported() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT TO "billing admin" USING (owner_id = current_user);
"#,
    );
    let model = translator(ConfidenceLevel::A).generate_model(&db);

    assert!(
        model
            .todos
            .iter()
            .any(|todo| todo.message.contains("billing admin")
                && todo.message.contains("billing_admin")),
        "the role-name rewrite must name both the original and the OpenFGA identifier, got: {:#?}",
        model.todos
    );
}

// ---------------------------------------------------------------------------
// DSL and JSON parity.
// ---------------------------------------------------------------------------

/// The DSL and the JSON model are rendered from one plan, so they must describe
/// the same relations. A variant handled by only one renderer would let an
/// operator load a model that grants more than the `.fga` file they reviewed.
#[test]
fn json_model_declares_the_same_relations_as_the_dsl() {
    // Exercises collision renaming, role scoping, inheritance, a public flag, a
    // union, and a table present only as a deny-all.
    let db = db_of(
        r"
CREATE TABLE aaa.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE zzz.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.projects FOR SELECT TO analyst USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES zzz.projects(id), is_public BOOLEAN);
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_all ON tasks FOR ALL USING (
  EXISTS (SELECT 1 FROM zzz.projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
CREATE POLICY tasks_public ON tasks FOR SELECT USING (is_public = TRUE);
CREATE TABLE audit(id UUID PRIMARY KEY);
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator.generate_model(&db).dsl;
    let json = translator.generate_json_model(&db);

    let mut from_dsl: Vec<String> = Vec::new();
    let mut current_type = String::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            current_type = name.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            if let Some((relation, _)) = rest.split_once(':') {
                from_dsl.push(format!("{current_type}#{}", relation.trim()));
            }
        }
    }

    let mut from_json: Vec<String> = json
        .type_definitions
        .iter()
        .flat_map(|definition| {
            definition
                .relations
                .iter()
                .flat_map(|relations| relations.keys())
                .map(|relation| format!("{}#{relation}", definition.type_name))
        })
        .collect();

    from_dsl.sort();
    from_json.sort();
    assert!(
        from_dsl.len() > 20,
        "expected a substantial model to compare, got {from_dsl:?}"
    );
    assert_eq!(from_dsl, from_json, "DSL and JSON must agree\n{dsl}");
}

// ---------------------------------------------------------------------------
// Ownership columns.
// ---------------------------------------------------------------------------

/// Each ownership column is a distinct relationship. Collapsing two of them into
/// one relation unions their subjects, so a policy that only admits `owner_id`
/// starts admitting everyone named by the other column.
#[test]
fn distinct_ownership_columns_get_distinct_relations() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    let select =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let update =
        relation_definition(&dsl, "docs", "can_update").expect("docs should define can_update");
    assert_ne!(
        select, update,
        "SELECT admits owner_id and UPDATE admits editor_id, so they cannot share a relation:\n{dsl}"
    );

    // Every ownership query must populate the relation its own column feeds.
    for query in translator.generate_tuple_queries(&db) {
        let column = if query.sql.contains(r#"|| "owner_id""#) {
            &select
        } else if query.sql.contains(r#"|| "editor_id""#) {
            &update
        } else {
            continue;
        };
        assert!(
            query.sql.contains(&format!("'{column}' AS relation")),
            "this query feeds the wrong relation, expected '{column}':\n{}",
            query.sql
        );
    }
}

// ---------------------------------------------------------------------------
// Correlated subqueries through an intermediate table.
// ---------------------------------------------------------------------------

/// When an `EXISTS` correlates to a column of an enclosing subquery, the linking
/// column is the enclosing one. Reading the scanned table's own key instead names
/// a type after that column and files two tables' rows under one object id.
#[test]
fn nested_correlated_exists_resolves_to_the_scanned_table() {
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_sel ON orgs FOR SELECT USING (owner_id = current_user);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id
          AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = p.org_id AND o.owner_id = current_user)));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    assert!(
        !type_names(&dsl).iter().any(|name| name == "id"),
        "a join column must not become a type:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "tasks", "can_select").as_deref(),
        Some("can_select from projects"),
        "the chain must resolve through projects:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some("can_select from orgs"),
        "and projects through orgs:\n{dsl}"
    );

    // projects rows link to orgs by org_id only; keying that link on projects.id
    // would grant a project the permissions of the org with the same identifier.
    for query in translator.generate_tuple_queries(&db) {
        if !query.sql.contains(r#"FROM "projects""#) || !query.sql.contains("'orgs:'") {
            continue;
        }
        assert!(
            query.sql.contains(r#"'orgs:' || "org_id""#),
            "a projects row must reference its org by org_id:\n{}",
            query.sql
        );
    }
}

/// A subquery that scans an entity table keyed by its own primary key is not a
/// membership join table. Treating it as one keys the parent objects by the child's
/// identifier, granting each row the permissions of the unrelated row that happens
/// to share its id.
#[test]
fn membership_join_on_the_scanned_tables_own_key_is_refused() {
    // No foreign key is declared, so parent inheritance cannot be confirmed either.
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_sel ON orgs FOR SELECT USING (owner_id = current_user);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
",
    );
    // Keep D-level classifications so the diagnostic itself is observable.
    let translator = translator(ConfidenceLevel::D);
    let model = translator.generate_model(&db);

    assert!(
        !type_names(&model.dsl).iter().any(|name| name == "id"),
        "a join column must not become a type:\n{}",
        model.dsl
    );
    assert_eq!(
        relation_definition(&model.dsl, "projects", "can_select").as_deref(),
        Some("no_access"),
        "an unconfirmable parent link must deny, not guess:\n{}",
        model.dsl
    );
    assert!(
        model.todos.iter().any(|todo| {
            todo.policy_name == "projects_sel" && todo.message.contains("own primary key")
        }),
        "the operator must be told why the subquery was refused, got: {:#?}",
        model.todos
    );
}
