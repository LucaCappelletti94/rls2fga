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

/// An inherited command reads the parent, so it consults the parent's SELECT rule
/// rather than the parent relation of the same name.
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
            Some("owner from projects"),
            "every inherited command reads the same parent-side rule:\n{dsl}"
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
        // An action body may carry a trailing read gate.
        let leading = |body: &str| {
            body.split(" and ")
                .next()
                .unwrap_or(body)
                .trim()
                .to_string()
        };
        let column = if query.sql.contains(r#"|| "owner_id""#) {
            leading(&select)
        } else if query.sql.contains(r#"|| "editor_id""#) {
            leading(&update)
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
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some("owner from orgs"),
        "projects requires ownership of its org:\n{dsl}"
    );
    let tasks_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    assert!(
        tasks_select.ends_with(" from projects"),
        "and tasks reaches that rule through projects, got '{tasks_select}':\n{dsl}"
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

/// A subquery scanning an entity by its own primary key is not a membership join, and
/// treating it as one pairs rows that merely share an id.
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

/// A one-row-per-parent membership table has its foreign key as its primary key.
/// It is still a membership table, so refusing it denies access the policy grants.
#[test]
fn membership_table_whose_primary_key_is_its_foreign_key_still_translates() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_owner(doc_id UUID PRIMARY KEY REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_owner o WHERE o.doc_id = docs.id AND o.user_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let model = translator.generate_model(&db);

    let can_select = relation_definition(&model.dsl, "docs", "can_select")
        .expect("docs should define can_select");
    assert_ne!(
        can_select, "no_access",
        "a membership table keyed by its foreign key must still grant access:\n{}",
        model.dsl
    );
    assert!(
        format_tuples(&translator.generate_tuple_queries(&db)).contains(r#"FROM "doc_owner""#),
        "membership rows must be collected from doc_owner"
    );
}

// ---------------------------------------------------------------------------
// Stability of generated names.
// ---------------------------------------------------------------------------

/// `min_confidence` selects how much of a schema is translated. It must not
/// change what the types are called, or tuples loaded from one run stop matching
/// a model generated by another.
#[test]
fn type_names_do_not_depend_on_the_confidence_threshold() {
    let sql = r"
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.docs FOR SELECT USING (tenant = current_setting('app.tenant'));
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
";
    let db = db_of(sql);
    let at_b = type_names(&translator(ConfidenceLevel::B).generate_model(&db).dsl);
    let at_d = type_names(&translator(ConfidenceLevel::D).generate_model(&db).dsl);

    assert_eq!(
        at_b, at_d,
        "the same schema must yield the same type names at every threshold"
    );
}

// ---------------------------------------------------------------------------
// OpenFGA identifier limits.
// ---------------------------------------------------------------------------

/// `OpenFGA` caps relation names at 50 characters and type names at 254. A longer
/// name is rejected when the model is written, which makes the whole artifact
/// unusable rather than just that relation.
#[test]
fn generated_names_respect_openfga_length_limits() {
    let long_column = "c".repeat(60);
    let long_table = "t".repeat(60);
    let long_parent = "p".repeat(60);
    let db = db_of(&format!(
        "CREATE TABLE {long_parent}(id UUID PRIMARY KEY, owner_id UUID);\n\
         ALTER TABLE {long_parent} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY parent_sel ON {long_parent} FOR SELECT USING (owner_id = current_user);\n\
         CREATE TABLE {long_table}(\n\
           id UUID PRIMARY KEY,\n\
           {long_column}_id UUID,\n\
           parent_ref UUID REFERENCES {long_parent}(id)\n\
         );\n\
         ALTER TABLE {long_table} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_sel ON {long_table} FOR SELECT USING ({long_column}_id = current_user);\n\
         CREATE POLICY inherit_upd ON {long_table} FOR UPDATE TO some_long_reporting_role USING (\n\
           EXISTS (SELECT 1 FROM {long_parent} p\n\
                   WHERE p.id = {long_table}.parent_ref AND p.owner_id = current_user));\n"
    ));
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    let mut relations = 0;
    let mut seen_types: Vec<&str> = Vec::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            let name = name.trim();
            assert!(
                name.chars().count() <= 254,
                "type '{name}' is {} characters, over the 254 limit",
                name.chars().count()
            );
            assert!(
                !seen_types.contains(&name),
                "type '{name}' is defined twice, which OpenFGA rejects:\n{dsl}"
            );
            seen_types.push(name);
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            let relation = rest.split_once(':').map_or(rest, |(name, _)| name).trim();
            relations += 1;
            assert!(
                relation.chars().count() <= 50,
                "relation '{relation}' is {} characters, over the 50 limit:\n{dsl}",
                relation.chars().count()
            );
        }
    }
    assert!(relations > 5, "expected a populated model, got:\n{dsl}");
}

/// `OpenFGA` refuses a model with a dangling reference, so every name a userset
/// reaches must exist.
#[test]
fn no_userset_references_an_undefined_relation() {
    let long_column = "c".repeat(60);
    let long_table = "t".repeat(60);
    let long_parent = "p".repeat(60);
    let db = db_of(&format!(
        "CREATE TABLE {long_parent}(id UUID PRIMARY KEY, owner_id UUID);\n\
         ALTER TABLE {long_parent} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY parent_sel ON {long_parent} FOR SELECT USING (owner_id = current_user);\n\
         CREATE TABLE {long_table}(\n\
           id UUID PRIMARY KEY,\n\
           {long_column}_id UUID,\n\
           parent_ref UUID REFERENCES {long_parent}(id)\n\
         );\n\
         ALTER TABLE {long_table} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_sel ON {long_table} FOR SELECT USING ({long_column}_id = current_user);\n\
         CREATE POLICY inherit_upd ON {long_table} FOR UPDATE USING (\n\
           EXISTS (SELECT 1 FROM {long_parent} p\n\
                   WHERE p.id = {long_table}.parent_ref AND p.owner_id = current_user));\n"
    ));
    let json = translator(ConfidenceLevel::B).generate_json_model(&db);

    assert_model_is_internally_consistent(&json);
}

/// Runs every structural check over a generated model.
fn assert_model_is_internally_consistent(
    json: &rls2fga::generator::json_model::AuthorizationModel,
) {
    let declared: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> = json
        .type_definitions
        .iter()
        .map(|definition| {
            let relations = definition
                .relations
                .iter()
                .flat_map(|relations| relations.keys())
                .map(String::as_str)
                .collect();
            (definition.type_name.as_str(), relations)
        })
        .collect();

    for definition in &json.type_definitions {
        for (relation, userset) in definition.relations.iter().flatten() {
            check_userset_references(
                &declared,
                &json.type_definitions,
                &definition.type_name,
                relation,
                userset,
            );
        }
    }
}

/// The userset a type declares for one relation.
fn declared_userset<'model>(
    declared_types: &'model [rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    relation: &str,
) -> Option<&'model rls2fga::generator::json_model::Userset> {
    declared_types
        .iter()
        .find(|definition| definition.type_name == type_name)?
        .relations
        .as_ref()?
        .get(relation)
}

/// Types a tupleset relation can reach, from its declared subject types.
fn targets_of(
    declared_types: &[rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    tupleset: &str,
) -> Vec<String> {
    declared_types
        .iter()
        .filter(|definition| definition.type_name == type_name)
        .flat_map(|definition| definition.metadata.iter())
        .filter_map(|metadata| metadata.relations.get(tupleset))
        .flat_map(|relation| &relation.directly_related_user_types)
        .map(|reference| reference.type_name.clone())
        .collect()
}

fn check_userset_references(
    declared: &std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>>,
    declared_types: &[rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    relation: &str,
    userset: &rls2fga::generator::json_model::Userset,
) {
    use rls2fga::generator::json_model::Userset;
    let own = declared.get(type_name);
    match userset {
        Userset::This { .. } => {}
        Userset::ComputedUserset { computed_userset } => {
            assert!(
                own.is_some_and(|rels| rels.contains(computed_userset.relation.as_str())),
                "{type_name}#{relation} computes '{}', which {type_name} does not define",
                computed_userset.relation
            );
        }
        Userset::TupleToUserset { tuple_to_userset } => {
            let tupleset = tuple_to_userset.tupleset.relation.as_str();
            assert!(
                own.is_some_and(|rels| rels.contains(tupleset)),
                "{type_name}#{relation} walks '{tupleset}', which {type_name} does not define"
            );
            // `OpenFGA` rejects a tupleset that is computed or that admits a
            // wildcard, so an indirection has to start from a concrete assignment.
            assert!(
                matches!(
                    declared_userset(declared_types, type_name, tupleset),
                    Some(Userset::This { .. })
                ),
                "{type_name}#{relation} walks '{tupleset}', which must be directly assignable"
            );
            for reference in declared_types
                .iter()
                .filter(|definition| definition.type_name == type_name)
                .flat_map(|definition| definition.metadata.iter())
                .filter_map(|metadata| metadata.relations.get(tupleset))
                .flat_map(|tupleset| &tupleset.directly_related_user_types)
            {
                assert!(
                    reference.wildcard.is_none(),
                    "{type_name}#{relation} walks '{tupleset}', which admits '{}:*'",
                    reference.type_name
                );
            }
            // The relation is evaluated on whatever types the tupleset admits, so
            // each of them has to define it.
            let computed = tuple_to_userset.computed_userset.relation.as_str();
            for target in targets_of(declared_types, type_name, tupleset) {
                assert!(
                    declared
                        .get(target.as_str())
                        .is_some_and(|rels| rels.contains(computed)),
                    "{type_name}#{relation} walks '{tupleset}' to '{target}' and reads \
                     '{computed}', which {target} does not define"
                );
            }
        }
        Userset::Union { union } => {
            for child in &union.child {
                check_userset_references(declared, declared_types, type_name, relation, child);
            }
        }
        Userset::Intersection { intersection } => {
            for child in &intersection.child {
                check_userset_references(declared, declared_types, type_name, relation, child);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inherited and joined subqueries.
// ---------------------------------------------------------------------------

/// A policy inheriting from a parent requires the specific parent-side rule it
/// names, not everything the parent grants. Referencing the parent's whole
/// `can_select` imports its other permissive policies.
#[test]
fn inheritance_requires_only_the_rule_the_policy_names() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_own ON projects FOR SELECT USING (owner_id = current_user);
CREATE POLICY projects_public ON projects FOR SELECT USING (is_public = TRUE);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    // Level B keeps the parent's public-flag policy, which is the whole point.
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    let projects_select = relation_definition(&dsl, "projects", "can_select")
        .expect("projects should define can_select");
    assert!(
        projects_select.contains("public_viewer"),
        "the parent's own public policy still applies to the parent:\n{dsl}"
    );

    let tasks_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    assert_eq!(
        tasks_select, "owner from projects",
        "the task policy names ownership of the project, not any access to it:\n{dsl}"
    );
}

/// A membership subquery that joins a second table carries a condition on that
/// table. Dropping it grants access to every row the join would have excluded.
#[test]
fn membership_subquery_with_a_join_is_refused() {
    let db = db_of(
        r"
CREATE TABLE departments(id UUID PRIMARY KEY, region TEXT);
CREATE TABLE user_permissions(id UUID PRIMARY KEY, user_id UUID, dept_id UUID REFERENCES departments(id));
CREATE TABLE orders(id UUID PRIMARY KEY, region TEXT);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_sel ON orders FOR SELECT USING (
  EXISTS (SELECT 1 FROM user_permissions up JOIN departments d ON up.dept_id = d.id
          WHERE up.user_id = current_user AND d.region = orders.region));
",
    );
    let model = translator(ConfidenceLevel::D).generate_model(&db);

    assert_eq!(
        relation_definition(&model.dsl, "orders", "can_select").as_deref(),
        Some("no_access"),
        "a join the model cannot express must deny, not drop the condition:\n{}",
        model.dsl
    );
    assert!(
        model
            .todos
            .iter()
            .any(|todo| todo.policy_name == "orders_sel"),
        "the operator must be told the subquery was refused, got: {:#?}",
        model.todos
    );
}

/// A membership subquery joining back to its own table must still expose the `member`
/// relation the userset reads.
#[test]
fn self_referential_membership_defines_the_relation_it_reads() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM docs d2 JOIN doc_members dm ON dm.doc_id = d2.id
          WHERE d2.id = docs.id AND dm.user_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::A).generate_model(&db).dsl;

    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    let (read, tupleset) = can_delete
        .split_once(" from ")
        .unwrap_or_else(|| panic!("can_delete should walk a tupleset, got '{can_delete}':\n{dsl}"));
    let tupleset = tupleset.split(" and ").next().unwrap_or(tupleset).trim();
    assert!(
        relation_definition(&dsl, "docs", tupleset).is_some(),
        "can_delete walks '{tupleset}', which docs does not define:\n{dsl}"
    );
    let read = read.rsplit("and ").next().unwrap_or(read).trim();
    assert!(
        relation_definition(&dsl, "docs", read).is_some(),
        "can_delete reads '{read}', which docs does not define:\n{dsl}"
    );
    assert_ne!(
        read, "no_access",
        "the membership rule must survive:\n{dsl}"
    );
}

// ---------------------------------------------------------------------------
// Duplicated output.
// ---------------------------------------------------------------------------

/// `FOR UPDATE` covers two phases, so one untranslatable clause is translated
/// twice. The operator should still be told once: a doubled list inflates the
/// apparent amount of manual work and hides how many policies really need review.
#[test]
fn one_clause_is_reported_once_even_when_it_covers_two_phases() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user AND status = 'live');
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user AND status = 'live');
",
    );
    let model = translator(ConfidenceLevel::D).generate_model(&db);

    for policy in ["docs_sel", "docs_upd"] {
        let count = model
            .todos
            .iter()
            .filter(|todo| todo.policy_name == policy && todo.message.contains("status"))
            .count();
        assert_eq!(
            count, 1,
            "{policy} should report its attribute guard once, got {count}: {:#?}",
            model.todos
        );
    }
}

/// Inheriting from itself means the parent plan is the plan being built, so the inner
/// rule has to land on it.
#[test]
fn self_referential_inheritance_keeps_the_rule_it_reads() {
    let db = db_of(
        r"
CREATE TABLE docs(
  id UUID PRIMARY KEY,
  parent_id UUID REFERENCES docs(id),
  owner_id UUID,
  is_public BOOLEAN
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM docs parent WHERE parent.id = docs.parent_id
          AND (parent.owner_id = current_user OR parent.is_public = TRUE)));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    let (read, tupleset) = can_delete
        .split_once(" from ")
        .unwrap_or_else(|| panic!("can_delete should walk a tupleset, got '{can_delete}':\n{dsl}"));
    let tupleset = tupleset.split(" and ").next().unwrap_or(tupleset).trim();
    assert!(
        relation_definition(&dsl, "docs", tupleset).is_some(),
        "can_delete walks '{tupleset}', which docs does not define:\n{dsl}"
    );
    let read = read.rsplit("and ").next().unwrap_or(read).trim();
    assert!(
        relation_definition(&dsl, "docs", read).is_some(),
        "can_delete reads '{read}', which docs does not define:\n{dsl}"
    );
}

/// A relation carries one kind of subject, so an ownership column must not take the
/// name a parent pointer needs.
#[test]
fn an_ownership_column_cannot_take_over_a_parent_pointer() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(
  id UUID PRIMARY KEY,
  projects_id UUID,
  project_id UUID REFERENCES projects(id)
);
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_own_column ON tasks FOR SELECT USING (projects_id = current_user);
CREATE POLICY tasks_parent_link ON tasks FOR DELETE USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.generate_model(&db).dsl;

    let can_delete =
        relation_definition(&dsl, "tasks", "can_delete").expect("tasks should define can_delete");
    let (_, tupleset) = can_delete
        .split_once(" from ")
        .expect("inheritance walks a tupleset");
    let tupleset = tupleset.split(" and ").next().unwrap_or(tupleset).trim();
    assert_eq!(
        relation_definition(&dsl, "tasks", tupleset).as_deref(),
        Some("[projects]"),
        "the tupleset '{tupleset}' must accept projects, not whatever claimed the name first:\n{dsl}"
    );

    // Each generated query has to write a subject the relation accepts.
    for query in translator.generate_tuple_queries(&db) {
        if !query.sql.contains(&format!("'{tupleset}' AS relation")) {
            continue;
        }
        assert!(
            query.sql.contains("'projects:' ||"),
            "a query feeding '{tupleset}' must write projects objects:\n{}",
            query.sql
        );
    }
    assert_model_is_internally_consistent(&translator.generate_json_model(&db));
}

/// Wildcards, a role scope and two levels of indirection still satisfy every rule
/// `OpenFGA` enforces on a write.
#[test]
fn a_layered_model_stays_internally_consistent() {
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_own ON orgs FOR SELECT USING (owner_id = current_user);
CREATE POLICY orgs_pub ON orgs FOR SELECT USING (is_public = TRUE);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT TO analyst USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
CREATE TABLE members(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), user_id UUID);
CREATE TABLE notes(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_sel ON notes FOR SELECT USING (
  EXISTS (SELECT 1 FROM members m WHERE m.project_id = notes.project_id
          AND m.user_id = current_user));
",
    );
    assert_model_is_internally_consistent(&translator(ConfidenceLevel::B).generate_json_model(&db));
}

/// Two `define` lines for one relation make the DSL unparseable.
#[test]
fn no_type_defines_a_relation_twice() {
    let db = db_of(
        r"
CREATE TABLE teams(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
CREATE POLICY teams_sel ON teams FOR SELECT USING (owner_id = current_user);
CREATE TABLE docs(
  id UUID PRIMARY KEY,
  can_select_id UUID,
  no_access_id UUID,
  owner_id UUID,
  teams_id UUID,
  team_ref UUID REFERENCES teams(id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_a_reserved ON docs FOR SELECT USING (can_select_id = current_user);
CREATE POLICY docs_b_deny ON docs FOR UPDATE USING (no_access_id = current_user);
CREATE POLICY docs_c_owner ON docs FOR DELETE USING (owner_id = current_user);
CREATE POLICY docs_d_named ON docs FOR INSERT WITH CHECK (teams_id = current_user);
CREATE POLICY docs_e_parent ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM teams t WHERE t.id = docs.team_ref AND t.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    let mut current = String::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            current = name.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            let relation = rest.split_once(':').map_or(rest, |(name, _)| name).trim();
            assert!(
                seen.insert((current.clone(), relation.to_string())),
                "type {current} defines '{relation}' twice:\n{dsl}"
            );
        }
    }
    assert!(seen.len() > 8, "expected a populated model, got:\n{dsl}");
    assert_model_is_internally_consistent(&translator(ConfidenceLevel::B).generate_json_model(&db));
}

/// A RESTRICTIVE clause is a barrier, so a conjunct the model cannot express has to
/// keep denying.
#[test]
fn a_restrictive_clause_never_drops_an_attribute_conjunct() {
    let schema = |restriction: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, deleted_at TIMESTAMP, \
             tenant_id UUID);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);\n\
             CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING ({restriction});\n"
        )
    };
    let body = |restriction: &str| {
        // At a stricter threshold the policy is dropped and the deny-fill hides this.
        let model = translator(ConfidenceLevel::C).generate_model(&db_of(&schema(restriction)));
        relation_definition(&model.dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("docs should define can_select for '{restriction}'"))
    };

    let barrier_only = body("deleted_at IS NULL");
    assert!(
        barrier_only.contains("no_access"),
        "an inexpressible restriction must deny, got '{barrier_only}'"
    );

    // Anding a relationship onto the same barrier must not discard the barrier.
    let with_relationship = body("deleted_at IS NULL AND tenant_id = current_user");
    assert!(
        with_relationship.contains("no_access"),
        "the 'deleted_at IS NULL' barrier vanished, leaving '{with_relationship}'"
    );
    assert_ne!(
        with_relationship,
        body("tenant_id = current_user"),
        "the restriction with a barrier must be stricter than the one without it"
    );

    // The same holds when the barrier hides inside a branch of a union.
    let nested =
        body("(deleted_at IS NULL AND tenant_id = current_user) OR owner_id = current_user");
    assert!(
        nested.contains("no_access"),
        "a barrier nested in a union vanished, leaving '{nested}'"
    );

    // A denied barrier must not also ask for runtime enforcement.
    let model = translator(ConfidenceLevel::C).generate_model(&db_of(&schema(
        "deleted_at IS NULL AND tenant_id = current_user",
    )));
    let notes: Vec<&str> = model
        .todos
        .iter()
        .filter(|todo| todo.policy_name == "docs_bar")
        .map(|todo| todo.message.as_str())
        .collect();
    assert!(
        notes.iter().any(|note| note.contains("denied")),
        "the denial must be reported, got {notes:?}"
    );
    assert!(
        !notes
            .iter()
            .any(|note| note.contains("requires runtime enforcement")),
        "a denied barrier cannot also ask for runtime enforcement, got {notes:?}"
    );
}

/// An inherited rule is named after the rule, not the child policy that asked for
/// it, or the parent grows a clone per child.
#[test]
fn an_inherited_parent_rule_is_named_after_the_rule_itself() {
    let schema = |tasks_policy: &str| {
        format!(
            "CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);\n\
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY proj_sel ON projects FOR SELECT USING (owner_id = current_user);\n\
             CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));\n\
             ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY {tasks_policy} ON tasks FOR SELECT USING (\n\
               EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id\n\
                       AND (p.owner_id = current_user OR p.is_public = TRUE)));\n\
             CREATE TABLE notes(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));\n\
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY notes_sel ON notes FOR SELECT USING (\n\
               EXISTS (SELECT 1 FROM projects p WHERE p.id = notes.project_id\n\
                       AND (p.owner_id = current_user OR p.is_public = TRUE)));\n"
        )
    };
    let inherited_relations = |dsl: &str| {
        let mut found: Vec<(String, String)> = Vec::new();
        let mut current = String::new();
        for line in dsl.lines() {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_prefix("type ") {
                current = name.trim().to_string();
            } else if let Some(rest) = trimmed.strip_prefix("define ") {
                let (relation, body) = rest.split_once(':').expect("a define carries a body");
                if current == "projects" && relation.starts_with("inherited_") {
                    found.push((relation.to_string(), body.trim().to_string()));
                }
            }
        }
        found
    };

    let dsl = translator(ConfidenceLevel::B)
        .generate_model(&db_of(&schema("tasks_sel")))
        .dsl;
    let inherited = inherited_relations(&dsl);
    assert_eq!(
        inherited.len(),
        1,
        "both children inherit the same rule, so projects needs it once, got {inherited:?}:\n{dsl}"
    );

    // Renaming a child policy must not rename a relation on the parent.
    let renamed = translator(ConfidenceLevel::B)
        .generate_model(&db_of(&schema("tasks_select_v2")))
        .dsl;
    assert_eq!(
        inherited_relations(&renamed),
        inherited,
        "renaming the child policy renamed the parent's inherited rule"
    );

    // Both children must still point at that one relation.
    for table in ["tasks", "notes"] {
        let body = relation_definition(&dsl, table, "can_select")
            .unwrap_or_else(|| panic!("{table} should define can_select"));
        assert_eq!(
            body,
            format!("{} from projects", inherited[0].0),
            "{table} must walk the shared inherited rule"
        );
    }
}

/// The parent's own RLS filters the subquery, so the inherited rule is `AND`ed with
/// the parent's `can_select`.
#[test]
fn inheritance_is_gated_by_the_parent_own_select_rule() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY proj_own ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id
          AND (p.owner_id = current_user OR p.is_public = TRUE)));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    let can_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    let (_, tupleset) = can_select
        .split_once(" from ")
        .expect("inheritance walks a tupleset");
    let walked = can_select
        .split_once(" from ")
        .map(|(relation, _)| relation.to_string())
        .expect("inheritance names a parent relation");
    assert_eq!(tupleset, "projects");

    let parent_rule = relation_definition(&dsl, "projects", &walked)
        .unwrap_or_else(|| panic!("projects should define '{walked}':\n{dsl}"));
    assert!(
        parent_rule.contains("can_select"),
        "the inherited rule '{walked}' = '{parent_rule}' must be gated by the parent's own \
         can_select, or a public project nobody may select still grants its tasks:\n{dsl}"
    );
    assert_model_is_internally_consistent(&translator(ConfidenceLevel::B).generate_json_model(&db));
}

/// A parent without RLS is unfiltered, so gating there would deny rows `PostgreSQL`
/// returns.
#[test]
fn inheritance_from_an_unprotected_parent_is_not_gated() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id
          AND (p.owner_id = current_user OR p.is_public = TRUE)));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
    let can_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    let (walked, _) = can_select
        .split_once(" from ")
        .expect("inheritance walks a tupleset");
    let parent_rule = relation_definition(&dsl, "projects", walked)
        .unwrap_or_else(|| panic!("projects should define '{walked}':\n{dsl}"));
    assert!(
        !parent_rule.contains("can_select"),
        "an unprotected parent applies no filter, so '{walked}' = '{parent_rule}' must not be \
         gated:\n{dsl}"
    );
}

/// A rule the parent's own `can_select` already allows needs no gate.
#[test]
fn a_redundant_select_gate_is_left_out() {
    let inherited_body = |parent_policies: &str| {
        let db = db_of(&format!(
            "CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID, \
             is_public BOOLEAN);\n\
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;\n\
             {parent_policies}\
             CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));\n\
             ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY tasks_sel ON tasks FOR SELECT USING (\n\
               EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id\n\
                       AND p.owner_id = current_user));\n"
        ));
        let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
        let can_select = relation_definition(&dsl, "tasks", "can_select")
            .expect("tasks should define can_select");
        let (walked, _) = can_select
            .split_once(" from ")
            .expect("inheritance walks a tupleset");
        (
            walked.to_string(),
            relation_definition(&dsl, "projects", walked),
            dsl,
        )
    };

    // The parent admits exactly the rule the child names, so no gate is needed.
    let (walked, body, dsl) = inherited_body(
        "CREATE POLICY proj_own ON projects FOR SELECT USING (owner_id = current_user);\n",
    );
    assert_eq!(
        walked, "owner",
        "the child should walk the parent's own relation, got '{walked}':\n{dsl}"
    );
    assert_eq!(
        body.as_deref(),
        Some("[user]"),
        "no gated relation should be synthesized:\n{dsl}"
    );

    // The rule is one branch of the parent's union, so it still implies visibility.
    let (walked, _, dsl) = inherited_body(
        "CREATE POLICY proj_own ON projects FOR SELECT USING (owner_id = current_user);\n\
         CREATE POLICY proj_pub ON projects FOR SELECT USING (is_public = TRUE);\n",
    );
    assert_eq!(
        walked, "owner",
        "a rule the parent's union already contains needs no gate, got '{walked}':\n{dsl}"
    );

    // The parent admits strictly less than the rule, so the gate has to stay.
    let (walked, body, dsl) = inherited_body(
        "CREATE POLICY proj_editor ON projects FOR SELECT USING (editor_id = current_user);\n",
    );
    assert!(
        body.is_some_and(|body| body.contains("can_select")),
        "a rule the parent does not already allow must stay gated, got '{walked}':\n{dsl}"
    );
}

/// A `SELECT` policy reading its own table needs itself, which `PostgreSQL` rejects
/// as infinite recursion, so one such policy makes the whole table unreadable.
#[test]
fn a_select_policy_reading_its_own_table_denies_the_table() {
    // The plain policy alone would grant every row to its owner.
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tree ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    assert_eq!(
        relation_definition(&model.dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "a recursive SELECT policy makes every read fail, so nothing is readable:\n{}",
        model.dsl
    );
    assert!(
        model
            .todos
            .iter()
            .any(|todo| todo.policy_name == "docs_tree" && todo.message.contains("recursion")),
        "the operator must be told the policy raises infinite recursion, got {:#?}",
        model.todos
    );

    // The same shape through a join recurses identically.
    let joined = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs d2 JOIN doc_members dm ON dm.doc_id = d2.id
          WHERE d2.id = docs.id AND dm.user_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::A).generate_model(&joined).dsl;
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "a membership subquery reading its own table recurses too:\n{dsl}"
    );
}

/// A non-`SELECT` policy may read its own table, since expanding it needs the
/// table's `SELECT` policies rather than itself.
#[test]
fn a_non_select_policy_may_read_its_own_table() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    assert!(
        can_delete.contains(" from "),
        "the delete rule still walks the parent pointer, got '{can_delete}':\n{dsl}"
    );
    assert_ne!(
        can_delete, "no_access",
        "a non-SELECT self reference is valid SQL and must not be denied:\n{dsl}"
    );
}

/// A self reference reads a different row, so it is gated like any other parent.
#[test]
fn a_self_referential_rule_is_gated_like_any_other_parent() {
    let db = db_of(
        r"
CREATE TABLE docs(
  id UUID PRIMARY KEY,
  parent_id UUID REFERENCES docs(id),
  owner_id UUID,
  is_public BOOLEAN
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM docs parent WHERE parent.id = docs.parent_id
          AND (parent.owner_id = current_user OR parent.is_public = TRUE)));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    let Some((read, _)) = can_delete.split_once(" from ") else {
        panic!("can_delete should walk a tupleset, got '{can_delete}':\n{dsl}");
    };
    let read = read.rsplit("and ").next().unwrap_or(read).trim();
    let rule = relation_definition(&dsl, "docs", read)
        .unwrap_or_else(|| panic!("docs should define '{read}':\n{dsl}"));
    assert!(
        rule.contains("can_select"),
        "the parent row must still be selectable, so '{read}' = '{rule}' needs the gate:\n{dsl}"
    );
}

/// Naming a row to update or delete reads it, which `PostgreSQL` gates on the
/// `SELECT` policies. `INSERT` reads nothing.
#[test]
fn updating_and_deleting_a_row_requires_being_able_to_select_it() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;

    for action in ["can_update", "can_delete"] {
        let body = relation_definition(&dsl, "docs", action)
            .unwrap_or_else(|| panic!("docs should define {action}:\n{dsl}"));
        assert!(
            body.contains("can_select"),
            "{action} = '{body}' must require reading the row:\n{dsl}"
        );
    }
    let insert =
        relation_definition(&dsl, "docs", "can_insert").expect("docs should define can_insert");
    assert!(
        !insert.contains("can_select"),
        "an INSERT reads nothing, so can_insert = '{insert}' must stay ungated:\n{dsl}"
    );
    assert_model_is_internally_consistent(&translator(ConfidenceLevel::B).generate_json_model(&db));
}

/// No `SELECT` policy means no row can be named for a per-row update or delete.
#[test]
fn without_a_select_policy_no_row_can_be_updated_or_deleted() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    assert!(
        can_delete.contains("can_select"),
        "can_delete = '{can_delete}' must require reading the row:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "with no SELECT policy the read must be denied, which denies the delete with it:\n{dsl}"
    );
}

/// The recursion is a property of the `SQL`, not of how well the pattern was
/// recognized.
#[test]
fn a_recursive_select_policy_denies_reads_even_when_unrecognized() {
    let db = db_of(
        r"
CREATE TABLE t1(id INTEGER PRIMARY KEY, parent_id INTEGER, owner TEXT);
ALTER TABLE t1 ENABLE ROW LEVEL SECURITY;
CREATE POLICY t1_own ON t1 FOR SELECT USING (owner = current_user);
CREATE POLICY t1_tree ON t1 FOR SELECT USING (
  EXISTS (SELECT 1 FROM t1 p WHERE p.id = t1.parent_id AND p.owner = current_user));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    assert_eq!(
        relation_definition(&model.dsl, "t1", "can_select").as_deref(),
        Some("no_access"),
        "every read of t1 raises infinite recursion, so nothing is readable:\n{}",
        model.dsl
    );
    assert!(
        model
            .todos
            .iter()
            .any(|todo| todo.message.contains("recursion")),
        "the operator must be told why, got {:#?}",
        model.todos
    );
}

/// A membership table that grants no reads hides every membership row, so the
/// subquery matches nothing.
#[test]
fn membership_through_an_unreadable_join_table_grants_nothing() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    assert_eq!(
        relation_definition(&model.dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "no membership row is readable, so the policy grants nothing:\n{}",
        model.dsl
    );
    assert!(
        model.todos.iter().any(|todo| {
            todo.message.contains("doc_members") && todo.message.contains("membership")
        }),
        "the operator must be told which table hides the rows, got {:#?}",
        model.todos
    );
}

/// Which membership rows a user sees is up to the join table's own policies, which
/// no relation can carry, so the translation says so.
#[test]
fn membership_through_a_guarded_join_table_is_disclosed() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_self ON doc_members FOR SELECT USING (user_id = current_user);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    let can_select = relation_definition(&model.dsl, "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(" from "),
        "the membership grant stays, got '{can_select}':\n{}",
        model.dsl
    );
    assert!(
        model.todos.iter().any(|todo| {
            todo.message.contains("doc_members") && todo.message.contains("membership")
        }),
        "the operator must be told the join table filters memberships, got {:#?}",
        model.todos
    );
}

/// A join table without RLS needs no caveat.
#[test]
fn membership_through_an_open_join_table_needs_no_caveat() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    assert!(
        !model.todos.iter().any(|todo| {
            todo.message.contains("doc_members") && todo.message.contains("membership")
        }),
        "an unprotected join table needs no note, got {:#?}",
        model.todos
    );
}

/// RLS with no policy is a default deny, so such a parent hides every row from the
/// subquery.
#[test]
fn inheriting_from_a_parent_with_no_policies_grants_nothing() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B).generate_model(&db).dsl;
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some("no_access"),
        "a parent with RLS and no policies denies reads:\n{dsl}"
    );
    let can_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    let (read, _) = can_select
        .split_once(" from ")
        .unwrap_or_else(|| panic!("expected an inherited walk, got '{can_select}':\n{dsl}"));
    let rule = relation_definition(&dsl, "projects", read)
        .unwrap_or_else(|| panic!("projects should define '{read}':\n{dsl}"));
    assert!(
        rule.contains("can_select"),
        "the rule '{read}' = '{rule}' must be gated, which is what denies it here:\n{dsl}"
    );
    assert_model_is_internally_consistent(&translator(ConfidenceLevel::B).generate_json_model(&db));
}

/// A relation no permission can reach needs no tuple query.
#[test]
fn no_tuple_query_feeds_a_relation_no_permission_reaches() {
    let db = db_of(
        r"
CREATE TABLE t1(id INTEGER PRIMARY KEY, parent_id INTEGER, owner TEXT);
ALTER TABLE t1 ENABLE ROW LEVEL SECURITY;
CREATE POLICY t1_own ON t1 FOR SELECT USING (owner = current_user);
CREATE POLICY t1_tree ON t1 FOR SELECT USING (
  EXISTS (SELECT 1 FROM t1 p WHERE p.id = t1.parent_id AND p.owner = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator.generate_model(&db).dsl;
    // The recursive policy makes every read fail.
    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "t1", action).as_deref(),
            Some("no_access"),
            "{action} should deny for this schema:\n{dsl}"
        );
    }

    for query in translator.generate_tuple_queries(&db) {
        assert!(
            !query.sql.contains("AS relation"),
            "nothing can consult a t1 relation, so this query is dead:\n{}",
            query.sql
        );
    }
}

/// Per relation, not per table: a table denying reads can still grant inserts.
#[test]
fn a_relation_reached_only_by_insert_keeps_its_tuples() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, parent_id INTEGER, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.editor_id = current_user));
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator.generate_model(&db).dsl;
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the recursive read policy denies reads:\n{dsl}"
    );
    let can_insert =
        relation_definition(&dsl, "docs", "can_insert").expect("docs should define can_insert");
    assert_ne!(can_insert, "no_access", "the INSERT policy grants:\n{dsl}");

    assert!(
        translator
            .generate_tuple_queries(&db)
            .iter()
            .any(|query| query.sql.contains(&format!("'{can_insert}' AS relation"))),
        "can_insert reads '{can_insert}', so its tuples are still needed:\n{dsl}"
    );
}

/// A model that grants normally keeps every query it needs.
#[test]
fn a_granting_model_keeps_its_tuple_queries() {
    let db = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let queries = translator.generate_tuple_queries(&db);
    assert!(
        queries
            .iter()
            .any(|query| query.sql.contains("'owner' AS relation")),
        "the ownership query is still needed: {queries:#?}"
    );
    assert!(
        queries
            .iter()
            .any(|query| query.sql.contains("'projects' AS relation")),
        "the parent bridge is still needed: {queries:#?}"
    );
}

/// A write policy on a table whose reads are denied can never match, so say so.
#[test]
fn a_write_policy_without_readable_rows_is_reported() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B).generate_model(&db);
    let reports = model
        .todos
        .iter()
        .filter(|todo| todo.message.contains("docs") && todo.message.contains("SELECT policy"))
        .count();
    assert_eq!(
        reports, 1,
        "the unreachable DELETE policy must be reported once, got {:#?}",
        model.todos
    );

    // A table that grants reads has nothing to report.
    let readable = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    assert!(
        !translator(ConfidenceLevel::B)
            .generate_model(&readable)
            .todos
            .iter()
            .any(|todo| todo.message.contains("SELECT policy")),
        "a readable table needs no such note"
    );

    // An INSERT reads nothing, so an insert-only table is not affected either.
    let insert_only = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
",
    );
    assert!(
        !translator(ConfidenceLevel::B)
            .generate_model(&insert_only)
            .todos
            .iter()
            .any(|todo| todo.message.contains("SELECT policy")),
        "an INSERT needs no read, so nothing is unreachable"
    );
}
