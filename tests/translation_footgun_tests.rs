//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{ConfidenceLevel, PatternClass};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::notes::{NoteSeverity, TranslationNote};
use rls2fga::generator::records::{RecordDerivation, ValueSource};
use rls2fga::generator::relations::RelationShapes;
use rls2fga::generator::tuple_generator::{format_tuples, TupleQuery};
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

/// Whether a relation of `type_name` grants nobody, following a body that is only the
/// name of another relation, which is how the derived write relations are spelled.
fn relation_denies(dsl: &str, type_name: &str, relation: &str) -> bool {
    let mut name = relation.to_string();
    for _ in 0..4 {
        let Some(body) = relation_definition(dsl, type_name, &name) else {
            return false;
        };
        if body == "no_access" {
            return true;
        }
        name = body;
    }
    false
}

/// Whether an action relation grants nobody, allowing for a `TO` scope: an intersection
/// one of whose parts is `no_access` denies whatever the other parts admit.
fn action_relation_denies(dsl: &str, type_name: &str, relation: &str) -> bool {
    let mut name = relation.to_string();
    for _ in 0..4 {
        let Some(body) = relation_definition(dsl, type_name, &name) else {
            return false;
        };
        if body.split(" and ").any(|part| part.trim() == "no_access") {
            return true;
        }
        if body.contains(' ') {
            return false;
        }
        name = body;
    }
    false
}

/// Every type the model declares with no relation under it, in declaration order.
fn types_declaring_no_relation(dsl: &str) -> Vec<String> {
    let mut empty = Vec::new();
    let mut current: Option<String> = None;
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            if let Some(previous) = current.take() {
                empty.push(previous);
            }
            current = Some(name.trim().to_string());
        } else if trimmed.starts_with("define ") {
            current = None;
        }
    }
    empty.extend(current);
    empty
}

/// Every relation `type_name` defines, paired with its body, in declaration order.
fn relation_definitions(dsl: &str, type_name: &str) -> Vec<(String, String)> {
    let mut in_type = false;
    let mut defined = Vec::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            in_type = name.trim() == type_name;
            continue;
        }
        if in_type {
            if let Some(rest) = trimmed.strip_prefix("define ") {
                if let Some((name, body)) = rest.split_once(':') {
                    defined.push((name.trim().to_string(), body.trim().to_string()));
                }
            }
        }
    }
    defined
}

/// Name of the relation `type_name` declares with `pg_role` subjects, if any.
fn pg_role_relation(dsl: &str, type_name: &str) -> Option<String> {
    let mut in_type = false;
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            in_type = name.trim() == type_name;
            continue;
        }
        if in_type {
            if let Some(rest) = trimmed.strip_prefix("define ") {
                if let Some((name, subjects)) = rest.split_once(':') {
                    if subjects.trim() == "[pg_role]" {
                        return Some(name.trim().to_string());
                    }
                }
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

const COLLIDING_SCHEMAS: &str = r"
CREATE SCHEMA app;
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("collision should produce a renamed second type");

    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
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
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

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

    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
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
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
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

    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        assert!(
            !(query.sql.contains(r#"FROM "zzz"."projects""#) && query.sql.contains("'projects:'")),
            "zzz.projects has no RLS, so its rows must not be filed under aaa.projects' type:\n{}",
            query.sql
        );
    }
}

/// The generator refers to its own structural relations by name, so a table
/// named after one must not take it on a type that also needs it. Holding
/// `no_access` turns every denied action into a granted parent link.
#[test]
fn a_table_named_after_a_structural_relation_does_not_take_it() {
    for reserved in [
        "no_access",
        "public_viewer",
        "member",
        "owner_user",
        "owner_team",
    ] {
        let db = db_of(&format!(
            "
CREATE TABLE {reserved}(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE {reserved} ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_sel ON {reserved} FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, parent_id UUID REFERENCES {reserved}(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM {reserved} p
          WHERE p.id = tasks.parent_id AND p.owner_id = current_user));
"
        ));
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();

        assert_ne!(
            relation_definition(&dsl, "tasks", reserved).as_deref(),
            Some(format!("[{reserved}]").as_str()),
            "the parent link took the structural relation '{reserved}':\n{dsl}"
        );
    }
}

/// The generator assembles an action from relations it names, so a column whose
/// relation would take one of those names leaves it defined twice and pointing at
/// itself.
#[test]
fn a_column_named_after_an_action_relation_does_not_take_it() {
    for reserved in [
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_using",
        "can_update_check",
        "can_insert_returning",
        "can_upsert",
        "can_select_for_update",
    ] {
        let db = db_of(&format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, {reserved}_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING ({reserved}_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING ({reserved}_id = current_user)
  WITH CHECK (editor_id = current_user);
"
        ));
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();

        let defined = relation_definitions(&dsl, "docs");
        let mut names: Vec<&str> = defined.iter().map(|(name, _)| name.as_str()).collect();
        let declared = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            declared,
            names.len(),
            "a column named '{reserved}_id' took the action relation:\n{dsl}"
        );
        for (name, body) in &defined {
            assert!(
                !body.split_whitespace().any(|token| token == name),
                "'{name}' is defined as itself:\n{dsl}"
            );
        }
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

/// Two policies on one table may spell its name differently. Grouping them by that
/// spelling builds the table twice, and the second group's actions overwrite the
/// first, so a RESTRICTIVE barrier can disappear.
#[test]
fn policies_compose_however_each_one_spells_the_table() {
    let schema = |restrictive_on: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);\n\
             CREATE POLICY docs_reviewed ON {restrictive_on} AS RESTRICTIVE FOR SELECT\n\
               USING (reviewer_id = current_user);\n"
        )
    };
    let read_of = |restrictive_on: &str| {
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db_of(&schema(restrictive_on)))
            .outputs_accepting_gaps()
            .model();
        relation_definition(&dsl, "docs", "can_select")
    };

    assert_eq!(
        read_of("docs").as_deref(),
        Some("owner and reviewer"),
        "the bare spelling must keep the barrier, or this comparison proves nothing"
    );
    assert_eq!(
        read_of("\"docs\"").as_deref(),
        Some("owner and reviewer"),
        "quoting the table in the RESTRICTIVE policy must not drop it"
    );
}

/// `PostgreSQL` resolves an unqualified table reference through the search path, so a
/// policy may name a table in another schema without qualifying it. Leaving it
/// unresolved drops the policy and denies what RLS grants.
#[test]
fn a_policy_naming_its_table_without_the_schema_still_translates() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the policy names the table the search path resolves:\n{dsl}"
    );
    assert!(
        !tuples_reading_from(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
            r#""docs""#
        )
        .is_empty(),
        "the ownership relation needs its rows"
    );
}

/// Two schemas may hold a table of the same name, and the search path decides which one
/// an unqualified policy means: the first entry holding it wins, which is what
/// `PostgreSQL` does. Guessing the other one binds the policy to the wrong rows.
#[test]
fn a_policy_naming_a_table_two_schemas_hold_follows_the_search_path() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
SET search_path TO aaa, public;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = model.model();

    let reads: Vec<(String, Option<String>)> = type_names(&dsl)
        .into_iter()
        .filter(|name| name != "user")
        .map(|name| {
            let definition = relation_definition(&dsl, &name, "can_select");
            (name, definition)
        })
        .collect();

    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("owner"))
            .count(),
        1,
        "exactly one of the two tables carries the policy:\n{dsl}"
    );
    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("no_access"))
            .count(),
        1,
        "the table the path does not select must read nothing:\n{dsl}"
    );

    // The policy resolves to `aaa.docs`, and a table carrying a policy claims the
    // canonical type name, so the untouched `public.docs` is the renamed one.
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the first path entry holding the name wins:\n{dsl}"
    );
}

/// A policy may name its table without the schema. Matching that spelling against the
/// schema qualified name as text tells the operator RLS denies a command that its own
/// policy grants.
#[test]
fn a_filtered_policy_named_without_its_schema_is_reported_as_filtered() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        model.notes().iter().any(|note| {
            note.message()
                .contains("fell below the confidence threshold")
                && note.message().contains("SELECT")
        }),
        "the dropped SELECT policy must be reported as dropped, got {:#?}",
        model.notes()
    );
    assert!(
        !model.notes().iter().any(|note| {
            note.message().contains("No permissive policy") && note.message().contains("SELECT")
        }),
        "a policy PostgreSQL applies must not be reported as absent, got {:#?}",
        model.notes()
    );
}

/// A table that only appears as a deny-all must not take the canonical name from
/// a table with real policies: enabling RLS on an unrelated empty table would
/// otherwise rename a type whose tuples are already loaded.
#[test]
fn deny_only_table_does_not_take_the_name_of_a_table_with_policies() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

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
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "tasks", relation).as_deref(),
            Some("owner from projects"),
            "every inherited command reads the same parent-side rule:\n{dsl}"
        );
    }
}

/// `PRIMARY KEY (tenant_id, id)` says `id` alone is not unique, so using it as
/// the object identifier merges rows across tenants. Phase 4 names such a row by
/// every key column instead, which is the only answer that keeps two rows apart:
/// shortening the name, by truncation or by taking one column, hands each row the
/// other's access.
#[test]
fn a_composite_primary_key_names_a_row_by_every_key_column() {
    let db = db_of(
        r"
CREATE TABLE docs(tenant_id UUID, id UUID, owner_id UUID, PRIMARY KEY (tenant_id, id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "tenant_id"::text"#),
        "the name starts at the first key column, in declared order:\n{rendered}"
    );
    assert!(
        rendered.contains(r#"|| '|' || CASE WHEN "id"::text"#),
        "the second key column joins the first, or two tenants share one object:\n{rendered}"
    );
    assert!(
        !rendered.contains("composite primary key"),
        "the loss this reported is gone, so nothing may still claim it:\n{rendered}"
    );
    assert!(
        !rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "one column of the key alone must never name the row:\n{rendered}"
    );
}

/// The target caps an identifier, and the crate never sees the data, so it states the
/// budget rather than listing the rows past it. Only where the key's type could reach
/// the cap: a note on every table would say nothing.
#[test]
fn a_table_whose_key_could_overrun_is_told_its_budget() {
    let budget_of = |declaration: &str, table: &str| -> Option<usize> {
        let db = db_of(&format!(
            "{declaration}
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON {table} FOR SELECT USING (owner_id = current_user);
"
        ));
        translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .find_map(|note| match note {
                TranslationNote::RowIdentifierBudget { table: t, budget } if t == table => {
                    Some(*budget)
                }
                _ => None,
            })
    };

    assert_eq!(
        budget_of(
            "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);",
            "docs"
        ),
        Some(251),
        "a text key can reach the cap, so the operator gets the exact number"
    );
    assert_eq!(
        budget_of(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);",
            "docs"
        ),
        None,
        "a uuid renders 36 safe characters, so saying anything here would be noise"
    );
    assert_eq!(
        budget_of(
            "CREATE TABLE a_longer_table_name(id TEXT PRIMARY KEY, owner_id TEXT);",
            "a_longer_table_name"
        ),
        Some(236),
        "the cap covers the whole name, so a longer type leaves the key less room"
    );
}

/// The budget note states a contract the operator has to check, and the model is
/// complete without it, so it must not read as the model diverging from the database.
#[test]
fn the_budget_note_does_not_claim_a_divergence() {
    let db = db_of(
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translation = translator(ConfidenceLevel::B).translate(&db);
    assert_eq!(
        translation
            .clone()
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .filter(|note| note.severity().diverges_from_database())
            .count(),
        0,
        "a stated budget is not a loss the model already took"
    );
    assert!(
        translation.outputs().is_ok(),
        "and it must not close the ordinary door"
    );
}

/// The subject side has its own cap and its own unit, so the generated query needs its
/// own guard: an owner name past it aborts the whole load exactly as an object does.
#[test]
fn the_generated_query_guards_the_subject_length_too() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let rendered = format_tuples(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains("octet_length("),
        "a text owner can overrun the subject cap, so the query must leave it out:\n{rendered}"
    );
    assert!(
        rendered.contains("<= 512"),
        "and the subject cap is 512, not the object's 256:\n{rendered}"
    );
    assert!(
        !rendered.contains("AND length("),
        "the uuid key cannot overrun, so no object guard belongs here:\n{rendered}"
    );
}

/// Without a primary key or a unique constraint two rows can share `id`, so
/// keying objects on it merges their permissions.
#[test]
fn column_no_constraint_makes_unique_does_not_identify_objects() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        !rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "a non-unique column must not identify objects:\n{rendered}"
    );
    assert!(
        rendered.contains("does not identify a row"),
        "the operator must be told why no ownership tuples were emitted:\n{rendered}"
    );
}

/// A `NOT NULL UNIQUE` column identifies a row as well as a primary key does,
/// so refusing it would deny access the policy grants.
#[test]
fn not_null_unique_column_identifies_objects_without_a_primary_key() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID NOT NULL UNIQUE, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "a uniquely constrained column identifies objects:\n{rendered}"
    );
}

const SPLIT_INSERT_AND_SELECT: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, author_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (author_id = current_user);
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
";

/// Returning a table column, or naming an `ON CONFLICT` target, also checks the
/// new row against the `SELECT` policies, so inserting a row the author cannot
/// read back fails even though plain `INSERT` succeeds.
#[test]
fn reading_the_inserted_row_back_needs_select_as_well_as_insert() {
    let db = db_of(SPLIT_INSERT_AND_SELECT);
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let insert = relation_definition(&dsl, "docs", "can_insert")
        .expect("an INSERT policy defines can_insert");
    let readback = relation_definition(&dsl, "docs", "can_insert_returning")
        .unwrap_or_else(|| panic!("reading the new row back needs its own relation:\n{dsl}"));

    assert_eq!(
        readback,
        format!("{insert} and can_select"),
        "reading back requires the insert rule and the read:\n{dsl}"
    );
}

/// When the same expression governs both commands the readback relation repeats
/// `can_insert`, and a relation that says nothing is noise.
#[test]
fn readback_relation_is_absent_when_inserting_implies_reading() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_user)
    WITH CHECK (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert!(
        relation_definition(&dsl, "docs", "can_insert_returning").is_none(),
        "the insert rule already implies the read:\n{dsl}"
    );
}

/// `INSERT ... ON CONFLICT ... DO UPDATE` updates the conflicting row, so
/// `PostgreSQL` applies the UPDATE policies to it and to the merged row. An insert
/// policy alone does not allow it.
#[test]
fn an_upsert_requires_the_update_policies_as_well_as_the_insert() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_upsert").as_deref(),
        Some("can_insert and can_update"),
        "an upsert needs the UPDATE policies as well as the INSERT ones:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_update").as_deref(),
        Some("no_access"),
        "no UPDATE policy leaves the upsert denied:\n{dsl}"
    );
}

/// Where no row can be inserted at all the upsert relation repeats `can_insert`,
/// and a relation that says nothing is noise.
#[test]
fn upsert_relation_is_absent_where_no_row_can_be_inserted() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_insert").as_deref(),
        Some("no_access"),
        "no INSERT policy denies inserts:\n{dsl}"
    );
    assert!(
        relation_definition(&dsl, "docs", "can_upsert").is_none(),
        "a denied insert already denies the upsert:\n{dsl}"
    );
}

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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains("no_access"),
        "an untranslatable RESTRICTIVE policy must gate can_select, got 'define can_select: {can_select}'\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.subject() == "docs_tenant"),
        "the dropped RESTRICTIVE policy must be reported, got: {:#?}",
        model.notes()
    );
}

/// One permissive read plus a barrier only `contractor` is subject to.
const ROLE_SCOPED_BARRIER: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
";

/// A RESTRICTIVE policy binds only the roles it names, so a user outside them keeps
/// whatever the permissive policies grant.
#[test]
fn a_role_scoped_restrictive_policy_leaves_other_roles_unconstrained() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "the contractor scope must reach the model:\n{}",
            model.model()
        )
    });
    let limited = relation_definition(&model.model(), "docs", "can_select")
        .and_then(|can_select| {
            relation_definition(&model.model(), "docs", can_select.trim()).or(Some(can_select))
        })
        .expect("docs should define can_select");
    assert!(
        limited.contains(&format!("but not usage from {scope}")),
        "a user outside the role's inherited privileges must keep the grant, got \
         '{limited}':\n{}",
        model.model()
    );
}

/// The subtracted side of a barrier is consulted like any other, so its tuples must
/// survive the reachability filter. Without them the barrier subtracts nobody and the
/// bound role keeps the access it forbids.
#[test]
fn a_role_scoped_barrier_keeps_the_tuples_it_subtracts() {
    let db = db_of(ROLE_SCOPED_BARRIER);
    let translator = translator(ConfidenceLevel::B);
    let model = translator.translate(&db).outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "the contractor scope must reach the model:\n{}",
            model.model()
        )
    });

    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
    assert!(
        tuples.iter().any(|query| {
            query.sql.contains(&format!("'{scope}' AS relation"))
                && query.sql.contains("'pg_role:contractor' AS subject")
        }),
        "the subtracted role needs its tuples, got: {:#?}",
        tuples.iter().map(|query| &query.sql).collect::<Vec<_>>()
    );
}

/// A barrier reaches the JSON model as a `difference` node, which `OpenFGA` validates
/// like any other userset.
#[test]
fn a_role_scoped_barrier_emits_a_consistent_json_model() {
    let db = db_of(ROLE_SCOPED_BARRIER);
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .json_model();

    assert_model_is_internally_consistent(&json);
    let serialized = serde_json::to_string(&json).expect("model should serialize");
    assert!(
        serialized.contains(r#""difference""#),
        "the barrier must survive into the JSON model, got:\n{serialized}"
    );
}

/// Two barriers bind two roles, so each wraps the result of the one before it rather
/// than replacing it.
#[test]
fn two_role_scoped_barriers_each_bind_their_own_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID, approver_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
CREATE POLICY docs_approve ON docs AS RESTRICTIVE FOR SELECT TO auditor
  USING (approver_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let limits: Vec<String> = model
        .model()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("define limit_"))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| format!("limit_{name}"))
        .collect();
    let [first, second] = limits.as_slice() else {
        panic!(
            "each barrier needs its own relation, got {limits:?}:\n{}",
            model.model()
        );
    };

    let outer = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    let (outer, inner) = if outer.trim() == *second {
        (second, first)
    } else {
        (first, second)
    };
    let outer_body = relation_definition(&model.model(), "docs", outer)
        .unwrap_or_else(|| panic!("{outer} should be defined:\n{}", model.model()));
    assert_eq!(
        outer_body.matches(inner.as_str()).count(),
        2,
        "the outer barrier applies to both sides of the inner one, got '{outer_body}':\n{}",
        model.model()
    );
    assert_eq!(
        model.model().matches("but not").count(),
        2,
        "each barrier subtracts its own role:\n{}",
        model.model()
    );
}

/// Changing a row needs it readable, and a barrier can take that readability away, so
/// the read gate stays even when the rule sits behind one.
#[test]
fn a_write_behind_a_barrier_keeps_its_read_gate() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_edit ON docs FOR UPDATE USING (editor_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR ALL TO contractor
  USING (reviewer_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_update_using = relation_definition(&model.model(), "docs", "can_update_using")
        .or_else(|| relation_definition(&model.model(), "docs", "can_update"))
        .expect("docs should define the update phase");
    assert!(
        can_update_using.contains("can_select"),
        "an editor who cannot read the row cannot change it, got '{can_update_using}':\n{}",
        model.model()
    );
}

/// A barrier over an inherited rule holds a reference the alias passes rewrite, so a
/// pass that skips one side leaves the model dangling.
#[test]
fn a_barrier_over_an_inherited_rule_keeps_its_references() {
    let db = db_of(
        r"
CREATE TABLE parents(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE parents ENABLE ROW LEVEL SECURITY;
CREATE POLICY parents_own ON parents FOR SELECT USING (owner_id = current_user);
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES parents(id), reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_inherit ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM parents p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
",
    );
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .json_model();

    assert_model_is_internally_consistent(&json);
}

/// An unscoped RESTRICTIVE policy binds everyone, so nothing is subtracted.
#[test]
fn an_unscoped_restrictive_policy_binds_every_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT
  USING (reviewer_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert!(
        !model.model().contains("but not"),
        "a barrier every role is subject to needs no exclusion:\n{}",
        model.model()
    );
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(" and "),
        "the barrier stays a conjunct, got '{can_select}':\n{}",
        model.model()
    );
}

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
    let tuples = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();

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
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        type_names(&model.model()).iter().any(|name| name == "docs"),
        "an RLS-enabled table must appear in the model:\n{}",
        model.model()
    );
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
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
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_insert").as_deref(),
        Some("owner"),
        "the INSERT policy must still translate:\n{}",
        model.model()
    );
    for relation in ["can_select", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.model()));
    assert!(
        can_select.contains("no_access"),
        "filtered-out policies leave the table denied, got 'define can_select: {can_select}'"
    );
}

/// A dropped permissive policy leaves the model denying what RLS grants. Saying
/// no policy covers the command instead tells the operator that `PostgreSQL`
/// denies it, which is the opposite of the truth.
#[test]
fn a_command_denied_only_by_filtering_is_not_reported_as_unpolicied() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_pub ON docs FOR SELECT USING (is_public = TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        !messages
            .iter()
            .any(|message| message.contains("No permissive policy on 'docs' covers SELECT")),
        "a permissive SELECT policy exists and was dropped: {messages:#?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("confidence threshold") && message.contains("SELECT")),
        "the operator must be told the policy was dropped: {messages:#?}"
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
    let _classified = translator.classify(&db);
    let model = translator.translate(&db).outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("docs_tenant"),
        "a dropped permissive policy must still be named:\n{report}"
    );
    assert!(
        report.contains('D'),
        "the report must state the confidence that caused the drop:\n{report}"
    );
}

/// The report is where an operator learns why a policy vanished, so "no known
/// pattern" sends them re-reading a clause the translator could have named.
#[test]
fn report_names_the_function_call_that_defeated_recognition() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (tenant_of(owner_id) = 'acme');
",
    );
    let translator = translator(ConfidenceLevel::B);
    let _classified = translator.classify(&db);
    let model = translator.translate(&db).outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("tenant_of"),
        "the call the operator has to go read must be named:\n{report}"
    );
    assert!(
        !report.contains("does not match any known pattern"),
        "a named call replaces the generic reason rather than joining it:\n{report}"
    );
}

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
    let _classified = translator.classify(&db);
    let model = translator.translate(&db).outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("docs_owner"),
        "translated policies stay in the report:\n{report}"
    );
    assert!(
        report.contains("docs_tenant"),
        "a policy dropped below the confidence threshold must still be listed:\n{report}"
    );
}

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
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("billing admin")
                && note.message().contains("billing_admin")),
        "the role-name rewrite must name both the original and the OpenFGA identifier, got: {:#?}",
        model.notes()
    );
}

/// The DSL and the JSON model are rendered from one plan, so they must describe
/// the same relations. A variant handled by only one renderer would let an
/// operator load a model that grants more than the `.fga` file they reviewed.
#[test]
fn json_model_declares_the_same_relations_as_the_dsl() {
    // Exercises collision renaming, role scoping, inheritance, a public flag, a
    // union, and a table present only as a deny-all.
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
    let json = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .json_model();

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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

    let select =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let update =
        relation_definition(&dsl, "docs", "can_update").expect("docs should define can_update");
    assert_ne!(
        select, update,
        "SELECT admits owner_id and UPDATE admits editor_id, so they cannot share a relation:\n{dsl}"
    );

    // Every ownership query must populate the relation its own column feeds.
    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

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
    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        if !query.sql.contains(r#"FROM "projects""#) || !query.sql.contains("'orgs:'") {
            continue;
        }
        assert!(
            query.sql.contains(r#"'orgs:' || CASE WHEN "org_id"::text"#),
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
    let model = translator.translate(&db).outputs_accepting_gaps();

    assert!(
        !type_names(&model.model()).iter().any(|name| name == "id"),
        "a join column must not become a type:\n{}",
        model.model()
    );
    assert_eq!(
        relation_definition(&model.model(), "projects", "can_select").as_deref(),
        Some("no_access"),
        "an unconfirmable parent link must deny, not guess:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.subject() == "projects_sel" && note.message().contains("own primary key")
        }),
        "the operator must be told why the subquery was refused, got: {:#?}",
        model.notes()
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
    let model = translator.translate(&db).outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert_ne!(
        can_select,
        "no_access",
        "a membership table keyed by its foreign key must still grant access:\n{}",
        model.model()
    );
    assert!(
        format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries()
        )
        .contains(r#"FROM "doc_owner""#),
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
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.docs FOR SELECT USING (tenant = current_setting('app.tenant'));
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
";
    let db = db_of(sql);
    let at_b = type_names(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model(),
    );
    let at_d = type_names(
        &translator(ConfidenceLevel::D)
            .translate(&db)
            .outputs_accepting_gaps()
            .model(),
    );

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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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

/// Operators at the outermost nesting level of a DSL definition body.
fn top_level_operators(body: &str) -> std::collections::BTreeSet<&'static str> {
    let mut depth = 0i32;
    let mut found = std::collections::BTreeSet::new();
    for (idx, ch) in body.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if depth == 0 => {
                for op in [" but not ", " and ", " or "] {
                    if body[idx..].starts_with(op) {
                        found.insert(op.trim());
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// Every mixed expression in the `OpenFGA` language reference groups with
/// parentheses, so one operator never sits beside a different one.
#[test]
fn no_definition_mixes_operators_without_parentheses() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT TO auditor USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs FOR SELECT USING (tenant_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let mut checked = 0;
    for line in dsl.lines() {
        let Some(body) = line
            .trim()
            .strip_prefix("define ")
            .and_then(|rest| rest.split_once(':'))
            .map(|(_, body)| body.trim())
        else {
            continue;
        };
        let operators = top_level_operators(body);
        assert!(
            operators.len() <= 1,
            "'{}' mixes {:?} at one level:\n{dsl}",
            line.trim(),
            operators
        );
        checked += 1;
    }
    assert!(checked > 5, "expected a populated model:\n{dsl}");
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
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .json_model();

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
        Userset::Difference { difference } => {
            for side in [&difference.base, &difference.subtract] {
                check_userset_references(declared, declared_types, type_name, relation, side);
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    let model = translator(ConfidenceLevel::D)
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "orders", "can_select").as_deref(),
        Some("no_access"),
        "a join the model cannot express must deny, not drop the condition:\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.subject() == "orders_sel"),
        "the operator must be told the subquery was refused, got: {:#?}",
        model.notes()
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
  EXISTS (SELECT 1 FROM doc_members dm
          WHERE dm.doc_id = docs.id AND dm.user_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    let model = translator(ConfidenceLevel::D)
        .translate(&db)
        .outputs_accepting_gaps();

    for policy in ["docs_sel", "docs_upd"] {
        let count = model
            .notes()
            .iter()
            .filter(|note| note.subject() == policy && note.message().contains("status"))
            .count();
        assert_eq!(
            count,
            1,
            "{policy} should report its attribute guard once, got {count}: {:#?}",
            model.notes()
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();

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
    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        if !query.sql.contains(&format!("'{tupleset}' AS relation")) {
            continue;
        }
        assert!(
            query.sql.contains("'projects:' ||"),
            "a query feeding '{tupleset}' must write projects objects:\n{}",
            query.sql
        );
    }
    assert_model_is_internally_consistent(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
        let db = db_of(&schema(restriction));
        let model = translator(ConfidenceLevel::C)
            .translate(&db)
            .outputs_accepting_gaps();
        relation_definition(&model.model(), "docs", "can_select")
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
    let db = db_of(&schema("deleted_at IS NULL AND tenant_id = current_user"));
    let model = translator(ConfidenceLevel::C)
        .translate(&db)
        .outputs_accepting_gaps();
    let notes: Vec<String> = model
        .notes()
        .iter()
        .filter(|note| note.subject() == "docs_bar")
        .map(TranslationNote::message)
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
        .translate(&db_of(&schema("tasks_sel")))
        .outputs_accepting_gaps()
        .model();
    let inherited = inherited_relations(&dsl);
    assert_eq!(
        inherited.len(),
        1,
        "both children inherit the same rule, so projects needs it once, got {inherited:?}:\n{dsl}"
    );

    // Renaming a child policy must not rename a relation on the parent.
    let renamed = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema("tasks_select_v2")))
        .outputs_accepting_gaps()
        .model();
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
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
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "a recursive SELECT policy makes every read fail, so nothing is readable:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.subject() == "docs"
                && note.message().contains("recursion")
                && note.message().contains("docs reads docs")
        }),
        "the operator must be told the table's reads loop on itself, got {:#?}",
        model.notes()
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
    let dsl = translator(ConfidenceLevel::A)
        .translate(&joined)
        .outputs_accepting_gaps()
        .model();
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

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
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "t1", "can_select").as_deref(),
        Some("no_access"),
        "every read of t1 raises infinite recursion, so nothing is readable:\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "the operator must be told why, got {:#?}",
        model.notes()
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "no membership row is readable, so the policy grants nothing:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "the operator must be told which table hides the rows, got {:#?}",
        model.notes()
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(" from "),
        "the membership grant stays, got '{can_select}':\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "the operator must be told the join table filters memberships, got {:#?}",
        model.notes()
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert!(
        !model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "an unprotected join table needs no note, got {:#?}",
        model.notes()
    );
}

/// A membership table whose only read policy targets a role hides every row from a
/// user outside that role, so the grant it feeds requires that role too.
#[test]
fn membership_readable_only_by_a_role_requires_that_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_read ON doc_members FOR SELECT TO auditor USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let model = translator.translate(&db).outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "docs must scope the membership grant by role:\n{}",
            model.model()
        )
    });
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(&format!("from {scope}")),
        "reading docs must require the role that can read doc_members, got '{can_select}':\n{}",
        model.model()
    );

    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
    assert!(
        tuples.iter().any(|q| {
            q.sql.contains("'docs:'")
                && q.sql.contains(&format!("'{scope}' AS relation"))
                && q.sql.contains("'pg_role:auditor' AS subject")
        }),
        "the scope relation needs auditor tuples on docs, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
}

/// One read policy any role may use makes the membership rows reachable without a
/// role, so narrowing the grant would deny access `PostgreSQL` allows.
#[test]
fn membership_readable_by_public_keeps_the_grant_unscoped() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_audit ON doc_members FOR SELECT TO auditor USING (true);
CREATE POLICY dm_self ON doc_members FOR SELECT USING (user_id = current_user);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        pg_role_relation(&model.model(), "docs"),
        None,
        "an unscoped read policy leaves the membership grant open to every role:\n{}",
        model.model()
    );
}

/// Permissive read policies are an OR, so being in either role is enough.
#[test]
fn membership_readable_by_two_roles_admits_either_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_audit ON doc_members FOR SELECT TO auditor USING (true);
CREATE POLICY dm_support ON doc_members FOR SELECT TO support USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let model = translator.translate(&db).outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "docs must scope the membership grant by role:\n{}",
            model.model()
        )
    });
    let tuples = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
    for role in ["auditor", "support"] {
        assert!(
            tuples.iter().any(|q| {
                q.sql.contains("'docs:'")
                    && q.sql.contains(&format!("'{scope}' AS relation"))
                    && q.sql.contains(&format!("'pg_role:{role}' AS subject"))
            }),
            "either role can read the membership rows, so {role} needs scope tuples, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
    }
}

/// `current_user` inside a `SECURITY DEFINER` function is the function owner, the
/// same value for every caller, so the policy is not per-user ownership.
#[test]
fn security_definer_current_user_is_not_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION app_uid() RETURNS UUID LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "the definer's identity is not the caller's, so the row owner is not the caller:\n{}",
        model.model()
    );
}

/// Declaring the function in the registry asserts its semantics, which outranks what
/// the body and the security mode suggest.
#[test]
fn an_explicitly_registered_accessor_outranks_its_security_mode() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION app_uid() RETURNS UUID LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = TranslatorBuilder::new()
        .with_registry_json(r#"{"app_uid": {"kind": "current_user_accessor", "returns": "uuid"}}"#)
        .expect("registry should parse")
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "a declared accessor stays one:\n{}",
        model.model()
    );
    assert!(
        !model
            .notes()
            .iter()
            .any(|note| note.message().contains("runs as its owner")),
        "the note only fires where the translation refused, got {:#?}",
        model.notes()
    );
}

/// A dropped policy tells the operator nothing about the cause, so the function that
/// cannot identify the caller is named.
#[test]
fn an_owner_bound_accessor_is_reported_by_name() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION app_uid() RETURNS UUID LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("app_uid") && note.message().contains("owner")),
        "the operator must be told which function runs as its owner, got {:#?}",
        model.notes()
    );
}

/// The same body under the default `SECURITY INVOKER` does identify the caller.
#[test]
fn security_invoker_current_user_stays_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION app_uid() RETURNS UUID LANGUAGE sql AS 'SELECT current_user::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "an invoker accessor is per-caller ownership:\n{}",
        model.model()
    );
}

/// A session setting is unaffected by whose privileges the function runs with, so a
/// `SECURITY DEFINER` body reading one still identifies the caller.
#[test]
fn security_definer_current_setting_still_identifies_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE FUNCTION app_uid() RETURNS UUID LANGUAGE sql SECURITY DEFINER
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "a session setting is per-caller regardless of the security mode:\n{}",
        model.model()
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
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
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
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model(),
    );
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
    // The recursive policy makes every read fail.
    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "t1", action).as_deref(),
            Some("no_access"),
            "{action} should deny for this schema:\n{dsl}"
        );
    }

    for query in translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries()
    {
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
    let dsl = translator.translate(&db).outputs_accepting_gaps().model();
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
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries()
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
    let queries = translator
        .translate(&db)
        .outputs_accepting_gaps()
        .tuple_queries();
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
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let reports = model
        .notes()
        .iter()
        .filter(|note| note.message().contains("docs") && note.message().contains("SELECT policy"))
        .count();
    assert_eq!(
        reports,
        1,
        "the unreachable DELETE policy must be reported once, got {:#?}",
        model.notes()
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
            .translate(&readable)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains("SELECT policy")),
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
            .translate(&insert_only)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains("SELECT policy")),
        "an INSERT needs no read, so nothing is unreachable"
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

/// `CREATE POLICY p ON docs;` stores neither clause. `PostgreSQL` then has no
/// permissive `USING` qual and no permissive `WITH CHECK`, so the table is
/// closed on every command. Reading the missing clause as `TRUE` opens the
/// table to everyone.
#[test]
fn a_policy_with_no_clause_at_all_grants_nothing() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_bare ON docs;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
        assert!(
            definition.contains("no_access"),
            "a clauseless policy admits no row, so {relation} must deny, got \
             'define {relation}: {definition}'"
        );
    }
}

/// A `SELECT` policy with no `USING` contributes no permissive read qual, and it
/// is the only one here, so nothing is readable.
#[test]
fn a_select_policy_with_no_using_clause_grants_no_read() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.model()));
    assert!(
        can_select.contains("no_access"),
        "a SELECT policy with no USING reads nothing, got 'define can_select: {can_select}'"
    );
}

/// `WITH CHECK` admits the new row and says nothing about the existing one. With
/// no `USING` clause anywhere, `PostgreSQL` finds no permissive qual for the row
/// being changed, so no `UPDATE` can ever succeed. Mirroring the check backwards
/// onto the `USING` side grants what `PostgreSQL` refuses.
#[test]
fn an_update_policy_with_no_using_clause_updates_no_row() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE WITH CHECK (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_update = relation_definition(&model.model(), "docs", "can_update")
        .unwrap_or_else(|| panic!("docs should define can_update:\n{}", model.model()));
    assert!(
        can_update.contains("no_access"),
        "no USING clause admits the row to change, got 'define can_update: {can_update}'"
    );
}

/// The clause a command reads decides whether a policy covers it. Telling the
/// operator the `UPDATE` policy fell below the confidence threshold says
/// `PostgreSQL` grants the update, which is the opposite of the truth.
#[test]
fn a_command_a_policy_names_without_the_clause_it_needs_is_reported_as_unpolicied() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE WITH CHECK (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|message| {
            message.contains("No permissive policy on 'docs' covers") && message.contains("UPDATE")
        }),
        "RLS denies the UPDATE outright and the report must say so: {messages:#?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("confidence threshold")),
        "nothing was dropped by confidence here: {messages:#?}"
    );
}

/// A membership table whose only read policy stores no `USING` shows no row, so
/// the parent policy's `EXISTS` finds nothing and the grant is empty.
#[test]
fn membership_read_policy_with_no_using_clause_denies_the_parent_grant() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_sel ON doc_members FOR SELECT;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user)
);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.model()));
    assert!(
        can_select.contains("no_access"),
        "no membership row is visible, so the grant is empty, got \
         'define can_select: {can_select}'"
    );
}

/// A locking read (`SELECT ... FOR UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`,
/// `FOR KEY SHARE`) is filtered by the `UPDATE` policies' `USING` clause as well
/// as by the `SELECT` policies, so `can_select` answers for more rows than
/// `PostgreSQL` returns.
#[test]
fn a_locking_read_needs_the_rows_an_update_may_touch() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user) WITH CHECK (TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    let locking = relation_definition(&model.model(), "docs", "can_select_for_update")
        .unwrap_or_else(|| {
            panic!(
                "docs should define can_select_for_update:\n{}",
                model.model()
            )
        });
    assert_eq!(
        locking,
        "can_update_using",
        "a locking read sees the rows an UPDATE may touch:\n{}",
        model.model()
    );
    assert_ne!(
        Some(locking.as_str()),
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        "everyone reads this table, but only an owner may lock a row"
    );
}

/// With no `UPDATE` policy, `PostgreSQL` has no permissive `USING` qual for the
/// row being locked, so a locking read returns nothing even where a plain read
/// returns every row.
#[test]
fn a_locking_read_is_denied_where_no_policy_admits_an_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select_for_update").as_deref(),
        Some("can_update"),
        "the locking read answers with the update rule:\n{}",
        model.model()
    );
    let can_update = relation_definition(&model.model(), "docs", "can_update")
        .unwrap_or_else(|| panic!("docs should define can_update:\n{}", model.model()));
    assert!(
        can_update.contains("no_access"),
        "and that rule denies, got 'define can_update: {can_update}'"
    );
}

/// Where the two `UPDATE` clauses agree there is no separate `USING` relation, so
/// the locking read still needs a name of its own to point at.
#[test]
fn a_locking_read_is_answered_even_where_the_update_clauses_agree() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        relation_definition(&model.model(), "docs", "can_update_using").is_none(),
        "one clause means one relation:\n{}",
        model.model()
    );
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select_for_update").as_deref(),
        Some("can_update"),
        "the locking read answers with the update rule:\n{}",
        model.model()
    );
}

/// "No permissive policy covers UPDATE" sends the operator looking for a policy
/// they already wrote. The report has to name the one that stores no clause.
#[test]
fn report_names_the_policy_whose_clause_is_absent() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE WITH CHECK (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("'docs_upd' names UPDATE without a USING clause")),
        "the policy at fault must be named: {messages:#?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("'docs_sel'")),
        "a policy storing the clause it needs is not at fault: {messages:#?}"
    );
}

/// A clauseless policy fails both halves, and the two halves read different
/// clauses, so the operator needs both named.
#[test]
fn report_names_both_clauses_a_bare_policy_omits() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_bare ON docs;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|message| {
            message.contains("'docs_bare' names SELECT, UPDATE, DELETE without a USING clause")
        }),
        "the commands a missing USING denies must be named: {messages:#?}"
    );
    assert!(
        messages.iter().any(|message| {
            message.contains("'docs_bare' names INSERT without a WITH CHECK clause")
        }),
        "an INSERT reads the WITH CHECK alone: {messages:#?}"
    );
}

/// A policy storing no clause contributes nothing, but another policy may still
/// grant the command, so the note must not claim the command is denied.
#[test]
fn a_clauseless_policy_beside_a_working_one_is_not_reported_as_a_denial() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bare ON docs FOR SELECT;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "the working policy still grants reads:\n{}",
        model.model()
    );
    let note = messages
        .iter()
        .find(|message| message.contains("'docs_bare'"))
        .unwrap_or_else(|| panic!("the clauseless policy is worth naming: {messages:#?}"));
    assert!(
        note.contains("names SELECT without a USING clause"),
        "the absent clause is the point: {note}"
    );
    assert!(
        !note.contains("denie"),
        "reads are granted by the other policy, so this note claims no denial: {note}"
    );
}

/// A policy the schema gives no clause constrains nothing, so it must not mint a
/// role scope relation, a `pg_role` type, or a note asking for memberships that
/// nothing consults.
#[test]
fn a_clauseless_policy_mints_no_role_scope() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR ALL TO auditor;
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        pg_role_relation(&model.model(), "docs"),
        None,
        "the barrier stores no clause, so it binds nothing:\n{}",
        model.model()
    );
    assert!(
        !type_names(&model.model())
            .iter()
            .any(|name| name == "pg_role"),
        "no relation reads a role here:\n{}",
        model.model()
    );
    assert!(
        !model
            .notes()
            .iter()
            .any(|note| note.message().contains("inheriting members")),
        "asking for tuples nothing consults is noise: {:#?}",
        model.notes()
    );
}

/// A RESTRICTIVE `UPDATE` policy storing only a `WITH CHECK` guards the new row and
/// says nothing about the existing one, so it narrows `can_update` while leaving a
/// locking read alone. `SELECT ... FOR UPDATE` returns the rows the permissive
/// `USING` admits, whatever the barrier would refuse to write.
#[test]
fn a_restrictive_update_check_narrows_the_write_but_not_the_lock() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE WITH CHECK (reviewer_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let check = relation_definition(&dsl, "docs", "can_update_check")
        .unwrap_or_else(|| panic!("docs should define can_update_check:\n{dsl}"));
    assert!(
        check.contains("reviewer"),
        "the barrier guards the new row, got 'define can_update_check: {check}'"
    );

    let using = relation_definition(&dsl, "docs", "can_update_using")
        .unwrap_or_else(|| panic!("docs should define can_update_using:\n{dsl}"));
    assert!(
        !using.contains("reviewer"),
        "a WITH CHECK says nothing about the existing row, got \
         'define can_update_using: {using}'"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "so a locking read is not narrowed by the barrier either:\n{dsl}"
    );
}

/// A RESTRICTIVE `UPDATE` policy storing a `USING` binds the existing row, and
/// `PostgreSQL` mirrors that clause onto the new row as well, so both halves of the
/// update carry it and a locking read is narrowed too.
#[test]
fn a_restrictive_update_barrier_binds_both_halves_of_the_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user)
  WITH CHECK (editor_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE USING (reviewer_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    for relation in ["can_update_using", "can_update_check"] {
        let definition = relation_definition(&dsl, "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{dsl}"));
        assert!(
            definition.contains("reviewer"),
            "the barrier binds {relation}, got 'define {relation}: {definition}'"
        );
    }
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "and a locking read carries it through the USING half:\n{dsl}"
    );
}

/// Coverage reads the schema's own policies, grouped by the table each name resolves
/// to. Grouping by the spelling instead loses the clauseless policy for a table
/// another policy spells differently, and the operator is never told which policy
/// admits nothing.
#[test]
fn a_clauseless_policy_is_found_through_any_spelling_of_its_table() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bare ON "docs" FOR SELECT;
"#,
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "the policy that stores a clause still grants reads:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| note
            .message()
            .contains("'docs_bare' names SELECT without a USING clause")),
        "the clauseless policy belongs to the same table however it spells it: {:#?}",
        model.notes()
    );
}

/// `PostgreSQL` 18, role alice, rows carrying `ARRAY['alice']`, `ARRAY['alice','bob']`,
/// `ARRAY[]`, `NULL`, `ARRAY[NULL]`, `ARRAY['alice',NULL]` and `ARRAY['bob']`: a
/// policy `USING (current_user = ANY (editors))` returns exactly the three rows
/// holding 'alice', and `SELECT id, unnest(editors)` filtered to 'alice' returns
/// the same three. The translation is exact, not a widening, so it earns a
/// relation rather than a refusal.
#[test]
fn caller_listed_in_an_array_column_is_a_relationship_not_a_refusal() {
    for clause in [
        "current_user = ANY (editors)",
        "editors @> ARRAY[current_user]",
        "ARRAY[current_user] <@ editors",
        "ARRAY[current_user] && editors",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, editors TEXT[]);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_editors ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let dsl = translator.translate(&db).outputs_accepting_gaps().model();
        let rendered = format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
        );

        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{clause}`: docs must define can_select:\n{dsl}"));
        assert_ne!(
            can_select, "no_access",
            "`{clause}`: RLS grants three rows, so the model must not deny:\n{dsl}"
        );

        let relation = can_select.trim().to_string();
        let body = relation_definition(&dsl, "docs", &relation).unwrap_or_else(|| {
            panic!("`{clause}`: can_select points at '{relation}' which is undefined:\n{dsl}")
        });
        assert!(
            body.contains("user"),
            "`{clause}`: '{relation}' must admit users, got '{body}':\n{dsl}"
        );

        // Without the unnesting scan the relation exists but can never be populated,
        // which denies exactly the rows PostgreSQL grants.
        assert!(
            rendered.to_lowercase().contains("unnest"),
            "`{clause}`: the array column has to be expanded to produce tuples:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""editors""#),
            "`{clause}`: the tuple query must read the array column:\n{rendered}"
        );
    }
}

/// An array column and a subquery both sit to the right of `= ANY`, and only the
/// column can be expanded. Treating a subquery as one emitted
/// `UNNEST("(SELECT user_id FROM doc_members WHERE doc_id = docs"."id)")`, which
/// splits on the dot and names two columns that do not exist, under a relation named
/// after the same text. The caller has to sit on the left for the array recognizer to
/// look at the right at all, so that is the shape this pins.
#[test]
fn any_over_a_subquery_is_never_expanded_as_an_array_column() {
    const MEMBERS: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, editors TEXT[]);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

    for clause in [
        "current_user = ANY (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user = ANY (SELECT user_id FROM doc_members)",
    ] {
        let db = db_of(&format!(
            "{MEMBERS}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let rendered = format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
        );

        assert!(
            !rendered.to_lowercase().contains("unnest"),
            "`{clause}`: a subquery is not an array to expand:\n{rendered}"
        );
        assert!(
            !rendered.contains("SELECT user_id"),
            "`{clause}`: the subquery text must not reach the generated SQL:\n{rendered}"
        );
    }

    // The object-key spelling is real membership and must keep its P4 translation.
    let db = db_of(&format!(
        "{MEMBERS}CREATE POLICY docs_members ON docs FOR SELECT
           USING (id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user));"
    ));
    let translator = translator(ConfidenceLevel::B);
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );
    assert!(
        rendered.contains(r#"FROM "doc_members""#),
        "membership through the join table still produces its tuples:\n{rendered}"
    );
}

/// `PostgreSQL` 18, role alice, rows carrying `{"owner":"alice"}`, `{"owner":"bob"}`,
/// `{"owner":null}`, `{}`, a NULL column and `{"owner":"carol"}`: a policy
/// `USING (data ->> 'owner' = current_user)` returns exactly the rows whose extracted
/// text equals the caller, since `->>` yields NULL for a missing key, a null value and
/// a null column, and the comparison then filters. `SELECT id, data ->> 'owner'` with
/// the NULLs dropped enumerates the same pairs, so this is exact too.
#[test]
fn caller_named_in_a_jsonb_field_is_ownership_not_a_refusal() {
    for clause in [
        "data ->> 'owner' = current_user",
        "current_user = data ->> 'owner'",
        "(data ->> 'owner')::text = current_user",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, data JSONB);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_json ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let dsl = translator.translate(&db).outputs_accepting_gaps().model();
        let rendered = format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
        );

        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{clause}`: docs must define can_select:\n{dsl}"));
        assert_ne!(
            can_select, "no_access",
            "`{clause}`: RLS grants the matching rows, so the model must not deny:\n{dsl}"
        );

        assert!(
            rendered.contains(r#""data" ->> 'owner'"#),
            "`{clause}`: the tuple query must extract the field:\n{rendered}"
        );
    }
}

/// A JSON key is a SQL string literal, and a quote inside it would close that literal
/// and let the rest execute. The identifier path is already guarded by
/// `quote_sql_identifier`, so the key is the remaining injection point.
#[test]
fn a_quote_in_a_jsonb_key_cannot_break_out_of_its_literal() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_json ON docs FOR SELECT
  USING (data ->> 'ow''ner' = current_user);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let rendered = format_tuples(
        &translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    if rendered.contains("->>") {
        assert!(
            rendered.contains("'ow''ner'"),
            "the quote must stay doubled inside the literal:\n{rendered}"
        );
    }
}

/// A jsonb or array comparison against a literal is an attribute guard, exactly as
/// `status = 'published'` is. Leaving it unrecognized made the same policy shape behave
/// differently depending on whether the attribute lived in a column or a document: the
/// plain spelling reached P7 and kept its relationship half, the jsonb one collapsed the
/// whole `AND` to `no_access`.
#[test]
fn a_jsonb_or_array_attribute_guard_keeps_the_relationship_it_guards() {
    const PLAIN: &str = "status = 'published'";
    let plain_db = db_of(&format!(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB, tags TEXT[], status TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_hybrid ON docs FOR SELECT
           USING (owner_id = current_user AND {PLAIN});"
    ));
    let expected = relation_definition(
        &translator(ConfidenceLevel::C)
            .translate(&plain_db)
            .outputs_accepting_gaps()
            .model(),
        "docs",
        "can_select",
    )
    .expect("the plain spelling defines can_select");
    assert_eq!(
        expected, "owner",
        "guard precondition: the plain attribute guard keeps its relationship half"
    );

    for guard in [
        "data ->> 'status' = 'published'",
        "data @> '{\"public\": true}'",
        "tags && ARRAY['x', 'y']",
        "tags @> ARRAY['x']",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB, tags TEXT[], status TEXT);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_hybrid ON docs FOR SELECT
               USING (owner_id = current_user AND {guard});"
        ));
        let dsl = translator(ConfidenceLevel::C)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();
        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{guard}`: docs must define can_select:\n{dsl}"));
        assert_eq!(
            can_select, expected,
            "`{guard}`: must behave like `{PLAIN}`, which yields '{expected}':\n{dsl}"
        );
    }
}

/// A dropped attribute guard is a widening, so the operator has to be told which guard
/// they are now enforcing themselves.
#[test]
fn a_dropped_jsonb_attribute_guard_names_the_field_it_stopped_checking() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_hybrid ON docs FOR SELECT
  USING (owner_id = current_user AND data ->> 'status' = 'published');
",
    );
    let model = translator(ConfidenceLevel::C)
        .translate(&db)
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|m| m.contains("status")),
        "the field no longer being checked must be named: {messages:#?}"
    );
}

const MEMBERSHIP_SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT, role TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

/// Model and tuples for a single `SELECT` policy over `MEMBERSHIP_SCHEMA`.
fn membership_translation(clause: &str) -> (String, String) {
    let db = db_of(&format!(
        "{MEMBERSHIP_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    (
        translator.translate(&db).outputs_accepting_gaps().model(),
        format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
        ),
    )
}

/// `caller IN (SELECT user_id FROM m WHERE m.fk = outer.id)` is the membership `EXISTS`
/// written the other way round. `PostgreSQL` 18, role alice, over rows covering a member,
/// a non-member, no membership row at all, a row whose `user_id` is NULL, a member beside
/// a NULL, and a member failing a residual predicate: the `IN`, `= ANY` and `EXISTS`
/// spellings agree on every row, the only difference being NULL against false where
/// `user_id` is NULL, and both filter the row out. So all three must translate alike.
#[test]
fn the_caller_inside_a_membership_subquery_translates_like_the_exists_spelling() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        !expected_dsl.contains("can_select: no_access"),
        "guard precondition: the EXISTS spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user = ANY (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user IN (SELECT dm.user_id FROM doc_members dm WHERE dm.doc_id = docs.id)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` must yield the same model as the EXISTS spelling"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the EXISTS spelling"
        );
    }
}

/// A residual predicate no tuple can express has to survive the rewrite, since it is what
/// tells the operator the membership relation is wider than the policy.
#[test]
fn a_residual_predicate_survives_the_caller_in_subquery_rewrite() {
    let (expected_dsl, _) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND role = 'admin' \
         AND user_id = current_user)",
    );
    let (dsl, _) = membership_translation(
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
         AND role = 'admin')",
    );
    assert_eq!(
        dsl, expected_dsl,
        "the role predicate must reach the same place it does through EXISTS"
    );
}

/// Without a correlation to the outer table the predicate is row independent: it admits
/// every row once the caller is a member of anything. Translating it as per-row
/// membership would answer a different question, so all three spellings go through the
/// holder, which grants the rows together.
#[test]
fn an_uncorrelated_membership_subquery_translates_through_a_holder() {
    for clause in [
        "EXISTS (SELECT 1 FROM doc_members WHERE user_id = current_user)",
        "current_user IN (SELECT user_id FROM doc_members)",
        "current_user = ANY (SELECT user_id FROM doc_members)",
    ] {
        let (dsl, _) = membership_translation(clause);
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("member from doc_members_holder"),
            "`{clause}` names no row, so it grants them together:\n{dsl}"
        );
    }
}

/// `IN (SELECT ... LIMIT 1)` tests membership of one arbitrary row, not of the whole
/// result, so translating it as full membership grants rows the policy refuses. The
/// operand extractor is shared with the object-key spelling, which had the same hole.
#[test]
fn a_row_limited_membership_subquery_is_refused() {
    for clause in [
        "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user LIMIT 1)",
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id LIMIT 1)",
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user FETCH FIRST 1 ROWS ONLY)",
    ] {
        let (dsl, _) = membership_translation(clause);
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` limits the rows it tests, so it cannot be full membership:\n{dsl}"
        );
    }
}

/// Whatever is wrong with the refusal of `clause`, across the classification, the model,
/// and the membership tuples alike. Empty when every output refuses it.
///
/// Collected rather than asserted so one test reports every spelling of a clause instead
/// of stopping at the first, which is how a guard wired into one extractor and not the
/// other stays hidden.
fn shaped_membership_subquery_complaints(clause: &str, shaping: &str) -> Vec<String> {
    let db = db_of(&format!(
        "{MEMBERSHIP_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    let mut complaints = Vec::new();

    let classified = translator.classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one classified policy for `{clause}`");
    };
    let pattern = &policy
        .using_classification
        .as_ref()
        .expect("USING should classify")
        .pattern;
    match pattern {
        PatternClass::Unknown { reason, .. } if reason.contains(shaping) => {}
        PatternClass::Unknown { reason, .. } => {
            complaints.push(format!(
                "`{clause}` refuses without naming {shaping}: {reason}"
            ));
        }
        classified => {
            complaints.push(format!(
                "`{clause}` shapes its rows, yet classified {classified:?}"
            ));
        }
    }

    let outputs = translator.translate(&db).outputs_accepting_gaps();
    let dsl = outputs.model();
    let can_select = relation_definition(&dsl, "docs", "can_select");
    if can_select.as_deref() != Some("no_access") {
        complaints.push(format!(
            "`{clause}` must fall closed, can_select is {can_select:?}"
        ));
    }
    let membership_tuples = tuples_reading_from(&outputs.tuple_queries(), "doc_members");
    if !membership_tuples.is_empty() {
        complaints.push(format!(
            "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
        ));
    }
    let denial_disclosed = outputs
        .notes()
        .iter()
        .map(TranslationNote::message)
        .any(|message| message.contains("the model denies what RLS grants"));
    if !denial_disclosed {
        complaints.push(format!(
            "`{clause}` narrows the grant, so a note must say so: {:#?}",
            outputs
                .notes()
                .iter()
                .map(TranslationNote::message)
                .collect::<Vec<_>>()
        ));
    }
    complaints
}

/// Every spelling of a shaped subquery has to be refused, since they share one analyzer.
fn assert_every_spelling_refused(spellings: &[(&str, &str)]) {
    let complaints: Vec<String> = spellings
        .iter()
        .flat_map(|(clause, shaping)| shaped_membership_subquery_complaints(clause, shaping))
        .collect();
    assert!(
        complaints.is_empty(),
        "a subquery that shapes its rows must be refused in every spelling:\n{}",
        complaints.join("\n")
    );
}

/// `GROUP BY` collapses the rows into groups, so the subquery stops returning the rows a
/// membership relation would hold.
#[test]
fn a_grouped_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             GROUP BY user_id)",
            "GROUP BY",
        ),
    ]);
}

/// `HAVING count(*) > 1` is the two-person rule, admitting only rows backed by a second
/// membership row, while a membership relation grants every member.
#[test]
fn a_membership_subquery_filtered_by_having_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             GROUP BY user_id HAVING count(*) > 1)",
            "HAVING",
        ),
    ]);
}

/// `QUALIFY` filters on a window function, keeping one row per partition.
#[test]
fn a_qualify_filtered_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             QUALIFY row_number() OVER (PARTITION BY user_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
    ]);
}

/// `DISTINCT ON` keeps one arbitrary row per key and drops the rest.
#[test]
fn a_distinct_on_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "id IN (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "id = ANY (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "current_user IN (SELECT DISTINCT ON (role) user_id FROM doc_members \
             WHERE doc_id = docs.id)",
            "DISTINCT ON",
        ),
    ]);
}

/// `TABLESAMPLE` returns a fraction of the rows, so the subquery finds a fraction of the
/// memberships and a different fraction on every statement unless `REPEATABLE` pins it.
#[test]
fn a_sampled_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members TABLESAMPLE BERNOULLI (10) \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members TABLESAMPLE BERNOULLI (10) \
             WHERE user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members TABLESAMPLE SYSTEM (10) \
             WHERE user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members TABLESAMPLE SYSTEM (10) \
             REPEATABLE (42) WHERE doc_id = docs.id)",
            "TABLESAMPLE",
        ),
    ]);
}

/// A `WITH` clause binds a name inside the subquery, and that binding shadows the real
/// table of the same name, so the `FROM` no longer names the table the analyzer resolves.
///
/// Probed on `PostgreSQL` 18.4: the `EXISTS` spelling below admits 0 of 5 rows where the
/// same policy without the `WITH` admits all 5.
#[test]
fn a_membership_subquery_that_binds_its_own_names_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT 1 FROM doc_members \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "WITH",
        ),
        (
            "id IN (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "WITH",
        ),
        (
            "id = ANY (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "WITH",
        ),
        (
            "current_user IN (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT user_id FROM doc_members \
             WHERE doc_id = docs.id)",
            "WITH",
        ),
    ]);
}

/// A locking read applies the locked table's `UPDATE` policies on top of its `SELECT`
/// ones, so the subquery finds fewer membership rows than the table holds.
///
/// Probed on `PostgreSQL` 18.4 with a membership table whose `UPDATE` policy admits three
/// of its ten rows: both `FOR UPDATE` and `FOR SHARE` admit 3 of 10 where the unlocked
/// spelling admits all 10. `FOR NO KEY UPDATE` and `FOR KEY SHARE` are absent here only
/// because `sqlparser` refuses them, see `docs/upstream/sqlparser-row-locking-clauses.md`.
#[test]
fn a_membership_subquery_that_locks_its_rows_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user FOR UPDATE)",
            "row lock",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user FOR UPDATE)",
            "row lock",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user FOR SHARE)",
            "row lock",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id FOR SHARE)",
            "row lock",
        ),
    ]);
}

/// `EXISTS` is blind to a row limit that cannot empty the result, but `OFFSET` and a zero
/// limit can empty it, and then the policy admits fewer rows than full membership.
#[test]
fn an_exists_membership_subquery_whose_row_limit_can_empty_it_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user OFFSET 1)",
            "OFFSET",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user LIMIT 0)",
            "LIMIT",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user LIMIT (SELECT count(*) FROM doc_members))",
            "LIMIT",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user FETCH FIRST 0 ROWS ONLY)",
            "FETCH",
        ),
    ]);
}

/// The guard must not over-fire: inside `EXISTS` a limit of at least one row cannot change
/// whether a row exists, and `SELECT 1 ... LIMIT 1` is the idiom people write.
#[test]
fn an_exists_membership_subquery_keeping_at_least_one_row_still_translates() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert_eq!(
        relation_definition(&expected_dsl, "docs", "can_select").as_deref(),
        Some("member from docs"),
        "guard precondition: the plain spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user LIMIT 1)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user LIMIT ALL)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user OFFSET 0)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user FETCH FIRST 1 ROWS ONLY)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` cannot empty the subquery, so it must translate unchanged"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the unlimited spelling"
        );
    }
}

/// The guard must not over-fire on plain `DISTINCT` either: dropping duplicate rows leaves
/// the set of values the membership test reads untouched.
#[test]
fn a_distinct_membership_subquery_still_translates() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
    );
    assert_eq!(
        relation_definition(&expected_dsl, "docs", "can_select").as_deref(),
        Some("member from docs"),
        "guard precondition: the plain spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "id IN (SELECT DISTINCT doc_id FROM doc_members WHERE user_id = current_user)",
        "id = ANY (SELECT DISTINCT doc_id FROM doc_members WHERE user_id = current_user)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` tests the same set as the spelling without DISTINCT"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the spelling without DISTINCT"
        );
    }
}

/// `pg_dump` parenthesises every conjunct it deparses, so `WHERE ((a = b) AND (c = d))`
/// is the spelling any policy read back from `PostgreSQL` carries. Parsing has already
/// fixed precedence, so those parentheses cannot change what the policy means.
#[test]
fn a_membership_policy_translates_the_same_however_it_is_parenthesised() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members \
         WHERE doc_members.doc_id = docs.id AND doc_members.user_id = current_user)",
    );
    assert_eq!(
        relation_definition(&expected_dsl, "docs", "can_select").as_deref(),
        Some("member from docs"),
        "guard precondition: the unparenthesised spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "(EXISTS ( SELECT 1 FROM doc_members \
          WHERE ((doc_members.doc_id = docs.id) AND (doc_members.user_id = current_user))))",
        "EXISTS (SELECT 1 FROM doc_members \
         WHERE ((doc_members.doc_id = docs.id) AND (doc_members.user_id = current_user)))",
        "EXISTS (SELECT 1 FROM doc_members \
         WHERE (doc_members.doc_id = docs.id) AND (doc_members.user_id = current_user))",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` differs from the unparenthesised spelling only in parentheses"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the unparenthesised spelling"
        );
    }
}

/// The same for the `IN` spelling, whose subquery `pg_dump` parenthesises too.
#[test]
fn the_in_membership_spelling_translates_the_same_however_it_is_parenthesised() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
    );
    assert_eq!(
        relation_definition(&expected_dsl, "docs", "can_select").as_deref(),
        Some("member from docs"),
        "guard precondition: the unparenthesised spelling must translate:\n{expected_dsl}"
    );

    let (dsl, tuples) = membership_translation(
        "(id IN ( SELECT doc_members.doc_id FROM doc_members \
         WHERE ((doc_members.user_id = current_user))))",
    );
    assert_eq!(
        dsl, expected_dsl,
        "the parenthesised IN subquery must translate like the flat one"
    );
    assert_eq!(
        tuples, expected_tuples,
        "the parenthesised IN subquery must yield the same tuples"
    );
}

/// Parent inheritance reads the same subquery `WHERE`, so it loses the parent link to
/// the same parentheses.
#[test]
fn parent_inheritance_translates_the_same_however_it_is_parenthesised() {
    const PARENT_SCHEMA: &str = "
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_own ON projects FOR SELECT USING (owner_id = current_user);
";
    let inherited = |clause: &str| {
        let db = db_of(&format!(
            "{PARENT_SCHEMA}CREATE POLICY tasks_sel ON tasks FOR SELECT USING ({clause});"
        ));
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .model();
        relation_definition(&dsl, "tasks", "can_select")
    };

    assert_eq!(
        inherited(
            "EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id \
             AND p.owner_id = current_user)"
        )
        .as_deref(),
        Some("owner from projects"),
        "guard precondition: the unparenthesised spelling must inherit"
    );
    assert_eq!(
        inherited(
            "(EXISTS ( SELECT 1 FROM projects p WHERE ((p.id = tasks.project_id) \
             AND (p.owner_id = current_user))))"
        )
        .as_deref(),
        Some("owner from projects"),
        "pg_dump's parentheses must not cost the parent link"
    );
}

/// An extra membership predicate is spliced into a conjunction of NULL guards, so one
/// that is itself a disjunction has to keep its parentheses or it breaks out of the
/// `AND` and the query emits tuples for rows the policy refuses.
#[test]
fn a_disjunctive_membership_predicate_stays_parenthesised_in_the_tuple_query() {
    let (_, tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id \
         AND doc_members.user_id = current_user \
         AND (doc_members.role = 'editor' OR doc_members.role = 'admin'))",
    );
    assert!(
        tuples.contains("AND (role = 'editor' OR role = 'admin')"),
        "the disjunction must stay inside its own parentheses:\n{tuples}"
    );
}

/// Model and tuples for `sql` at the default threshold.
fn translation(sql: &str) -> (String, String) {
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    (
        translator.translate(&db).outputs_accepting_gaps().model(),
        format_tuples(
            &translator
                .translate(&db)
                .outputs_accepting_gaps()
                .tuple_queries(),
        ),
    )
}

/// `pg_dump` never declares a key inline: it emits `ALTER TABLE ONLY t ADD CONSTRAINT`
/// as a separate statement. Without the primary key nothing identifies a row, so the
/// table gets no tuple query at all and the operator has a model they cannot populate.
#[test]
fn a_primary_key_declared_by_alter_table_identifies_rows() {
    let schema = |key: &str, constraint: &str| {
        format!(
            "CREATE TABLE users (id UUID PRIMARY KEY);\n\
             CREATE TABLE docs (id UUID {key}, owner_id UUID NOT NULL REFERENCES users(id));\n\
             {constraint}\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);\n"
        )
    };
    let (inline_dsl, inline_tuples) = translation(&schema("PRIMARY KEY", ""));
    assert!(
        inline_tuples.contains("FROM \"docs\""),
        "guard precondition: the inline spelling must emit an ownership query:\n{inline_tuples}"
    );

    let (dsl, tuples) = translation(&schema(
        "NOT NULL",
        "ALTER TABLE ONLY docs ADD CONSTRAINT docs_pkey PRIMARY KEY (id);\n",
    ));
    assert_eq!(
        dsl, inline_dsl,
        "a key declared by ALTER TABLE is the same key"
    );
    assert_eq!(
        tuples, inline_tuples,
        "a key declared by ALTER TABLE still identifies the object"
    );
}

/// The `id` fallback needs the column to be unique and `NOT NULL` before it will name a
/// row, and `pg_dump` declares uniqueness the same separate way.
#[test]
fn a_unique_constraint_declared_by_alter_table_identifies_rows() {
    let schema = |unique: &str, constraint: &str| {
        format!(
            "CREATE TABLE users (id UUID PRIMARY KEY);\n\
             CREATE TABLE docs (id UUID NOT NULL {unique}, \
             owner_id UUID NOT NULL REFERENCES users(id));\n\
             {constraint}\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);\n"
        )
    };
    let (inline_dsl, inline_tuples) = translation(&schema("UNIQUE", ""));
    assert!(
        inline_tuples.contains("FROM \"docs\""),
        "guard precondition: the inline spelling must emit an ownership query:\n{inline_tuples}"
    );

    let (dsl, tuples) = translation(&schema(
        "",
        "ALTER TABLE ONLY docs ADD CONSTRAINT docs_id_key UNIQUE (id);\n",
    ));
    assert_eq!(
        dsl, inline_dsl,
        "a unique constraint declared by ALTER TABLE is the same constraint"
    );
    assert_eq!(
        tuples, inline_tuples,
        "a unique NOT NULL id still identifies the object"
    );
}

/// A foreign key declared by `ALTER TABLE` is what resolves a membership column to the
/// table it points at. Without it the column name alone is consulted, which mints a
/// singular type no table backs and leaves the real one unreferenced.
#[test]
fn a_foreign_key_declared_by_alter_table_resolves_the_parent_type() {
    let schema = |references: &str, constraint: &str| {
        format!(
            "CREATE TABLE users (id UUID PRIMARY KEY);\n\
             CREATE TABLE teams (id UUID PRIMARY KEY);\n\
             CREATE TABLE team_members (team_id UUID NOT NULL {references}, \
             user_id UUID NOT NULL);\n\
             CREATE TABLE docs (id UUID PRIMARY KEY, team_id UUID NOT NULL);\n\
             {constraint}\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_team ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM team_members\n\
               WHERE team_members.team_id = docs.team_id \
               AND team_members.user_id = current_user));\n"
        )
    };
    let (inline_dsl, inline_tuples) = translation(&schema("REFERENCES teams(id)", ""));
    assert_eq!(
        relation_definition(&inline_dsl, "docs", "can_select").as_deref(),
        Some("member from teams"),
        "guard precondition: the inline spelling must reach the teams type:\n{inline_dsl}"
    );

    let (dsl, tuples) = translation(&schema(
        "",
        "ALTER TABLE ONLY team_members ADD CONSTRAINT tm_team_fkey \
         FOREIGN KEY (team_id) REFERENCES teams(id);\n",
    ));
    assert!(
        !type_names(&dsl).contains(&"team".to_string()),
        "the schema declares 'teams', so no 'team' type may be invented:\n{dsl}"
    );
    assert_eq!(
        dsl, inline_dsl,
        "a foreign key declared by ALTER TABLE is the same key"
    );
    assert_eq!(
        tuples, inline_tuples,
        "the membership query must read the table the key points at"
    );
}

/// Relations an exclusion subtracts, on the object's own type.
///
/// A `TupleToUserset` contributes its tupleset, which is a relation on the object,
/// and not its computed side, which resolves on whatever type the tupleset reaches.
fn subtracted_relations_on_the_object(
    userset: &rls2fga::generator::json_model::Userset,
    out: &mut std::collections::BTreeSet<String>,
) {
    use rls2fga::generator::json_model::Userset;
    match userset {
        Userset::This { .. } => {}
        Userset::ComputedUserset { computed_userset } => {
            out.insert(computed_userset.relation.clone());
        }
        Userset::TupleToUserset { tuple_to_userset } => {
            out.insert(tuple_to_userset.tupleset.relation.clone());
        }
        Userset::Union { union } => {
            for child in &union.child {
                subtracted_relations_on_the_object(child, out);
            }
        }
        Userset::Intersection { intersection } => {
            for child in &intersection.child {
                subtracted_relations_on_the_object(child, out);
            }
        }
        Userset::Difference { difference } => {
            subtracted_relations_on_the_object(&difference.base, out);
            subtracted_relations_on_the_object(&difference.subtract, out);
        }
    }
}

/// Walk every `Difference` in the model, yielding `(type, subtracted relation)`.
fn subtractions(
    json: &rls2fga::generator::json_model::AuthorizationModel,
) -> Vec<(String, String)> {
    use rls2fga::generator::json_model::Userset;

    fn walk(userset: &Userset, type_name: &str, out: &mut Vec<(String, String)>) {
        match userset {
            Userset::Difference { difference } => {
                let mut subtracted = std::collections::BTreeSet::new();
                subtracted_relations_on_the_object(&difference.subtract, &mut subtracted);
                out.extend(
                    subtracted
                        .into_iter()
                        .map(|relation| (type_name.to_string(), relation)),
                );
                walk(&difference.base, type_name, out);
                walk(&difference.subtract, type_name, out);
            }
            Userset::Union { union } => {
                for child in &union.child {
                    walk(child, type_name, out);
                }
            }
            Userset::Intersection { intersection } => {
                for child in &intersection.child {
                    walk(child, type_name, out);
                }
            }
            Userset::This { .. }
            | Userset::ComputedUserset { .. }
            | Userset::TupleToUserset { .. } => {}
        }
    }

    let mut out = Vec::new();
    for definition in &json.type_definitions {
        for (name, userset) in definition.relations.iter().flatten() {
            let _ = name;
            walk(userset, &definition.type_name, &mut out);
        }
    }
    out
}

/// On reconnect the consumer replays from an earlier point and reconstructs what a
/// row used to imply by supplying the previous version's records as extra context.
/// That is exact only while adding a record cannot revoke access. Union and
/// intersection preserve it, exclusion does not, so nothing an exclusion subtracts
/// may depend on the object's own column values.
///
/// Holds today: the one exclusion the generator emits subtracts `member` reached
/// through a role scope, whose tuple names a literal role and exists for every row
/// of the table regardless of its values.
#[test]
fn no_exclusion_subtracts_anything_derived_from_the_object_row() {
    use rls2fga::generator::records::{Guard, RecordDerivation, ValueSource};

    let mut checked = 0;
    for schema in exclusion_emitting_schemas() {
        let db = db_of(&schema);
        let translator = translator(ConfidenceLevel::B);
        let json = translator
            .translate(&db)
            .outputs_accepting_gaps()
            .json_model();
        let queries = translator
            .translate(&db)
            .outputs_accepting_gaps()
            .tuple_queries();

        for (type_name, relation) in subtractions(&json) {
            checked += 1;
            for query in &queries {
                let Some(description) = &query.description else {
                    continue;
                };
                let RecordDerivation::FromRow {
                    template, guards, ..
                } = &description.derivation
                else {
                    // A joining source reads a second table, so a change there could
                    // withdraw the subtraction without the row changing at all.
                    assert!(
                        !feeds(description, &type_name, &relation),
                        "{type_name}#{relation} is subtracted yet fed by a joining source: {}",
                        query.comment
                    );
                    continue;
                };
                if template.object_type != type_name || template.relation != relation {
                    continue;
                }

                assert!(
                    matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                    "{type_name}#{relation} is subtracted, so its subject may not come \
                     from the row: {:?} in {}",
                    template.subject_key,
                    query.comment
                );
                let identity = match template.object_key.parts() {
                    [ValueSource::Column(column)] => column.clone(),
                    other => panic!("an object key is one column, got {other:?}"),
                };
                for guard in guards {
                    assert!(
                        matches!(guard, Guard::NotNull(column) if *column == identity),
                        "{type_name}#{relation} is subtracted, so no row value may decide \
                         whether its tuple exists: {guard:?} in {}",
                        query.comment
                    );
                }
            }
        }
    }

    assert!(
        checked >= 2,
        "the corpus must actually emit exclusions, checked {checked}"
    );
}

/// True when `description` populates `relation` on `type_name`.
fn feeds(
    description: &rls2fga::generator::records::RecordDescription,
    type_name: &str,
    relation: &str,
) -> bool {
    match &description.derivation {
        RecordDerivation::FromRow { template, .. } => {
            template.object_type == type_name && template.relation == relation
        }
        // A joining description names no template, so it cannot be attributed to a
        // relation from here and is reported as not feeding it.
        _ => false,
    }
}

/// Schemas whose emitted model contains an exclusion. A RESTRICTIVE policy bound to
/// a role is the only shape that produces one today.
///
/// The fixture corpus emits none at the default threshold: `role_scoped_restrictive`
/// carries a RESTRICTIVE policy that falls below it and so falls closed instead,
/// which is why these are written here rather than read from a fixture.
fn exclusion_emitting_schemas() -> Vec<String> {
    vec![
        "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN NOT NULL DEFAULT FALSE);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_public ON docs FOR SELECT USING (is_public = TRUE);
CREATE POLICY docs_barrier ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (owner_id = current_user);
"
        .to_string(),
        // Two barriers, so the outer exclusion subtracts a scope while its base
        // already contains one.
        "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN NOT NULL DEFAULT FALSE);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_public ON docs FOR SELECT USING (is_public = TRUE);
CREATE POLICY docs_contractor ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (owner_id = current_user);
CREATE POLICY docs_auditor ON docs AS RESTRICTIVE FOR SELECT TO auditor
  USING (owner_id = current_user);
"
        .to_string(),
    ]
}

/// Does `relation`'s transitive expansion on `type_name` cross a type boundary or
/// subtract anything? Both make a relation undecidable from one row, and both are
/// visible in the emitted model without consulting the analysis under test.
fn expansion_leaves_the_row(
    json: &rls2fga::generator::json_model::AuthorizationModel,
    type_name: &str,
    relation: &str,
    seen: &mut std::collections::BTreeSet<String>,
) -> bool {
    use rls2fga::generator::json_model::Userset;

    fn walk(
        json: &rls2fga::generator::json_model::AuthorizationModel,
        type_name: &str,
        userset: &Userset,
        seen: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        match userset {
            Userset::This { .. } => false,
            Userset::ComputedUserset { computed_userset } => {
                expansion_leaves_the_row(json, type_name, &computed_userset.relation, seen)
            }
            Userset::TupleToUserset { .. } | Userset::Difference { .. } => true,
            Userset::Union { union } => union
                .child
                .iter()
                .any(|child| walk(json, type_name, child, seen)),
            Userset::Intersection { intersection } => intersection
                .child
                .iter()
                .any(|child| walk(json, type_name, child, seen)),
        }
    }

    if !seen.insert(format!("{type_name}#{relation}")) {
        // A cycle is not a boundary crossing by itself.
        return false;
    }
    json.type_definitions
        .iter()
        .filter(|definition| definition.type_name == type_name)
        .filter_map(|definition| definition.relations.as_ref())
        .filter_map(|relations| relations.get(relation))
        .any(|userset| walk(json, type_name, userset, seen))
}

/// A wrongly true flag grants access no policy granted, so the test asserts that
/// direction: nothing flagged decidable may cross a type boundary, subtract, or take
/// its records from a table other than the one keying the object.
#[test]
fn no_relation_is_flagged_decidable_that_leaves_its_own_row() {
    use rls2fga::generator::records::{RecordDerivation, ValueSource};

    let registry_json =
        r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;
    let (mut trues, mut falses) = (0, 0);

    for schema in decidability_schemas() {
        let (classified, db, registry) = support_classify(&schema, registry_json);
        // The same classification the analysis reads, or the test inspects a model
        // the analysis never saw. Building it through a registry-less translator was
        // exactly that mistake: the analysis saw `member from docs` while the model
        // said `no_access`, and a wrongly true flag passed unnoticed.
        let planned = rls2fga::translator::Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        let shapes = planned.relations();
        let json = planned.clone().outputs_accepting_gaps().json_model();
        let queries = planned.outputs_accepting_gaps().tuple_queries();

        for row in shapes {
            if !row.from_one_row {
                falses += 1;
                continue;
            }
            trues += 1;

            let mut seen = std::collections::BTreeSet::new();
            assert!(
                !expansion_leaves_the_row(&json, &row.type_name, &row.relation, &mut seen),
                "{}#{} is flagged decidable yet its expansion crosses a type boundary \
                 or subtracts",
                row.type_name,
                row.relation
            );

            // Every source feeding it must read one table, key the object by that
            // table's own primary key, and name a user from the row. A record keyed
            // by a foreign column describes a different object, which a change to
            // this row does not own.
            let mut tables = std::collections::BTreeSet::new();
            for query in &queries {
                let Some(description) = &query.description else {
                    continue;
                };
                let RecordDerivation::FromRow {
                    table, template, ..
                } = &description.derivation
                else {
                    continue;
                };
                if template.object_type != row.type_name || template.relation != row.relation {
                    continue;
                }
                tables.insert(table.clone());
                assert!(
                    !matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                    "{}#{} is flagged decidable yet its subject is a literal: {}",
                    row.type_name,
                    row.relation,
                    query.comment
                );
                let [ValueSource::Column(object_column)] = template.object_key.parts() else {
                    panic!("an object key is one column, got {:?}", template.object_key);
                };
                assert_eq!(
                    Some(object_column.as_str()),
                    primary_key_of(&db, table).as_deref(),
                    "{}#{} is flagged decidable yet its object is keyed by a column that \
                     is not {table}'s primary key: {}",
                    row.type_name,
                    row.relation,
                    query.comment
                );
            }
            assert!(
                tables.len() <= 1,
                "{}#{} is flagged decidable yet its records come from {tables:?}",
                row.type_name,
                row.relation
            );
        }
    }
    assert!(
        trues >= 4,
        "the corpus must contain decidable relations or the direction is untested, saw {trues}"
    );
    assert!(
        falses >= 4,
        "and undecidable ones, or the analysis is answering true for everything, saw {falses}"
    );
}

/// The single-column primary key of `table`, through the public schema accessors.
fn primary_key_of(db: &ParserDB, table: &str) -> Option<String> {
    use rls2fga::parser::sql_parser::{ColumnLike, DatabaseLike, TableLike};

    db.tables()
        .find(|candidate| candidate.table_name() == table)?
        .primary_key_column(db)
        .ok()
        .flatten()
        .map(|column| column.column_name().to_string())
}

/// Classify `sql` with a registry, mirroring what the container tests do.
fn support_classify(
    sql: &str,
    registry_json: &str,
) -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    ParserDB,
    rls2fga::classifier::function_registry::FunctionRegistry,
) {
    let db = db_of(sql);
    let mut registry = rls2fga::classifier::function_registry::FunctionRegistry::new();
    registry
        .load_from_json(registry_json)
        .expect("the registry parses");
    let classified = rls2fga::classifier::policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// Schemas covering both answers: ownership and list membership resolve from the row
/// to a user, while a flag, a membership table, a parent link and a role scope do not.
///
/// The last two matter for the direction that counts. In the first schema every
/// action relation also unions the wildcard, which makes it undecidable whatever the
/// analysis says about the other children, so a rule wrongly reporting a type
/// boundary as decidable would stay invisible. A table whose only policy is a
/// membership subquery, and one whose only policy inherits from a parent, each give
/// an action relation that is nothing but a tuple-to-userset.
fn decidability_schemas() -> Vec<String> {
    let mut schemas = vec![
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE notes (id TEXT PRIMARY KEY, folder_id TEXT REFERENCES folders(id), owner_id TEXT,
                    editors TEXT[], meta JSONB, is_public BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE note_members (note_id TEXT REFERENCES notes(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_owner ON folders FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY notes_owner ON notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY notes_editors ON notes FOR SELECT USING (auth_current_user_id() = ANY (editors));
CREATE POLICY notes_meta ON notes FOR SELECT
    USING (meta ->> 'owner_id' = auth_current_user_id());
CREATE POLICY notes_public ON notes FOR SELECT USING (is_public = TRUE);
CREATE POLICY notes_members ON notes FOR SELECT USING (EXISTS (
    SELECT 1 FROM note_members WHERE note_members.note_id = notes.id
      AND note_members.user_id = auth_current_user_id()));
"
        .to_string(),
        // Membership alone: `can_select` is exactly `member from notes`.
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY);
-- A primary key of its own, so nothing but the object key being a foreign
-- column can decide this shape is undecidable.
CREATE TABLE doc_members (id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (EXISTS (
    SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id
      AND doc_members.user_id = auth_current_user_id()));
"
        .to_string(),
        // Parent inheritance alone: `can_select` is exactly `owner from projects`.
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_own ON projects FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY tasks_inherit ON tasks FOR SELECT USING (EXISTS (
    SELECT 1 FROM projects p WHERE p.id = tasks.project_id
      AND p.owner_id = auth_current_user_id()));
"
        .to_string(),
    ];
    schemas.extend(exclusion_emitting_schemas());
    schemas
}

/// A column compared against a literal constant is decided by the row, exactly as a
/// boolean flag is, so it earns the same wildcard rather than falling closed. The
/// tuple query then qualifies rows the way the flag's query already does.
#[test]
fn an_attribute_guard_over_a_literal_grants_the_rows_it_admits() {
    let schema = |clause: &str| {
        format!(
            "CREATE TABLE articles(id UUID PRIMARY KEY, status TEXT, priority INT, \
             is_public BOOLEAN NOT NULL DEFAULT FALSE);\n\
             ALTER TABLE articles ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY articles_sel ON articles FOR SELECT USING ({clause});\n"
        )
    };

    // The boolean flag is the shape this generalises, so it is the reference.
    let (flag_dsl, flag_tuples) = translation(&schema("is_public = TRUE"));
    assert_eq!(
        relation_definition(&flag_dsl, "articles", "can_select").as_deref(),
        Some("public_viewer"),
        "guard precondition: the boolean flag must grant the wildcard:\n{flag_dsl}"
    );

    for (clause, expected_sql) in [
        ("status = 'published'", "AND \"status\" = 'published';"),
        ("priority >= 3", "AND \"priority\" >= 3;"),
        ("status <> 'draft'", "AND \"status\" <> 'draft';"),
        // The column may sit on the right, and the operator reads column-first.
        ("3 <= priority", "AND \"priority\" >= 3;"),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        assert_eq!(
            relation_definition(&dsl, "articles", "can_select").as_deref(),
            Some("public_viewer"),
            "`{clause}` is decided by the row, so it grants like the flag:\n{dsl}"
        );
        assert_eq!(
            dsl, flag_dsl,
            "`{clause}` must produce the same model as the flag it generalises"
        );
        assert!(
            tuples.contains(expected_sql),
            "`{clause}` must qualify rows in SQL, got:\n{tuples}"
        );
        // The flag's own query is the shape being copied, so the rest must match.
        assert_eq!(
            tuples.lines().count(),
            flag_tuples.lines().count(),
            "`{clause}` must emit one query, like the flag:\n{tuples}"
        );
    }
}

/// The wildcard is only correct because the compared value is a literal constant. A
/// value the caller supplies would grant everyone access to rows scoped to one
/// caller, and one the clock supplies would outlive the row it was computed from, so
/// neither may reach that emission.
#[test]
fn only_a_literal_constant_earns_the_attribute_wildcard() {
    use rls2fga::classifier::recognizers::attribute_literal_predicate;

    let schema = |clause: &str| {
        format!(
            "CREATE TABLE articles(id UUID PRIMARY KEY, status TEXT, owner_id TEXT, \
             expires_at TIMESTAMPTZ);\n\
             ALTER TABLE articles ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY articles_sel ON articles FOR SELECT USING ({clause});\n"
        )
    };

    for clause in [
        // The clock decides these, not the row, so a static tuple computed once would
        // keep granting after the value passed. They earn a condition instead, which
        // the service re-evaluates on every check.
        "expires_at > now()",
        "expires_at <= current_timestamp",
        "expires_at > CURRENT_DATE",
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        let select = relation_definition(&dsl, "articles", "can_select")
            .expect("articles defines can_select");
        assert_ne!(
            select, "public_viewer",
            "`{clause}` must not earn the unconditional wildcard:\n{dsl}"
        );
        assert!(
            select.starts_with("gate_"),
            "`{clause}` must resolve through a conditional gate, got `{select}`:\n{dsl}"
        );
        // The gate's wildcard is admitted only through a condition, and the model
        // declares that condition.
        assert!(
            dsl.contains(":* with when_"),
            "the gate's wildcard must carry its condition:\n{dsl}"
        );
        assert!(
            dsl.contains("condition when_"),
            "the model must declare the condition it names:\n{dsl}"
        );
        // And the tuple carries the row's own value, since the request cannot know it.
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "the tuple must carry the row's value as context:\n{tuples}"
        );
        assert!(
            !tuples.contains("'public_viewer' AS relation"),
            "`{clause}` must emit no unconditional wildcard tuple:\n{tuples}"
        );
    }

    // And the recognizer itself refuses anything that is not a literal, which is what
    // the emission depends on.
    for clause in [
        "status = current_user",
        "status > now()",
        "status = owner_id",
        "status = upper('a')",
    ] {
        let expr = parse_using_expr(&schema(clause));
        assert!(
            attribute_literal_predicate(&expr).is_none(),
            "`{clause}` compares against something the row does not fix, so it must \
             carry no predicate"
        );
    }
}

/// The `USING` expression of the one policy `schema` declares.
fn parse_using_expr(schema: &str) -> sqlparser::ast::Expr {
    use rls2fga::parser::sql_parser::{DatabaseLike, PolicyLike};

    let db = db_of(schema);
    let expr = db
        .policies()
        .next()
        .expect("the schema declares one policy")
        .using_expression(&db)
        .expect("the policy stores a USING clause")
        .clone();
    expr
}

/// Two condition parameters cannot share one name. A column named exactly like the
/// parameter the request supplies collapsed them into one, and the expression compared
/// the value against itself.
#[test]
fn a_column_named_after_the_request_parameter_keeps_its_own_condition_parameter() {
    let schema = "CREATE TABLE jobs(id UUID PRIMARY KEY, request_time TIMESTAMPTZ);\n\
                  ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY jobs_sel ON jobs FOR SELECT USING (request_time > now());\n";

    let (dsl, tuples) = translation(schema);

    let condition = dsl
        .lines()
        .find(|line| line.trim_start().starts_with("condition when_"))
        .expect("the model declares its condition");
    let expression = dsl
        .lines()
        .find(|line| line.contains(" > "))
        .expect("the condition compares the row against the request")
        .trim()
        .to_string();

    // The comparison must have two distinct sides, whatever the row's parameter ends
    // up being called.
    let (left, right) = expression
        .split_once(" > ")
        .expect("the expression is a comparison");
    assert_ne!(
        left.trim(),
        right.trim(),
        "the row and the request must be separate parameters:\n{dsl}"
    );
    assert!(
        condition.matches("timestamp").count() == 2,
        "both parameters must survive in the signature, got `{condition}`"
    );
    // The context supplies the row's parameter, so the key has to be the renamed
    // parameter while the value still reads the real column.
    let row_parameter = left.trim();
    assert!(
        tuples.contains(&format!(
            "jsonb_build_object('{row_parameter}', \"request_time\")"
        )),
        "the context key must be the row's parameter `{row_parameter}`:\n{tuples}"
    );
    assert!(
        condition.contains(&format!("{row_parameter}: timestamp")),
        "the signature must declare that parameter, got `{condition}`"
    );
}

/// The name is a contract with the caller, who has to pass exactly that key at check
/// time, so a deployment with its own convention configures it.
#[test]
fn the_request_time_parameter_name_is_configurable() {
    let schema = "CREATE TABLE jobs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
                  ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY jobs_sel ON jobs FOR SELECT USING (expires_at > now());\n";
    let db = db_of(schema);

    let default_dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
    assert!(
        default_dsl.contains("request_time: timestamp"),
        "the default name is request_time:\n{default_dsl}"
    );

    let configured = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_request_time_parameter("as_of")
        .build();
    let dsl = configured.translate(&db).outputs_accepting_gaps().model();

    assert!(
        dsl.contains("as_of: timestamp"),
        "the configured name reaches the signature:\n{dsl}"
    );
    assert!(
        dsl.contains("expires_at > as_of"),
        "the configured name reaches the expression:\n{dsl}"
    );
    assert!(
        !dsl.contains("request_time"),
        "the default must not survive alongside it:\n{dsl}"
    );
}

/// A tuple's context must be RFC 3339. `DATE` renders as `2099-01-01` and `TIMESTAMP`
/// as `2099-01-01T12:00:00`, and `OpenFGA` v1.11.6 refuses both at load while accepting
/// the model that named them, so the guard shipped a relation whose tuples could never
/// arrive. Rendering an instant instead would not save either: resolving one needs a
/// time zone, and the loader's session decides it while the reader's differs.
#[test]
fn only_a_zoned_timestamp_column_earns_a_condition_parameter() {
    let schema = |column_type: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at {column_type});\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > now());\n"
        )
    };

    for zoneless in ["DATE", "TIMESTAMP", "TIMESTAMP WITHOUT TIME ZONE"] {
        let (dsl, tuples) = translation(&schema(zoneless));
        assert!(
            !dsl.contains("condition when_"),
            "{zoneless} must declare no condition:\n{dsl}"
        );
        assert!(
            !tuples.contains("jsonb_build_object"),
            "{zoneless} must emit no context OpenFGA would refuse:\n{tuples}"
        );
        // The refusal has to precede every mint, or the type keeps a gate relation
        // nothing defines a condition for.
        assert!(
            !dsl.contains("gate_"),
            "{zoneless} must leave no gate relation behind:\n{dsl}"
        );
        assert!(
            dsl.contains("define can_select: no_access"),
            "{zoneless} must fall closed:\n{dsl}"
        );
    }

    for zoned in ["TIMESTAMPTZ", "TIMESTAMP WITH TIME ZONE"] {
        let (dsl, tuples) = translation(&schema(zoned));
        assert!(
            dsl.contains("expires_at > request_time"),
            "{zoned} must keep its condition:\n{dsl}"
        );
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "{zoned} must supply the row's value as context:\n{tuples}"
        );
    }
}

/// The three outcomes that shared one prose channel have to be separable by type,
/// because only one of them is a failure. The sharpest case is the same schema at two
/// thresholds: at `D` the crate could not classify the expression, at `B` the caller's
/// own threshold dropped it, and a message-matching consumer cannot tell those apart.
#[test]
fn each_outcome_carries_its_own_severity() {
    let refused = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";
    let db = db_of(refused);

    let severities = |level: ConfidenceLevel| -> Vec<NoteSeverity> {
        translator(level)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .map(TranslationNote::severity)
            .collect()
    };

    assert!(
        severities(ConfidenceLevel::D).contains(&NoteSeverity::Unhandled),
        "nobody classified the expression, so it is a gap: {:?}",
        severities(ConfidenceLevel::D)
    );
    assert!(
        !severities(ConfidenceLevel::D).contains(&NoteSeverity::BelowThreshold),
        "the threshold admitted it, so it did not drop it"
    );
    assert!(
        severities(ConfidenceLevel::B).contains(&NoteSeverity::BelowThreshold),
        "the caller's own threshold dropped it: {:?}",
        severities(ConfidenceLevel::B)
    );
    assert!(
        !severities(ConfidenceLevel::B).contains(&NoteSeverity::Unhandled),
        "a clause the caller chose to drop is not an unhandled expression"
    );

    // A hybrid leaves its attribute half to the application, which is neither a gap
    // nor complete.
    let hybrid = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, status TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT \
                  USING (owner_id = current_user AND status = 'active');\n";
    let hybrid_db = db_of(hybrid);
    let hybrid_outputs = translator(ConfidenceLevel::C)
        .translate(&hybrid_db)
        .outputs_accepting_gaps();
    let hybrid_notes = hybrid_outputs.notes();
    assert!(
        hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Partial),
        "the attribute half is a documented partial: {hybrid_notes:?}"
    );

    // And a command the database itself denies is not a failure of anything.
    assert!(
        hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Faithful),
        "no policy covers INSERT, which RLS denies too: {hybrid_notes:?}"
    );
    assert!(
        !hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Unhandled),
        "nothing here went unclassified: {hybrid_notes:?}"
    );
}

/// `UPDATE t SET c = 1` names no row, so it reads none, and `PostgreSQL` applies the
/// `UPDATE` policies to it without the `SELECT` policies. `can_update` intersects
/// `can_select`, so for that one statement shape it demands a permission the database
/// does not, and no relation answered for it.
#[test]
fn a_blanket_update_answers_through_its_own_relation() {
    let schema = "CREATE TABLE notes(id UUID PRIMARY KEY, reader_id TEXT, writer_id TEXT);\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY notes_read ON notes FOR SELECT USING (reader_id = current_user);\n\
                  CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_id = current_user);\n";
    let (dsl, _) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "notes", "can_update").as_deref(),
        Some("writer and can_select"),
        "a per-row update still reads the row it names:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "notes", "can_update_without_reading").as_deref(),
        Some("writer"),
        "a blanket update reads nothing, so the read gate must not apply:\n{dsl}"
    );
}

/// An action relation nobody defined reads as "the consumer decides", which is how a
/// coverage gap becomes open access. Every table type carries the relation even where
/// no rule admits an update.
#[test]
fn every_table_defines_the_blanket_update_relation() {
    let schema = "CREATE TABLE notes(id UUID PRIMARY KEY, owner_id TEXT);\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY notes_read ON notes FOR SELECT USING (owner_id = current_user);\n";
    let (dsl, _) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "notes", "can_update_without_reading").as_deref(),
        Some("can_update"),
        "with no update rule it points at the denial rather than going missing:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "notes", "can_update").as_deref(),
        Some("no_access"),
        "and that denial is what it points at:\n{dsl}"
    );
}

/// A relation nothing names is declared, receives no tuple query, and can never be
/// granted, so the model advertises access it cannot give.
///
/// The plan asked for the pruned set to equal the set the tuple side skips. It cannot:
/// the tuple side also skips a relation only a denying permission names, and dropping
/// that one would leave the model referring to something it does not define. The
/// property that does hold, and is the one worth keeping, is the other direction, so
/// this asserts both that nothing unnamed survives and that nothing named was taken.
#[test]
fn no_type_declares_a_relation_no_permission_names() {
    let mut cases: Vec<(String, Option<String>)> = decidability_schemas()
        .into_iter()
        .map(|schema| (schema, None))
        .collect();
    // The role hierarchy is the shape that produced orphans: `can_select` inlines it,
    // and its own relations then name nothing.
    cases.push((
        std::fs::read_to_string("tests/fixtures/role_in_list/input.sql")
            .expect("the role_in_list fixture should exist"),
        Some(
            std::fs::read_to_string("tests/fixtures/role_in_list/function_registry.json")
                .expect("the role_in_list registry should exist"),
        ),
    ));

    for (schema, registry_json) in &cases {
        let db = db_of(schema);
        let mut registry = rls2fga::classifier::function_registry::FunctionRegistry::new();
        if let Some(json) = registry_json {
            registry.load_from_json(json).expect("registry parses");
        }
        let classified = rls2fga::classifier::policy_classifier::classify_policies(&db, &registry);
        let outputs = rls2fga::translator::Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps();
        let dsl = outputs.model();

        // Not `assert_model_is_internally_consistent` here: its tupleset-assignability
        // rule is stricter than `OpenFGA` v1.11.6, which accepts this fixture's model
        // in the `P2_role_in_list` container scenario. Pruning too much would show up
        // there and in every parity case.
        let named = relation_names_definitions_use(&dsl);
        for relation in defined_relation_names(&dsl) {
            assert!(
                relation.starts_with("can_") || named.contains(&relation),
                "`{relation}` is declared and no definition names it:\n{dsl}"
            );
        }
    }
}

/// Every relation the DSL declares, across every type.
fn defined_relation_names(dsl: &str) -> Vec<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("define "))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .collect()
}

/// A role the database exempts from row level security holds more than the model says,
/// and the model cannot say otherwise: it describes the rules, and the bypass is the
/// absence of them. Reporting it is the only honest option, and staying silent is what
/// makes an exempt service account look constrained.
#[test]
fn a_role_that_bypasses_row_level_security_is_reported() {
    let schema = "CREATE ROLE reporting BYPASSRLS;\n\
                  CREATE ROLE app_user LOGIN;\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let db = db_of(schema);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let exempt: Vec<String> = outputs
        .notes()
        .iter()
        .filter(|note| note.severity() == NoteSeverity::Exempt)
        .map(TranslationNote::message)
        .collect();
    assert_eq!(exempt.len(), 1, "one role bypasses, got {exempt:?}");
    assert!(
        exempt[0].contains("reporting"),
        "the report has to name the role: {exempt:?}"
    );
    assert!(
        !exempt[0].contains("app_user"),
        "a plain role is not exempt: {exempt:?}"
    );
    // The model still describes only the rules that do apply.
    assert!(
        outputs.model().contains("define can_select: owner"),
        "the policy still translates:\n{}",
        outputs.model()
    );
}

/// Without `FORCE ROW LEVEL SECURITY` the table's owner is exempt from every policy on
/// it, so the model is stricter than the database for them. With it, nobody is.
#[test]
fn a_table_that_does_not_force_row_level_security_is_reported() {
    let schema = |force: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             {force}\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n"
        )
    };
    let exempt_notes = |sql: &str| -> Vec<String> {
        let db = db_of(sql);
        translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Exempt)
            .map(TranslationNote::message)
            .collect()
    };

    let unforced = exempt_notes(&schema(""));
    assert_eq!(
        unforced.len(),
        1,
        "the owner bypass is a finding: {unforced:?}"
    );
    assert!(
        unforced[0].contains("docs"),
        "and it names the table: {unforced:?}"
    );

    let forced = exempt_notes(&schema("ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n"));
    assert!(
        forced.is_empty(),
        "FORCE removes the owner bypass, so there is nothing to report: {forced:?}"
    );
}

/// Saying "the table's owner" sends the reader back to their schema to find out whether
/// the exempt principal is the account their application connects as. Now that
/// `sql-traits` keeps `ALTER TABLE ... OWNER TO`, the note can just say who.
#[test]
fn the_exempt_table_owner_is_named_when_the_schema_says_who_it_is() {
    let owned = "CREATE ROLE app_owner;\n\
                 CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                 ALTER TABLE docs OWNER TO app_owner;\n\
                 ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                 CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let unowned = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let exempt_notes = |sql: &str| -> Vec<String> {
        let db = db_of(sql);
        translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Exempt)
            .map(TranslationNote::message)
            .collect()
    };

    let named = exempt_notes(owned);
    assert_eq!(named.len(), 1, "one table, one owner bypass: {named:?}");
    assert!(
        named[0].contains("app_owner"),
        "the exempt role has a name, so the note uses it: {named:?}"
    );

    // A schema that never says who owns the table still has the bypass, and the note
    // still has to report it without inventing a role.
    let anonymous = exempt_notes(unowned);
    assert_eq!(
        anonymous.len(),
        1,
        "the bypass is there either way: {anonymous:?}"
    );
    assert!(
        anonymous[0].contains("owner") && !anonymous[0].contains("app_owner"),
        "with no owner recorded it stays generic: {anonymous:?}"
    );
}

/// Every name a definition body mentions. Loose across types on purpose: a relation
/// reached through a tuple-to-userset is named from the type that walks to it.
fn relation_names_definitions_use(dsl: &str) -> std::collections::BTreeSet<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("define "))
        .filter_map(|rest| rest.split_once(':'))
        .flat_map(|(_, body)| {
            body.split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .collect()
}

/// `EXISTS (SELECT 1 FROM m WHERE user_id = caller)` names no column of the guarded
/// table, so it admits every row at once to whoever appears in `m`. Denying instead is
/// safe but wrong, and pairing every row with every member is not loadable at any real
/// size. One holder object per member source carries the members, and every row points
/// at it, so the facts grow as rows plus members.
#[test]
fn an_uncorrelated_membership_check_translates_through_a_holder() {
    let schema = "CREATE TABLE staff(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n";
    let (dsl, tuples) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("member from staff_holder"),
        "the row's grant reads as membership of the holder:\n{dsl}"
    );
    assert!(
        dsl.contains("define staff_holder: [staff_holder]"),
        "the row points at the holder:\n{dsl}"
    );
    assert!(
        dsl.contains("type staff_holder"),
        "and the holder is a type of its own:\n{dsl}"
    );
    // Rows plus members, never rows times members.
    assert!(
        tuples.contains("'staff_holder:all' AS subject"),
        "every row points at the one holder:\n{tuples}"
    );
    assert!(
        tuples.contains("SELECT DISTINCT 'staff_holder:all' AS object"),
        "and the members attach to it once each:\n{tuples}"
    );
}

/// Two policies reading different member tables must not pool their members, and two
/// reading the same one may share. That is why the holder is per member source rather
/// than per table or per policy.
#[test]
fn a_holder_is_shared_per_member_source_and_never_across_them() {
    let schema = "CREATE TABLE staff(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE auditors(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY);\n\
                  CREATE TABLE notes(id UUID PRIMARY KEY);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_staff ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n\
                  CREATE POLICY docs_audit ON docs FOR DELETE USING (\n\
                    EXISTS (SELECT 1 FROM auditors WHERE auditors.user_id = current_user));\n\
                  CREATE POLICY notes_staff ON notes FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n";
    let (dsl, tuples) = translation(schema);

    assert_eq!(
        dsl.matches("type staff_holder").count(),
        1,
        "two policies reading staff share one holder:\n{dsl}"
    );
    assert!(
        dsl.contains("type auditors_holder"),
        "and a different member table gets its own:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("member from staff_holder"),
        "staff decides reads:\n{dsl}"
    );
    assert!(
        relation_definition(&dsl, "docs", "can_delete")
            .is_some_and(|rule| rule.contains("member from auditors_holder")),
        "auditors decide deletes, and they are not pooled with staff:\n{dsl}"
    );
    // Each holder is fed only from its own table.
    assert!(
        tuples.contains("'staff_holder:all' AS object,")
            && tuples.contains("'auditors_holder:all' AS object,"),
        "each holder loads its own members:\n{tuples}"
    );
}

/// A correlated check still has to translate as a per-row membership. The holder is for
/// the shape that names no outer column, and reading it too widely would grant a whole
/// table where only one row was meant.
#[test]
fn a_correlated_membership_check_does_not_become_a_holder() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
                  CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), \
                  user_id TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id \
                    AND doc_members.user_id = current_user));\n";
    let (dsl, _) = translation(schema);

    assert!(
        !dsl.contains("_holder"),
        "a check naming the outer row is per row, not per table:\n{dsl}"
    );
}

/// A policy is created once and then tuned, so a migration bundle carries the final
/// rule in an `ALTER POLICY` rather than in the `CREATE POLICY`. Translating the
/// original is an over-grant whenever the alteration narrowed the policy, which is the
/// whole reason such a schema used to be refused outright.
#[test]
fn the_model_follows_a_policy_altered_after_creation() {
    let created = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let narrowed = format!("{created}ALTER POLICY docs_sel ON docs USING (FALSE);\n");

    let (before, _) = translation(created);
    assert_eq!(
        relation_definition(&before, "docs", "can_select").as_deref(),
        Some("owner"),
        "the created policy grants the owner:\n{before}"
    );

    let (after, tuples) = translation(&narrowed);
    assert_eq!(
        relation_definition(&after, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the altered policy grants nobody, and the model has to say so:\n{after}"
    );
    assert!(
        !tuples.contains("'owner' AS relation"),
        "and no tuple may still feed the superseded rule:\n{tuples}"
    );
}

/// Two schemas holding a table of the same name must not collapse into one type.
///
/// Collapsing them would let a policy on one answer for rows of the other, which is the
/// over-grant an earlier session traced to grouping policies by their raw spelling. The
/// `schema_search_path` fixture carries the shape: `app.docs` guarded by a policy that
/// names its table bare, `archive.docs` guarded by one that names it in full, and only
/// the search path says which `docs` the bare one means.
#[test]
fn two_schemas_holding_one_table_name_get_two_types() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_search_path/input.sql")
            .expect("the fixture is readable"),
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    let guarded: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| {
            relation_definition(&dsl, name, "can_select").as_deref() == Some("owner_login")
        })
        .collect();

    assert_eq!(
        guarded.len(),
        2,
        "each table keeps its own read rule, so two types carry it:\n{dsl}"
    );

    // The renaming has to be reported, or an operator loading tuples under the canonical
    // name feeds them to whichever table won it.
    let renamed = guarded
        .iter()
        .find(|name| *name != "docs")
        .expect("one of the two is renamed");
    assert!(
        translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains(renamed.as_str())
                && note.message().contains("collision")),
        "the collision must be named, got {:#?}",
        translator(ConfidenceLevel::A)
            .translate(&db)
            .outputs_accepting_gaps()
            .notes()
    );
}

/// A dump carries roles, grants, sequences, indexes, views, enums, domains, generated
/// columns, comments, an owner and a composite key. None of that is a policy, and the
/// translator has to walk past all of it and still read the policies that are there.
#[test]
fn the_furniture_of_a_real_schema_does_not_disturb_the_policies() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_objects/input.sql")
            .expect("the fixture is readable"),
    );
    let outputs = translator(ConfidenceLevel::C)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select")
            .as_deref()
            .map(|d| d.contains("owner_login")),
        Some(true),
        "the ownership policy still reads its column:\n{dsl}"
    );

    // The owner the table was handed is exempt from every policy on it, and saying so is
    // the only way an operator learns the model is narrower than the database.
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("auditor") && note.message().contains("exempt")),
        "the exempt owner must be named, got {:#?}",
        outputs.notes()
    );

    // A key over two columns leaves no single-column object identifier, so the table it
    // keys cannot take one from somewhere else.
    assert!(
        type_names(&dsl).iter().any(|name| name == "doc_links"),
        "the composite-key table is still translated:\n{dsl}"
    );
}

const TEAMS_SCHEMA: &str = "
CREATE TABLE teams(id UUID PRIMARY KEY, name TEXT);
CREATE TABLE members(id UUID PRIMARY KEY, team_id UUID REFERENCES teams(id), user_id TEXT);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
";

/// Whatever is wrong with the refusal of a `SELECT` policy on `teams`, across the
/// classification, its reason, the model and the membership tuples alike. Empty when
/// every output refuses it and says why.
fn refused_teams_policy_complaints(clause: &str, reason_names: &str) -> Vec<String> {
    let db = db_of(&format!(
        "{TEAMS_SCHEMA}CREATE POLICY teams_members ON teams FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    let mut complaints = Vec::new();

    let classified = translator.classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one classified policy for `{clause}`");
    };
    let pattern = &policy
        .using_classification
        .as_ref()
        .expect("USING should classify")
        .pattern;
    match pattern {
        PatternClass::Unknown { reason, .. } if reason.contains(reason_names) => {}
        PatternClass::Unknown { reason, .. } => complaints.push(format!(
            "`{clause}` refuses without naming {reason_names}: {reason}"
        )),
        classified => complaints.push(format!("`{clause}` must not classify, got {classified:?}")),
    }

    let outputs = translator.translate(&db).outputs_accepting_gaps();
    let dsl = outputs.model();
    let can_select = relation_definition(&dsl, "teams", "can_select");
    if can_select.as_deref() != Some("no_access") {
        complaints.push(format!(
            "`{clause}` must fall closed, can_select is {can_select:?}"
        ));
    }
    let membership_tuples = tuples_reading_from(&outputs.tuple_queries(), "\"members\"");
    if !membership_tuples.is_empty() {
        complaints.push(format!(
            "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
        ));
    }
    // A type named after the projected column is the shape the phantom holder takes.
    let phantom: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| name != "teams" && name != "user" && name != "members")
        .collect();
    if !phantom.is_empty() {
        complaints.push(format!("`{clause}` invented the types {phantom:?}"));
    }
    complaints
}

/// A subquery selecting anything but a column has no column to correlate on, and taking
/// the outer one instead grants every membership row under a type named after it.
/// `min(team_id)` admits the lowest team alone on `PostgreSQL` 18, the model admitted
/// every team the caller belongs to.
#[test]
fn an_in_subquery_selecting_something_other_than_a_column_is_refused() {
    let complaints: Vec<String> = [
        "id IN (SELECT min(team_id) FROM members WHERE user_id = current_user)",
        "id = ANY (SELECT min(team_id) FROM members WHERE user_id = current_user)",
        "id IN (SELECT team_id || '' FROM members WHERE user_id = current_user)",
        "id IN (SELECT * FROM members WHERE user_id = current_user)",
        "id IN (SELECT row_number() OVER (ORDER BY team_id) FROM members \
         WHERE user_id = current_user)",
    ]
    .iter()
    .flat_map(|clause| {
        refused_teams_policy_complaints(clause, "selects an expression rather than a column")
    })
    .collect();
    assert!(
        complaints.is_empty(),
        "a subquery selecting no column cannot be membership:\n{}",
        complaints.join("\n")
    );
}

/// A cast changes the value, not only its type: `PostgreSQL` stores `(om.org_id)::uuid`
/// and matches the normalized uuid, while a tuple keyed on the raw column carries the
/// spelling the column holds. Probed on 18: the row is admitted by the policy and missed
/// by the tuple, so the cast cannot be dropped.
#[test]
fn an_in_subquery_selecting_a_cast_is_refused() {
    // Refused by the analyzer rather than by the projection guard: a cast is a column
    // reference, and what it cannot be is the key a tuple carries.
    let complaints = refused_teams_policy_complaints(
        "id IN (SELECT team_id::uuid FROM members WHERE user_id = current_user)",
        "could not infer a unique membership join",
    );
    assert!(
        complaints.is_empty(),
        "a cast projection cannot key a tuple:\n{}",
        complaints.join("\n")
    );
}

const TENANT_SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, tenant_id UUID);
CREATE TABLE m(doc_id UUID REFERENCES docs(id), tenant_id UUID, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

/// The selected column is a correlation, so a second one written out in the `WHERE` makes
/// two, and one relation carries one. Probed on `PostgreSQL` 18 over a caller named on a
/// doc in another tenant: both correlations admit doc 1 alone, the selected column alone
/// admits docs 1 and 2, and the written-out one alone admits docs 1 and 3. Neither half is
/// the policy, so the pair is refused, which is what the `EXISTS` spelling already does.
#[test]
fn an_in_subquery_carrying_two_correlations_is_refused() {
    let clauses = [
        "id IN (SELECT m.doc_id FROM m WHERE m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
        "id = ANY (SELECT m.doc_id FROM m WHERE m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
        // The same policy as an EXISTS, refused today, pinned so the two cannot drift.
        "EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
    ];
    let mut complaints = Vec::new();
    for clause in clauses {
        let db = db_of(&format!(
            "{TENANT_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let outputs = translator.translate(&db).outputs_accepting_gaps();
        let dsl = outputs.model();
        let can_select = relation_definition(&dsl, "docs", "can_select");
        if can_select.as_deref() != Some("no_access") {
            complaints.push(format!(
                "`{clause}` drops one of its two correlations, can_select is {can_select:?}"
            ));
        }
        let membership_tuples = tuples_reading_from(&outputs.tuple_queries(), "\"m\"");
        if !membership_tuples.is_empty() {
            complaints.push(format!(
                "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
            ));
        }
    }
    assert!(
        complaints.is_empty(),
        "a subquery correlated twice cannot become one relation:\n{}",
        complaints.join("\n")
    );
}

const DOC_LINKS_SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_login TEXT);
CREATE TABLE doc_links(
  id UUID PRIMARY KEY,
  parent_id UUID NOT NULL REFERENCES docs(id),
  label TEXT
);
ALTER TABLE doc_links ENABLE ROW LEVEL SECURITY;
";

/// `parent_id IN (SELECT id FROM parents WHERE <owner>)` names one parent row per child
/// row, so it is parent inheritance. Reading it as a subquery over a membership table
/// finds no column to correlate on and grants the whole table through a holder: probed on
/// `PostgreSQL` 18, only links to owned docs are visible, while the holder admits every
/// link to anyone owning any doc.
#[test]
fn an_in_subquery_naming_the_parent_by_its_key_inherits_from_the_parent() {
    let db = db_of(&format!(
        "{DOC_LINKS_SCHEMA}CREATE POLICY docs_owner ON docs FOR SELECT \
         USING (owner_login = current_user);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY doc_links_visible ON doc_links FOR SELECT \
         USING (parent_id IN (SELECT id FROM docs WHERE owner_login = current_user));"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "doc_links", "can_select").expect("doc_links defines can_select");
    assert!(
        can_select.contains("from docs"),
        "the link inherits from the doc it names, got `{can_select}`:\n{dsl}"
    );
    assert!(
        !can_select.contains("holder"),
        "a per-row link is not a table-wide holder, got `{can_select}`:\n{dsl}"
    );
    assert!(
        !type_names(&dsl).iter().any(|name| name.contains("holder")),
        "no holder type is minted for a correlated policy:\n{dsl}"
    );
}

/// The object-key spelling is the `EXISTS` spelling written the other way round. Probed on
/// `PostgreSQL` 18 over rows covering a member, a non-member, no membership row at all, a
/// membership row whose key is NULL, a member beside a NULL key, and a member failing a
/// residual predicate: `IN`, `= ANY` and `EXISTS` disagree on zero rows. So the model and
/// the tuples have to match byte for byte, or the fix has narrowed the shape.
#[test]
fn the_object_key_in_subquery_translates_like_the_exists_spelling() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        !expected_dsl.contains("can_select: no_access"),
        "guard precondition: the EXISTS spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
        "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
        "id IN (SELECT dm.doc_id FROM doc_members dm WHERE dm.user_id = current_user)",
        "docs.id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` must yield the same model as the EXISTS spelling"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the EXISTS spelling"
        );
    }
}

/// A residual predicate is what tells the operator the relation is wider than the policy,
/// so it has to survive the rewrite of the object-key spelling too.
#[test]
fn a_residual_predicate_survives_the_object_key_in_subquery_rewrite() {
    let (expected_dsl, _) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND role = 'admin' \
         AND user_id = current_user)",
    );
    let (dsl, _) = membership_translation(
        "id IN (SELECT doc_id FROM doc_members WHERE role = 'admin' AND user_id = current_user)",
    );
    assert_eq!(
        dsl, expected_dsl,
        "the role predicate must reach the same place it does through EXISTS"
    );
}

/// The `IN` form leaves to scoping which side of `doc_id = doc_id` is the guarded row and
/// which the membership row. Read without that scope the correlation vanishes, and the
/// policy reads as "the caller is a member of something", which grants the table whole.
#[test]
fn a_membership_column_spelled_like_the_guarded_key_still_correlates() {
    let db = db_of(
        r"
CREATE TABLE docs(doc_id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(doc_id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT
  USING (doc_id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("member from docs"),
        "the shared column name still names one doc per membership row:\n{dsl}"
    );
    assert!(
        !type_names(&dsl).iter().any(|name| name.contains("holder")),
        "a correlated policy mints no holder:\n{dsl}"
    );
}

/// Reading a table expands its `SELECT` policies, and any table those read expands its
/// own, so a loop anywhere in that closure makes `PostgreSQL` raise rather than filter.
/// Verified on `postgres:18`: every read of either table raises, owned rows included.
fn cycle_pair_schema(command: &str) -> ParserDB {
    db_of(&format!(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, b_id INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, a_id INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (b_id) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR {command} USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM b WHERE b.id = a.b_id AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR {command} USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM a WHERE a.id = b.a_id AND a.owner_id = current_user));
"
    ))
}

/// A cycle spanning two tables denies reads of both, and the owner arm does not save
/// them: `PostgreSQL` detects the loop when it expands the policy, before any row is
/// evaluated.
#[test]
fn a_read_cycle_across_two_tables_denies_both() {
    let db = cycle_pair_schema("SELECT");
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["a", "b"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "every read of '{table}' raises infinite recursion, so nothing is readable:\n{dsl}"
        );
    }

    let mut complaints = Vec::new();
    for table in ["a", "b"] {
        if !outputs.notes().iter().any(|note| {
            note.subject() == table
                && note.message().contains("recursion")
                && note.message().contains("SELECT")
                && note.message().contains("a reads b")
                && note.message().contains("b reads a")
        }) {
            complaints.push(format!("no note walks the loop for '{table}'"));
        }
    }
    assert!(
        complaints.is_empty(),
        "{complaints:?}, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "PostgreSQL raises here rather than granting, so nothing may claim the model \
         denies what RLS grants, got {:#?}",
        outputs.notes()
    );

    for query in outputs.tuple_queries() {
        assert!(
            !query.sql.contains("AS relation"),
            "nothing can consult a relation of either table, so this query is dead:\n{}",
            query.sql
        );
    }
}

/// Written `FOR ALL`, the same loop reaches the commands that read no row. Probed: a
/// plain `INSERT` and a constant blanket `UPDATE` both raise, because the recursive
/// `USING` is what feeds them.
#[test]
fn a_read_cycle_reaches_the_commands_that_read_no_row() {
    let db = cycle_pair_schema("ALL");
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
    let mut granted = Vec::new();
    for table in ["a", "b"] {
        for relation in [
            "can_select",
            "can_insert",
            "can_update",
            "can_update_without_reading",
            "can_delete",
        ] {
            if !relation_denies(&dsl, table, relation) {
                granted.push(format!("{table}.{relation}"));
            }
        }
    }
    assert!(
        granted.is_empty(),
        "the recursive USING feeds every command, so {granted:?} must deny:\n{dsl}"
    );
}

/// A three-table loop is the same reachability question, and closing only the two-table
/// case would leave it open.
#[test]
fn a_read_cycle_across_three_tables_denies_all_three() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE c(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE b ADD CONSTRAINT b_c FOREIGN KEY (nx) REFERENCES c(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
ALTER TABLE c ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR SELECT USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM c WHERE c.id = b.nx AND c.owner_id = current_user));
CREATE POLICY pc ON c FOR SELECT USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM a WHERE a.id = c.nx AND a.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
    for table in ["a", "b", "c"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "'{table}' sits on the loop, so its reads raise:\n{dsl}"
        );
    }
}

/// Reachability, not membership. Probed: reading `x` raises even though `x` is on no
/// loop, and the parent gate does not save it, since its owner arm grants on its own.
#[test]
fn a_table_that_only_reaches_a_read_cycle_is_denied_too() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
CREATE TABLE x(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
ALTER TABLE x ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
CREATE POLICY px ON x FOR SELECT USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM a WHERE a.id = x.nx AND a.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "x", "can_select").as_deref(),
        Some("no_access"),
        "reading 'x' expands a policy that reaches the loop, so it raises:\n{dsl}"
    );
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| { note.subject() == "x" && note.message().contains("recursion") }),
        "the operator must be told why 'x' denies, got {:#?}",
        outputs.notes()
    );
}

/// A RESTRICTIVE `SELECT` policy is expanded on a read exactly like a permissive one, so
/// it carries a loop the same way. Probed: both tables raise.
#[test]
fn a_read_cycle_through_a_restrictive_policy_denies_both() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (owner_id = current_user);
CREATE POLICY par ON a AS RESTRICTIVE FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();
    for table in ["a", "b"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "the restrictive arm is expanded too, so '{table}' raises:\n{dsl}"
        );
    }
}

/// A write clause reading a looping table cannot be evaluated either. Probed: the read
/// of `docs` is fine while its `INSERT` raises, and a plain sibling `INSERT` policy does
/// not save it, so the command denies rather than the clause dropping.
#[test]
fn a_write_clause_reading_a_recursive_table_denies_that_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_user));
CREATE POLICY pds ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY pdi_plain ON docs FOR INSERT WITH CHECK (owner_id = current_user);
CREATE POLICY pdi_loop ON docs FOR INSERT WITH CHECK (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the read policy of 'docs' reads nothing that loops, so reads still translate:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_insert").as_deref(),
        Some("no_access"),
        "one INSERT check reads 'm', whose reads raise, so the whole INSERT raises:\n{dsl}"
    );
    assert!(
        outputs.notes().iter().any(|note| {
            note.subject() == "docs"
                && note.message().contains("recursion")
                && note.message().contains("INSERT")
                && note.message().contains("m reads m")
                && !note.message().contains("SELECT")
        }),
        "the note names the INSERT and the loop, and reads of 'docs' are fine, so it must \
         not name SELECT, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "PostgreSQL raises here rather than granting, so nothing may claim the model \
         denies what RLS grants, got {:#?}",
        outputs.notes()
    );
}

/// Either `UPDATE` clause blocking raises the whole statement. Probed: with only the
/// `WITH CHECK` reading the looping table, the read of the guarded table is fine while
/// both the blanket and the row-scoped update raise.
#[test]
fn an_update_check_reading_a_recursive_table_denies_every_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_user));
CREATE POLICY pds ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY pdu ON docs FOR UPDATE USING (owner_id = current_user) WITH CHECK (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the read clause reads nothing that loops, so reads still translate:\n{dsl}"
    );
    for relation in ["can_update", "can_update_without_reading"] {
        assert!(
            relation_denies(&dsl, "docs", relation),
            "the check cannot be planned, so {relation} raises rather than filtering:\n{dsl}"
        );
    }
    assert!(
        outputs.notes().iter().any(|note| {
            note.subject() == "docs"
                && note.message().contains("recursion")
                && note.message().contains("UPDATE")
        }),
        "the note must name the UPDATE, got {:#?}",
        outputs.notes()
    );
    // This policy is blocked on one clause and live on the other, so it still reaches the
    // translation loop. Skipping the blocked clause is the only thing keeping the report
    // from asking for membership rows of a table whose reads raise, and the DSL is
    // identical either way, so nothing else here would notice.
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("membership table 'm'")),
        "no relation reads 'm', so nothing may report on which of its rows are visible, \
         got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "PostgreSQL raises the update rather than granting it, so nothing diverges, got {:#?}",
        outputs.notes()
    );
}

/// The loop is a thing the operator has to fix in SQL, so the note walks it in the
/// schema's own spelling rather than in the model's type names, which lowercase and can
/// carry a disambiguating suffix.
#[test]
fn a_read_recursion_note_names_tables_as_the_schema_spells_them() {
    let db = db_of(
        r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES app.docs(id), owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tree ON app.docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM app.docs p WHERE p.id = app.docs.parent_id AND p.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("app.docs reads app.docs")),
        "the note must name the table as the schema does, got {:#?}",
        outputs.notes()
    );
}

/// A policy whose every command the loop denies contributes nothing, so it must not leave
/// a role scope relation and a note asking the operator to load memberships nothing reads.
#[test]
fn a_fully_blocked_policy_leaves_no_role_scope_behind() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tree ON docs FOR SELECT TO auditor USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        pg_role_relation(&dsl, "docs"),
        None,
        "the only policy is denied outright, so nothing consults a role scope:\n{dsl}"
    );
    assert!(
        !type_names(&dsl).iter().any(|name| name == "pg_role"),
        "no relation references pg_role, so the type must not be declared:\n{dsl}"
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("auditor")),
        "nothing asks for role memberships nothing reads, got {:#?}",
        outputs.notes()
    );
}

/// The guard must not over-fire. A diamond sharing a table carries no loop, and probed
/// against `postgres:18` every read of it succeeds.
#[test]
fn a_diamond_sharing_a_table_without_a_cycle_still_translates() {
    let db = db_of(
        r"
CREATE TABLE g(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE e(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES g(id));
CREATE TABLE f(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES g(id));
CREATE TABLE d(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES e(id));
ALTER TABLE g ENABLE ROW LEVEL SECURITY;
ALTER TABLE e ENABLE ROW LEVEL SECURITY;
ALTER TABLE f ENABLE ROW LEVEL SECURITY;
ALTER TABLE d ENABLE ROW LEVEL SECURITY;
CREATE POLICY pg ON g FOR SELECT USING (owner_id = current_user);
CREATE POLICY pe ON e FOR SELECT USING (
  EXISTS (SELECT 1 FROM g WHERE g.id = e.nx AND g.owner_id = current_user));
CREATE POLICY pf ON f FOR SELECT USING (
  EXISTS (SELECT 1 FROM g WHERE g.id = f.nx AND g.owner_id = current_user));
CREATE POLICY pd ON d FOR SELECT USING (
  EXISTS (SELECT 1 FROM e WHERE e.id = d.nx AND e.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["d", "e", "f", "g"] {
        assert_ne!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "'{table}' is on no loop, so its reads must keep translating:\n{dsl}"
        );
    }
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "no loop exists here, so nothing may report one, got {:#?}",
        outputs.notes()
    );
}

/// A non-`SELECT` `USING` clause is not part of expanding a read, so it cannot close a
/// loop. Probed: `a`'s `UPDATE USING` reads `b` while `b`'s `SELECT USING` reads `a`, and
/// no statement raises.
#[test]
fn an_update_clause_pointing_back_is_not_a_read_cycle() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pas ON a FOR SELECT USING (owner_id = current_user);
CREATE POLICY pau ON a FOR UPDATE USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user))
  WITH CHECK (id IS NOT NULL);
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for (table, relation) in [
        ("a", "can_select"),
        ("b", "can_select"),
        ("a", "can_update"),
    ] {
        assert_ne!(
            relation_definition(&dsl, table, relation).as_deref(),
            Some("no_access"),
            "no read loop exists here, so {table}.{relation} must keep translating:\n{dsl}"
        );
    }
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "nothing loops here, got {:#?}",
        outputs.notes()
    );
}

/// A loop whose second leg sits on a table with row level security off never expands, so
/// it is not a loop. Probed: both reads succeed.
#[test]
fn a_cycle_through_a_table_without_row_level_security_is_not_a_cycle() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_ne!(
        relation_definition(&dsl, "a", "can_select").as_deref(),
        Some("no_access"),
        "'b' expands no policy, so reading 'a' terminates:\n{dsl}"
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "row level security is off on 'b', so nothing loops, got {:#?}",
        outputs.notes()
    );
}

/// The loop is a property of the schema, not of which policies survived filtering, so a
/// leg dropped for low confidence still makes `PostgreSQL` raise. Here `b` keeps a plain
/// ownership policy that grants on its own, so nothing gates the grant closed by accident.
#[test]
fn a_read_cycle_survives_a_leg_dropped_by_confidence_filtering() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb_loop ON b FOR SELECT USING (
  NOT EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
CREATE POLICY pb_own ON b FOR SELECT USING (owner_id = current_user);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "b", "can_select").as_deref(),
        Some("no_access"),
        "'pb_loop' still reads 'a' in the database, whatever the threshold dropped:\n{dsl}"
    );
}

/// A membership table whose own reads loop makes every read of the table that joins it
/// raise, so the grant denies. What this pins beyond the denial is the reporting: nothing
/// may ask the operator to load membership rows for a relation no permission reaches, and
/// no query may go looking for them. Probed on `postgres:18`: `SELECT` on `docs` raises
/// `infinite recursion detected in policy for relation "m"`.
#[test]
fn a_looping_membership_table_asks_for_no_tuples_and_no_disclosure() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_user));
CREATE POLICY pd ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    assert_looping_membership_is_silent(&db, "the correlated membership spelling");
}

/// The same for the uncorrelated spelling, which reaches a different judge beside the
/// correlated one and would otherwise be one recognizer away from reporting a gap that
/// does not exist.
#[test]
fn a_looping_uncorrelated_membership_table_asks_for_no_tuples_and_no_disclosure() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_user));
CREATE POLICY pd ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = current_user));
",
    );
    assert_looping_membership_is_silent(&db, "the uncorrelated membership spelling");
}

/// Reads of `docs` deny, the note names the loop rather than the membership table's row
/// visibility, and neither the report nor the tuple SQL asks for membership rows.
fn assert_looping_membership_is_silent(db: &ParserDB, spelling: &str) {
    let outputs = translator(ConfidenceLevel::B)
        .translate(db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "{spelling}: reading 'docs' expands a clause reading 'm', whose reads loop:\n{dsl}"
    );
    assert!(
        outputs.notes().iter().any(|note| {
            note.subject() == "docs"
                && note.message().contains("recursion")
                && note.message().contains("m reads m")
        }),
        "{spelling}: the note must name the loop, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("membership table 'm'")),
        "{spelling}: no permission reaches a membership relation, so nothing may report on \
         which of its rows are visible, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "{spelling}: PostgreSQL raises here rather than granting, so nothing diverges, got {:#?}",
        outputs.notes()
    );
    let queries = outputs.tuple_queries();
    let asking: Vec<&str> = queries
        .iter()
        .filter(|query| query.sql.contains(" m ") || query.sql.contains(" m\n"))
        .map(|query| query.comment.lines().next().unwrap_or(""))
        .collect();
    assert!(
        asking.is_empty(),
        "{spelling}: no relation reads 'm', so no query may load it: {asking:?}"
    );
}

/// A condition name is global to the model while a `PostgreSQL` policy name is unique
/// only per table, so one name reused across tables must not collapse two guards into
/// one spec. Here the two guards compare opposite ways, so sharing a spec inverts one of
/// them: rows of `campaigns` that have not started pass the model check while the
/// database hides them.
#[test]
fn two_tables_reusing_one_policy_name_get_their_own_condition() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/shared_policy_name/input.sql")
            .expect("the shared_policy_name fixture is readable"),
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let campaigns = condition_of_gate(&dsl, "campaigns");
    let embargoes = condition_of_gate(&dsl, "embargoes");
    assert_ne!(
        campaigns, embargoes,
        "the two guards are different rules, so they cannot share one condition:\n{dsl}"
    );

    let specs = condition_expressions(&dsl);
    assert_eq!(
        specs.get(&campaigns).map(String::as_str),
        Some("starts_at <= request_time"),
        "the campaigns guard admits what already started:\n{dsl}"
    );
    assert_eq!(
        specs.get(&embargoes).map(String::as_str),
        Some("lifts_at > request_time"),
        "the embargoes guard admits what has not lifted:\n{dsl}"
    );
}

/// The condition a type's conditional gate points at.
fn condition_of_gate(dsl: &str, type_name: &str) -> String {
    let (_, subjects) = relation_definitions(dsl, type_name)
        .into_iter()
        .find(|(name, _)| name.starts_with("gate_"))
        .unwrap_or_else(|| panic!("{type_name} should define a conditional gate:\n{dsl}"));
    subjects
        .split(" with ")
        .nth(1)
        .unwrap_or_else(|| panic!("the gate of {type_name} carries no condition:\n{dsl}"))
        .trim_end_matches(']')
        .trim()
        .to_string()
}

/// Every condition the DSL declares, by name, with its expression.
fn condition_expressions(dsl: &str) -> std::collections::BTreeMap<String, String> {
    let mut found = std::collections::BTreeMap::new();
    let mut lines = dsl.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim().strip_prefix("condition ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once('(') else {
            continue;
        };
        if let Some(body) = lines.peek() {
            found.insert(name.trim().to_string(), body.trim().to_string());
        }
    }
    found
}

/// `docs.can_select` and whether any query loads the membership table, for a schema whose
/// membership table carries `policies`.
fn membership_readability(policies: &str) -> (String, bool, Vec<String>) {
    let db = db_of(&format!(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
{policies}
CREATE POLICY pd ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_user));
"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let select = relation_definition(&dsl, "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{dsl}"));
    let loads_m = outputs
        .tuple_queries()
        .iter()
        .any(|query| query.sql.contains("FROM \"m\""));
    let notes = outputs
        .notes()
        .iter()
        .map(|note| note.message().clone())
        .collect();
    (select, loads_m, notes)
}

/// A membership read policy that cannot admit a row leaves the guarded table's subquery
/// with nothing to find, so the guarded table grants nothing. Probed on `postgres:18` with
/// one membership row naming the caller: the read of `m` returns 0 and so does the read of
/// `docs`, for every spelling below.
#[test]
fn a_membership_read_policy_that_cannot_admit_a_row_denies_the_guarded_table() {
    let mut complaints = Vec::new();
    for policy in [
        "CREATE POLICY pm ON m FOR SELECT USING (false);",
        // Parenthesised the way pg_dump writes it back.
        "CREATE POLICY pm ON m FOR SELECT USING ((false));",
        "CREATE POLICY pm ON m FOR SELECT USING (NOT true);",
        // An AND is empty as soon as either side is, whatever the other side says.
        "CREATE POLICY pm ON m FOR SELECT USING (false AND m.user_id = current_user);",
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user AND false);",
        // Both sides of an OR empty is still empty.
        "CREATE POLICY pm ON m FOR SELECT USING (false OR false);",
        // Every permissive read policy empty, so none of them grants.
        "CREATE POLICY pm ON m FOR SELECT USING (false);\n\
         CREATE POLICY pm2 ON m FOR SELECT USING (false AND m.user_id = current_user);",
        // FOR ALL applies its USING to reads too.
        "CREATE POLICY pm ON m FOR ALL USING (false);",
    ] {
        let (select, loads_m, notes) = membership_readability(policy);
        if select != "no_access" {
            complaints.push(format!("`{policy}` left can_select as `{select}`"));
        }
        if loads_m {
            complaints.push(format!("`{policy}` still loads membership rows"));
        }
        if !notes
            .iter()
            .any(|note| note.contains("'m' grants no reads"))
        {
            complaints.push(format!("`{policy}` reported no reason: {notes:?}"));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// A RESTRICTIVE read policy narrows whatever the permissive ones admit, so one that
/// cannot admit a row closes the table however wide they are. Probed: a permissive
/// `USING (true)` beside a restrictive `USING (false)` returns 0 rows.
#[test]
fn a_restrictive_kill_switch_on_a_membership_table_denies_the_guarded_table() {
    let mut complaints = Vec::new();
    for policy in [
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (false);",
        // The permissive side being a real rule changes nothing: the barrier still closes.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (false);",
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR ALL USING (false);",
    ] {
        let (select, loads_m, notes) = membership_readability(policy);
        if select != "no_access" {
            complaints.push(format!("`{policy}` left can_select as `{select}`"));
        }
        if loads_m {
            complaints.push(format!("`{policy}` still loads membership rows"));
        }
        if !notes
            .iter()
            .any(|note| note.contains("'m' grants no reads"))
        {
            complaints.push(format!("`{policy}` reported no reason: {notes:?}"));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// The guard must not over-fire. Anything whose emptiness depends on the data, or that the
/// crate simply does not recognise, keeps its disclosed grant: denying there would refuse
/// what RLS allows on the strength of a guess. Probed row counts are in the comments.
#[test]
fn a_membership_read_policy_that_may_admit_a_row_keeps_its_grant() {
    let mut complaints = Vec::new();
    for policy in [
        // 1 row.
        "CREATE POLICY pm ON m FOR SELECT USING (true);",
        // 1 row: the OR still has a live side.
        "CREATE POLICY pm ON m FOR SELECT USING (false OR m.user_id = current_user);",
        // 1 row.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);",
        // 0 rows for this data only, and the crate cannot tell, so it must not claim to.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = 'nobody');",
        // 0 rows, but the crate folds no arithmetic, so this is not proven either.
        "CREATE POLICY pm ON m FOR SELECT USING (1 = 2);",
        // One empty policy beside a live one still leaves the live one granting.
        "CREATE POLICY pm ON m FOR SELECT USING (false);\n\
         CREATE POLICY pm2 ON m FOR SELECT USING (m.user_id = current_user);",
        // A restrictive barrier that hides only some rows is the documented widening.
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (m.user_id = current_user);",
        // A non-read policy says nothing about reads.
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmd ON m FOR DELETE USING (false);",
        // A barrier bound to named roles leaves everyone outside them whatever the
        // permissive policies grant, so closing the table would refuse those readers what
        // RLS allows. The three-way answer cannot say "closed for these roles only".
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT TO contractor USING (false);",
    ] {
        let (select, loads_m, _) = membership_readability(policy);
        if select == "no_access" {
            complaints.push(format!("`{policy}` denied a grant RLS may allow"));
        }
        if !loads_m {
            complaints.push(format!("`{policy}` stopped loading membership rows"));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// The model and the notes for a table whose primary key is `key`.
fn barrier_outputs(key: &str) -> (String, Vec<String>) {
    let db = db_of(&format!(
        r"
CREATE TABLE docs ({key}, owner_id UUID, secret BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT TO contractor
    USING (secret = false);
"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let notes = outputs
        .notes()
        .iter()
        .map(|note| note.message().clone())
        .collect();
    (outputs.model(), notes)
}

/// A barrier bound to roles is folded as `(base and rule) or (base but not member from
/// scope)`, so the roles it binds are whoever the scope relation holds. Without a
/// single-column key no scope tuples can be emitted, and subtracting an empty set leaves the
/// barrier binding nobody, which is the one direction a missing input must never take. It has
/// to bind everyone instead: denying more than RLS is safe, granting more is not.
#[test]
fn a_role_limited_barrier_with_no_scope_tuples_binds_everyone() {
    let (dsl, notes) = barrier_outputs("tenant TEXT, id TEXT");

    assert!(
        !dsl.contains("but not"),
        "no scope tuples can say who is bound, so nothing may be excused from the barrier:\n{dsl}"
    );
    assert!(
        !dsl.contains("[pg_role]"),
        "a scope relation nothing can fill must not be published:\n{dsl}"
    );
    assert!(
        !dsl.contains("type pg_role"),
        "and neither must the type it would need:\n{dsl}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("docs_bar") && note.contains("everyone")),
        "the operator must be told the barrier now binds more than RLS does, got {notes:#?}"
    );
    assert!(
        !notes.iter().any(|note| note.contains("inheriting members")),
        "nothing may ask for memberships no relation reads, got {notes:#?}"
    );
}

/// The guard must not over-fire: with a key the scope tuples can name, the barrier binds the
/// roles it names and leaves everyone else alone, which is what `PostgreSQL` does.
#[test]
fn a_role_limited_barrier_with_scope_tuples_still_binds_only_its_roles() {
    let (dsl, notes) = barrier_outputs("id TEXT PRIMARY KEY");

    assert!(
        dsl.contains("but not"),
        "a fillable scope excuses everyone outside the bound roles:\n{dsl}"
    );
    assert!(
        dsl.contains("[pg_role]"),
        "the scope relation the exclusion reads has to be declared:\n{dsl}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("docs_bar") && note.contains("pg_role")),
        "and the operator is asked to fill it, got {notes:#?}"
    );
}

const INHERITANCE_PARENT_SCHEMA: &str = r"
CREATE TABLE docs(id INT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE secret_docs(classification TEXT) INHERITS (docs);
";

/// `INHERITS` does not extend the parent's primary key over the child, so parent row 1
/// and child row 1 are two rows `PostgreSQL` filters separately while `docs:1` is one
/// object, and a plain `FROM` loads both rows' tuples into it. Verified on 18.4: each
/// owner sees exactly their own row through the parent. So the parent's tuple queries
/// read `FROM ONLY`, and the child rows that drops are disclosed.
#[test]
fn an_inheritance_parents_tuples_read_only_its_own_rows() {
    let db = db_of(INHERITANCE_PARENT_SCHEMA);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(&tuples, "FROM ONLY \"docs\"").is_empty(),
        "an inheritance parent's tuples must come from its own rows alone, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(&tuples, "FROM \"docs\"").is_empty(),
        "a plain FROM loads child rows into parent objects, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );

    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, children }
                if table == "docs" && children == &["secret_docs".to_string()]
        )),
        "dropping child rows must be disclosed and name the child, got: {:#?}",
        outputs.notes()
    );

    // The narrowing lives in the tuples alone: the model is unchanged.
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
        Some("owner")
    );
}

/// A partitioned root holds no rows of its own, so `ONLY` there would load nothing and
/// silently deny every row. Its keys also span every partition, so the plain read is
/// exact. The root must stay untouched.
#[test]
fn a_partitioned_roots_tuples_still_read_every_partition() {
    let db = db_of(
        r"
CREATE TABLE measurements(id INT PRIMARY KEY, owner_id TEXT) PARTITION BY RANGE (id);
ALTER TABLE measurements ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON measurements FOR SELECT USING (owner_id = current_user);
CREATE TABLE measurements_q1 PARTITION OF measurements FOR VALUES FROM (1) TO (100);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(&tuples, "FROM \"measurements\"").is_empty(),
        "a partitioned root's tuples come from every partition, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(&tuples, "ONLY").is_empty(),
        "ONLY on a partitioned root reads zero rows, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { .. }
        )),
        "partitions are not the inheritance narrowing, got: {:#?}",
        outputs.notes()
    );
}

/// `PostgreSQL` reads a membership table's children through the policy's plain `FROM`,
/// and the membership tuple query mirrors that read, so it must not gain `ONLY` even
/// while the guarded table's own queries do: the narrowing applies to the rows a type
/// mints objects from, never to the rows a foreign table contributes.
#[test]
fn a_membership_tables_child_rows_still_grant() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE press_docs(embargo TEXT) INHERITS (docs);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
CREATE TABLE super_members(note TEXT) INHERITS (doc_members);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user)
);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(&tuples, "FROM \"doc_members\"").is_empty(),
        "membership tuples mirror the policy's inheritance-inclusive read, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(&tuples, "ONLY \"doc_members\"").is_empty(),
        "ONLY on the membership read would deny rows PostgreSQL grants, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        !tuples_reading_from(&tuples, "FROM ONLY \"docs\"").is_empty(),
        "the guarded table has a child, so its own bridge reads ONLY, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. } if table == "docs"
        )),
        "the guarded table narrows and says so, got: {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. }
                if table == "doc_members"
        )),
        "doc_members has no type, so no note names it, got: {:#?}",
        outputs.notes()
    );
}

/// A child can be a parent in turn, and the rule is per table: every type whose table
/// has `INHERITS` children reads only its own rows, the middle of a chain included.
#[test]
fn an_inheritance_childs_own_type_reads_only_its_own_rows_too() {
    let db = db_of(
        r"
CREATE TABLE docs(id INT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE secret_docs(classification TEXT) INHERITS (docs);
ALTER TABLE ONLY secret_docs ADD CONSTRAINT secret_docs_pkey PRIMARY KEY (id);
ALTER TABLE secret_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY c ON secret_docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE deep_docs(reason TEXT) INHERITS (secret_docs);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    for table in ["docs", "secret_docs"] {
        assert!(
            !tuples_reading_from(&tuples, &format!("FROM ONLY \"{table}\"")).is_empty(),
            "'{table}' has inheritance children, so its tuples read ONLY, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
        assert!(
            tuples_reading_from(&tuples, &format!("FROM \"{table}\"")).is_empty(),
            "'{table}' must not also read its children, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
    }
    for (table, child) in [("docs", "secret_docs"), ("secret_docs", "deep_docs")] {
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::InheritanceParentReadsOwnRowsOnly { table: t, children }
                    if t == table && children == &[child.to_string()]
            )),
            "'{table}' must disclose dropping '{child}', got: {:#?}",
            outputs.notes()
        );
    }
}

/// `PostgreSQL` applies a `TO role` clause with `has_privs_of_role` semantics: an
/// inheriting member of the role is admitted, a `NOINHERIT` member and a
/// `GRANT ... WITH INHERIT FALSE` grantee are not, while `pg_has_role(.., 'MEMBER')`
/// holds for all three. Probed on 18.4: `USING (true) TO editors` over three rows
/// answers 3 to the inheriting member and 0 to the other two. So a `TO` scope walks
/// `usage`, the kind the crate already defines as "every grant in the chain
/// inherits", never plain membership.
#[test]
fn a_to_scoped_policy_walks_usage_not_member() {
    let db = db_of(
        r"
CREATE ROLE editors;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editors USING (owner_id = current_user);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from scope_"),
        "a TO scope admits inheriting members, which is the usage kind:\n{dsl}"
    );
    assert!(
        !can_select.contains("member from scope_"),
        "membership admits NOINHERIT members PostgreSQL refuses:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "pg_role", "usage").as_deref(),
        Some("[user]"),
        "the walked relation must be declared for the operator to load:\n{dsl}"
    );
    assert!(
        relation_definition(&dsl, "pg_role", "member").is_none(),
        "nothing reads plain membership here, so declaring it would mislead:\n{dsl}"
    );
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.to_string().contains("reads pg_role 'usage'")),
        "the note must name the kind the operator loads, got: {:#?}",
        outputs.notes()
    );
}

/// The RESTRICTIVE fold excuses everyone outside the bound roles, and `PostgreSQL`
/// draws that line with `has_privs_of_role` too. Probed on 18.4: a barrier
/// `TO editors` binds the inheriting member (1 of 3 rows) and leaves the `NOINHERIT`
/// member alone (3 of 3). Excusing by `member` would bind users `PostgreSQL` excuses.
#[test]
fn a_to_scoped_barrier_excuses_by_usage_not_membership() {
    let db = db_of(
        r"
CREATE ROLE editors;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO editors USING (owner_id = current_user);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let limit = relation_definitions(&dsl, "docs")
        .into_iter()
        .find(|(name, _)| name.starts_with("limit_"))
        .map(|(_, body)| body)
        .expect("the barrier must fold into a limit_ relation");
    assert!(
        limit.contains("but not usage from scope_"),
        "the excused set is who lacks the role's inherited privileges:\n{dsl}"
    );
    assert!(
        !limit.contains("but not member from scope_"),
        "excusing non-members binds NOINHERIT members PostgreSQL excuses:\n{dsl}"
    );
}

/// A membership table readable only by named roles scopes the parent grant, and the
/// reader `PostgreSQL` admits is again the inheriting member, so the read scope walks
/// `usage` like every other `TO` consumer.
#[test]
fn a_membership_read_scope_walks_usage() {
    let db = db_of(
        r"
CREATE ROLE auditor;
CREATE TABLE users(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL REFERENCES users(id)
);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY m ON doc_members FOR SELECT TO auditor USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)
);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from read_scope_"),
        "only the roles that may read memberships inherit the grant:\n{dsl}"
    );
    assert!(
        !can_select.contains("member from read_scope_"),
        "membership admits readers PostgreSQL refuses:\n{dsl}"
    );
}

/// `PostgreSQL` resolves `TO CURRENT_USER`, `TO CURRENT_ROLE` and `TO SESSION_USER`
/// to the role executing `CREATE POLICY` (probed on 18.4: `pg_policies.roles` stores
/// `{postgres}`, or `{app_admin}` under `SET ROLE app_admin`), so the symbolic form
/// never reaches a dump and a schema file cannot know the role. Minting a
/// `pg_role:current_user` object asks the operator to populate a role that does not
/// exist, so the spelling is refused instead: a permissive policy falls closed.
#[test]
fn a_pseudo_role_scope_is_refused_not_minted() {
    for spelling in ["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER"] {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO {spelling} USING (owner_id = current_user);
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert!(
            relation_denies(&dsl, "docs", "can_select"),
            "`TO {spelling}` binds a role the schema cannot name, so the grant falls \
             closed:\n{dsl}"
        );
        assert!(
            pg_role_relation(&dsl, "docs").is_none(),
            "no scope relation may ask for tuples of a role that does not exist \
             (`TO {spelling}`):\n{dsl}"
        );
        assert!(
            !outputs
                .tuple_queries()
                .iter()
                .any(|q| q.sql.contains("pg_role:")),
            "no tuple may name a pseudo-role object (`TO {spelling}`), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        let note = outputs.notes().iter().find(|note| {
            matches!(
                note,
                TranslationNote::PolicyBoundToDdlTimeRole { policy, spellings }
                    if policy == "p" && spellings == &[spelling.to_string()]
            )
        });
        assert!(
            note.is_some(),
            "the refusal must name the spelling (`TO {spelling}`), got: {:#?}",
            outputs.notes()
        );
        assert_eq!(
            note.map(TranslationNote::severity),
            Some(NoteSeverity::Unhandled),
            "the model denies what the created policy would grant, which has to block \
             the outputs (`TO {spelling}`)"
        );
    }
}

/// The restrictive direction is the over-grant: probed on 18.4, a `LOGIN` owner under
/// `FORCE ROW LEVEL SECURITY` creating `AS RESTRICTIVE ... TO CURRENT_USER` sees 1 of
/// 2 rows while the old model excused everyone from the unfillable scope and granted
/// both. An unknowable scope has to bind everyone instead, named roles beside it
/// included, since a barrier that also binds the DDL runner cannot be narrowed to the
/// names alone.
#[test]
fn a_pseudo_role_barrier_binds_everyone() {
    for to_clause in ["CURRENT_USER", "editors, CURRENT_USER"] {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO {to_clause} USING (owner_id = current_user);
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert!(
            !dsl.contains("but not"),
            "an unfillable scope must not excuse anyone (`TO {to_clause}`):\n{dsl}"
        );
        let can_select =
            relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
        assert!(
            can_select.contains("public_viewer and owner"),
            "the barrier binds everyone, so the rule intersects the grant \
             (`TO {to_clause}`):\n{dsl}"
        );
        assert!(
            !outputs
                .tuple_queries()
                .iter()
                .any(|q| q.sql.contains("pg_role:")),
            "no tuple may name a pseudo-role object (`TO {to_clause}`), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyBoundToDdlTimeRole { policy, .. } if policy == "r"
            )),
            "the widening must be disclosed (`TO {to_clause}`), got: {:#?}",
            outputs.notes()
        );
    }
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

/// `PostgreSQL` refuses to store these shapes at all: `only WITH CHECK expression
/// allowed for INSERT` and `WITH CHECK cannot be applied to SELECT or DELETE`, both
/// probed verbatim on 18.4. Translating one describes a database that cannot exist,
/// and the `FOR INSERT USING` spelling used to mint `can_insert` through the
/// USING-to-check mirror.
#[test]
fn an_illegal_clause_refuses_the_policy() {
    let cases = [
        (
            "CREATE POLICY p ON docs FOR INSERT USING (owner_id = current_user);",
            "only WITH CHECK expression allowed for INSERT",
        ),
        (
            "CREATE POLICY p ON docs FOR SELECT WITH CHECK (owner_id = current_user);",
            "WITH CHECK cannot be applied to SELECT or DELETE",
        ),
        (
            "CREATE POLICY p ON docs FOR DELETE WITH CHECK (owner_id = current_user);",
            "WITH CHECK cannot be applied to SELECT or DELETE",
        ),
    ];
    for (policy_sql, rule) in cases {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policy_sql}
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        for action in ["can_select", "can_insert", "can_update", "can_delete"] {
            assert!(
                relation_denies(&dsl, "docs", action),
                "an impossible policy grants nothing ({policy_sql}), {action}:\n{dsl}"
            );
        }
        assert!(
            outputs.tuple_queries().is_empty(),
            "an impossible policy asks for no tuples ({policy_sql}), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyClauseIllegal { policy, rule: r }
                    if policy == "p" && r == rule
            )),
            "the refusal must quote PostgreSQL's own sentence ({policy_sql}), got: {:#?}",
            outputs.notes()
        );
        assert!(
            !outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyClauseAbsent { policy, .. } if policy == "p"
            )),
            "an illegal clause is not an absent one, and saying both misleads \
             ({policy_sql}), got: {:#?}",
            outputs.notes()
        );
    }
}

/// Every `(relation, subject column)` a relation takes from a row of its own table.
fn row_subject_columns(shapes: &[RelationShapes]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in shapes {
        for shape in &entry.shapes {
            if let RecordDerivation::FromRow { template, .. } = &shape.derivation {
                if let ValueSource::Column(column) = template.subject_key.part() {
                    out.push((entry.relation.clone(), column.clone()));
                }
            }
        }
    }
    out
}

/// `current_setting` returns whatever the key holds, so which key it names is the whole
/// question. Reading every call as the caller turns a tenant identifier into a user and
/// grants one tuple per tenant, and reading none of them leaves a policy that only ever
/// spells the call inline undecidable.
#[test]
fn only_a_named_setting_key_becomes_a_user_subject() {
    let owner_sql = r"
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_p ON notes USING (owner = current_setting('app.user_id', true));
";
    let tenant_sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY rows_p ON rows_ USING (tenant_id = current_setting('app.tenant_id', true));
";
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let owner_db = db_of(owner_sql);
    let granted = row_subject_columns(&translator.translate(&owner_db).relations());
    assert!(
        !granted.is_empty(),
        "the named key is the caller, so the owner column decides the row"
    );
    for (relation, column) in &granted {
        assert_eq!(
            column, "owner",
            "notes#{relation} grants the wrong column as a user"
        );
    }

    let tenant_db = db_of(tenant_sql);
    let tenant_relations = translator.translate(&tenant_db).relations();
    assert!(
        row_subject_columns(&tenant_relations).is_empty(),
        "no key names the caller here, so nothing may become a user subject: {tenant_relations:#?}"
    );
}

/// One predicate decides who the caller is, so a named key read inline reaches every
/// recognizer that asks it. The call itself never reaches what the loader runs: the
/// subject comes from the row, and a `current_setting` in a loader query would read the
/// loader's own session and load nothing.
#[test]
fn a_named_key_read_inline_reaches_every_recognizer_and_leaves_the_loader_clean() {
    let cases = [
        (
            "ownership",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
",
        ),
        (
            "membership through a subquery",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  current_setting('app.user_id', true) IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id)
);
",
        ),
        (
            "an array column's elements",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, viewers TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (current_setting('app.user_id', true) = ANY (viewers));
",
        ),
        (
            "a jsonb field",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (data ->> 'owner' = current_setting('app.user_id', true));
",
        ),
        (
            "a role the caller holds",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (pg_has_role(current_setting('app.user_id', true), 'editors', 'MEMBER'));
",
        ),
    ];

    for (label, sql) in cases {
        let db = db_of(sql);
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        assert!(
            !relation_denies(&dsl, "docs", "can_select"),
            "{label}: the named key is the caller, so reads are not denied:\n{dsl}"
        );
        let queries = outputs.tuple_queries();
        assert!(
            !queries.is_empty(),
            "{label}: a granting relation needs tuples to grant through:\n{dsl}"
        );
        let tuples = format_tuples(&queries);
        assert!(
            !tuples.contains("current_setting"),
            "{label}: the loader reads rows, not the caller's own session:\n{tuples}"
        );
    }
}

/// A scalar subquery in the accessor position is read as the caller, but only when it is
/// nothing but its projection. Given a `FROM` or a `WHERE` it is a conjunct in disguise:
/// it yields NULL when nothing survives, which filters every row out, while the pattern
/// keeps only a column name and would grant the column unconditionally.
#[test]
fn a_filtering_accessor_subquery_is_refused_not_read_as_the_caller() {
    let guarded = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE TABLE kill_switch(name TEXT PRIMARY KEY, enabled BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  owner_id = (SELECT current_setting('app.user_id', true)
              FROM kill_switch WHERE name = 'docs_read' AND enabled)
);
";
    let bare = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = (SELECT current_setting('app.user_id', true)));
";
    let emptied = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = (SELECT current_setting('app.user_id', true) LIMIT 0));
";

    for (label, sql) in [("a read of a table", guarded), ("a row limit", emptied)] {
        let db = db_of(sql);
        let relations = translator(ConfidenceLevel::B).translate(&db).relations();
        assert!(
            row_subject_columns(&relations).is_empty(),
            "{label} can empty the subquery, so the column it compares is not the caller"
        );
    }

    let db = db_of(bare);
    let relations = translator(ConfidenceLevel::B).translate(&db).relations();
    assert_eq!(
        row_subject_columns(&relations)
            .iter()
            .map(|(_, column)| column.as_str())
            .collect::<Vec<_>>(),
        ["owner_id"],
        "a subquery that is only its projection is still the caller"
    );
}

/// Phase 1, test 4. A permissive `WITH CHECK` the threshold dropped must not come
/// back through the bucket-level mirror. `for_each_policy_target_expr` honours the
/// suppression per policy, but the composed check falls back to the composed
/// `USING` when the bucket ends up empty, which resurrects exactly the clause that
/// was refused and grants the update the model meant to deny. Only the check half
/// falls closed: the surviving `USING` still answers a locking read.
#[test]
fn a_filtered_with_check_does_not_resurrect_through_the_bucket_mirror() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user)
  WITH CHECK (opaque_gate(id));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps()
        .model();

    assert_ne!(
        relation_definition(&dsl, "docs", "can_update").as_deref(),
        Some("owner"),
        "the dropped WITH CHECK came back as the USING:\n{dsl}"
    );
    assert!(
        relation_denies(&dsl, "docs", "can_update_check"),
        "a check with no surviving arm has to fall closed:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "a locking read filters by the USING alone, which survived:\n{dsl}"
    );
}

/// Phase 1, test 5. A clause the caller's threshold dropped is named by a typed note
/// carrying what it cost, which is the only machine readable channel for it: the
/// surviving-policy summary is built from the filtered set by design, and prose in
/// the report is not something a program reads.
#[test]
fn a_clause_the_threshold_dropped_is_named_by_a_typed_note() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let dropped: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. }))
        .collect();
    assert_eq!(
        dropped.len(),
        1,
        "one note per dropped clause: {:?}",
        outputs.notes()
    );
    let TranslationNote::ClauseBelowThreshold {
        table,
        policy,
        mode,
        clause,
        confidence,
        commands,
        relations,
    } = dropped[0]
    else {
        unreachable!("filtered above")
    };
    assert_eq!(
        (
            table.as_str(),
            policy.as_str(),
            mode.as_str(),
            clause.as_str(),
            *confidence
        ),
        (
            "docs",
            "docs_opaque",
            "PERMISSIVE",
            "USING",
            ConfidenceLevel::D
        )
    );
    assert_eq!(commands, &["SELECT".to_string()]);
    assert_eq!(relations, &["can_select".to_string()]);
    assert_eq!(
        dropped[0].severity(),
        NoteSeverity::BelowThreshold,
        "the caller's own threshold is not an unhandled expression"
    );
}

/// Phase 1, test 5, second half. A `FOR ALL` policy is translated once per phase, so
/// the note has to be one per lost clause rather than one per phase it fed.
#[test]
fn a_dropped_for_all_policy_reports_one_note_per_clause_not_per_phase() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR ALL USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
CREATE POLICY docs_opaque ON docs FOR ALL USING (opaque_gate(id))
  WITH CHECK (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let clauses: Vec<(&str, &[String])> = outputs
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::ClauseBelowThreshold {
                clause, commands, ..
            } => Some((clause.as_str(), commands.as_slice())),
            _ => None,
        })
        .collect();

    assert_eq!(
        clauses,
        vec![
            (
                "USING",
                ["SELECT", "UPDATE", "DELETE"].map(String::from).as_slice()
            ),
            (
                "WITH CHECK",
                ["INSERT", "UPDATE"].map(String::from).as_slice()
            ),
        ],
        "two stored clauses, two notes, each naming the commands it fed"
    );

    // A FOR ALL USING feeds both UPDATE targets, which share `can_update` and
    // `can_update_without_reading`, so an undeduplicated list names each twice and
    // stops matching the scar it is supposed to describe.
    for note in outputs.notes() {
        let TranslationNote::ClauseBelowThreshold { relations, .. } = note else {
            continue;
        };
        let mut unique = relations.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            &unique, relations,
            "the note names each diverged relation once: {relations:?}"
        );
    }
}

/// A permissive policy the threshold empties is now retained through the filter, so
/// the generator can say what was lost. Retaining it must not resurrect its side
/// effects: registration runs before translation, so a policy contributing no
/// expression would otherwise still mint a role scope relation and ask the operator
/// to load `pg_role` memberships that nothing consults.
#[test]
fn a_policy_the_threshold_emptied_mints_no_scope_relation() {
    let db = db_of(
        "CREATE ROLE auditor;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_scoped ON docs FOR SELECT TO auditor USING (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert!(
        !dsl.contains("scope_"),
        "the emptied policy contributes no expression, so nothing may reference a \
         scope relation for it:\n{dsl}"
    );
    assert!(
        !dsl.contains("type pg_role"),
        "and no role type is minted for it:\n{dsl}"
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyRoleScope { .. })),
        "nor a note asking for memberships nothing reads: {:?}",
        outputs.notes()
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ClauseBelowThreshold { policy, .. } if policy == "docs_scoped"
        )),
        "but the loss itself is still reported: {:?}",
        outputs.notes()
    );
}

/// Phase 2, test 7. A table whose rows no tuple can name still carried its policy's
/// grant into the model, so `OpenFGA` denied everyone where `PostgreSQL` grants the
/// viewer and the only place that said so was a comment in the tuple SQL.
#[test]
fn a_grant_no_tuple_can_fill_denies_and_is_reported() {
    for (cause, declaration, expected_reason) in [
        (
            "no primary key and an 'id' that identifies no row",
            "CREATE TABLE shares(id UUID, viewer TEXT);",
            "no primary key, and 'id' is nullable or not uniquely constrained, so it does \
             not identify a row",
        ),
        (
            "no primary key and no 'id'",
            "CREATE TABLE shares(paper_id UUID, viewer TEXT);",
            "missing object identifier column",
        ),
    ] {
        let db = db_of(&format!(
            "{declaration}
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON shares FOR SELECT USING (viewer = current_user);
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert_eq!(
            relation_definition(&dsl, "shares", "can_select").as_deref(),
            Some("no_access"),
            "{cause}: no fact can name a row, so the read denies rather than standing as \
             a permission nothing can satisfy:\n{dsl}"
        );
        let named: Vec<&TranslationNote> = outputs
            .notes()
            .iter()
            .filter(|note| matches!(note, TranslationNote::RowsCannotBeNamed { .. }))
            .collect();
        let [note] = named.as_slice() else {
            panic!(
                "{cause}: the model denies what PostgreSQL grants, so exactly one note \
                 has to say so: {:#?}",
                outputs.notes()
            );
        };
        let TranslationNote::RowsCannotBeNamed {
            table,
            reason,
            sources,
        } = note
        else {
            unreachable!("filtered above")
        };
        assert_eq!(
            (table.as_str(), sources.as_slice()),
            ("shares", &["ownership tuples".to_string()][..])
        );
        assert_eq!(
            reason, expected_reason,
            "{cause}: the note names the cause the tuple script names"
        );
        assert!(
            note.severity().diverges_from_database(),
            "{cause}: a grant nothing can fill is a disagreement with the database"
        );
    }
}

/// Phase 2, test 7, corpus shaped. An `OpenFGA` grant names an object, so every pattern
/// that grants needs a row identity, and a pattern arm that forgets leaves a permission
/// nothing can satisfy. This ranges over every arm that emits a tuple source keyed on
/// the guarded table's rows, so a new arm forgetting the check fails here.
#[test]
fn no_pattern_grants_on_a_table_whose_rows_cannot_be_named() {
    // Each case names the tuple query its arm would have emitted, so a denial reached
    // through some other refusal cannot pass for the guard under test.
    const GRANT_SCHEMA: &str = "CREATE TABLE owner_grants(grantee_owner_id UUID,
  granted_owner_id UUID, role_id INTEGER);
CREATE FUNCTION get_owner_role(u TEXT, t TEXT) RETURNS INTEGER LANGUAGE sql STABLE
AS 'SELECT 0';";
    const GRANT_REGISTRY: &str = r#"{"get_owner_role": {"kind": "role_threshold",
        "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3},
        "grant_table": "owner_grants", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id"}}"#;
    let cases: [(&str, &str, &str, Option<&str>); 13] = [
        ("ownership", "", "USING (viewer = current_user)", None),
        (
            "array membership",
            "",
            "USING (current_user = ANY (editors))",
            None,
        ),
        (
            "jsonb field ownership",
            "",
            "USING (meta ->> 'owner' = current_user)",
            None,
        ),
        ("public-flag", "", "USING (is_public)", None),
        ("constant-TRUE", "", "USING (true)", None),
        ("attribute-gate", "", "USING (status = 'open')", None),
        (
            "policy scope",
            "CREATE ROLE auditor;",
            "TO auditor USING (viewer = current_user)",
            None,
        ),
        (
            "bridge tuples to 'link'",
            "CREATE TABLE links(link_id UUID, user_id TEXT);",
            "USING (EXISTS (SELECT 1 FROM links l WHERE l.link_id = shares.paper_id \
             AND l.user_id = current_user))",
            None,
        ),
        (
            "bridge tuples to 'papers'",
            "",
            "USING (EXISTS (SELECT 1 FROM papers p WHERE p.id = shares.paper_id \
             AND p.owner = current_user))",
            None,
        ),
        (
            "membership holder",
            "CREATE TABLE staff(user_id TEXT);",
            "USING (EXISTS (SELECT 1 FROM staff s WHERE s.user_id = current_user))",
            None,
        ),
        (
            "role gate",
            "",
            "USING (pg_has_role(current_user, 'editor', 'MEMBER'))",
            None,
        ),
        (
            "explicit grant",
            GRANT_SCHEMA,
            "USING (get_owner_role(current_user, viewer) >= 2)",
            Some(GRANT_REGISTRY),
        ),
        (
            "explicit grant",
            GRANT_SCHEMA,
            "USING (get_owner_role(current_user, viewer) IN (2, 3))",
            Some(GRANT_REGISTRY),
        ),
    ];

    for (what, extra_schema, policy_tail, registry_json) in cases {
        let db = db_of(&format!(
            "CREATE TABLE papers(id UUID PRIMARY KEY, owner TEXT);
{extra_schema}
CREATE TABLE shares(paper_id UUID REFERENCES papers(id), viewer TEXT, editors TEXT[],
  meta JSONB, is_public BOOLEAN, status TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_own ON papers FOR SELECT USING (owner = current_user);
CREATE POLICY shares_read ON shares FOR SELECT {policy_tail};
"
        ));
        let mut builder = TranslatorBuilder::new().with_min_confidence(ConfidenceLevel::C);
        if let Some(json) = registry_json {
            builder = builder.with_registry_json(json).expect("registry json");
        }
        let outputs = builder.build().translate(&db).outputs_accepting_gaps();
        let dsl = outputs.model();

        let sources: Vec<String> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::RowsCannotBeNamed { table, sources, .. } if table == "shares" => {
                    Some(sources.clone())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            sources.iter().any(|source| source.starts_with(what)),
            "{what}: the arm has to say which tuple query it could not emit, got \
             {sources:?} from {:#?}",
            outputs.notes()
        );

        for relation in [
            "can_select",
            "can_insert",
            "can_update",
            "can_delete",
            "can_update_without_reading",
            "can_select_for_update",
        ] {
            assert!(
                action_relation_denies(&dsl, "shares", relation),
                "{what}: nothing can name a row of 'shares', so '{relation}' grants \
                 nobody:\n{dsl}"
            );
        }

        // Whatever the arm minted before it fell closed has to go with it. A scope
        // relation nothing can fill asks the operator for `pg_role` memberships no rule
        // reads, and a type left with no relation is a holder or a parent the grant no
        // longer reaches.
        assert!(
            !dsl.contains("scope_"),
            "{what}: no tuple can fill a scope on 'shares', so none may be declared:\n{dsl}"
        );
        for empty in types_declaring_no_relation(&dsl) {
            assert_eq!(
                empty, "user",
                "{what}: '{empty}' outlived the expression that minted it:\n{dsl}"
            );
        }
    }
}

/// Phase 2, test 7, the trap. `PostgreSQL` raises on a looping read rather than
/// granting, so the model denying is faithful and nothing may claim a divergence. A
/// table whose rows also cannot be named must not scar for the commands the loop
/// already blocks, since the policy loop never translates them and no tuple query was
/// ever going to be emitted.
#[test]
fn a_table_whose_reads_loop_does_not_scar_for_rows_it_cannot_name() {
    let db = db_of(
        "CREATE TABLE a(k UUID, viewer TEXT, PRIMARY KEY (k, viewer));
CREATE TABLE b(k UUID, viewer TEXT, PRIMARY KEY (k, viewer));
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY a_read ON a FOR SELECT USING (EXISTS (SELECT 1 FROM b WHERE b.k = a.k));
CREATE POLICY b_read ON b FOR SELECT USING (EXISTS (SELECT 1 FROM a WHERE a.k = b.k));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyReadRecursion { .. })),
        "the loop itself is still reported: {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "PostgreSQL raises here rather than granting, so nothing may claim the model \
         denies what RLS grants, got {:#?}",
        outputs.notes()
    );
}

/// A write rule that only requires the parent row to exist inherits the parent's own
/// read rule and nothing more. Translating the constant instead would mint a
/// `public_viewer` relation on the parent and ask an operator to load a wildcard tuple
/// per parent row that no rule reads, which is an unreferenced grant on the parent.
#[test]
fn a_bare_delegation_emits_the_parent_gate_and_nothing_else() {
    let sql = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (id INT PRIMARY KEY, paper_id INT REFERENCES papers(id), viewer TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_own ON papers FOR SELECT USING (owner = auth_uid());
CREATE POLICY shares_insert ON paper_shares FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM papers p WHERE p.id = paper_id));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();
    let (classified, registry) = translator.classify_with_effective_registry(&db);
    let outputs = rls2fga::translator::Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.model();

    assert!(
        model.contains("define can_insert: can_select from papers"),
        "the parent's read rule is the whole requirement:\n{model}"
    );
    assert!(
        !model.contains("public_viewer"),
        "a constant inner rule adds no relation to the parent:\n{model}"
    );
    assert!(
        !model.contains("inherited_"),
        "there is no rule to name beyond the parent's own:\n{model}"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("public_viewer")),
        "no operator is asked for a wildcard tuple no rule reads"
    );
}

/// The sharing subquery reads its table as the caller, so that table's own rules decide
/// which sharing rows count. A sharing table nobody can read leaves the subquery nothing
/// to find, so the parent grants nobody. Emitting facts from rows the caller cannot see
/// would grant through shares that do not exist for them.
#[test]
fn a_share_table_nobody_can_read_grants_nothing_through_it() {
    let sql = "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_hidden ON paper_shares FOR SELECT USING (false);
CREATE POLICY papers_shared ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )])
        .build();
    let (classified, registry) = translator.classify_with_effective_registry(&db);
    let outputs = rls2fga::translator::Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let model = outputs.model();

    assert!(
        model.contains("define can_select: no_access"),
        "a sharing table nobody reads grants nobody:\n{model}"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("FROM \"paper_shares\"")),
        "no facts are read from a table the caller cannot see"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                if join_table == "paper_shares"
        )),
        "the reason the grant vanished is named: {:?}",
        outputs.notes()
    );
}

/// One database written two ways must not land in two behaviours, so the two spellings
/// of each caller carried set emit byte identical DSL.
///
/// Asserted per database rather than across the family: jsonb containment is a different
/// predicate, which the probe behind D6 established, so nothing here compares against it.
#[test]
fn one_caller_carried_set_written_two_ways_emits_one_model() {
    fn model(clause: &str, preamble: &str, attribute: SessionAttribute) -> String {
        let db = db_of(&format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             {preamble}\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        ));
        TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_session_attributes(vec![attribute])
            .build()
            .translate(&db)
            .outputs_accepting_gaps()
            .model()
            .clone()
    }

    const CLAIM: &str = "jsonb_array_elements_text(\
                         current_setting('request.jwt.claims')::jsonb -> 'teams')";
    const WRAPPER: &str = "CREATE FUNCTION user_teams() RETURNS SETOF TEXT LANGUAGE sql STABLE\n\
          AS 'SELECT unnest(string_to_array(current_setting(''app.teams'', true), '','')) ';\n";
    let token = || {
        SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        )
    };
    let in_form = model(&format!("team_id IN (SELECT {CLAIM})"), "", token());
    let array_form = model(
        &format!("team_id = ANY (ARRAY(SELECT {CLAIM}))"),
        "",
        token(),
    );
    assert_eq!(
        in_form, array_form,
        "a token carried list must not answer differently for being spelled with ARRAY"
    );
    assert!(
        in_form.contains("define can_select: gate_p_"),
        "the shape must actually translate rather than agreeing on a denial: {in_form}"
    );

    let setting = || SessionAttribute::setting("app.teams", SessionAttributeKind::SetAttribute);
    let in_form = model("team_id IN (SELECT user_teams())", WRAPPER, setting());
    let array_form = model(
        "team_id = ANY (ARRAY(SELECT user_teams()))",
        WRAPPER,
        setting(),
    );
    assert_eq!(
        in_form, array_form,
        "a function carried set must not answer differently for being spelled with ARRAY"
    );
    assert!(
        in_form.contains("define can_select: gate_p_"),
        "the shape must actually translate rather than agreeing on a denial: {in_form}"
    );
}

/// The two shapes D6 and D7 refuse, pinned so admitting either needs a red test first.
///
/// Containment matches only the string elements of a jsonb array, so a claim of `[1,2]`
/// against `'1'` answers false where the two admitted spellings answer true. A function
/// body reading a table puts the authority in that table, where a value the caller sends
/// would let it assert its own membership.
#[test]
fn a_set_the_authority_does_not_supply_is_refused() {
    fn classify(preamble: &str, clause: &str, attribute: SessionAttribute) -> PatternClass {
        let db = db_of(&format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             CREATE TABLE members(user_id TEXT, team_id TEXT);\n\
             {preamble}\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        ));
        TranslatorBuilder::new()
            .with_session_attributes(vec![attribute])
            .build()
            .classify(&db)[0]
            .using_classification
            .as_ref()
            .expect("expected a USING classification")
            .pattern
            .clone()
    }

    let containment = classify(
        "",
        "current_setting('request.jwt.claims')::jsonb -> 'teams' ? team_id",
        SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        ),
    );
    assert!(
        matches!(containment, PatternClass::Unknown { .. }),
        "containment is a different predicate, not a third spelling, got {containment:?}"
    );

    let from_a_table = classify(
        "CREATE FUNCTION user_teams() RETURNS SETOF TEXT LANGUAGE sql STABLE\n\
           AS 'SELECT team_id FROM members WHERE user_id = current_setting(''app.teams'', true)';\n",
        "team_id IN (SELECT user_teams())",
        SessionAttribute::setting("app.teams", SessionAttributeKind::SetAttribute),
    );
    assert!(
        matches!(from_a_table, PatternClass::Unknown { .. }),
        "a table owns its own facts, so the caller may not assert them, got {from_a_table:?}"
    );
}

/// A real list has no delimiter, so nothing may synthesise one into the caller contract.
///
/// The delimited string contract tells the caller to send what `string_to_array` would
/// produce, which is the one reachable wrong allow in the feature. Leaking that sentence
/// onto a shape with no delimiter would state a hazard that does not exist and name a
/// separator the policy never wrote.
#[test]
fn a_list_source_states_no_separator_in_its_caller_contract() {
    let db = db_of(
        "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
         ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON documents FOR SELECT USING (team_id IN (SELECT \
         jsonb_array_elements_text(current_setting('request.jwt.claims')::jsonb -> 'teams')));\n",
    );
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes(vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        )])
        .build()
        .translate(&db)
        .outputs_accepting_gaps();

    let contract = outputs
        .notes()
        .iter()
        .find_map(|note| match note {
            TranslationNote::CallerSuppliesConditionParameter {
                parameter,
                separator,
                ..
            } => Some((parameter.clone(), separator.clone())),
            _ => None,
        })
        .expect("every request scoped gate states its contract with the caller");
    assert_eq!(contract.0, "request_jwt_claims_teams");
    assert_eq!(
        contract.1, None,
        "a list carries no separator, so none may be invented"
    );
    assert!(
        !outputs.report().contains("string_to_array"),
        "the delimited string contract must not leak onto a shape with no delimiter"
    );
}

// ---------------------------------------------------------------------------
// The correlated column.
// ---------------------------------------------------------------------------

/// The column of `table` a bridge shape on it reads to name the parent.
fn bridge_subject_column(relations: &[RelationShapes], table: &str) -> Option<String> {
    relations
        .iter()
        .flat_map(|entry| &entry.shapes)
        .find_map(|shape| match &shape.derivation {
            RecordDerivation::FromRow {
                table: from,
                template,
                ..
            } if from == table => match template.subject_key.part() {
                ValueSource::Column(name) => Some(name.clone()),
                _ => None,
            },
            _ => None,
        })
}

const CORRELATION_SCHEMA: &str = "
CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT REFERENCES customers(id), status TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), sku TEXT, status TEXT);
";

fn correlated_relations(using: &str) -> Vec<RelationShapes> {
    let db = db_of(&format!(
        "{CORRELATION_SCHEMA}
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON line_items FOR SELECT USING ({using});
"
    ));
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(&db)
        .relations()
}

/// The membership bridge used to be keyed on the membership table's own column name,
/// which the guarded table may also carry under a different meaning. A row was then
/// granted through a value the policy never compared.
#[test]
fn a_membership_bridge_reads_the_column_the_policy_correlates() {
    let correlates_sku = correlated_relations(
        "sku IN (SELECT status FROM orders \
         WHERE customer_id = current_setting('app.user_id', true))",
    );
    let correlates_status = correlated_relations(
        "status IN (SELECT status FROM orders \
         WHERE customer_id = current_setting('app.user_id', true))",
    );

    assert_eq!(
        bridge_subject_column(&correlates_sku, "line_items").as_deref(),
        Some("sku"),
        "the policy compares line_items.sku, so the bridge reads sku"
    );
    assert_eq!(
        bridge_subject_column(&correlates_status, "line_items").as_deref(),
        Some("status"),
        "the policy compares line_items.status, so the bridge reads status"
    );
}

/// A bridge the schema cannot write leaves the grant above it satisfiable by nobody.
/// The renderer can only say so in a comment, so the loss is settled while the plan is
/// built and reaches `notes`.
#[test]
fn a_bridge_the_schema_cannot_write_is_reported() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM doc_members dm WHERE dm.doc_id = nonexistent AND dm.user_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let reported = outputs.notes().iter().any(|note| {
        matches!(note, TranslationNote::BridgeColumnMissing { table, column, .. }
            if table == "docs" && column == "nonexistent")
    });
    assert!(
        reported,
        "the missing bridge column has to be a note: {:?}",
        outputs.notes()
    );
    assert!(
        relation_denies(&outputs.model(), "docs", "can_select"),
        "a grant whose bridge nobody writes has to fall closed:\n{}",
        outputs.model()
    );
}

/// The request-scoped gate names the guarded row by the join table's own column, so
/// that column has to hold the row's identifier. Correlated against anything else it
/// names another row, or none.
#[test]
fn a_request_gate_correlated_on_a_non_key_column_is_refused() {
    let db = db_of(
        "CREATE TABLE papers(id INT PRIMARY KEY, batch TEXT);
CREATE TABLE shares(paper_batch TEXT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM shares s WHERE s.paper_batch = papers.batch
    AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
    );
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )])
        .build()
        .translate(&db)
        .outputs_accepting_gaps();

    assert!(
        outputs.notes().iter().any(|note| {
            matches!(note, TranslationNote::ExpressionRefused { reason, .. }
                if reason.contains("does not identify a row"))
        }),
        "the refusal has to name the column that decides it: {:?}",
        outputs.notes()
    );
    assert!(
        relation_denies(&outputs.model(), "papers", "can_select"),
        "a gate keyed on a value that names no row has to fall closed:\n{}",
        outputs.model()
    );
}

/// A row named by a two-column key is named the same way on both ends of a bridge. The
/// bridge used to demand a single-column key and vanish into a comment without one.
#[test]
fn a_bridge_names_a_row_by_its_whole_key() {
    let db = db_of(
        "CREATE TABLE papers(id INT PRIMARY KEY);
CREATE TABLE paper_shares(paper_id INT REFERENCES papers(id), viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON paper_shares FOR SELECT USING (
  EXISTS (SELECT 1 FROM papers p WHERE p.id = paper_id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .outputs_accepting_gaps();

    let bridge = outputs
        .tuple_queries()
        .into_iter()
        .find(|query| query.comment.contains("bridge"))
        .expect("the delegation to the parent needs a bridge");
    assert!(
        !bridge.sql.trim_start().starts_with("--"),
        "the bridge has to be a query, not a comment: {}",
        bridge.sql
    );
    assert!(
        bridge.sql.contains("\"paper_id\"") && bridge.sql.contains("\"viewer\""),
        "both key columns name the row: {}",
        bridge.sql
    );
}
