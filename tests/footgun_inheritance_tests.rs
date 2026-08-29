//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Parent rules through a foreign key, `INHERITS` children, and partitions.

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

mod support;

use support::footgun::{
    assert_model_is_internally_consistent, db_of, membership_translation, relation_definition,
    translation, translator, tuples_reading_from, type_names,
};

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
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

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
        .expect("translation should plan")
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
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model(),
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
            .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model(),
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
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.model()));
    assert!(
        can_select.contains("no_access"),
        "no membership row is visible, so the grant is empty, got \
         'define can_select: {can_select}'"
    );
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
            .expect("translation should plan")
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
    let sql = support::qualify_table_declarations(
        &format!(
            "{}CREATE POLICY docs_members ON docs FOR SELECT USING (
EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id
  AND doc_members.user_id = current_user
  AND (doc_members.role = 'editor' OR doc_members.role = 'admin')));",
            support::footgun::MEMBERSHIP_SCHEMA
        ),
        &["docs", "doc_members"],
    );
    let (_, tuples) = translation(&sql);
    assert!(
        tuples.contains("AND (role = 'editor' OR role = 'admin')"),
        "the disjunction must stay inside its own parentheses:\n{tuples}"
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
        .expect("translation should plan")
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
    let sql =
        support::qualify_table_declarations(INHERITANCE_PARENT_SCHEMA, &["docs", "secret_docs"]);
    let db = db_of(&sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(tuples, "FROM ONLY \"public\".\"docs\"").is_empty(),
        "an inheritance parent's tuples must come from its own rows alone, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(tuples, "FROM \"public\".\"docs\"").is_empty(),
        "a plain FROM loads child rows into parent objects, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );

    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, children }
                if table.to_string() == "public.docs" && children.iter().map(ToString::to_string).collect::<Vec<_>>() == vec!["public.secret_docs".to_string()]
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
    let sql = support::qualify_table_declarations(
        r"
CREATE TABLE measurements(id INT PRIMARY KEY, owner_id TEXT) PARTITION BY RANGE (id);
ALTER TABLE measurements ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON measurements FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.measurements_q1 PARTITION OF measurements FOR VALUES FROM (1) TO (100);
",
        &["measurements"],
    );
    let db = db_of(&sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(tuples, "FROM \"public\".\"measurements\"").is_empty(),
        "a partitioned root's tuples come from every partition, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(tuples, "ONLY").is_empty(),
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

/// A child can be a parent in turn, and the rule is per table: every type whose table
/// has `INHERITS` children reads only its own rows, the middle of a chain included.
#[test]
fn an_inheritance_childs_own_type_reads_only_its_own_rows_too() {
    let sql = support::qualify_table_declarations(
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
        &["docs", "secret_docs", "deep_docs"],
    );
    let db = db_of(&sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    for (table, source) in [
        ("docs", "\"public\".\"docs\""),
        ("secret_docs", "\"public\".\"secret_docs\""),
    ] {
        assert!(
            !tuples_reading_from(tuples, &format!("FROM ONLY {source}")).is_empty(),
            "'{table}' has inheritance children, so its tuples read ONLY, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
        assert!(
            tuples_reading_from(tuples, &format!("FROM {source}")).is_empty(),
            "'{table}' must not also read its children, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
    }
    for (table, child) in [
        ("public.docs", "public.secret_docs"),
        ("public.secret_docs", "public.deep_docs"),
    ] {
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::InheritanceParentReadsOwnRowsOnly { table: t, children }
                    if t.to_string() == table && children.iter().map(ToString::to_string).collect::<Vec<_>>() == vec![child.to_string()]
            )),
            "'{table}' must disclose dropping '{child}', got: {:#?}",
            outputs.notes()
        );
    }
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
    .expect("translation should plan")
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
