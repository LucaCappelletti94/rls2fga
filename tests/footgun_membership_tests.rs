//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Membership through a join table, and the holder a row-independent grant gets.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{ConfidenceLevel, ExistsMembership, PatternClass};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::notes::TranslationNote;
use rls2fga::generator::records::{RecordDerivation, ValueSource};
use rls2fga::generator::relations::RelationShapes;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

mod support;

use support::footgun::{
    db_of, membership_translation, pg_role_relation, relation_definition, relation_denies,
    scope_admits_role, translation, translator, tuples_reading_from, type_names,
    CORRELATION_SCHEMA,
};

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
            PatternClass::P4ExistsMembership(ExistsMembership { join_table, fk_column, user_column, .. })
                if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
        ),
        "= ANY (subquery) should match IN (subquery) membership, got: {:?}",
        using.pattern
    );
}

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
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

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

    // projects rows link to orgs by org_id only. Keying that link on projects.id
    // would grant a project the permissions of the org with the same identifier.
    for query in translator
        .translate(&db)
        .expect("translation should plan")
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
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

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
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

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
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries()
        )
        .contains(r#"FROM "doc_owner""#),
        "membership rows must be collected from doc_owner"
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
        .expect("translation should plan")
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
    assert_ne!(
        read, "no_access",
        "the membership rule must survive:\n{dsl}"
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
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
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries();
    assert!(
        scope_admits_role(&tuples, "docs:", &scope, "auditor"),
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
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        pg_role_relation(&model.model(), "docs"),
        None,
        "an unscoped read policy leaves the membership grant open to every role:\n{}",
        model.model()
    );
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

/// A clock on the only holder source must remove the plain member subject.
#[test]
fn a_clocked_holder_does_not_admit_an_unconditioned_member_tuple() {
    let schema = "CREATE TABLE reviewers(user_id TEXT, vetted_at TIMESTAMPTZ);\n\
                  CREATE TABLE memos(id UUID PRIMARY KEY);\n\
                  ALTER TABLE memos ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY memos_reviewers ON memos FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM reviewers WHERE reviewers.user_id = current_user \
                    AND reviewers.vetted_at > now()));\n";
    let (dsl, tuples) = translation(schema);

    let member = relation_definition(&dsl, "reviewers_holder", "member")
        .unwrap_or_else(|| panic!("reviewers_holder must define member:\n{dsl}"));
    assert!(
        member.starts_with("[user with when_") && member.ends_with(']'),
        "the holder should admit only the conditioned user:\n{dsl}"
    );
    assert!(
        !member.contains("[user,") && !member.contains(", user]"),
        "an unconditioned tuple would bypass the clock:\n{dsl}"
    );
    assert!(
        tuples.contains(" AS condition, jsonb_build_object('vetted_at', MAX(\"vetted_at\"))"),
        "the tuple loader still carries the clock context:\n{tuples}"
    );
}

/// A shared member relation keeps the plain subject when a plain source feeds it too.
#[test]
fn a_mixed_clocked_and_plain_member_relation_keeps_both_subjects() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
                  CREATE TABLE plain_members(doc_id UUID REFERENCES docs(id), user_id TEXT);\n\
                  CREATE TABLE expiring_members(\n\
                    doc_id UUID REFERENCES docs(id), user_id TEXT, vetted_at TIMESTAMPTZ);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_plain ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM plain_members p \
                    WHERE p.doc_id = docs.id AND p.user_id = current_user));\n\
                  CREATE POLICY docs_clocked ON docs FOR DELETE USING (\n\
                    EXISTS (SELECT 1 FROM expiring_members e \
                    WHERE e.doc_id = docs.id AND e.user_id = current_user \
                    AND e.vetted_at > now()));\n";
    let (dsl, _) = translation(schema);

    let member = relation_definition(&dsl, "docs", "member")
        .unwrap_or_else(|| panic!("docs must define member:\n{dsl}"));
    assert!(
        member.contains("[user, user with when_"),
        "the plain source still needs unconditioned member tuples:\n{dsl}"
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
    .expect("translation should plan")
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

/// A caller-set share becomes one object per share row, keyed on the join table's own
/// primary key, so two viewers of one row do not collide on one object. A join table with
/// no primary key cannot name its rows apart, so the arm refuses and falls closed rather
/// than emit a load `OpenFGA` rejects as a duplicate.
#[test]
fn a_caller_set_membership_over_a_keyless_share_table_falls_closed() {
    let sql = "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
CREATE POLICY papers_p ON papers FOR SELECT USING (
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
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let model = outputs.model();

    assert!(
        model.contains("define can_select: no_access"),
        "the share arm is the only grant on papers, so a refusal falls closed:\n{model}"
    );
    assert!(
        !model.contains("paper_shares_share"),
        "no per-share type is minted when the share rows cannot be named apart:\n{model}"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "papers_p" && reason.contains("no primary key")
        )),
        "the reason the grant vanished is named: {:?}",
        outputs.notes()
    );
}

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
                ValueSource::Column(name) => Some(name.to_string()),
                _ => None,
            },
            _ => None,
        })
}

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
        .expect("translation should plan")
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
        .expect("translation should plan")
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
