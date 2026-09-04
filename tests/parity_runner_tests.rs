//! The generic parity runner, and what it has to catch.
//!
//! A case here declares a schema, a seed and its callers. Which relations answer which
//! statement, and how a row is named, come from the translation, so nothing in a case
//! repeats that analysis. The runner compares every principal against every object for
//! every statement, in both directions.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use rls2fga::types::{ActionAnswer, ActionStatement};

mod support;

use support::parity::{assert_agrees, Mutations, ParityCase, Principal};

const OWNERSHIP: &str = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_delete ON docs FOR DELETE
    USING (owner_id = current_setting('app.user_id', true));
";

const MEMBERSHIP: &str = "
CREATE TABLE projects(id TEXT PRIMARY KEY, name TEXT);
CREATE TABLE project_members(project_id TEXT REFERENCES projects(id), user_id TEXT);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_select ON projects FOR SELECT USING (EXISTS (
    SELECT 1 FROM project_members m
    WHERE m.project_id = projects.id
      AND m.user_id = current_setting('app.user_id', true)));
";

/// Two readers, one of whom owns nothing.
fn ownership_case() -> ParityCase {
    ParityCase::reading(
        "runner-ownership",
        OWNERSHIP,
        &[
            "INSERT INTO docs(id, owner_id, title) VALUES ('d1', 'alice', 'first'),
                                                          ('d2', 'bob', 'second')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT, UPDATE, DELETE ON docs TO alice, bob",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ],
    )
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn the_runner_agrees_on_direct_ownership() {
    let case = ownership_case();
    let mismatches = support::parity::run(&case).await;
    assert_agrees(&case, &mismatches);
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn the_runner_agrees_on_membership() {
    let case = ParityCase::reading(
        "runner-membership",
        MEMBERSHIP,
        &[
            "INSERT INTO projects(id, name) VALUES ('p1', 'one'), ('p2', 'two')",
            "INSERT INTO project_members(project_id, user_id) VALUES ('p1', 'alice')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON projects, project_members TO alice, bob",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ],
    );
    let mismatches = support::parity::run(&case).await;
    assert_agrees(&case, &mismatches);
}

/// A RESTRICTIVE policy scoped to a role, which the model expresses by subtracting the
/// role from the grant. The caller's role memberships are declared, since no tuple query
/// can know them.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn the_runner_agrees_on_a_role_scoped_restriction() {
    let case = ParityCase::reading(
        "runner-role-scoped",
        "
CREATE TABLE notes(id TEXT PRIMARY KEY, owner_id TEXT, reviewed BOOLEAN);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_select ON notes FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY notes_reviewed ON notes AS RESTRICTIVE FOR SELECT TO contractor
    USING (reviewed = TRUE);
",
        &[
            "INSERT INTO notes(id, owner_id, reviewed) VALUES
                ('n1', 'alice', TRUE), ('n2', 'alice', FALSE),
                ('n3', 'carol', TRUE), ('n4', 'carol', FALSE)",
            "CREATE ROLE alice LOGIN; CREATE ROLE carol LOGIN;
             GRANT SELECT ON notes TO alice, carol;
             GRANT contractor TO carol",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("carol", "carol", "app.user_id", "carol")
                .holding(&["contractor"]),
        ],
    )
    .after(&["CREATE ROLE contractor"]);
    let mismatches = support::parity::run(&case).await;
    assert_agrees(&case, &mismatches);
}

/// Agreement is agreement, whichever way it goes.
///
/// The runner carries no one-sidedness rejection. A hand-written case counted grants and
/// denials because it checked the pairs its author chose; this one checks every pair, so a
/// model that answered everything the same way would be caught by the comparison itself.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn both_one_sided_cases_pass() {
    let all_granted = ParityCase::reading(
        "runner-all-granted",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (true);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    assert_agrees(&all_granted, &support::parity::run(&all_granted).await);

    let all_denied = ParityCase::reading(
        "runner-all-denied",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (false);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    assert_agrees(&all_denied, &support::parity::run(&all_denied).await);
}

/// A harness that has never caught anything is not yet a harness.
///
/// The statement answers are doctored on their way in, so `can_select` grants with nothing
/// asked. Every row the database hides from a caller then has to be reported.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn the_runner_finds_a_planted_divergence() {
    let case = ownership_case();
    let mismatches = support::parity::run_with(&case, support::parity::Class::Exact, |answers| {
        answers
            .into_iter()
            .map(|mut entry| {
                if entry.statement == ActionStatement::Select {
                    entry.answer = ActionAnswer::Judged(Vec::new());
                }
                entry
            })
            .collect()
    })
    .await;

    let over_grants = mismatches
        .mismatches()
        .into_iter()
        .filter(|mismatch| {
            mismatch.statement == ActionStatement::Select && mismatch.openfga && !mismatch.postgres
        })
        .count();
    assert_eq!(
        over_grants, 2,
        "each reader is hidden from one row, so both are over-grants: {mismatches:#?}"
    );
    assert!(
        mismatches
            .mismatches()
            .into_iter()
            .all(|mismatch| mismatch.statement == ActionStatement::Select),
        "only the doctored statement diverges: {mismatches:#?}"
    );
}

/// A no-op `UPDATE` exercises `USING` and never `WITH CHECK`, so the new row is named.
///
/// The policy admits the caller's own rows and its `WITH CHECK` refuses handing a row to
/// somebody else, which only a declared change can reach.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn an_update_candidate_exercises_with_check() {
    let schema = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_update ON docs FOR UPDATE
    USING (owner_id = current_setting('app.user_id', true))
    WITH CHECK (owner_id = current_setting('app.user_id', true));
";
    let seed = [
        "INSERT INTO docs(id, owner_id) VALUES ('d1', 'alice'), ('d2', 'bob')",
        "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
         GRANT SELECT, UPDATE ON docs TO alice, bob",
    ];
    let principals = || {
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ]
    };

    // Keeping the owner passes both clauses, so every own row updates.
    let keeps_owner = ParityCase::reading("runner-update-keeps", schema, &seed, principals())
        .writing(
            "docs",
            Mutations {
                update_set: Some("owner_id = owner_id".to_string()),
                insert: None,
            },
        );
    let kept = support::parity::run(&keeps_owner).await;
    assert_agrees(&keeps_owner, &kept);

    // Handing the row away passes `USING` and fails `WITH CHECK`, so PostgreSQL refuses
    // and no row is updated. The model judges the row the write would produce, which the
    // stored tuples say nothing about, so the runner declines to compare rather than
    // comparing against the row that still exists. Naming that limit here is what stops a
    // later reader believing this direction is covered.
    let gives_away = ParityCase::reading("runner-update-gives", schema, &seed, principals())
        .writing(
            "docs",
            Mutations {
                update_set: Some("owner_id = 'somebody_else'".to_string()),
                insert: None,
            },
        );
    let given = support::parity::run(&gives_away).await;
    assert_agrees(&gives_away, &given);
    assert!(
        kept.mismatches().is_empty() && given.mismatches().is_empty(),
        "neither shape may disagree"
    );
}

/// Ported from `quoted_nested_membership_parity_postgres18_and_openfga`.
///
/// A membership subquery whose own nested read is on a protected table: the model cannot
/// prove the nested read, so the shape falls closed, and `PostgreSQL` denies too because
/// the reader sees no row of `"Memberships"`.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_nested_protected_read_denies_on_both_sides() {
    let case = ParityCase::reading(
        "runner-quoted-nested-membership",
        r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE memberships(doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE TABLE "Memberships"(doc_id TEXT REFERENCES docs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Memberships" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM memberships m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND EXISTS (
        SELECT 1 FROM "Memberships"
      )
  )
);
"#,
        &[
            r#"INSERT INTO docs(id) VALUES ('d1');
               INSERT INTO memberships(doc_id, user_id) VALUES ('d1', 'app_reader');
               INSERT INTO "Memberships"(doc_id) VALUES ('d1')"#,
            r#"CREATE ROLE app_reader LOGIN;
               GRANT SELECT ON docs, memberships, "Memberships" TO app_reader"#,
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run_disclosing(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// Ported from `quoted_definer_owner_parity_postgres18_and_openfga`.
///
/// `actor` and `"Actor"` are different roles, so the function's owner is not the table's
/// and the definer read does not bypass row-level security.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_split_function_owner_does_not_bypass_row_level_security() {
    let case = ParityCase::reading(
        "runner-quoted-definer-owner",
        r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members OWNER TO actor;
GRANT SELECT ON doc_members TO "Actor";
CREATE FUNCTION is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_temp AS
'SELECT EXISTS (
    SELECT 1 FROM doc_members m
    WHERE m.doc_id = d
      AND m.user_id = current_setting(''app.current_user_id'', true)
)';
ALTER FUNCTION is_member(TEXT) OWNER TO "Actor";
CREATE POLICY docs_members ON docs FOR SELECT USING (is_member(id));
"#,
        &[
            "INSERT INTO docs(id) VALUES ('d1');
             INSERT INTO doc_members(id, doc_id, user_id) VALUES ('dm1', 'd1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        vec![Principal::with_setting(
            "app_reader",
            "app_reader",
            "app.current_user_id",
            "app_reader",
        )],
    )
    .after(&[r#"CREATE ROLE actor; CREATE ROLE "Actor""#]);
    let run = support::parity::run_disclosing(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// Ported from `strict_function_null_parity_postgres18_and_openfga`.
///
/// A `STRICT` function returns NULL for a NULL argument, so the row with no gate value
/// is hidden however the body reads.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_strict_function_hides_the_null_row() {
    let case = ParityCase::reading(
        "runner-strict-function-null",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY, gate TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT true';
CREATE POLICY docs_select ON docs FOR SELECT USING (strict_true(gate));
",
        &[
            "INSERT INTO docs(id, gate) VALUES ('d-null', NULL), ('d-value', 'present')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&case).await;
    for (row, visible) in [("d-null", false), ("d-value", true)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `reserved_type_name_parity_postgres18_and_openfga`.
///
/// Two tables whose canonical names differ and whose reserved-word rename collides. A
/// shared type would name a row of each as one object, which the runner sees because it
/// asks both readers about both tables.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_reserved_name_collision_keeps_two_types() {
    let case = ParityCase::reading(
        "runner-reserved-type-name",
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE t_self(id TEXT PRIMARY KEY, editor_id TEXT);
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_self ENABLE ROW LEVEL SECURITY;
CREATE POLICY a ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY b ON t_self FOR SELECT USING (editor_id = current_user);
"#,
        &[
            r#"INSERT INTO "self"(id, owner_id) VALUES ('shared', 'alice');
               INSERT INTO t_self(id, editor_id) VALUES ('shared', 'bob')"#,
            r#"CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
               GRANT SELECT ON "self", t_self TO alice, bob"#,
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    let run = support::parity::run(&case).await;
    assert_agrees(&case, &run);
    // One key value in two tables, so a shared type shows up as a grant the database
    // denies. Four pairs, one granted each way.
    assert_eq!(
        run.observations
            .iter()
            .filter(
                |observation| observation.statement == ActionStatement::Select
                    && observation.postgres
            )
            .count(),
        2,
        "each reader owns exactly one of the two rows: {run:#?}"
    );
}

/// Ported from `reserved_parent_type_parity_postgres18_and_openfga`.
///
/// A parent whose name `OpenFGA` reserves, reached through a child's membership policy.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_reserved_parent_is_referenced_by_its_defined_name() {
    let case = ParityCase::reading(
        "runner-reserved-parent-type",
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE child_docs(id TEXT PRIMARY KEY, parent_id TEXT REFERENCES "self"(id));
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE child_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_owner ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY inherit ON child_docs FOR SELECT USING (EXISTS (
    SELECT 1 FROM "self" p WHERE p.id = child_docs.parent_id AND p.owner_id = current_user));
"#,
        &[
            r#"INSERT INTO "self"(id, owner_id) VALUES ('p1', 'alice');
               INSERT INTO child_docs(id, parent_id) VALUES ('c1', 'p1')"#,
            r#"CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
               GRANT SELECT ON "self", child_docs TO alice, bob"#,
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    let run = support::parity::run(&case).await;
    for (subject, visible) in [("alice", true), ("bob", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            "child_docs:c1",
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// A caller identified by the ordinary session setting.
fn app_reader() -> Vec<Principal> {
    vec![Principal::with_setting(
        "app_reader",
        "app_reader",
        "app.current_user_id",
        "app_reader",
    )]
}

/// Ported from `qualified_registry_identity_parity_postgres18_and_openfga`.
///
/// `other.uid()` is not the accessor the registry names, so the policy is not an
/// ownership check and the shape falls closed.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_qualified_call_is_not_the_declared_accessor() {
    let case = ParityCase::reading(
        "runner-qualified-registry-identity",
        r"
CREATE SCHEMA auth;
CREATE SCHEMA other;
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION auth.uid() RETURNS TEXT LANGUAGE sql AS
    'SELECT current_setting(''app.current_user_id'', true)';
CREATE FUNCTION other.uid() RETURNS TEXT LANGUAGE sql AS
    'SELECT ''nobody''';
CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = other.uid());
",
        &[
            "INSERT INTO docs(id, owner_id) VALUES ('d1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        app_reader(),
    )
    .with_registry(r#"{"auth.uid": {"kind": "current_user_accessor", "returns": "text"}}"#);
    let run = support::parity::run_disclosing(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// Ported from `function_local_search_path_parity_postgres18_and_openfga`.
///
/// The function sets its own `search_path`, so the membership table it reads is the one
/// that path names, not the caller's.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_function_local_search_path_picks_the_membership_table() {
    let case = ParityCase::reading(
        "runner-function-local-search-path",
        r"
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE a.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
CREATE TABLE b.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO b, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_select ON docs FOR SELECT USING (public.is_member(id));
SET search_path TO a, public;
",
        &[
            "INSERT INTO public.docs(id) VALUES ('d1');
             INSERT INTO b.doc_members(id, doc_id, user_id) VALUES ('m1', 'd1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN;
             GRANT USAGE ON SCHEMA b TO app_reader;
             GRANT SELECT ON docs, b.doc_members TO app_reader",
        ],
        app_reader(),
    );
    let run = support::parity::run(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        true,
    );
    assert_agrees(&case, &run);
}

/// Ported from `resolved_membership_table_parity_postgres18_and_openfga`.
///
/// Two schemas hold a table of the same name and the policy names it unqualified, which
/// the catalog cannot place, so nothing is granted on a guess.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn an_unplaceable_membership_table_grants_nothing() {
    let case = ParityCase::reading(
        "runner-resolved-membership-table",
        r"
CREATE SCHEMA app;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
CREATE TABLE app.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE TABLE public.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE ROLE app_reader LOGIN;
GRANT USAGE ON SCHEMA app TO app_reader;
GRANT SELECT ON public.docs, app.memberships, public.memberships TO app_reader;
SET search_path TO app, public;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m
        WHERE m.doc_id = docs.id
          AND m.user_id = current_setting('app.current_user_id', true)));
INSERT INTO public.docs VALUES ('d1');
INSERT INTO app.memberships VALUES ('d1', 'other_user');
INSERT INTO public.memberships VALUES ('d1', 'app_reader');
",
        &[],
        app_reader(),
    );
    let run = support::parity::run(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `restrictive_flag_pair_parity_postgres18_and_openfga`.
///
/// A blanket permissive read beside a RESTRICTIVE flag: only the flagged row is visible,
/// which the model can only express with a relation per predicate.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_restrictive_flag_narrows_a_blanket_read() {
    let case = ParityCase::reading(
        "runner-restrictive-flag-pair",
        r"
CREATE TABLE union_docs(id TEXT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE union_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON union_docs FOR SELECT USING (true);
CREATE POLICY r ON union_docs AS RESTRICTIVE FOR SELECT USING (is_public);
",
        &[
            "INSERT INTO union_docs(id, is_public) VALUES ('p1', TRUE), ('h1', FALSE)",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON union_docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&case).await;
    for (row, visible) in [("p1", true), ("h1", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("union_docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `cross_command_wildcard_parity_postgres18_and_openfga`.
///
/// A blanket DELETE beside a flag-gated SELECT: the wildcard the DELETE needs must not
/// widen the read.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_blanket_delete_does_not_widen_the_read() {
    let case = ParityCase::reading(
        "runner-cross-command-wildcard",
        r"
CREATE TABLE union_docs(id TEXT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE union_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY s ON union_docs FOR SELECT USING (is_public);
CREATE POLICY d ON union_docs FOR DELETE USING (true);
",
        &[
            "INSERT INTO union_docs(id, is_public) VALUES ('p1', TRUE), ('h1', FALSE)",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT, DELETE ON union_docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&case).await;
    for (row, visible) in [("p1", true), ("h1", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("union_docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `qualified_clock_shadow_parity_postgres18_and_openfga`.
///
/// `app.now()` is a declared function, not the builtin clock, so a temporal condition
/// against the request clock would answer a different question.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_shadowed_clock_is_not_the_request_clock() {
    let case = ParityCase::reading(
        "runner-qualified-clock-shadow",
        "
CREATE SCHEMA app;
CREATE FUNCTION app.now() RETURNS TIMESTAMPTZ LANGUAGE sql IMMUTABLE
    AS $$SELECT 'infinity'::timestamptz$$;
CREATE TABLE docs (id INT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (expires_at > app.now());
",
        &[
            "INSERT INTO docs (id, expires_at) VALUES (1, now() + interval '1 year')",
            "CREATE ROLE alice LOGIN;
             GRANT USAGE ON SCHEMA app TO alice;
             GRANT SELECT ON docs TO alice",
        ],
        vec![Principal::as_role("alice", "alice").with_clock()],
    );
    let run = support::parity::run_disclosing(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// Two readers of one fixture, told apart by the setting alone.
fn two_setting_readers(first: &str, second: &str) -> Vec<Principal> {
    vec![
        Principal::with_setting(first, "app_user", "app.current_user_id", first),
        Principal::with_setting(second, "app_user", "app.current_user_id", second),
    ]
}

/// Rows two owners hold, and the role that may read them.
const OWNED_NOTES_SEED: &str = "INSERT INTO users(id) VALUES ('alice'), ('bob');
     INSERT INTO notes(id, owner_id) VALUES ('note-alice', 'alice'), ('note-bob', 'bob')";

/// Ported from `absent_clause_parity_postgres18_and_openfga`.
///
/// An `UPDATE` policy storing only `WITH CHECK` says nothing about the existing row, so
/// no row is updatable however the check reads.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn an_update_policy_without_using_updates_nothing() {
    let case = ParityCase::from_fixture(
        "runner-clause-absent",
        "clause_absent",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .writing(
        "notes",
        Mutations {
            update_set: Some("owner_id = owner_id".to_string()),
            insert: None,
        },
    );
    let run = support::parity::run(&case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-alice",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-alice",
        ActionStatement::Update,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `locking_read_parity_postgres18_and_openfga`.
///
/// A locking read is filtered by the `UPDATE` policies' `USING` clause on top of the
/// `SELECT` policies, so it returns fewer rows than a plain read.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_locking_read_applies_the_update_policy() {
    let case = ParityCase::from_fixture(
        "runner-locking-read",
        "locking_read",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&case).await;
    // Every row reads, only the caller's own row locks.
    for (row, plain, locking) in [("note-alice", true, true), ("note-bob", true, false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            plain,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::SelectForUpdate,
            locking,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `altered_policy_parity_postgres18_and_openfga`.
///
/// `ALTER POLICY` supersedes the clause the policy was created with, so the rule enforced
/// is the narrowed one and never the original.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn an_altered_policy_is_read_as_altered() {
    let case = ParityCase::from_fixture(
        "runner-policy-altered",
        "policy_altered",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&case).await;
    // The original clause admitted everything; the altered one admits the owner alone.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-bob",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `folded_identifier_parity_postgres18_and_openfga`.
///
/// `PostgreSQL` folds an unquoted identifier, so the schema's spelling is not the stored
/// name, and every comparison has to use the stored one.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn folded_identifiers_name_one_table() {
    let case = ParityCase::from_fixture(
        "runner-folded-identifiers",
        "folded_identifiers",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id) VALUES ('own', 'alice'), ('shared', 'bob');
             INSERT INTO note_members(id, note_id, user_id) VALUES ('m1', 'shared', 'alice')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON notes, note_members TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&case).await;
    // Alice owns one row and is a member of the other, so both read for her.
    for row in ["own", "shared"] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            true,
        );
    }
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "notes:own",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `two_owner_columns_parity_postgres18_and_openfga`.
///
/// One table judged through two owner values with different thresholds, so a delegate
/// needs a higher role than an owner to read the same row.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn two_owner_columns_grant_independently() {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const RECORD: &str = "00000000-0000-0000-0000-00000000ee01";

    let case = ParityCase::from_fixture(
        "runner-two-owner-columns",
        "two_owner_columns",
        &[
            &format!(
                "INSERT INTO users(id) VALUES ('{ALICE}'), ('{BOB}'), ('{CAROL}');
                 INSERT INTO records(id, owner_id, delegate_id)
                     VALUES ('{RECORD}', '{ALICE}', '{BOB}');
                 INSERT INTO owner_grants(grantee_owner_id, granted_owner_id, role_id)
                     VALUES ('{CAROL}', '{BOB}', 2)"
            ),
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON records, users, owner_grants TO app_user",
        ],
        vec![
            Principal::with_setting(ALICE, "app_user", "app.current_user_id", ALICE),
            Principal::with_setting(BOB, "app_user", "app.current_user_id", BOB),
            Principal::with_setting(CAROL, "app_user", "app.current_user_id", CAROL),
        ],
    );
    let run = support::parity::run(&case).await;
    // The owner reads at 2, the delegate itself reads at 4, and a viewer of the delegate
    // holds only 2, which the delegate pointer does not admit.
    for (subject, visible) in [(ALICE, true), (BOB, true), (CAROL, false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("records:{RECORD}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}
