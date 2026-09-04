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
    let mismatches = support::parity::run_with(&case, |answers| {
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
        .iter()
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
            .iter()
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
        kept.is_empty() && given.is_empty(),
        "neither shape may disagree"
    );
}
