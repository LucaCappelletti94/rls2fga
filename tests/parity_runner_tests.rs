//! The generic parity runner, and what it has to catch.
//!
//! A case here declares a schema, a seed and its callers. Which relations answer which
//! statement, and how a row is named, come from the translation, so nothing in a case
//! repeats that analysis. The runner compares every principal against every object for
//! every statement, in both directions.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use std::sync::Arc;

use rls2fga::types::{ActionAnswer, ActionStatement};

mod support;

use support::parity::{assert_agrees, Cluster, Mutations, ParityCase, Principal};

/// Every case, one at a time against one container pair.
///
/// One test rather than twenty-two: the pair has to outlive every case, and a container
/// that is removed when it drops cannot be parked in a static without leaking it after the
/// process exits. Each case still runs in its own task, so a panic fails that case, names
/// it, and leaves the rest to run.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_parity_case_agrees() {
    let cluster = Arc::new(Cluster::start().await);
    let mut failures = Vec::new();
    let total = CASES.len();

    if let Err(joined) =
        tokio::spawn(the_runner_agrees_on_direct_ownership(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "the_runner_agrees_on_direct_ownership: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(the_runner_agrees_on_membership(Arc::clone(&cluster))).await {
        failures.push(format!(
            "the_runner_agrees_on_membership: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(the_runner_agrees_on_a_role_scoped_restriction(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "the_runner_agrees_on_a_role_scoped_restriction: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(both_one_sided_cases_pass(Arc::clone(&cluster))).await {
        failures.push(format!(
            "both_one_sided_cases_pass: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(the_runner_finds_a_planted_divergence(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "the_runner_finds_a_planted_divergence: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_update_candidate_exercises_with_check(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_update_candidate_exercises_with_check: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_nested_protected_read_denies_on_both_sides(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_nested_protected_read_denies_on_both_sides: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_split_function_owner_does_not_bypass_row_level_security(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_split_function_owner_does_not_bypass_row_level_security: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(a_strict_function_hides_the_null_row(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_strict_function_hides_the_null_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_reserved_name_collision_keeps_two_types(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_reserved_name_collision_keeps_two_types: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_reserved_parent_is_referenced_by_its_defined_name(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_reserved_parent_is_referenced_by_its_defined_name: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_qualified_call_is_not_the_declared_accessor(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_qualified_call_is_not_the_declared_accessor: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_function_local_search_path_picks_the_membership_table(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_function_local_search_path_picks_the_membership_table: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_unplaceable_membership_table_grants_nothing(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_unplaceable_membership_table_grants_nothing: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_restrictive_flag_narrows_a_blanket_read(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_restrictive_flag_narrows_a_blanket_read: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_blanket_delete_does_not_widen_the_read(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_blanket_delete_does_not_widen_the_read: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_shadowed_clock_is_not_the_request_clock(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_shadowed_clock_is_not_the_request_clock: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_update_policy_without_using_updates_nothing(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_update_policy_without_using_updates_nothing: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_locking_read_applies_the_update_policy(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_locking_read_applies_the_update_policy: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(an_altered_policy_is_read_as_altered(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "an_altered_policy_is_read_as_altered: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(folded_identifiers_name_one_table(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "folded_identifiers_name_one_table: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(two_owner_columns_grant_independently(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "two_owner_columns_grant_independently: {}",
            panic_message(joined)
        ));
    }

    if let Err(joined) = tokio::spawn(an_uncorrelated_membership_admits_every_row(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_uncorrelated_membership_admits_every_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_parent_key_subquery_inherits_the_parents_rule(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_parent_key_subquery_inherits_the_parents_rule: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_correlated_column_membership_compares_the_named_columns(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_correlated_column_membership_compares_the_named_columns: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_read_and_a_write_are_judged_separately(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_read_and_a_write_are_judged_separately: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(an_aliased_quoted_guard_falls_closed(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "an_aliased_quoted_guard_falls_closed: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(mutually_recursive_policies_return_no_row(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "mutually_recursive_policies_return_no_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(a_partition_is_named_after_its_root(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_partition_is_named_after_its_root: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_composite_foreign_key_membership_joins_on_both_columns(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_composite_foreign_key_membership_joins_on_both_columns: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_joined_inner_rule_drops_the_unjoined_row(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_joined_inner_rule_drops_the_unjoined_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_quoted_role_is_a_different_role(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_quoted_role_is_a_different_role: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_declared_session_set_grants_beside_the_owner(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_declared_session_set_grants_beside_the_owner: {}",
            panic_message(joined)
        ));
    }
    assert!(
        failures.is_empty(),
        "{} of {total} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The case names, so the count a failure reports is the count that ran.
const CASES: [&str; 33] = [
    "the_runner_agrees_on_direct_ownership",
    "the_runner_agrees_on_membership",
    "the_runner_agrees_on_a_role_scoped_restriction",
    "both_one_sided_cases_pass",
    "the_runner_finds_a_planted_divergence",
    "an_update_candidate_exercises_with_check",
    "a_nested_protected_read_denies_on_both_sides",
    "a_split_function_owner_does_not_bypass_row_level_security",
    "a_strict_function_hides_the_null_row",
    "a_reserved_name_collision_keeps_two_types",
    "a_reserved_parent_is_referenced_by_its_defined_name",
    "a_qualified_call_is_not_the_declared_accessor",
    "a_function_local_search_path_picks_the_membership_table",
    "an_unplaceable_membership_table_grants_nothing",
    "a_restrictive_flag_narrows_a_blanket_read",
    "a_blanket_delete_does_not_widen_the_read",
    "a_shadowed_clock_is_not_the_request_clock",
    "an_update_policy_without_using_updates_nothing",
    "a_locking_read_applies_the_update_policy",
    "an_altered_policy_is_read_as_altered",
    "folded_identifiers_name_one_table",
    "two_owner_columns_grant_independently",
    "an_uncorrelated_membership_admits_every_row",
    "a_parent_key_subquery_inherits_the_parents_rule",
    "a_correlated_column_membership_compares_the_named_columns",
    "a_read_and_a_write_are_judged_separately",
    "an_aliased_quoted_guard_falls_closed",
    "mutually_recursive_policies_return_no_row",
    "a_partition_is_named_after_its_root",
    "a_composite_foreign_key_membership_joins_on_both_columns",
    "a_joined_inner_rule_drops_the_unjoined_row",
    "a_quoted_role_is_a_different_role",
    "a_declared_session_set_grants_beside_the_owner",
];

/// The message a panicking case left, so a failure reads like a test failure.
fn panic_message(joined: tokio::task::JoinError) -> String {
    if !joined.is_panic() {
        return joined.to_string();
    }
    let payload = joined.into_panic();
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
        })
        .unwrap_or_else(|| "panicked with no message".to_string())
}

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

async fn the_runner_agrees_on_direct_ownership(cluster: Arc<Cluster>) {
    let case = ownership_case();
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

async fn the_runner_agrees_on_membership(cluster: Arc<Cluster>) {
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
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

/// A RESTRICTIVE policy scoped to a role, which the model expresses by subtracting the
/// role from the grant. The caller's role memberships are declared, since no tuple query
/// can know them.
async fn the_runner_agrees_on_a_role_scoped_restriction(cluster: Arc<Cluster>) {
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
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

/// Agreement is agreement, whichever way it goes.
///
/// The runner carries no one-sidedness rejection. A hand-written case counted grants and
/// denials because it checked the pairs its author chose; this one checks every pair, so a
/// model that answered everything the same way would be caught by the comparison itself.
async fn both_one_sided_cases_pass(cluster: Arc<Cluster>) {
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
    assert_agrees(
        &all_granted,
        &support::parity::run(&cluster, &all_granted).await,
    );

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
    assert_agrees(
        &all_denied,
        &support::parity::run(&cluster, &all_denied).await,
    );
}

/// A harness that has never caught anything is not yet a harness.
///
/// The statement answers are doctored on their way in, so `can_select` grants with nothing
/// asked. Every row the database hides from a caller then has to be reported.
async fn the_runner_finds_a_planted_divergence(cluster: Arc<Cluster>) {
    let case = ownership_case();
    let mismatches =
        support::parity::run_with(&cluster, &case, support::parity::Class::Exact, |answers| {
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
async fn an_update_candidate_exercises_with_check(cluster: Arc<Cluster>) {
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
                // `owner_id = owner_id` leaves the value the policy reads unchanged, so
                // the resulting row decides as the existing one does.
                update_set: Some("owner_id = owner_id".to_string()),
                insert: None,
                check_neutral: true,
            },
        );
    let kept = support::parity::run(&cluster, &keeps_owner).await;
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
                check_neutral: false,
            },
        );
    let given = support::parity::run(&cluster, &gives_away).await;
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
async fn a_nested_protected_read_denies_on_both_sides(cluster: Arc<Cluster>) {
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
    let run = support::parity::run_disclosing(&cluster, &case).await;
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
async fn a_split_function_owner_does_not_bypass_row_level_security(cluster: Arc<Cluster>) {
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
    let run = support::parity::run_disclosing(&cluster, &case).await;
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
async fn a_strict_function_hides_the_null_row(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_reserved_name_collision_keeps_two_types(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_reserved_parent_is_referenced_by_its_defined_name(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_qualified_call_is_not_the_declared_accessor(cluster: Arc<Cluster>) {
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
    let run = support::parity::run_disclosing(&cluster, &case).await;
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
async fn a_function_local_search_path_picks_the_membership_table(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn an_unplaceable_membership_table_grants_nothing(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_restrictive_flag_narrows_a_blanket_read(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_blanket_delete_does_not_widen_the_read(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_shadowed_clock_is_not_the_request_clock(cluster: Arc<Cluster>) {
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
    let run = support::parity::run_disclosing(&cluster, &case).await;
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
async fn an_update_policy_without_using_updates_nothing(cluster: Arc<Cluster>) {
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
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
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
async fn a_locking_read_applies_the_update_policy(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-locking-read",
        "locking_read",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
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
async fn an_altered_policy_is_read_as_altered(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-policy-altered",
        "policy_altered",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
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
async fn folded_identifiers_name_one_table(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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
async fn two_owner_columns_grant_independently(cluster: Arc<Cluster>) {
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
    let run = support::parity::run(&cluster, &case).await;
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

/// The accessor these inline schemas declare.
const ACCESSOR: &str =
    r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;

/// Ported from `uncorrelated_membership_parity_postgres18_and_openfga`.
///
/// A membership check naming no column of the guarded table admits every row, and two
/// membership rows for one member are one fact, not two.
#[allow(clippy::too_many_lines)]
async fn an_uncorrelated_membership_admits_every_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-uncorrelated-membership",
        "
CREATE TABLE staff (id TEXT PRIMARY KEY, user_id TEXT NOT NULL);
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_staff ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));
",
        &[
            // Two rows for one member, so a holder written per membership row rather than
            // per member shows up as a duplicate.
            "INSERT INTO staff(id, user_id) VALUES ('s-1', 'alice'), ('s-2', 'alice');
             INSERT INTO docs(id) VALUES ('d-1'), ('d-2'), ('d-3')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs, staff TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for row in ["d-1", "d-2", "d-3"] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("docs:{row}"),
            ActionStatement::Select,
            true,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "bob",
            &format!("docs:{row}"),
            ActionStatement::Select,
            false,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `parent_key_in_subquery_parity_postgres18_and_openfga`.
///
/// `parent_id IN (SELECT id FROM parent_docs WHERE ...)` is the parent's own rule reached
/// through the key, so the child inherits it.
async fn a_parent_key_subquery_inherits_the_parents_rule(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-parent-key-in-subquery",
        "
CREATE TABLE parent_docs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
CREATE TABLE doc_links (
    id TEXT PRIMARY KEY,
    parent_id TEXT NOT NULL REFERENCES parent_docs(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE parent_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_docs_owner ON parent_docs FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY doc_links_visible ON doc_links FOR SELECT
    USING (parent_id IN (SELECT id FROM parent_docs WHERE owner_id = auth_current_user_id()));
",
        &[
            "INSERT INTO parent_docs(id, owner_id) VALUES ('p-alice', 'alice'), ('p-bob', 'bob');
             INSERT INTO doc_links(id, parent_id)
                 VALUES ('l-alice', 'p-alice'), ('l-bob', 'p-bob')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON parent_docs, doc_links TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, own, other) in [("alice", "l-alice", "l-bob"), ("bob", "l-bob", "l-alice")] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("doc_links:{own}"),
            ActionStatement::Select,
            true,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("doc_links:{other}"),
            ActionStatement::Select,
            false,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `correlated_column_membership_parity_postgres18_and_openfga`.
///
/// The subquery projects `status` and the outer column is `sku`, so the comparison is not
/// the one a key-shaped read would make.
async fn a_correlated_column_membership_compares_the_named_columns(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-correlated-column-membership",
        "
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE line_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    sku TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (sku IN (SELECT status FROM orders WHERE customer_id = auth_current_user_id()));
",
        &[
            // Each caller owns one order status, and each line item carries the other
            // caller's status in its own `status` column.
            "INSERT INTO orders(id, customer_id, status) VALUES
                 ('o-alice', 'alice', 'WIDGET'), ('o-bob', 'bob', 'GADGET');
             INSERT INTO line_items(id, order_id, sku, status) VALUES
                 ('li-alice', 'o-alice', 'WIDGET', 'GADGET'),
                 ('li-bob', 'o-bob', 'GADGET', 'WIDGET')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON orders, line_items TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "line_items:li-alice",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "line_items:li-bob",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `blanket_update_parity_postgres18_and_openfga`.
///
/// The read and the write are judged by different columns, so a row readable to one
/// caller is writable to another.
async fn a_read_and_a_write_are_judged_separately(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-blanket-update",
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    reader_user_id TEXT NOT NULL REFERENCES users(id),
    writer_user_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (reader_user_id = auth_current_user_id());
CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_user_id = auth_current_user_id());
",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, reader_user_id, writer_user_id, body) VALUES
                 ('bu-both', 'alice', 'alice', 'original'),
                 ('bu-write-only', 'bob', 'alice', 'original'),
                 ('bu-read-only', 'alice', 'bob', 'original'),
                 ('bu-neither', 'bob', 'bob', 'original')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR)
    .writing(
        "notes",
        Mutations {
            // `body` is read by no policy, so the resulting row decides as the
            // existing one does.
            update_set: Some("body = 'changed'".to_string()),
            insert: None,
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    // A `WHERE` reads the row, so an `UPDATE` naming rows needs the read as well as the
    // write, which is why the row the caller may write but not read updates nothing. The
    // blanket form, which the original case asserted from its seed rather than measuring,
    // is not compared: see `COMPARED` in the runner for why it cannot be.
    for (row, readable, writable) in [
        ("bu-both", true, true),
        ("bu-write-only", false, false),
        ("bu-read-only", true, false),
        ("bu-neither", false, false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            readable,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Update,
            writable,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `aliased_quoted_guard_parity_postgres18_and_openfga`.
///
/// The guard reads the outer table's own column through its quoted name, which is not a
/// membership condition, so the shape falls closed.
async fn an_aliased_quoted_guard_falls_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-aliased-quoted-guard",
        r#"
CREATE TABLE "M"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE members(doc_id TEXT REFERENCES "M"(id), owner_id TEXT);
ALTER TABLE "M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY m_owner ON "M" FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM members m
    WHERE m.doc_id = "M".id
      AND "M".owner_id = current_user
  )
);
"#,
        &[
            r#"INSERT INTO "M"(id, owner_id) VALUES ('d1', 'other_owner');
               INSERT INTO members(doc_id, owner_id) VALUES ('d1', 'app_reader')"#,
            r#"CREATE ROLE app_reader LOGIN; GRANT SELECT ON "M", members TO app_reader"#,
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "m:d1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// Ported from `read_recursion_parity_postgres18_and_openfga`.
///
/// Two policies each reading the other: `PostgreSQL` raises `42P17` on every read of
/// either, so no row is returned and the model must grant nothing.
async fn mutually_recursive_policies_return_no_row(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-read-recursion",
        "read_recursion",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO folders(id, owner_id) VALUES ('f-alice', 'alice'), ('f-bob', 'bob');
             INSERT INTO notes(id, owner_id, folder_id) VALUES
                 ('n-alice', 'alice', 'f-alice'), ('n-bob', 'bob', 'f-bob');
             UPDATE folders SET note_id = 'n-alice' WHERE id = 'f-alice';
             UPDATE folders SET note_id = 'n-bob' WHERE id = 'f-bob'",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON users, notes, folders TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    // Every read raises, so the database returns nothing to anybody.
    for subject in ["alice", "bob"] {
        for object in ["notes:n-alice", "folders:f-alice"] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                false,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `partitioned_table_parity_postgres18_and_openfga`.
///
/// A partition has no type of its own: its rows are named as objects of the root, so a
/// read through either the root or a partition asks the same question.
async fn a_partition_is_named_after_its_root(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-partitioned-table",
        "
CREATE TABLE events (id TEXT, tenant TEXT NOT NULL, region TEXT NOT NULL, PRIMARY KEY (id, region))
    PARTITION BY LIST (region);
CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
CREATE TABLE events_us PARTITION OF events FOR VALUES IN ('us');
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_visible ON events FOR SELECT USING (tenant = auth_current_user_id());
",
        &[
            "INSERT INTO events(id, tenant, region) VALUES
                 ('e-eu', 'alice', 'eu'), ('e-us', 'bob', 'us')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON events, events_eu, events_us TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR)
    // Reading a partition directly is unfiltered, since a parent's policies apply only to
    // rows reached through the parent. The runner found that, and the translation now
    // discloses it through `PartitionReadDirectlyIsUnfiltered`, pinned offline by
    // `a_partition_of_a_protected_root_discloses_its_direct_read`.
    .not_reading_directly(&["events_eu", "events_us"]);
    let run = support::parity::run(&cluster, &case).await;
    // The key is composite, so the object carries both parts.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "events:e-eu|eu",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "events:e-eu|eu",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `composite_fk_membership_parity_postgres18_and_openfga`.
///
/// The membership row is joined on two columns, so the bridge has to carry both or it
/// admits a row of another tenant.
async fn a_composite_foreign_key_membership_joins_on_both_columns(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-composite-fk-membership",
        "
CREATE TABLE projects (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE docs (
    doc_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE TABLE project_members (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, user_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_visible ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM project_members m
        WHERE m.tenant_id = docs.tenant_id
          AND m.project_id = docs.project_id
          AND m.user_id = auth_current_user_id()));
",
        &[
            // One project id in two tenants, so a bridge on the project alone would admit
            // the other tenant's document.
            "INSERT INTO projects(tenant_id, id) VALUES ('t1', 'p1'), ('t2', 'p1');
             INSERT INTO docs(doc_id, tenant_id, project_id) VALUES
                 ('d-t1', 't1', 'p1'), ('d-t2', 't2', 'p1');
             INSERT INTO project_members(tenant_id, project_id, user_id) VALUES
                 ('t1', 'p1', 'alice')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON projects, docs, project_members TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d-t1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d-t2",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `joined_inner_rule_parity_postgres18_and_openfga`.
///
/// The inner rule joins two tables, and the join drops an order with no customer, so a
/// bridge built from the key alone would admit it.
async fn a_joined_inner_rule_drops_the_unjoined_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-joined-inner-rule",
        "
CREATE TABLE customers (id TEXT PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
CREATE TABLE line_items (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id
                        WHERE c.id = auth_current_user_id()));
",
        &[
            "INSERT INTO customers(id, org_id) VALUES ('alice', 'acme'), ('bob', 'acme');
             INSERT INTO orders(id, customer_id) VALUES
                 ('o-alice', 'alice'), ('o-bob', 'bob'), ('o-none', NULL);
             INSERT INTO line_items(id, order_id) VALUES
                 ('li-alice', 'o-alice'), ('li-bob', 'o-bob'), ('li-none', 'o-none')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON customers, orders, line_items TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [("li-alice", true), ("li-bob", false), ("li-none", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("line_items:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `quoted_role_identity_parity_postgres18_and_openfga`.
///
/// `admin` and `"Admin"` are different roles, so a policy scoped to one admits nothing
/// through the other, and two policies of one name on two tables stay apart.
async fn a_quoted_role_is_a_different_role(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-quoted-role-identity",
        r#"
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE memos (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO admin USING (TRUE);
CREATE POLICY p ON memos FOR SELECT TO "Admin" USING (TRUE);
"#,
        &[
            "INSERT INTO docs (id) VALUES ('d1'); INSERT INTO memos (id) VALUES ('m1')",
            "CREATE ROLE alice LOGIN;
             GRANT SELECT ON docs, memos TO alice;
             GRANT admin TO alice",
        ],
        vec![Principal::as_role("alice", "alice").holding(&["admin"])],
    )
    .after(&[r#"CREATE ROLE admin; CREATE ROLE "Admin""#]);
    let run = support::parity::run(&cluster, &case).await;
    // The policy on `memos` names the quoted role, which alice does not hold.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "memos:m1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `session_attribute_parity_postgres18_and_openfga`.
///
/// One policy unioning the caller's own id with the set of keys it holds. A caller holding
/// no key leaves the setting unset, so the second arm is NULL rather than true.
async fn a_declared_session_set_grants_beside_the_owner(cluster: Arc<Cluster>) {
    /// The caller's held keys, as the condition's list parameter and as the setting.
    fn holder(subject: &str, keys: &[&str]) -> Principal {
        let mut principal = Principal::with_setting(subject, "app_writer", "app.user_id", subject)
            .with_context(serde_json::json!({ "app_subjects": keys }));
        principal
            .session
            .push(("app.subjects".to_string(), keys.join(",")));
        principal
    }

    let case = ParityCase::from_fixture(
        "runner-session-attribute",
        "connetto_or_policy",
        &[
            "INSERT INTO notes (id, owner) VALUES
                 (1, 'alice'), (2, 'team-a'), (3, 'bob'), (4, NULL)",
            "CREATE ROLE app_writer LOGIN; GRANT SELECT ON notes TO app_writer",
        ],
        vec![
            // The owner arm alone, the set arm alone, and both together.
            holder("alice", &[]),
            holder("bob", &["team-a"]),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // Row 1 reads through the owner arm, row 2 through the set arm, row 4 through neither.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:2",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_postgres(&case, &run, "bob", "notes:2", ActionStatement::Select, true);
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "notes:4",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}
