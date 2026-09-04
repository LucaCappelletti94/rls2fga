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
    if let Err(joined) = tokio::spawn(an_array_and_a_jsonb_field_name_the_caller(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_array_and_a_jsonb_field_name_the_caller: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_clock_guard_holds_on_a_zoned_and_a_dated_column(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_clock_guard_holds_on_a_zoned_and_a_dated_column: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(
        a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name(Arc::clone(&cluster)),
    )
    .await
    {
        failures.push(format!(
            "a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_composite_key_share_stays_within_its_tenant(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_composite_key_share_stays_within_its_tenant: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(a_caller_role_residual_falls_closed(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_caller_role_residual_falls_closed: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_computed_argument_is_not_captured_by_the_body(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_computed_argument_is_not_captured_by_the_body: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(a_failed_case_leaves_no_role_behind(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_failed_case_leaves_no_role_behind: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_role_scoped_membership_read_gates_the_parent(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_role_scoped_membership_read_gates_the_parent: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_noinherit_member_of_a_scoped_role_reads_nothing(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_noinherit_member_of_a_scoped_role_reads_nothing: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_shared_paper_reads_through_either_arm(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_shared_paper_reads_through_either_arm: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_token_claim_list_grants_by_membership(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_token_claim_list_grants_by_membership: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(one_shared_grant_ladder_answers_two_thresholds(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "one_shared_grant_ladder_answers_two_thresholds: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(three_refused_spellings_fall_closed(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "three_refused_spellings_fall_closed: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_missing_session_setting_is_not_a_denial(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_missing_session_setting_is_not_a_denial: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_request_time_guard_holds_at_two_instants(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_request_time_guard_holds_at_two_instants: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_grace_period_keeps_its_offset(Arc::clone(&cluster))).await {
        failures.push(format!(
            "a_grace_period_keeps_its_offset: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_expiring_share_leaves_the_owner_arm_alone(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_expiring_share_leaves_the_owner_arm_alone: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_expiring_share_keeps_its_grace_period(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_expiring_share_keeps_its_grace_period: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_expiring_membership_row_gates_its_own_document(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "an_expiring_membership_row_gates_its_own_document: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_expiring_holder_row_admits_the_caller_to_everything(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "an_expiring_holder_row_admits_the_caller_to_everything: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_definer_wrapper_answers_for_a_caller_without_the_grant(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_definer_wrapper_answers_for_a_caller_without_the_grant: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_restrictive_policy_binds_only_its_role(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_restrictive_policy_binds_only_its_role: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(one_policy_name_on_two_tables_keeps_two_comparisons(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "one_policy_name_on_two_tables_keeps_two_comparisons: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(two_viewers_of_one_paper_load_and_union(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "two_viewers_of_one_paper_load_and_union: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(two_expiring_viewers_of_one_paper_gate_independently(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "two_expiring_viewers_of_one_paper_gate_independently: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(two_deadlines_need_one_witnessing_row(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "two_deadlines_need_one_witnessing_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_clock_gated_record_replays_from_its_own_row(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "a_clock_gated_record_replays_from_its_own_row: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(a_share_record_replays_onto_another_types_object(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "a_share_record_replays_onto_another_types_object: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) =
        tokio::spawn(a_role_ladder_answers_four_thresholds(Arc::clone(&cluster))).await
    {
        failures.push(format!(
            "a_role_ladder_answers_four_thresholds: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_insert_that_reads_back_applies_the_select_policy(
        Arc::clone(&cluster),
    ))
    .await
    {
        failures.push(format!(
            "an_insert_that_reads_back_applies_the_select_policy: {}",
            panic_message(joined)
        ));
    }
    if let Err(joined) = tokio::spawn(an_upsert_applies_the_update_policy_too(Arc::clone(
        &cluster,
    )))
    .await
    {
        failures.push(format!(
            "an_upsert_applies_the_update_policy_too: {}",
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
const CASES: [&str; 64] = [
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
    "an_array_and_a_jsonb_field_name_the_caller",
    "a_clock_guard_holds_on_a_zoned_and_a_dated_column",
    "a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name",
    "a_composite_key_share_stays_within_its_tenant",
    "a_caller_role_residual_falls_closed",
    "a_computed_argument_is_not_captured_by_the_body",
    "a_failed_case_leaves_no_role_behind",
    "a_role_scoped_membership_read_gates_the_parent",
    "a_noinherit_member_of_a_scoped_role_reads_nothing",
    "a_shared_paper_reads_through_either_arm",
    "a_token_claim_list_grants_by_membership",
    "one_shared_grant_ladder_answers_two_thresholds",
    "three_refused_spellings_fall_closed",
    "a_missing_session_setting_is_not_a_denial",
    "a_request_time_guard_holds_at_two_instants",
    "a_grace_period_keeps_its_offset",
    "an_expiring_share_leaves_the_owner_arm_alone",
    "an_expiring_share_keeps_its_grace_period",
    "an_expiring_membership_row_gates_its_own_document",
    "an_expiring_holder_row_admits_the_caller_to_everything",
    "a_definer_wrapper_answers_for_a_caller_without_the_grant",
    "a_restrictive_policy_binds_only_its_role",
    "one_policy_name_on_two_tables_keeps_two_comparisons",
    "two_viewers_of_one_paper_load_and_union",
    "two_expiring_viewers_of_one_paper_gate_independently",
    "two_deadlines_need_one_witnessing_row",
    "a_clock_gated_record_replays_from_its_own_row",
    "a_share_record_replays_onto_another_types_object",
    "a_role_ladder_answers_four_thresholds",
    "an_insert_that_reads_back_applies_the_select_policy",
    "an_upsert_applies_the_update_policy_too",
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

/// Ported from `array_and_jsonb_membership_parity_postgres18_and_openfga`.
///
/// The caller as an element of an array column, and the caller named by a jsonb field.
/// An empty or NULL array admits nobody, and those rows stay readable only because the
/// jsonb arm still names the caller.
async fn an_array_and_a_jsonb_field_name_the_caller(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-array-jsonb-membership",
        "array_jsonb_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, editors, meta) VALUES
                 ('aj-editor-only', ARRAY['alice'], '{\"owner_id\":\"bob\"}'),
                 ('aj-meta-only', ARRAY['bob'], '{\"owner_id\":\"alice\"}'),
                 ('aj-both', ARRAY['alice'], '{\"owner_id\":\"alice\"}'),
                 ('aj-neither', ARRAY['bob'], '{\"owner_id\":\"bob\"}'),
                 ('aj-empty-array', ARRAY[]::TEXT[], '{\"owner_id\":\"alice\"}'),
                 ('aj-null-array', NULL, '{\"owner_id\":\"alice\"}'),
                 ('aj-null-element', ARRAY[NULL]::TEXT[], '{}'),
                 ('aj-missing-key', ARRAY['alice'], '{}')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [
        ("aj-editor-only", true),
        ("aj-meta-only", true),
        ("aj-both", true),
        ("aj-neither", false),
        // The array arm admits nobody here, the jsonb arm carries both rows.
        ("aj-empty-array", true),
        ("aj-null-array", true),
        ("aj-null-element", false),
        ("aj-missing-key", true),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `zoneless_temporal_guard_parity_postgres18_and_openfga`.
///
/// A guard against the clock on a zoned column and on a date, where the comparison
/// promotes the date to a timestamp in the session's zone.
async fn a_clock_guard_holds_on_a_zoned_and_a_dated_column(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-zoneless-temporal-guard",
        "
CREATE TABLE zoned_docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
CREATE TABLE dated_docs (id TEXT PRIMARY KEY, expires_on DATE);
ALTER TABLE zoned_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE dated_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zoned_unexpired ON zoned_docs FOR SELECT USING (expires_at > now());
CREATE POLICY dated_unexpired ON dated_docs FOR SELECT USING (expires_on > now());
",
        &[
            "INSERT INTO zoned_docs (id, expires_at) VALUES
                 ('z-live', TIMESTAMPTZ '2099-01-01 00:00:00+00'),
                 ('z-stale', TIMESTAMPTZ '2000-01-01 00:00:00+00');
             INSERT INTO dated_docs (id, expires_on) VALUES
                 ('d-live', DATE '2099-01-01'),
                 ('d-stale', DATE '2000-01-01')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON zoned_docs, dated_docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (object, visible) in [
        ("zoned_docs:z-live", true),
        ("zoned_docs:z-stale", false),
        ("dated_docs:d-live", true),
        ("dated_docs:d-stale", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    // The dated guard alone diverges: no tuple can carry a value the row does not decide,
    // so the live dated row is denied. The zoned guard has to keep its conditional tuples,
    // which losing them all would also satisfy under a bare no-over-grant check.
    support::parity::assert_only_disagreements(
        &case,
        &run,
        &[("app_user", "dated_docs:d-live", ActionStatement::Select)],
    );
}

/// Ported from `cross_row_residual_parity_postgres18_and_openfga`.
///
/// A share grants only when its weight beats the average across the whole share table,
/// which rows the granted row does not name decide.
async fn a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-cross-row-residual",
        "cross_row_residual",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'owner'), (2, 'owner'), (3, 'owner');
             INSERT INTO paper_shares (paper_id, viewer, weight) VALUES
                 (1, 'alice', 50), (2, 'bob', 30), (3, 'alice', 1)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            Principal::with_setting("alice", "app_reader", "app.user_id", "alice"),
            Principal::with_setting("bob", "app_reader", "app.user_id", "bob"),
            Principal::with_setting("carol", "app_reader", "app.user_id", "carol"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // The average of 50, 30 and 1 is 27, so only the first two shares beat it.
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:3", false),
        ("bob", "papers:2", true),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `composite_key_self_membership_parity_postgres18_and_openfga`.
///
/// The share is keyed on the tenant as well as the paper, so a bridge on the paper alone
/// would hand one tenant's reader the other tenant's paper of the same id.
async fn a_composite_key_share_stays_within_its_tenant(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-composite-key-self-membership",
        "
CREATE TABLE tenant_papers (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE tenant_shares (
    tenant_id TEXT NOT NULL,
    paper_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    PRIMARY KEY (tenant_id, paper_id, viewer)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE tenant_papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_visible ON tenant_papers FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM tenant_shares s
        WHERE s.tenant_id = tenant_papers.tenant_id
          AND s.paper_id = tenant_papers.id
          AND s.viewer = auth_current_user_id()));
",
        &[
            // One paper id in both tenants, plus one unshared paper.
            "INSERT INTO tenant_papers(tenant_id, id, title) VALUES
                 ('t1', 'p-shared', 'alpha'), ('t2', 'p-shared', 'beta'),
                 ('t1', 'p-solo', 'gamma');
             INSERT INTO tenant_shares(tenant_id, paper_id, viewer) VALUES
                 ('t1', 'p-shared', 'alice'), ('t2', 'p-shared', 'bob')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON tenant_papers, tenant_shares TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "tenant_papers:t1|p-shared", true),
        ("alice", "tenant_papers:t2|p-shared", false),
        ("bob", "tenant_papers:t2|p-shared", true),
        ("bob", "tenant_papers:t1|p-shared", false),
        ("alice", "tenant_papers:t1|p-solo", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `caller_role_residual_parity_postgres18_and_openfga`.
///
/// The residual asks whether the caller holds the role the membership row names. The
/// runner reads rows as the owning superuser, for whom `pg_has_role` is true of every
/// role, so a translation deciding that residual while loading would grant the row to a
/// caller the database denies it to.
async fn a_caller_role_residual_falls_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-caller-role-residual",
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(doc_id TEXT REFERENCES docs(id), user_id TEXT, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM doc_members m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND pg_has_role(m.tenant, 'USAGE')
  )
);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1');
             INSERT INTO doc_members(doc_id, user_id, tenant)
                 VALUES ('d1', 'app_reader', 'tenant_a')",
            // The caller is deliberately not granted `tenant_a`.
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs, doc_members TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    )
    .after(&["CREATE ROLE tenant_a"]);
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

/// Ported from `computed_argument_capture_parity_postgres18_and_openfga`.
///
/// A computed call argument is evaluated in the caller's scope, so a bare column inside it
/// must reach the body qualified or the body's own scan captures it.
async fn a_computed_argument_is_not_captured_by_the_body(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-computed-argument-capture",
        r"
CREATE TABLE leveled_docs(id TEXT PRIMARY KEY, level INT NOT NULL);
CREATE TABLE leveled_members(doc_id TEXT REFERENCES leveled_docs(id), user_id TEXT,
  level INT NOT NULL, min_level INT NOT NULL);
ALTER TABLE leveled_docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d TEXT, req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM leveled_members m WHERE m.doc_id = d AND m.user_id = current_user AND m.min_level <= req)';
CREATE POLICY p ON leveled_docs FOR SELECT USING (can_see(id, coalesce(level, 0)));
",
        &[
            // The poisoning row: the member's own `level` is high and `min_level` sits
            // between the two, so a captured reading admits what the row's level denies.
            "INSERT INTO leveled_docs(id, level) VALUES ('d1', 0);
             INSERT INTO leveled_members(doc_id, user_id, level, min_level)
                 VALUES ('d1', 'app_reader', 99, 50)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON leveled_docs, leveled_members TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    // `min_level` 50 against the row's level 0, so the database denies.
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "leveled_docs:d1",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_no_over_grant(&case, &run);
}

/// A case that fails must still drop its database and roles.
///
/// Roles are cluster-wide, so a case that kept its database left grants the next case's
/// reset could not drop, and one failure failed every later case. The planted case fails
/// on its last seed, after creating the role the successor reuses.
async fn a_failed_case_leaves_no_role_behind(cluster: Arc<Cluster>) {
    let planted = || {
        ParityCase::reading(
            "runner-planted-panic",
            "CREATE TABLE only_docs(id TEXT PRIMARY KEY);
             ALTER TABLE only_docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON only_docs FOR SELECT USING (id = current_user);",
            &[
                "CREATE ROLE reused_reader LOGIN; GRANT SELECT ON only_docs TO reused_reader",
                "INSERT INTO absent_table(id) VALUES ('x')",
            ],
            vec![Principal::as_role("reused_reader", "reused_reader")],
        )
    };
    let shared = Arc::clone(&cluster);
    let planted_case = planted();
    let failure = tokio::spawn(async move {
        support::parity::run(&shared, &planted_case).await;
    })
    .await;
    assert!(
        failure.is_err(),
        "the planted case has to fail, or it pins nothing"
    );

    // Same role name, so it can only be created if the failed case's cleanup ran.
    let successor = ParityCase::reading(
        "runner-planted-panic-successor",
        "CREATE TABLE only_docs(id TEXT PRIMARY KEY);
         ALTER TABLE only_docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON only_docs FOR SELECT USING (id = current_user);",
        &[
            "INSERT INTO only_docs(id) VALUES ('reused_reader'), ('someone_else')",
            "CREATE ROLE reused_reader LOGIN; GRANT SELECT ON only_docs TO reused_reader",
        ],
        vec![Principal::as_role("reused_reader", "reused_reader")],
    );
    let run = support::parity::run(&cluster, &successor).await;
    support::parity::assert_postgres(
        &successor,
        &run,
        "reused_reader",
        "only_docs:reused_reader",
        ActionStatement::Select,
        true,
    );
    assert_agrees(&successor, &run);
}

/// Ported from `role_scoped_membership_parity_postgres18_and_openfga`.
///
/// Only `auditor` may read the membership table, so a caller outside that role sees no
/// membership row and the parent policy grants nothing.
async fn a_role_scoped_membership_read_gates_the_parent(cluster: Arc<Cluster>) {
    let reader = |subject: &str, login: &str| {
        Principal::with_setting(subject, login, "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-role-scoped-membership",
        "role_scoped_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO docs(id) VALUES ('d1'), ('d2');
             INSERT INTO doc_members(id, doc_id, user_id)
                 VALUES ('dm-alice', 'd1', 'alice'), ('dm-bob', 'd1', 'bob')",
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON docs, doc_members TO app_alice;
             GRANT auditor TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON docs, doc_members TO app_bob",
        ],
        vec![
            reader("alice", "app_alice").holding(&["auditor"]),
            reader("bob", "app_bob"),
        ],
    )
    // The policy names the role, so it exists before the schema.
    .after(&["CREATE ROLE auditor"]);
    // The membership table's own row security is disclosed, and the answers still agree:
    // the tuple loader reads only the rows the auditor scope exposes.
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:d1", true),
        ("alice", "docs:d2", false),
        // Bob's membership row exists and he cannot see it, so the parent denies.
        ("bob", "docs:d1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    support::parity::assert_only_disagreements(&case, &run, &[]);
}

/// Ported from `noinherit_member_parity_postgres18_and_openfga`.
///
/// A policy `TO editors` admits the role's inheriting members only: `PostgreSQL` applies
/// the clause with `has_privs_of_role`, so a `NOINHERIT` member holds MEMBER and reads
/// nothing. Only the inheriting caller declares the holding.
async fn a_noinherit_member_of_a_scoped_role_reads_nothing(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-noinherit-member",
        "role_scope_inherit",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE app_alice LOGIN;
             GRANT editors TO app_alice;
             GRANT SELECT ON docs TO app_alice;
             CREATE ROLE app_bob LOGIN NOINHERIT;
             GRANT editors TO app_bob;
             GRANT SELECT ON docs TO app_bob",
        ],
        vec![
            Principal::as_role("alice", "app_alice").holding(&["editors"]),
            Principal::as_role("bob", "app_bob"),
        ],
    )
    .after(&["CREATE ROLE editors"]);
    let run = support::parity::run(&cluster, &case).await;
    // Two sided by construction: a model granting or denying everything cannot pass.
    for (subject, visible) in [("alice", true), ("bob", false)] {
        for object in ["docs:d1", "docs:d2"] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                visible,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_paper_parity_postgres18_and_openfga`.
///
/// One policy carrying two arms, ownership by the caller's identity and a share row whose
/// viewer is in the caller's held set, beside the share table's own set policy.
async fn a_shared_paper_reads_through_either_arm(cluster: Arc<Cluster>) {
    /// The caller's identity and held keys, as the setting and the condition parameter.
    fn holder(subject: &str, keys: &[&str]) -> Principal {
        let mut principal = Principal::with_setting(subject, "app_reader", "app.user_id", subject)
            .with_context(serde_json::json!({ "app_subjects": keys }));
        principal
            .session
            .push(("app.subjects".to_string(), keys.join(",")));
        principal
    }

    let case = ParityCase::from_fixture(
        "runner-shared-paper",
        "connetto_capability",
        &[
            // Paper 2 is shared with a key alice carries, paper 3 with one she does not.
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES (2, 'team-a'), (3, 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![holder("alice", &["team-a"]), holder("carol", &[])],
    );
    // The share table carries its own set policy, which is disclosed, and the answers
    // still agree because the loader reads the shares each caller may see.
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    support::parity::assert_only_disagreements(&case, &run, &[]);
}

/// Ported from `token_claim_set_parity_postgres18_and_openfga`.
///
/// The caller's set arrives as a real list inside the token rather than as a delimited
/// string. Two tables, one per spelling, because they are the same database and must land
/// the same way. The numeric claim against the row named `1` is what makes the rendering
/// rule load bearing: `jsonb_array_elements_text` yields a JSON number as its text, so a
/// model shipping the number unrendered answers differently.
async fn a_token_claim_list_grants_by_membership(cluster: Arc<Cluster>) {
    /// The caller's claim, as the token's jsonb and as the condition's list.
    ///
    /// The list is what `jsonb_array_elements_text` would produce, so a number renders as
    /// its text. An absent claim sends the empty list, and its read raises.
    fn bearer(subject: &str, teams: &[serde_json::Value]) -> Principal {
        let rendered: Vec<String> = teams
            .iter()
            .map(|team| match team {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .collect();
        let mut principal = Principal::as_role(subject, "app_reader")
            .with_context(serde_json::json!({ "request_jwt_claims_teams": rendered }));
        if subject == "unset" {
            return principal.reading_an_unset_setting();
        }
        principal.session.push((
            "request.jwt.claims".to_string(),
            serde_json::json!({ "teams": teams }).to_string(),
        ));
        principal
    }

    let case = ParityCase::from_fixture(
        "runner-token-claim-set",
        "token_claim_set",
        &[
            // Row 4 is named by the numeric claim, row 3 by nobody.
            "INSERT INTO documents (id, team_id) VALUES
                 (1, 'team-a'), (2, 'team-b'), (3, NULL), (4, '1');
             INSERT INTO reports (id, team_id) VALUES
                 (1, 'team-a'), (2, 'team-b'), (3, NULL), (4, '1')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON documents, reports TO app_reader",
        ],
        vec![
            // Every claim state the source covered: unset, empty, one team, two, numeric.
            bearer("unset", &[]),
            bearer("empty", &[]),
            bearer("team_a", &[serde_json::json!("team-a")]),
            bearer(
                "both",
                &[serde_json::json!("team-a"), serde_json::json!("team-b")],
            ),
            bearer("numeric", &[serde_json::json!(1)]),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // Both spellings have to land the same way, and a NULL team belongs to nobody.
    for table in ["documents", "reports"] {
        for (subject, row, visible) in [
            // An unset setting raises, which is the caller holding no token reading nothing.
            ("unset", 1, false),
            ("empty", 1, false),
            ("team_a", 1, true),
            ("team_a", 2, false),
            ("team_a", 3, false),
            ("team_a", 4, false),
            ("both", 1, true),
            ("both", 2, true),
            // The number renders as text, so it names the row spelled '1'.
            ("numeric", 4, true),
            ("numeric", 1, false),
        ] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                &format!("{table}:{row}"),
                ActionStatement::Select,
                visible,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_owner_grants_parity_postgres18_and_openfga`.
///
/// Two guarded tables read one role-threshold function at different levels, so a caller
/// between the thresholds reads a sample and not a spectrum. That caller is the point: a
/// model collapsing the two tables onto one ladder level fails here.
async fn one_shared_grant_ladder_answers_two_thresholds(cluster: Arc<Cluster>) {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const DAVE: &str = "00000000-0000-0000-0000-0000000000a4";
    const EVE: &str = "00000000-0000-0000-0000-0000000000a5";
    const ALPHA: &str = "00000000-0000-0000-0000-0000000000b1";
    const BETA: &str = "00000000-0000-0000-0000-0000000000b2";

    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_reader", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-shared-owner-grants",
        "shared_owner_grants",
        &[
            &format!(
                "INSERT INTO users (id) VALUES
                     ('{ALICE}'), ('{BOB}'), ('{CAROL}'), ('{DAVE}'), ('{EVE}');
                 INSERT INTO teams (id) VALUES ('{ALPHA}'), ('{BETA}');
                 INSERT INTO team_members (team_id, user_id) VALUES
                     ('{ALPHA}', '{BOB}'), ('{BETA}', '{CAROL}'), ('{BETA}', '{DAVE}');
                 INSERT INTO samples (id, owner_id) VALUES
                     ('{ALICE}', '{ALICE}'), ('{ALPHA}', '{ALPHA}');
                 INSERT INTO spectra (id, owner_id) VALUES
                     ('{ALICE}', '{ALICE}'), ('{ALPHA}', '{ALPHA}');
                 INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
                     ('{CAROL}', '{ALICE}', 3), ('{BETA}', '{ALICE}', 2), ('{EVE}', '{ALPHA}', 4)"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON users, teams, team_members, owner_grants, samples, spectra
                 TO app_reader",
        ],
        vec![
            reader(ALICE),
            reader(BOB),
            reader(CAROL),
            reader(DAVE),
            reader(EVE),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        // Alice owns hers outright, so both thresholds pass.
        (ALICE, format!("samples:{ALICE}"), true),
        (ALICE, format!("spectra:{ALICE}"), true),
        // Dave reaches Alice's owner at level 2 through team beta: the sample only.
        (DAVE, format!("samples:{ALICE}"), true),
        (DAVE, format!("spectra:{ALICE}"), false),
        // Carol's own grant is level 3, so both.
        (CAROL, format!("samples:{ALICE}"), true),
        (CAROL, format!("spectra:{ALICE}"), true),
        // Bob holds nothing over Alice's owner.
        (BOB, format!("samples:{ALICE}"), false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `refused_spellings_fall_closed_parity_postgres18_and_openfga`.
///
/// Three spellings the classifier must refuse rather than widen: a CASE whose FALSE arm
/// vetoes, an EXISTS carrying a comparison between two columns of the guarded table, and
/// a NULLIF hiding a row from its own principal. Every one denies in the database.
async fn three_refused_spellings_fall_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-refused-spellings",
        r"
CREATE TABLE case_docs(id TEXT PRIMARY KEY, archived BOOLEAN NOT NULL, is_public BOOLEAN NOT NULL);
CREATE TABLE filter_docs(id TEXT PRIMARY KEY, owner_id TEXT, reviewer_id TEXT);
CREATE TABLE filter_members(doc_id TEXT REFERENCES filter_docs(id), user_id TEXT);
CREATE TABLE sentinel_docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE case_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE filter_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sentinel_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY case_p ON case_docs FOR SELECT USING (
  CASE WHEN archived THEN FALSE WHEN is_public THEN TRUE ELSE FALSE END
);
CREATE POLICY filter_p ON filter_docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM filter_members m
    WHERE m.doc_id = filter_docs.id
      AND m.user_id = current_user
      AND filter_docs.owner_id = filter_docs.reviewer_id
  )
);
CREATE POLICY sentinel_p ON sentinel_docs FOR SELECT USING (
  NULLIF(owner_id, 'system') = current_user
);
",
        &[
            "INSERT INTO case_docs(id, archived, is_public) VALUES ('c1', TRUE, TRUE);
             INSERT INTO filter_docs(id, owner_id, reviewer_id)
                 VALUES ('f1', 'someone', 'someone_else');
             INSERT INTO filter_members(doc_id, user_id) VALUES ('f1', 'app_reader');
             INSERT INTO sentinel_docs(id, owner_id) VALUES ('s1', 'system')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON case_docs, filter_docs, filter_members TO app_reader;
             CREATE ROLE system LOGIN;
             GRANT SELECT ON sentinel_docs TO system",
        ],
        vec![
            Principal::as_role("app_reader", "app_reader"),
            Principal::as_role("system", "system"),
        ],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object) in [
        // The CASE veto denies the archived public row.
        ("app_reader", "case_docs:c1"),
        // Owner and reviewer differ, so the filter denies.
        ("app_reader", "filter_docs:f1"),
        // NULLIF hides the sentinel row from its own principal.
        ("system", "sentinel_docs:s1"),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            false,
        );
    }
    // All three refusals have to be reported, not just the one that makes the case
    // disclosed: a policy falling closed silently is the defect.
    support::parity::assert_discloses(&case, &run, &["case_docs", "filter_docs", "sentinel_docs"]);
    support::parity::assert_no_over_grant(&case, &run);
}

/// A caller missing a setting its policies read fails the case, unless it says so.
///
/// The runner reads a raise as a denial only where the caller declares it, because
/// everywhere else the raise is the case granting no privilege or naming no column. The
/// token fixture is the shape that raises: `current_setting` without `missing_ok`.
async fn a_missing_session_setting_is_not_a_denial(cluster: Arc<Cluster>) {
    let seed = [
        "INSERT INTO documents (id, team_id) VALUES (1, 'team-a');
         INSERT INTO reports (id, team_id) VALUES (1, 'team-a')",
        "CREATE ROLE app_reader LOGIN; GRANT SELECT ON documents, reports TO app_reader",
    ];
    let empty = || serde_json::json!({ "request_jwt_claims_teams": [] });
    // The same caller twice: once silently misconfigured, once declaring the raise.
    let planted = ParityCase::from_fixture(
        "runner-missing-setting",
        "token_claim_set",
        &seed,
        vec![Principal::as_role("nobody", "app_reader").with_context(empty())],
    );
    let shared = Arc::clone(&cluster);
    let failure = tokio::spawn(async move {
        support::parity::run(&shared, &planted).await;
    })
    .await;
    assert!(
        failure.is_err(),
        "a caller whose read raises without declaring it has to fail the case"
    );

    // Declared, yet the setting is there: the claim is stale and has to fail too.
    let stale_principal = {
        let mut principal = Principal::as_role("nobody", "app_reader")
            .with_context(empty())
            .reading_an_unset_setting();
        principal.session.push((
            "request.jwt.claims".to_string(),
            serde_json::json!({ "teams": [] }).to_string(),
        ));
        principal
    };
    let stale = ParityCase::from_fixture(
        "runner-stale-unset-claim",
        "token_claim_set",
        &seed,
        vec![stale_principal],
    );
    let shared = Arc::clone(&cluster);
    let stale_failure = tokio::spawn(async move {
        support::parity::run(&shared, &stale).await;
    })
    .await;
    assert!(
        stale_failure.is_err(),
        "a caller declaring a raise whose read succeeds has to fail the case"
    );

    let declared = ParityCase::from_fixture(
        "runner-missing-setting-declared",
        "token_claim_set",
        &seed,
        vec![Principal::as_role("nobody", "app_reader")
            .with_context(empty())
            .reading_an_unset_setting()],
    );
    let run = support::parity::run(&cluster, &declared).await;
    support::parity::assert_postgres(
        &declared,
        &run,
        "nobody",
        "documents:1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&declared, &run);
}

/// The request-scoped values the share cases declare.
const CALLER_AND_SUBJECTS: &str = r#"[
      { "key": "app.user_id", "kind": "caller_id" },
      { "key": "app.subjects", "kind": "set_attribute" }
    ]"#;

/// A caller identified by `app.user_id` and holding `keys` as `app.subjects`.
fn key_holder(subject: &str, keys: &[&str]) -> Principal {
    let mut principal = Principal::with_setting(subject, "app_reader", "app.user_id", subject)
        .with_context(serde_json::json!({ "app_subjects": keys }))
        .with_clock();
    principal
        .session
        .push(("app.subjects".to_string(), keys.join(",")));
    principal
}

/// Ported from `request_time_condition_parity_postgres18_and_openfga`.
///
/// A guard against `now()` cannot become tuples, since a tuple computed once keeps
/// granting after the value passed. It becomes a condition, and the second instant is what
/// proves the service evaluates it rather than the loader having baked the clock in.
async fn a_request_time_guard_holds_at_two_instants(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-request-time-condition",
        r#"
CREATE TABLE docs (id TEXT PRIMARY KEY, foo TEXT, "Foo" TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING ("Foo" > now());
"#,
        &[
            // The quoted column carries the boundary, the unquoted one is a decoy.
            "INSERT INTO docs (id, foo, \"Foo\") VALUES
                 ('d-live', 'text', '2099-01-01T00:00:00+00:00'),
                 ('d-stale', 'text', '2000-01-01T00:00:00+00:00'),
                 ('d-soon', 'text', '2027-01-01T00:00:00+00:00'),
                 ('d-null', 'text', NULL)",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .also_at(
        "1 year",
        "SELECT 'app_user'::text AS subject, 'docs:' || id AS object
         FROM docs WHERE \"Foo\" > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("docs:d-live", true),
        ("docs:d-stale", false),
        ("docs:d-soon", true),
        // A NULL boundary compares as unknown, so the row admits nobody.
        ("docs:d-null", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `interval_grace_condition_parity_postgres18_and_openfga`.
///
/// A grace period spelled `now() - interval '30 days'` must survive with its offset
/// intact, so a row that expired inside the window still reads and one past it does not.
async fn a_grace_period_keeps_its_offset(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-interval-grace-condition",
        "
CREATE TABLE docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_grace ON docs FOR SELECT USING (expires_at > now() - interval '30 days');
",
        &[
            // Relative to the run clock: valid, expired inside the grace, past it, none.
            "INSERT INTO docs (id, expires_at) VALUES
                 ('g-fresh', now() + interval '5 days'),
                 ('g-grace', now() - interval '10 days'),
                 ('g-stale', now() - interval '40 days'),
                 ('g-null', NULL)",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    // Twenty five days on, not a year: the fresh row expired twenty days ago and the
    // thirty day window still admits it, while the graced row has fallen out of it. Both
    // answers depend on the offset, so a future instant a year away would prove less.
    .also_at(
        "25 days",
        "SELECT 'app_user'::text AS subject, 'docs:' || id AS object
         FROM docs WHERE expires_at > $1::timestamptz - interval '30 days'",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("docs:g-fresh", true),
        // Expired ten days ago, which the thirty-day window still admits.
        ("docs:g-grace", true),
        ("docs:g-stale", false),
        ("docs:g-null", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `expiring_share_condition_parity_postgres18_and_openfga`.
///
/// The share arm carries a deadline, so the share expires while the ownership arm does
/// not. A year on the owner still reads and the shared paper is gone.
async fn an_expiring_share_leaves_the_owner_arm_alone(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-share-condition",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (2, 'team-a', now() + interval '1 day'),
                 (3, 'team-z', now() - interval '1 day')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![key_holder("alice", &["team-a"]), key_holder("carol", &[])],
    )
    .with_attributes(CALLER_AND_SUBJECTS)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('alice', 'team-a'), ('carol', '')) AS c(subject, keys)
         WHERE p.owner = c.subject
            OR EXISTS (
                SELECT 1 FROM paper_shares s
                WHERE s.paper_id = p.id
                  AND s.viewer = ANY(string_to_array(c.keys, ','))
                  AND s.expires_at > $1::timestamptz)",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `interval_grace_membership_condition_parity_postgres18_and_openfga`.
///
/// The same shape with a grace period on the share's deadline, so a share that expired ten
/// days ago still grants and one forty days ago does not.
async fn an_expiring_share_keeps_its_grace_period(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-interval-grace-membership",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now() - interval '30 days'
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (2, 'team-a', now() - interval '10 days'),
                 (3, 'team-z', now() - interval '40 days')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![key_holder("alice", &["team-a"]), key_holder("carol", &[])],
    )
    .with_attributes(CALLER_AND_SUBJECTS)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('alice', 'team-a'), ('carol', '')) AS c(subject, keys)
         WHERE p.owner = c.subject
            OR EXISTS (
                SELECT 1 FROM paper_shares s
                WHERE s.paper_id = p.id
                  AND s.viewer = ANY(string_to_array(c.keys, ','))
                  AND s.expires_at > $1::timestamptz - interval '30 days')",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        // Ten days expired, inside the window.
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `expiring_exists_membership_condition_parity_postgres18_and_openfga`.
///
/// The deadline sits on the membership row an EXISTS names, so each share gates its own
/// row rather than the caller as a whole.
async fn an_expiring_membership_row_gates_its_own_document(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-exists-membership",
        "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE doc_shares (
    doc_id INT,
    user_id TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (doc_id, user_id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM doc_shares s
        WHERE s.doc_id = docs.id AND s.user_id = current_user AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO docs (id) VALUES (1), (2), (3);
             INSERT INTO doc_shares (doc_id, user_id, expires_at) VALUES
                 (1, 'alice', now() + interval '1 day'),
                 (2, 'bob', now() - interval '1 day'),
                 (3, 'alice', now() + interval '1 day')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs, doc_shares TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice").with_clock(),
            Principal::as_role("bob", "bob").with_clock(),
        ],
    )
    .also_at(
        "1 year",
        "SELECT s.user_id AS subject, 'docs:' || d.id AS object
         FROM docs d JOIN doc_shares s ON s.doc_id = d.id
         WHERE s.expires_at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:1", true),
        ("alice", "docs:2", false),
        ("alice", "docs:3", true),
        // Bob's only share expired yesterday.
        ("bob", "docs:2", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `expiring_holder_membership_condition_parity_postgres18_and_openfga`.
///
/// The membership row names no document, so one live row admits the caller to every memo.
/// Alice holds an expired row beside a live one, which a model reading the wrong row of
/// the two would answer for.
async fn an_expiring_holder_row_admits_the_caller_to_everything(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-holder-membership",
        "
CREATE TABLE memos (id INT PRIMARY KEY);
CREATE TABLE reviewers (user_id TEXT, vetted_at TIMESTAMPTZ);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY memos_p ON memos FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM reviewers
        WHERE reviewers.user_id = current_user AND reviewers.vetted_at > now()
    )
);
",
        &[
            "INSERT INTO memos (id) VALUES (1), (2);
             INSERT INTO reviewers (user_id, vetted_at) VALUES
                 ('alice', now() - interval '1 day'),
                 ('alice', now() + interval '1 day'),
                 ('bob', now() - interval '1 day')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON memos, reviewers TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice").with_clock(),
            Principal::as_role("bob", "bob").with_clock(),
        ],
    )
    .also_at(
        "1 year",
        "SELECT r.user_id AS subject, 'memos:' || m.id AS object
         FROM memos m CROSS JOIN reviewers r
         WHERE r.vetted_at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "memos:1", true),
        ("alice", "memos:2", true),
        // Bob's one row is expired, so he reads nothing.
        ("bob", "memos:1", false),
        ("bob", "memos:2", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// The set attribute the viewer cases declare.
const SUBJECTS_ONLY: &str = r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#;

/// A caller identified only by the keys it holds as `app.subjects`.
fn subject_holder(subject: &str, keys: &[&str]) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader")
        .with_context(serde_json::json!({ "app_subjects": keys }));
    principal
        .session
        .push(("app.subjects".to_string(), keys.join(",")));
    principal
}

/// Ported from `definer_membership_parity_postgres18_and_openfga`.
///
/// A `SECURITY DEFINER` wrapper around the membership EXISTS, called by the guarded table
/// and by the membership table's own policy, so the self-reference `PostgreSQL` would
/// refuse to plan runs as the owner. The third caller holds no grant on the membership
/// table at all and the definer still answers for its docs.
async fn a_definer_wrapper_answers_for_a_caller_without_the_grant(cluster: Arc<Cluster>) {
    let reader = |subject: &str, login: &str| {
        Principal::with_setting(subject, login, "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-definer-membership",
        "definer_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob'), ('carol');
             INSERT INTO docs(id) VALUES ('d1'), ('d2');
             INSERT INTO doc_members(id, doc_id, user_id) VALUES
                 ('dm-alice', 'd1', 'alice'),
                 ('dm-bob', 'd1', 'bob'),
                 ('dm-carol', 'd2', 'carol')",
            // Carol is deliberately given nothing on the membership table.
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON docs, doc_members TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON docs, doc_members TO app_bob;
             CREATE ROLE app_carol LOGIN;
             GRANT SELECT ON docs TO app_carol",
        ],
        vec![
            reader("alice", "app_alice"),
            reader("bob", "app_bob"),
            reader("carol", "app_carol"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:d1", true),
        ("alice", "docs:d2", false),
        ("bob", "docs:d1", true),
        ("carol", "docs:d2", true),
        ("carol", "docs:d1", false),
        // The membership policy calls the same wrapper, so a member of d1 sees both rows.
        ("alice", "doc_members:dm-bob", true),
        ("alice", "doc_members:dm-carol", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `role_scoped_restrictive_parity_postgres18_and_openfga`.
///
/// A RESTRICTIVE policy scoped to `contractor` binds only that role, so an owner outside
/// it keeps the read the permissive policy grants.
async fn a_restrictive_policy_binds_only_its_role(cluster: Arc<Cluster>) {
    let reader = |subject: &str, login: &str| {
        Principal::with_setting(subject, login, "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-role-scoped-restrictive",
        "role_scoped_restrictive",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, reviewer_id) VALUES
                 ('note-reviewed', 'alice', 'alice'),
                 ('note-unreviewed', 'alice', 'bob'),
                 ('note-outside-the-role', 'bob', 'alice')",
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON users, notes TO app_alice;
             GRANT contractor TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON users, notes TO app_bob",
        ],
        vec![
            reader("alice", "app_alice").holding(&["contractor"]),
            reader("bob", "app_bob"),
        ],
    )
    .after(&["CREATE ROLE contractor"]);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "notes:note-reviewed", true),
        // Alice owns it and is a contractor, but is not its reviewer.
        ("alice", "notes:note-unreviewed", false),
        ("alice", "notes:note-outside-the-role", false),
        // Bob owns it and the barrier does not reach him.
        ("bob", "notes:note-outside-the-role", true),
        ("bob", "notes:note-reviewed", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_policy_name_condition_parity_postgres18_and_openfga`.
///
/// One policy name on two tables, comparing against the clock in opposite directions. A
/// condition named after the policy would collide, and one table would answer with the
/// other's comparison.
async fn one_policy_name_on_two_tables_keeps_two_comparisons(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-shared-policy-name",
        "
CREATE TABLE campaigns (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
CREATE TABLE embargoes (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE embargoes ENABLE ROW LEVEL SECURITY;
CREATE POLICY visible_now ON campaigns FOR SELECT TO PUBLIC USING (at <= now());
CREATE POLICY visible_now ON embargoes FOR SELECT TO PUBLIC USING (at > now());
",
        &[
            "INSERT INTO campaigns (id, at) VALUES
                 ('c-running', now() - interval '1 day'),
                 ('c-upcoming', now() + interval '1 day');
             INSERT INTO embargoes (id, at) VALUES
                 ('e-held', now() + interval '1 day'),
                 ('e-lifted', now() - interval '1 day')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON campaigns, embargoes TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .also_at(
        "1 year",
        "SELECT 'app_user'::text AS subject, 'campaigns:' || id AS object
         FROM campaigns WHERE at <= $1::timestamptz
         UNION ALL
         SELECT 'app_user'::text AS subject, 'embargoes:' || id AS object
         FROM embargoes WHERE at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    // The two comparisons are mirror images, so a collision shows as a swapped answer.
    for (object, visible) in [
        ("campaigns:c-running", true),
        ("campaigns:c-upcoming", false),
        ("embargoes:e-held", true),
        ("embargoes:e-lifted", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `two_viewers_of_one_paper_load_and_union_parity_postgres18_and_openfga`.
///
/// A paper shared to two viewers must load and union rather than collide. Keying every
/// share tuple on the paper put both viewers on one triple, which `OpenFGA` refuses as a
/// duplicate write, so the load itself is half the assertion.
async fn two_viewers_of_one_paper_load_and_union(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-two-viewers-of-one-paper",
        "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES
                 (1, 'viewer_x'), (1, 'viewer_y'), (2, 'viewer_z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            subject_holder("viewer_x", &["viewer_x"]),
            subject_holder("viewer_y", &["viewer_y"]),
            subject_holder("viewer_z", &["viewer_z"]),
        ],
    )
    .with_attributes(SUBJECTS_ONLY);
    // The share table's own row security is disclosed, and the answers still agree: its
    // policy exposes every share, so the loader reads what each caller would.
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object, visible) in [
        ("viewer_x", "papers:1", true),
        ("viewer_y", "papers:1", true),
        ("viewer_x", "papers:2", false),
        ("viewer_z", "papers:2", true),
        ("viewer_z", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    support::parity::assert_only_disagreements(&case, &run, &[]);
}

/// Ported from
/// `two_expiring_viewers_of_one_paper_gate_independently_parity_postgres18_and_openfga`.
///
/// Two shares of one paper, each carrying its own deadline, so one viewer's expiry must
/// not take the other's grant with it.
async fn two_expiring_viewers_of_one_paper_gate_independently(cluster: Arc<Cluster>) {
    let holder = |subject: &str| subject_holder(subject, &[subject]).with_clock();
    let case = ParityCase::reading(
        "runner-two-expiring-viewers",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (1, 'viewer_live', now() + interval '1 day'),
                 (1, 'viewer_gone', now() - interval '1 day')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![holder("viewer_live"), holder("viewer_gone")],
    )
    .with_attributes(SUBJECTS_ONLY)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('viewer_live', 'viewer_live'), ('viewer_gone', 'viewer_gone'))
             AS c(subject, keys)
         WHERE EXISTS (
             SELECT 1 FROM paper_shares s
             WHERE s.paper_id = p.id
               AND s.viewer = ANY(string_to_array(c.keys, ','))
               AND s.expires_at > $1::timestamptz)
         UNION ALL
         SELECT c.subject, 'paper_shares:' || s.paper_id || '|' || s.viewer AS object
         FROM paper_shares s
         CROSS JOIN (VALUES ('viewer_live'), ('viewer_gone')) AS c(subject)",
    );
    // The share table's own row security is disclosed, and the answers still agree.
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, visible) in [("viewer_live", true), ("viewer_gone", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            "papers:1",
            ActionStatement::Select,
            visible,
        );
    }
    support::parity::assert_only_disagreements(&case, &run, &[]);
}

/// Ported from `two_deadline_witness_parity_postgres18_and_openfga`.
///
/// Two deadlines on a membership table whose rows are not uniquely keyed by
/// `(doc, user)`. `PostgreSQL` grants only where one single row passes both comparisons,
/// so a model compressing the rows per column grants Bob, whose two rows each pass one
/// comparison and fail the other.
async fn two_deadlines_need_one_witnessing_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-two-deadline-witness",
        "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE members (
    id INT PRIMARY KEY,
    doc_id INT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL,
    trial_ends TIMESTAMPTZ NOT NULL,
    support_ends TIMESTAMPTZ NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM members m
        WHERE m.doc_id = docs.id AND m.user_id = current_user
          AND m.trial_ends > now() AND m.support_ends > now()
    )
);
",
        &[
            // Bob's two rows each pass one comparison, Carol's one row passes both.
            "INSERT INTO docs (id) VALUES (1), (2);
             INSERT INTO members (id, doc_id, user_id, trial_ends, support_ends) VALUES
                 (1, 1, 'bob', now() + interval '10 days', now() - interval '10 days'),
                 (2, 1, 'bob', now() - interval '10 days', now() + interval '10 days'),
                 (3, 1, 'carol', now() + interval '10 days', now() + interval '10 days'),
                 (4, 2, 'carol', now() + interval '10 days', now() - interval '10 days')",
            "CREATE ROLE bob LOGIN; CREATE ROLE carol LOGIN;
             GRANT SELECT ON docs, members TO bob, carol",
        ],
        vec![
            Principal::as_role("bob", "bob").with_clock(),
            Principal::as_role("carol", "carol").with_clock(),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        // Each column's latest value alone would admit Bob, one row does not.
        ("bob", "docs:1", false),
        ("carol", "docs:1", true),
        ("carol", "docs:2", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `clock_gated_from_row_parity_postgres18_and_openfga`.
///
/// A record keyed on the guarded table's own compound key, replayed from the row alone. One
/// row each side of `now()` per tenant, so a replay keyed on the tenant would answer for
/// both and a prefix of the key could not name the row it came from.
async fn a_clock_gated_record_replays_from_its_own_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-clock-gated-from-row",
        "
CREATE TABLE readings (
    tenant_id INT,
    reading_id INT,
    starts_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, reading_id)
);
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_visible ON readings FOR SELECT TO PUBLIC USING (starts_at <= now());
",
        &[
            "INSERT INTO readings (tenant_id, reading_id, starts_at) VALUES
                 (7, 9, now() - interval '1 day'),
                 (7, 10, now() + interval '1 day'),
                 (8, 9, now() - interval '1 day'),
                 (8, 10, now() + interval '1 day')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON readings TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .loading_from_rows()
    // A year back, not on: this guard admits more as time passes, so a later instant
    // takes nothing away and the runner refuses it. Earlier, nothing has started yet.
    .also_at(
        "-1 year",
        "SELECT 'app_user'::text AS subject,
                'readings:' || tenant_id || '|' || reading_id AS object
         FROM readings WHERE starts_at <= $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("readings:7|9", true),
        ("readings:7|10", false),
        ("readings:8|9", true),
        ("readings:8|10", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_paper_from_row_parity_postgres18_and_openfga`.
///
/// A record keyed on a foreign column, so one membership row states a record about another
/// type's object. The share arm replays from the share row and nothing runs its whole-table
/// query, while the owner arm and the share table's own rows still load whole.
async fn a_share_record_replays_onto_another_types_object(cluster: Arc<Cluster>) {
    /// The caller's identity and held keys, as the setting and the condition parameter.
    fn holder(subject: &str, keys: &[&str]) -> Principal {
        let mut principal = Principal::with_setting(subject, "app_reader", "app.user_id", subject)
            .with_context(serde_json::json!({ "app_subjects": keys }));
        principal
            .session
            .push(("app.subjects".to_string(), keys.join(",")));
        principal
    }

    let case = ParityCase::from_fixture(
        "runner-shared-paper-from-row",
        "connetto_capability",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES (2, 'team-a'), (3, 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![holder("alice", &["team-a"]), holder("carol", &[])],
    )
    .loading_from_rows();
    // The share table carries its own set policy, which is disclosed, and the answers agree.
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object, visible) in [
        // The owner arm, which loads whole.
        ("alice", "papers:1", true),
        // The share arm, which only the replay loads.
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    support::parity::assert_only_disagreements(&case, &run, &[]);
}

/// Ported from `translated_schema_parity_postgres18_and_openfga`.
///
/// The role ladder: one shared grant function answers four thresholds, read at 2, inserted
/// and updated at 3, deleted at 4. Five callers sit at different rungs, so a model
/// collapsing the thresholds answers one of them wrongly.
async fn a_role_ladder_answers_four_thresholds(cluster: Arc<Cluster>) {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const DAVE: &str = "00000000-0000-0000-0000-0000000000a4";
    const EVE: &str = "00000000-0000-0000-0000-0000000000a5";
    const ALPHA: &str = "00000000-0000-0000-0000-0000000000b1";
    const BETA: &str = "00000000-0000-0000-0000-0000000000b2";
    const DOC_1: &str = "00000000-0000-0000-0000-0000000000d1";
    const DOC_2: &str = "00000000-0000-0000-0000-0000000000d2";

    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_reader", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-translated-schema",
        "earth_metabolome",
        &[
            &format!(
                "INSERT INTO users (id) VALUES
                     ('{ALICE}'), ('{BOB}'), ('{CAROL}'), ('{DAVE}'), ('{EVE}');
                 INSERT INTO teams (id) VALUES ('{ALPHA}'), ('{BETA}');
                 INSERT INTO team_members (team_id, user_id) VALUES
                     ('{ALPHA}', '{BOB}'), ('{BETA}', '{DAVE}');
                 INSERT INTO ownables (id, owner_id) VALUES
                     ('{DOC_1}', '{ALICE}'), ('{DOC_2}', '{ALPHA}');
                 INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
                     ('{CAROL}', '{ALICE}', 3), ('{BETA}', '{ALICE}', 2), ('{EVE}', '{ALPHA}', 4)"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON users, teams, team_members, owner_grants TO app_reader;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ownables TO app_reader",
        ],
        vec![
            reader(ALICE),
            reader(BOB),
            reader(CAROL),
            reader(DAVE),
            reader(EVE),
        ],
    )
    .writing(
        "ownables",
        Mutations {
            // Rewriting the owner with itself exercises USING and WITH CHECK together, and
            // the ladder reads the owner alone, so the probe's fresh key changes no answer.
            update_set: Some("owner_id = owner_id".to_string()),
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    let doc_1 = format!("ownables:{DOC_1}");
    for (subject, statement, allowed) in [
        // Alice owns doc 1 outright, which is rung 4.
        (ALICE, ActionStatement::Select, true),
        (ALICE, ActionStatement::Delete, true),
        // Carol's own grant is rung 3: reads, writes, no delete.
        (CAROL, ActionStatement::Select, true),
        (CAROL, ActionStatement::Insert, true),
        (CAROL, ActionStatement::Delete, false),
        // Dave reaches rung 2 through team beta: reads only.
        (DAVE, ActionStatement::Select, true),
        (DAVE, ActionStatement::Insert, false),
        (DAVE, ActionStatement::Update, false),
        // Bob holds nothing over alice's owner.
        (BOB, ActionStatement::Select, false),
    ] {
        support::parity::assert_postgres(&case, &run, subject, &doc_1, statement, allowed);
    }
    assert_agrees(&case, &run);
}

/// Ported from `insert_readback_parity_postgres18_and_openfga`.
///
/// Split `INSERT` and `SELECT` policies: the author may insert a row, the owner may read
/// it. `PostgreSQL` applies both to `INSERT ... RETURNING`, and only the `WITH CHECK` to a
/// plain `INSERT`, which is what leaves one relation ungated and the other not.
async fn an_insert_that_reads_back_applies_the_select_policy(cluster: Arc<Cluster>) {
    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_user", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-insert-readback",
        "insert_readback",
        &[
            // One row per combination of owning and authoring.
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, author_id) VALUES
                 ('note-author-only', 'bob', 'alice'),
                 ('note-owner-only', 'alice', 'bob'),
                 ('note-both', 'alice', 'alice'),
                 ('note-neither', 'bob', 'bob')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT, INSERT ON notes TO app_user",
        ],
        vec![reader("alice"), reader("bob")],
    )
    .writing(
        "notes",
        Mutations {
            update_set: None,
            // The policies read owner and author, never the key.
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, row, statement, allowed) in [
        // Alice authors it, so the plain insert stands and the readback does not.
        ("alice", "note-author-only", ActionStatement::Insert, true),
        (
            "alice",
            "note-author-only",
            ActionStatement::InsertReturning,
            false,
        ),
        // Owned and authored by her, so both.
        ("alice", "note-both", ActionStatement::Insert, true),
        ("alice", "note-both", ActionStatement::InsertReturning, true),
        // Hers to read, not hers to write.
        ("alice", "note-owner-only", ActionStatement::Insert, false),
        ("bob", "note-owner-only", ActionStatement::Insert, true),
        (
            "bob",
            "note-neither",
            ActionStatement::InsertReturning,
            true,
        ),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("notes:{row}"),
            statement,
            allowed,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `upsert_parity_postgres18_and_openfga`.
///
/// An upsert may change the conflicting row, so `PostgreSQL` applies the `UPDATE` policies
/// on top of the `INSERT` one. A row the author may insert and the editor may not change
/// separates the two relations.
async fn an_upsert_applies_the_update_policy_too(cluster: Arc<Cluster>) {
    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_user", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-upsert",
        "upsert",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, author_id, editor_id) VALUES
                 ('note-alice-all', 'alice', 'alice', 'alice'),
                 ('note-author-only', 'bob', 'alice', 'bob'),
                 ('note-author-editor', 'bob', 'alice', 'alice'),
                 ('note-owner-author', 'alice', 'alice', 'bob'),
                 ('note-bob-all', 'bob', 'bob', 'bob')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT, INSERT, UPDATE ON notes TO app_user",
        ],
        vec![reader("alice"), reader("bob")],
    )
    .writing(
        "notes",
        Mutations {
            update_set: None,
            // The policies read owner, author and editor, never the key.
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, row, statement, allowed) in [
        // Alice authors it and does not edit it: the insert stands, the upsert does not.
        ("alice", "note-author-only", ActionStatement::Insert, true),
        (
            "alice",
            "note-author-only",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // She authors and edits it, and bob owns it. Naming the arbiter reads the
        // conflicting row, so the SELECT policy denies the upsert anyway.
        (
            "alice",
            "note-author-editor",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // Hers to read and to author, bob's to edit: the insert stands, the upsert does not.
        ("alice", "note-owner-author", ActionStatement::Insert, true),
        (
            "alice",
            "note-owner-author",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // Hers throughout, so both.
        (
            "alice",
            "note-alice-all",
            ActionStatement::InsertOnConflictUpdate,
            true,
        ),
        ("bob", "note-bob-all", ActionStatement::Insert, true),
        ("bob", "note-author-only", ActionStatement::Insert, false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("notes:{row}"),
            statement,
            allowed,
        );
    }
    assert_agrees(&case, &run);
}
