use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator;

mod support;

/// Full pipeline end-to-end test for the EMI schema.
/// This is the primary acceptance test.
#[test]
fn end_to_end_earth_metabolome() {
    // Stage 1-2: Parse
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");

    // Stage 4: Classify
    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 4, "Should classify all 4 policies");

    // Stage 5: Generate model
    let model = model_generator::generate_model(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    insta::assert_snapshot!("emi_model", model.dsl.trim());

    // Stage 6: Generate tuples
    let tuples = tuple_generator::generate_tuple_queries(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    insta::assert_snapshot!("emi_tuples", tuple_generator::format_tuples(&tuples));

    // Verify no TODOs for Level A/B output
    assert!(model.todos.is_empty(), "EMI schema should produce no TODOs");
}

/// A role hierarchy already orders its levels, so `role_admin` implies the
/// `role_viewer` that `can_select` grants and requiring the read again adds
/// nothing. The gate has to recognize that through the levels between them.
#[test]
fn end_to_end_emi_role_hierarchy_needs_no_read_gate() {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = model_generator::generate_model(
        &classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );

    for line in model.dsl.lines().map(str::trim) {
        let Some(body) = line
            .strip_prefix("define can_delete:")
            .or_else(|| line.strip_prefix("define can_update:"))
        else {
            continue;
        };
        assert!(
            !body.contains("can_select"),
            "'{line}' gates on a read the role level already implies:\n{}",
            model.dsl
        );
    }
}

/// Pipeline test: all EMI policies should be Level A confidence.
#[test]
fn end_to_end_emi_all_level_a() {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");

    let classified = policy_classifier::classify_policies(&db, &registry);

    for cp in &classified {
        for c in [&cp.using_classification, &cp.with_check_classification]
            .into_iter()
            .flatten()
        {
            assert_eq!(
                c.confidence,
                ConfidenceLevel::A,
                "Policy '{}' should be Level A, got Level {}",
                cp.name(),
                c.confidence,
            );
        }
    }
}
