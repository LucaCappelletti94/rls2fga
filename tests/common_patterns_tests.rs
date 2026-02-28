/// Tests for the most common real-world RLS patterns.
///
/// Each test verifies that the translator correctly classifies and generates
/// output for patterns commonly found in production `PostgreSQL` deployments.
use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::model_generator;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser;

mod support;

// ============================================================================
// Helper
// ============================================================================

fn classify_fixture(
    fixture: &str,
    registry_setup: impl FnOnce(&mut FunctionRegistry),
) -> (
    Vec<ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    let db = support::parse_fixture_db(fixture);
    let mut registry = FunctionRegistry::new();
    registry_setup(&mut registry);
    let classified = policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

fn classify_fixture_with_json_registry(
    fixture: &str,
) -> (
    Vec<ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    support::load_fixture_classified(fixture)
}

// ============================================================================
// 1. Tenant isolation — tenant_id = current_tenant_id()
//    This is the #1 SaaS pattern. Tests whether P3 recognizer handles
//    non-standard column names (tenant_id) with a registry-confirmed accessor.
// ============================================================================

#[test]
fn tenant_isolation_is_classified() {
    let (classified, _db, _reg) = classify_fixture("tenant_isolation", |reg| {
        reg.register_if_absent(
            "current_tenant_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(
        classified.len(),
        1,
        "Should find the tenant isolation policy"
    );
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P3DirectOwnership { column } => {
            assert_eq!(column, "tenant_id");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P3 with tenant_id, got: {other:?}");
        }
    }
}

// ============================================================================
// 2. Compound OR — owner_id = auth() OR is_public = TRUE
//    Very common "owner or public" pattern. Should be classified as P8(OR).
// ============================================================================

#[test]
fn compound_or_owner_or_public() {
    let (classified, db, registry) = classify_fixture("compound_or", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 1, "Should find one compound policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P8Composite { op, parts } => {
            assert_eq!(*op, BoolOp::Or, "Should be an OR composite");
            assert_eq!(parts.len(), 2, "Should have two sub-patterns");

            let has_p3 = parts
                .iter()
                .any(|p| matches!(p.pattern, PatternClass::P3DirectOwnership { .. }));
            let has_p6 = parts
                .iter()
                .any(|p| matches!(p.pattern, PatternClass::P6BooleanFlag { .. }));
            assert!(has_p3, "Should contain P3 (ownership)");
            assert!(has_p6, "Should contain P6 (boolean flag)");
        }
        other => {
            panic!("Expected P8 composite, got: {other:?}");
        }
    }

    // Verify model contains the composite relation
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::B);
    assert!(
        model.dsl.contains("owner or public_viewer"),
        "Model should contain 'owner or public_viewer', got:\n{}",
        model.dsl
    );

    // Verify tuple generation
    let tuples =
        tuple_generator::generate_tuple_queries(&classified, &db, &registry, ConfidenceLevel::B);
    assert!(!tuples.is_empty(), "Should generate tuple queries");
}

// ============================================================================
// 3. Supabase auth.uid() pattern — user_id = auth.uid()
//    Tests schema-qualified function names (auth.uid).
// ============================================================================

#[test]
fn supabase_auth_uid_pattern() {
    let sql = std::fs::read_to_string("tests/fixtures/supabase_auth/input.sql").unwrap();
    let db = sql_parser::parse_schema(&sql).expect("Supabase auth schema should parse");

    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth.uid",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);

    assert_eq!(classified.len(), 2, "expected both Supabase policies");
    for cp in &classified {
        let classification = cp
            .using_classification
            .as_ref()
            .or(cp.with_check_classification.as_ref())
            .expect("expected Supabase policy classification");
        assert!(
            matches!(
                classification.pattern,
                PatternClass::P3DirectOwnership { ref column } if column == "user_id"
            ),
            "auth.uid() should classify as direct ownership, got: {:?}",
            classification.pattern
        );
    }
}

// ============================================================================
// 4. IN-subquery membership — team_id IN (SELECT team_id FROM team_members ...)
//    Alternative to EXISTS. Very common in Supabase apps.
// ============================================================================

#[test]
fn in_subquery_membership() {
    let (classified, _db, _reg) = classify_fixture("in_subquery_membership", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 1, "Should find one IN-subquery policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P4ExistsMembership { join_table, .. } => {
            assert_eq!(join_table, "team_members");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P4 with team_members, got: {other:?}");
        }
    }
}

// ============================================================================
// 5. PostgreSQL current_user keyword — manager = current_user
//    Uses the SQL standard keyword, not a function call.
// ============================================================================

#[test]
fn current_user_keyword_equality() {
    let (classified, _db, _reg) = classify_fixture("current_user_equality", |_reg| {});

    assert_eq!(classified.len(), 1, "Should find one current_user policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P3DirectOwnership { column } => {
            assert_eq!(column, "manager");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => {
            panic!("Expected P3 with column 'manager', got: {other:?}");
        }
    }
}

// ============================================================================
// 6. Multiple permissive policies on same table
//    PostgreSQL OR's permissive policies together.
//    Tests: status = 'published' (attribute) + author_id = auth() (ownership)
// ============================================================================

#[test]
fn multi_policy_table_classification() {
    let (classified, db, registry) = classify_fixture("multi_policy_table", |reg| {
        reg.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );
    });

    assert_eq!(classified.len(), 3, "Should find all three policies");

    // Check the published_visible policy (status = 'published') → P9
    let published = classified
        .iter()
        .find(|c| c.name() == "published_visible")
        .expect("Should find published_visible policy");
    let pub_class = published.using_classification.as_ref().unwrap();

    match &pub_class.pattern {
        PatternClass::P9AttributeCondition { column, .. } => {
            assert_eq!(column, "status");
            assert_eq!(pub_class.confidence, ConfidenceLevel::C);
        }
        other => {
            panic!("Expected P9 for status column, got: {other:?}");
        }
    }

    // Check the author_sees_own policy (author_id = auth()) → P3
    let author = classified
        .iter()
        .find(|c| c.name() == "author_sees_own")
        .expect("Should find author_sees_own policy");
    let author_class = author.using_classification.as_ref().unwrap();
    assert!(
        matches!(author_class.pattern, PatternClass::P3DirectOwnership { .. }),
        "author_id = auth() should be P3, got: {:?}",
        author_class.pattern,
    );

    // Check that the model generates something reasonable
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
    assert!(!model.dsl.is_empty(), "Should generate a non-empty model");
}

// ============================================================================
// 7. Role IN-list (P2) — get_owner_role(...) IN (2, 3, 4)
//    Tests the P2 recognizer with integer values.
// ============================================================================

#[test]
fn role_in_list_classification() {
    let (classified, db, registry) = classify_fixture_with_json_registry("role_in_list");

    assert_eq!(classified.len(), 1, "Should find one role IN-list policy");
    let cp = &classified[0];
    let classification = cp
        .using_classification
        .as_ref()
        .expect("Should have USING classification");

    match &classification.pattern {
        PatternClass::P2RoleNameInList {
            function_name,
            role_names,
        } => {
            assert_eq!(function_name, "get_owner_role");
            assert_eq!(role_names.len(), 3, "Should have 3 integer values");
            assert!(
                role_names.contains(&"2".to_string())
                    && role_names.contains(&"3".to_string())
                    && role_names.contains(&"4".to_string()),
                "Should contain 2, 3, 4 as string representations"
            );
        }
        other => {
            panic!("Expected P2 with 3 integer values, got: {other:?}");
        }
    }

    // Verify model generation produces role threshold output
    let model = model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
    assert!(!model.dsl.is_empty(), "Should generate a non-empty model");
}

// ============================================================================
// Summary: end-to-end pipeline for all common patterns
// ============================================================================

#[test]
fn pipeline_summary_all_common_patterns() {
    let patterns = [
        ("simple_ownership", "P3: Direct ownership"),
        ("membership_check", "P4: EXISTS membership"),
        ("public_flag", "P6: Boolean flag"),
        ("compound_or", "P8: Compound OR (owner OR public)"),
    ];

    eprintln!("\n=== Common RLS Pattern Pipeline Summary ===\n");

    for (fixture, description) in patterns {
        let sql = std::fs::read_to_string(format!("tests/fixtures/{fixture}/input.sql")).unwrap();
        let db = sql_parser::parse_schema(&sql).unwrap();
        let mut registry = FunctionRegistry::new();
        registry.register_if_absent(
            "auth_current_user_id",
            &FunctionSemantic::CurrentUserAccessor {
                returns: "uuid".to_string(),
            },
        );

        let classified = policy_classifier::classify_policies(&db, &registry);
        let model =
            model_generator::generate_model(&classified, &db, &registry, ConfidenceLevel::D);
        let tuples = tuple_generator::generate_tuple_queries(
            &classified,
            &db,
            &registry,
            ConfidenceLevel::D,
        );

        let all_a = classified.iter().all(|cp| {
            cp.using_classification
                .as_ref()
                .is_none_or(|c| c.confidence >= ConfidenceLevel::B)
                && cp
                    .with_check_classification
                    .as_ref()
                    .is_none_or(|c| c.confidence >= ConfidenceLevel::B)
        });

        eprintln!(
            "{description}: {} policies, {} tuples, all>=B: {all_a}, todos: {}",
            classified.len(),
            tuples.len(),
            model.todos.len(),
        );

        if !model.todos.is_empty() {
            for todo in &model.todos {
                eprintln!(
                    "  TODO [{}]: {} - {}",
                    todo.level, todo.policy_name, todo.message
                );
            }
        }
    }
}
