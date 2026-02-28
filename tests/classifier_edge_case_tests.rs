use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser::parse_schema;

mod support;

// ── Registered function fallbacks ────────────────────────────────────────────

#[test]
fn registered_function_not_matching_any_pattern_falls_to_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (val + my_user_func() > 0);

CREATE FUNCTION my_user_func() RETURNS UUID LANGUAGE sql AS 'SELECT current_user';
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "my_user_func",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let c = classified[0]
        .using_classification
        .as_ref()
        .expect("should have USING");
    assert!(
        matches!(&c.pattern, PatternClass::Unknown { .. }),
        "Expected Unknown for non-matching pattern, got {:?}",
        c.pattern
    );
}

#[test]
fn registered_unknown_function_produces_registered_as_unknown_message() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (mystery_func(val));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "mystery_func",
        &FunctionSemantic::Unknown {
            reason: "semantics not analyzable".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    if let PatternClass::Unknown { reason, .. } = &c.pattern {
        assert!(
            reason.contains("registered as Unknown"),
            "Expected 'registered as Unknown' message, got: {reason}"
        );
    } else {
        panic!("Expected Unknown, got: {:?}", c.pattern);
    }
}

#[test]
fn registered_role_threshold_function_bare_call_gives_specific_message() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (role_level(val, id));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1, "editor": 2},
            "grant_table": "grants",
            "grant_grantee_col": "grantee",
            "grant_resource_col": "resource",
            "grant_role_col": "role"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    if let PatternClass::Unknown { reason, .. } = &c.pattern {
        assert!(
            reason.contains("did not match any recognized translation pattern"),
            "Expected 'did not match' message, got: {reason}"
        );
    } else {
        panic!("Expected Unknown, got: {:?}", c.pattern);
    }
}

// ── classifications() iterator ───────────────────────────────────────────────

#[test]
fn classifications_iterator_yields_both_using_and_with_check() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR UPDATE
    USING (owner_id = current_user)
    WITH CHECK (owner_id = current_user);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);

    let count = classified[0].classifications().count();
    assert_eq!(
        count, 2,
        "UPDATE policy with both USING and WITH CHECK should yield 2 classifications"
    );
}

#[test]
fn classifications_iterator_yields_one_for_select() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);

    let count = classified[0].classifications().count();
    assert_eq!(count, 1, "SELECT-only policy should yield 1 classification");
}

// ── scoped_roles() ───────────────────────────────────────────────────────────

#[test]
fn scoped_roles_returns_empty_for_public() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO PUBLIC USING (owner_id = current_user);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    assert!(
        classified[0].scoped_roles().is_empty(),
        "TO PUBLIC should return empty scoped_roles"
    );
}

#[test]
fn scoped_roles_returns_role_names() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO app_user, admin_role USING (owner_id = current_user);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let roles = classified[0].scoped_roles();
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&"admin_role".to_string()));
    assert!(roles.contains(&"app_user".to_string()));
}

// ── Composite patterns ───────────────────────────────────────────────────────

#[test]
fn p7_with_p3_inner_classified_correctly() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (owner_id = current_user AND status = 'published');
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P7AbacAnd { .. }),
        "Expected P7 for ownership + attribute AND, got: {:?}",
        c.pattern
    );
}

#[test]
fn p8_composite_or_with_all_relationship_parts() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (owner_id = current_user OR editor_id = current_user);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P8Composite { op: BoolOp::Or, .. }),
        "Expected P8 OR composite, got: {:?}",
        c.pattern
    );
}

#[test]
fn array_any_membership_classified_as_p9() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, allowed_users TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (current_user = ANY(allowed_users));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P9AttributeCondition { column, .. } if column == "allowed_users"
        ),
        "Expected P9 for = ANY(...), got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::B);
}

#[test]
fn array_overlap_classified_as_p9() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, tags TEXT[], user_tags TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (tags && user_tags);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P9AttributeCondition { .. }),
        "Expected P9 for array overlap (&&), got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::C);
}

#[test]
fn p5_with_p6_inner_does_not_classify_as_p5() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY, is_public BOOLEAN);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.is_public = TRUE
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        !matches!(&c.pattern, PatternClass::P5ParentInheritance { .. }),
        "P5 with P6 inner should be rejected, got: {:?}",
        c.pattern
    );
}

#[test]
fn p5_with_unknown_inner_generates_no_access_todo() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.val + mystery() > 0
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
}

// ── Confidence filtering ─────────────────────────────────────────────────────

#[test]
fn confidence_filter_drops_below_threshold_classifications() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY p_flag ON docs FOR SELECT USING (is_public = TRUE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);

    let filtered = filter_policies_for_output(&classified, ConfidenceLevel::A);
    let has_p3 = filtered.iter().any(|cp| {
        cp.classifications()
            .any(|c| matches!(&c.pattern, PatternClass::P3DirectOwnership { .. }))
    });
    assert!(has_p3, "P3 (confidence A) should survive A-level filter");

    let has_p6 = filtered.iter().any(|cp| {
        cp.classifications()
            .any(|c| matches!(&c.pattern, PatternClass::P6BooleanFlag { .. }))
    });
    assert!(
        !has_p6,
        "P6 (confidence B) should be dropped at A-level filter"
    );
}

// ── P2 variations ────────────────────────────────────────────────────────────

#[test]
fn role_accessor_equality_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (auth.role() = 'authenticated');
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList { role_names, .. } if role_names == &["authenticated"]
        ),
        "Expected P2 for role accessor = 'authenticated', got: {:?}",
        c.pattern
    );
}

#[test]
fn role_accessor_in_list_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (auth.role() IN ('authenticated', 'admin'));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList { role_names, .. } if role_names.len() == 2
        ),
        "Expected P2 with 2 role names, got: {:?}",
        c.pattern
    );
}

#[test]
fn pg_has_role_two_arg_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (pg_has_role('admin', 'MEMBER'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList { role_names, .. } if role_names == &["admin"]
        ),
        "Expected P2 for pg_has_role 2-arg, got: {:?}",
        c.pattern
    );
}

#[test]
fn pg_has_role_three_arg_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList { role_names, .. } if role_names == &["editor"]
        ),
        "Expected P2 for pg_has_role 3-arg, got: {:?}",
        c.pattern
    );
}

// ── P3 variations ────────────────────────────────────────────────────────────

#[test]
fn current_setting_as_user_accessor() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "current_setting",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "text".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "Expected P3 for current_setting accessor, got: {:?}",
        c.pattern
    );
}

#[test]
fn subquery_wrapped_accessor_caps_confidence_at_b() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = (SELECT auth.uid()));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth.uid",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P3DirectOwnership { .. }),
        "Expected P3, got: {:?}",
        c.pattern
    );
    assert_eq!(
        c.confidence,
        ConfidenceLevel::B,
        "Subquery-wrapped accessor should cap confidence at B"
    );
}

// ── Boolean / constant ───────────────────────────────────────────────────────

#[test]
fn negated_boolean_flag_classified_as_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (is_public = FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown { .. }),
        "Negated boolean flag (= FALSE) should classify as Unknown, got: {:?}",
        c.pattern
    );
}

#[test]
fn is_false_boolean_flag_classified_as_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (is_public IS FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown { .. }),
        "IS FALSE boolean flag should classify as Unknown, got: {:?}",
        c.pattern
    );
}

#[test]
fn constant_true_classified_as_p10() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (TRUE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P10ConstantBool { value: true }),
        "TRUE should classify as P10, got: {:?}",
        c.pattern
    );
}

#[test]
fn constant_false_classified_as_p10() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P10ConstantBool { value: false }),
        "FALSE should classify as P10, got: {:?}",
        c.pattern
    );
}

// ── P4 variations ────────────────────────────────────────────────────────────

#[test]
fn p4_in_subquery_form_classified_as_membership() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (id IN (SELECT doc_id FROM shares WHERE shares.user_id = current_user));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P4ExistsMembership { .. }),
        "InSubquery form should classify as P4, got: {:?}",
        c.pattern
    );
}

#[test]
fn p4_with_join_on_clause_extracts_fk_and_user_from_on() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, member_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM doc_members m
        JOIN docs d ON m.doc_id = d.id
        WHERE m.member_id = current_user
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P4ExistsMembership { .. }),
        "JOIN ON FK should classify as P4, got: {:?}",
        c.pattern
    );
}

#[test]
fn p4_with_user_col_in_on_clause_exercises_code_path() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM shares s
        JOIN docs d ON s.user_id = current_user
        WHERE s.doc_id = docs.id
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let _ = &classified[0];
}

#[test]
fn p4_on_clause_reversed_fk_extraction() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_access(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM doc_access a
        JOIN docs d ON d.id = a.doc_id
        WHERE a.user_id = current_user
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P4ExistsMembership { .. }),
        "Reversed ON-clause FK should classify as P4, got: {:?}",
        c.pattern
    );
}

#[test]
fn p4_conflicting_fk_columns_in_where_rejects() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, project_id UUID);
CREATE TABLE access(id UUID PRIMARY KEY, doc_id UUID, project_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM access a
        WHERE a.doc_id = docs.id AND a.project_id = docs.project_id AND a.user_id = current_user
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
}

#[test]
fn p4_on_clause_reversed_user_col_exercises_code_path() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM shares s
        JOIN docs d ON current_user = s.user_id
        WHERE s.doc_id = docs.id
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let _ = &classified[0];
}

#[test]
fn diagnose_p4_with_current_user_but_ambiguous_membership() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE log(id UUID PRIMARY KEY, doc_id UUID, editor UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM log WHERE log.editor = current_user
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
}

// ── P5 variations ────────────────────────────────────────────────────────────

#[test]
fn p5_conflicting_join_columns_classified_as_unknown() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id), alt_org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.id = docs.alt_org_id AND o.owner_id = current_user
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        !matches!(&c.pattern, PatternClass::P5ParentInheritance { .. }),
        "Conflicting join columns should NOT classify as P5, got: {:?}",
        c.pattern
    );
}

#[test]
fn p5_no_inner_predicates_skips_candidate() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o WHERE o.id = docs.org_id
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification.as_ref().unwrap();
    assert!(
        !matches!(&c.pattern, PatternClass::P5ParentInheritance { .. }),
        "No inner predicates should NOT classify as P5, got: {:?}",
        c.pattern
    );
}
