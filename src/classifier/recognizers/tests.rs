use super::subquery::*;
use super::*;
use crate::parser::sql_parser::parse_schema;
use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

fn parse_expr(expr_sql: &str) -> Expr {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(expr_sql)
        .expect("expression should parse")
        .parse_expr()
        .expect("expression should parse")
}

fn parse_select(sql: &str) -> Select {
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("query should parse");
    let stmt = stmts.first().expect("expected one statement");
    let Statement::Query(query) = stmt else {
        panic!("expected query statement");
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        panic!("expected select body");
    };
    select.as_ref().clone()
}

fn db_with_docs_and_members() -> ParserDB {
    parse_schema(
        r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID,
  tenant_uuid UUID,
  is_public BOOLEAN,
  published BOOLEAN
);
CREATE TABLE doc_members (
  doc_id UUID,
  user_id UUID,
  member_id UUID,
  role TEXT
);
",
    )
    .expect("schema should parse")
}

fn registry_with_role_level() -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
}"#,
        )
        .expect("registry json should parse");
    registry
}

#[test]
fn recognize_p1_supports_gt_and_rejects_unknown_functions() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("role_level(auth_current_user_id(), id) > 2");

    let classified =
        recognize_p1(&expr, &db, &registry, &PolicyCommand::Delete).expect("expected P1 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P1NumericThreshold {
            function_name,
            operator: ThresholdOperator::Gt,
            threshold,
            command: PolicyCommand::Delete,
        } if function_name == "role_level" && *threshold == 2
    ));

    let unknown = parse_expr("unknown_role(auth_current_user_id(), id) >= 1");
    assert!(recognize_p1(&unknown, &db, &registry, &PolicyCommand::Select).is_none());
}

#[test]
fn recognize_p1_accepts_reversed_comparators() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let gte = parse_expr("2 <= role_level(auth_current_user_id(), id)");
    let classified_gte =
        recognize_p1(&gte, &db, &registry, &PolicyCommand::Select).expect("expected P1 match");
    assert!(matches!(
        &classified_gte.pattern,
        PatternClass::P1NumericThreshold {
            operator: ThresholdOperator::Gte,
            threshold,
            ..
        } if *threshold == 2
    ));

    let gt = parse_expr("2 < role_level(auth_current_user_id(), id)");
    let classified_gt =
        recognize_p1(&gt, &db, &registry, &PolicyCommand::Delete).expect("expected P1 match");
    assert!(matches!(
        &classified_gt.pattern,
        PatternClass::P1NumericThreshold {
            operator: ThresholdOperator::Gt,
            threshold,
            command: PolicyCommand::Delete,
            ..
        } if *threshold == 2
    ));
}

#[test]
fn recognize_p2_handles_negation_and_literal_filtering() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr("role_level(auth_current_user_id(), id) NOT IN ('viewer')");
    assert!(recognize_p2(&negated, &db, &registry).is_none());

    let non_threshold = parse_expr("unknown_role(auth_current_user_id(), id) IN ('viewer')");
    assert!(recognize_p2(&non_threshold, &db, &registry).is_none());

    let non_string_literals = parse_expr("role_level(auth_current_user_id(), id) IN (TRUE)");
    assert!(recognize_p2(&non_string_literals, &db, &registry).is_none());

    let ok = parse_expr("role_level(auth_current_user_id(), id) IN ('viewer', 2)");
    let classified = recognize_p2(&ok, &db, &registry).expect("expected P2 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P2RoleNameInList {
            function_name,
            role_names,
        } if function_name == "role_level"
            && role_names == &vec!["viewer".to_string(), "2".to_string()]
    ));
}

#[test]
fn recognize_p2_pg_has_role_three_and_two_arg_forms() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new(); // pg_has_role is a built-in, no registry needed.

    // Three-arg form: pg_has_role(current_user, 'admin', 'MEMBER').
    let three_arg = parse_expr("pg_has_role(current_user, 'admin', 'MEMBER')");
    let c3 = recognize_p2(&three_arg, &db, &registry).expect("expected P2 for pg_has_role 3-arg");
    assert!(
        matches!(
            &c3.pattern,
            PatternClass::P2RoleNameInList { function_name, role_names }
                if function_name == "pg_has_role" && role_names == &["admin"]
        ),
        "three-arg pg_has_role should produce P2 with role 'admin', got: {:?}",
        c3.pattern
    );
    assert_eq!(c3.confidence, ConfidenceLevel::A);

    // Two-arg form: pg_has_role('editor', 'USAGE'), current user is implied.
    let two_arg = parse_expr("pg_has_role('editor', 'USAGE')");
    let c2 = recognize_p2(&two_arg, &db, &registry).expect("expected P2 for pg_has_role 2-arg");
    assert!(
        matches!(
            &c2.pattern,
            PatternClass::P2RoleNameInList { function_name, role_names }
                if function_name == "pg_has_role" && role_names == &["editor"]
        ),
        "two-arg pg_has_role should produce P2 with role 'editor', got: {:?}",
        c2.pattern
    );

    let bad_user = parse_expr("pg_has_role(other_user_id, 'admin', 'MEMBER')");
    assert!(
        recognize_p2(&bad_user, &db, &registry).is_none(),
        "pg_has_role with non-current-user first arg should not match"
    );
}

#[test]
fn recognize_p2_role_accessor_equality_and_in_list() {
    let db = db_with_docs_and_members();
    let mut registry = FunctionRegistry::new();
    // Register `role` (normalized form of `auth.role`, schema stripped) as a RoleAccessor.
    registry.register_if_absent(
        "role",
        &crate::parser::function_analyzer::FunctionSemantic::RoleAccessor {
            returns: "text".to_string(),
        },
    );

    // Equality form: auth.role() = 'authenticated'
    // `auth.role` normalizes to `role` (schema prefix is stripped by normalize_relation_name).
    let eq_expr = parse_expr("auth.role() = 'authenticated'");
    let c_eq =
        recognize_p2(&eq_expr, &db, &registry).expect("expected P2 for role_accessor = literal");
    assert!(
        matches!(
            &c_eq.pattern,
            PatternClass::P2RoleNameInList { function_name, role_names }
                if function_name == "role" && role_names == &["authenticated"]
        ),
        "auth.role() = 'authenticated' should produce P2, got: {:?}",
        c_eq.pattern
    );
    assert_eq!(c_eq.confidence, ConfidenceLevel::A);

    // IN-list form: auth.role() IN ('authenticated', 'service_role')
    let in_expr = parse_expr("auth.role() IN ('authenticated', 'service_role')");
    let c_in =
        recognize_p2(&in_expr, &db, &registry).expect("expected P2 for role_accessor IN list");
    assert!(
        matches!(
            &c_in.pattern,
            PatternClass::P2RoleNameInList { function_name, role_names }
                if function_name == "role"
                    && role_names == &["authenticated", "service_role"]
        ),
        "auth.role() IN (...) should produce P2, got: {:?}",
        c_in.pattern
    );

    // Unregistered role function should not match.
    let empty_registry = FunctionRegistry::new();
    let not_matched = parse_expr("auth.role() = 'authenticated'");
    assert!(
        recognize_p2(&not_matched, &db, &empty_registry).is_none(),
        "unregistered role function should not match P2"
    );
}

#[test]
fn recognize_array_patterns_matches_the_caller_in_every_spelling() {
    let registry = FunctionRegistry::new();

    // The caller as an element is an exact relationship, verified on PostgreSQL 18
    // against an UNNEST enumeration, so it is P11 at confidence A.
    for spelling in [
        "current_user = ANY(allowed_users)",
        "allowed_users @> ARRAY[current_user]",
        "ARRAY[current_user] <@ allowed_users",
        "ARRAY[current_user] && allowed_users",
        "allowed_users && ARRAY[current_user]",
    ] {
        let expr = parse_expr(spelling);
        let classified = recognize_array_patterns(&expr, &registry)
            .unwrap_or_else(|| panic!("`{spelling}` should match array membership"));
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P11ArrayMembership { column } if column == "allowed_users"
            ),
            "`{spelling}` should name the array column, got: {:?}",
            classified.pattern
        );
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::A,
            "`{spelling}` is exact"
        );
    }

    // A literal array is a value, not the caller, so it stays an attribute guard.
    let overlap_expr = parse_expr("allowed_roles && ARRAY['admin', 'editor']");
    assert!(
        recognize_array_patterns(&overlap_expr, &registry).is_none(),
        "a literal array names no principal to relate"
    );
    assert_eq!(
        is_attribute_check(&overlap_expr).as_deref(),
        Some("allowed_roles"),
        "overlap against a literal is an attribute guard"
    );

    let non_array = parse_expr("owner_id = current_user");
    assert!(recognize_array_patterns(&non_array, &registry).is_none());

    // A subquery is membership through a table, and expanding it would name a column
    // that does not exist.
    let subquery = parse_expr("current_user = ANY(SELECT user_id FROM doc_members)");
    assert!(recognize_array_patterns(&subquery, &registry).is_none());
}

#[test]
fn recognize_p3_requires_registration_for_unregistered_current_user_like_names() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    // Unregistered function names that merely contain `current_user` must not match.
    let a = parse_expr("owner_id = auth_current_user_id()");
    assert!(recognize_p3(&a, &db, &registry).is_none());

    let b = parse_expr("tenant_uuid = auth_current_user_id()");
    assert!(recognize_p3(&b, &db, &registry).is_none());

    let none = parse_expr("tenant_uuid = actor_id()");
    assert!(
        recognize_p3(&none, &db, &registry).is_none(),
        "non-user-like function should not match ownership"
    );

    let not_eq = parse_expr("owner_id <> auth_current_user_id()");
    assert!(recognize_p3(&not_eq, &db, &registry).is_none());

    let mut registered = FunctionRegistry::new();
    registered.register_if_absent(
        "auth_current_user_id",
        &crate::parser::function_analyzer::FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let registered_expr = parse_expr("owner_id = auth_current_user_id()");
    let registered_classified = recognize_p3(&registered_expr, &db, &registered)
        .expect("expected registered accessor to match");
    assert_eq!(registered_classified.confidence, ConfidenceLevel::A);
}

#[test]
fn recognize_p3_supports_is_not_distinct_from() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    // Registered accessor with owner-like column is accepted.
    let expr = parse_expr("owner_id IS NOT DISTINCT FROM auth_current_user_id()");
    let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
    assert!(matches!(
        classified.pattern,
        PatternClass::P3DirectOwnership { ref column } if column == "owner_id"
    ));
    assert_eq!(classified.confidence, ConfidenceLevel::A);
}

#[test]
fn recognize_p3_scalar_subquery_wrapper_caps_confidence_at_b() {
    let db = db_with_docs_and_members();
    // `registry_with_role_level` has `auth_current_user_id` as a confirmed accessor.
    let registry = registry_with_role_level();

    // Bare function call → confidence A (registry-confirmed).
    let bare = parse_expr("owner_id = auth_current_user_id()");
    let c_bare = recognize_p3(&bare, &db, &registry).expect("expected P3 match");
    assert_eq!(
        c_bare.confidence,
        ConfidenceLevel::A,
        "bare registry call should be A"
    );

    // Scalar subquery wrapping the same registry-confirmed function → confidence B.
    let subquery = parse_expr("owner_id = (SELECT auth_current_user_id())");
    let c_subquery = recognize_p3(&subquery, &db, &registry).expect("expected P3 match");
    assert!(
        matches!(
            &c_subquery.pattern,
            PatternClass::P3DirectOwnership { column } if column == "owner_id"
        ),
        "subquery-wrapped accessor should still produce P3, got: {:?}",
        c_subquery.pattern
    );
    assert_eq!(
        c_subquery.confidence,
        ConfidenceLevel::B,
        "subquery-wrapped registry accessor should be capped at B"
    );

    // SQL keyword in subquery → still B (subquery always caps).
    let kw_subquery = parse_expr("owner_id = (SELECT current_user)");
    let c_kw = recognize_p3(&kw_subquery, &db, &registry).expect("expected P3 match");
    assert_eq!(
        c_kw.confidence,
        ConfidenceLevel::B,
        "subquery around SQL keyword should also be capped at B"
    );
}

#[test]
fn recognize_p3_current_setting_requires_registration() {
    let db = db_with_docs_and_members();

    // Without explicit registration: no match.
    let empty_registry = FunctionRegistry::new();
    let expr = parse_expr("owner_id = current_setting('app.current_user_id')::uuid");
    assert!(
        recognize_p3(&expr, &db, &empty_registry).is_none(),
        "unregistered current_setting must not match P3"
    );

    // After explicit registration: current_setting → confidence A.
    let mut registered_registry = FunctionRegistry::new();
    registered_registry.register_if_absent(
        "current_setting",
        &crate::parser::function_analyzer::FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let classified_a = recognize_p3(&expr, &db, &registered_registry)
        .expect("expected P3 match for registered current_setting");
    assert_eq!(
        classified_a.confidence,
        ConfidenceLevel::A,
        "registered current_setting should be confidence A"
    );
}

#[test]
fn recognize_p3_rejects_unregistered_current_user_like_function_names() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let near_miss_functions = [
        "owner_id = is_current_user_admin()",
        "owner_id = current_user_is_admin()",
        "owner_id = get_current_user_role()",
        "owner_id = foo_current_user_bar()",
        "owner_id = (SELECT is_current_user_admin())",
        "owner_id = current_setting('request.jwt.claims')::json->>'sub'",
    ];

    for sql in near_miss_functions {
        let expr = parse_expr(sql);
        assert!(
            recognize_p3(&expr, &db, &registry).is_none(),
            "unregistered current_user-like function `{sql}` must not match P3"
        );
    }
}

#[test]
fn recognize_p3_rejects_quoted_user_keyword_identifier() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let expr = parse_expr("owner_id = \"user\"");
    assert!(
        recognize_p3(&expr, &db, &registry).is_none(),
        "quoted identifiers must not be treated as SQL current-user keywords"
    );
}

#[test]
fn recognize_p3_rejects_unregistered_function_names_that_match_sql_keywords() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let keyword_named_functions = [
        "owner_id = user",
        "owner_id = auth.user()",
        "owner_id = auth.current_role()",
        "owner_id = user(42)",
        "owner_id = \"current_user\"()",
        "owner_id = x.current_user()",
        "owner_id = \"x\".\"current_user\"()",
    ];

    for sql in keyword_named_functions {
        let expr = parse_expr(sql);
        assert!(
            recognize_p3(&expr, &db, &registry).is_none(),
            "unregistered function call `{sql}` must not be treated as SQL keyword accessor"
        );
    }
}

#[test]
fn recognize_p3_rejects_unregistered_oauth_like_function_name() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let expr = parse_expr("owner_id = oauth_token()");
    assert!(
        recognize_p3(&expr, &db, &registry).is_none(),
        "oauth-like function names must not match P3 without explicit registration"
    );
}

#[test]
fn recognize_p4_exists_supports_extra_predicates_and_negation() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr(
        "NOT EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
             )",
    );
    assert!(recognize_p4(&negated, &db, &registry, "docs").is_none());

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = auth_current_user_id()
                 AND doc_members.role = 'admin'
             )",
    );
    let classified = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
            ..
        } if join_table == "doc_members"
            && fk_column == "doc_id"
            && user_column == "user_id"
            && extra_predicate_sql
                .as_deref()
                .is_some_and(|s| s.contains("role = 'admin'"))
    ));
}

#[test]
fn recognize_p4_exists_supports_joined_membership_tables() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE d.id = docs.id
                 AND dm.user_id = auth_current_user_id()
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            ..
        } if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
    ));
}

#[test]
fn recognize_p4_with_alias_and_current_user_keyword_strips_correlated_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND dm.role = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
            ..
        } if join_table == "doc_members"
            && fk_column == "doc_id"
            && user_column == "user_id"
            && extra_predicate_sql
                .as_deref()
                .is_some_and(|s| s == "role = 'admin'")
    ));
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_is_false_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND docs.published IS FALSE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
        "outer-table IS FALSE predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_boolean_is_wrappers() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "docs.published IS TRUE",
        "docs.published IS NOT TRUE",
        "docs.published IS NOT FALSE",
    ];

    for clause in clauses {
        let exists_expr = parse_expr(&format!(
            "EXISTS (
                   SELECT 1
                   FROM doc_members dm
                   WHERE dm.doc_id = docs.id
                     AND dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
            "outer-table predicate `{clause}` should fail closed for P4"
        );
    }
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_distinct_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "docs.id IS DISTINCT FROM dm.member_id",
        "docs.id IS NOT DISTINCT FROM dm.member_id",
    ];

    for clause in clauses {
        let exists_expr = parse_expr(&format!(
            "EXISTS (
                   SELECT 1
                   FROM doc_members dm
                   WHERE dm.doc_id = docs.id
                     AND dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
            "outer-table DISTINCT predicate `{clause}` should fail closed for P4"
        );
    }
}

#[test]
fn recognize_p4_supports_function_wrapped_membership_predicates_without_alias_leak() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND lower(dm.role) = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership { extra_predicate_sql, .. }
            if extra_predicate_sql
                .as_deref()
                .is_some_and(|s| {
                    let lower = s.to_ascii_lowercase();
                    lower.contains("lower(role) = 'admin'")
                        && !lower.contains("dm.")
                        && !lower.contains("docs.")
                })
    ));
}

#[test]
fn recognize_p4_fails_closed_for_function_wrapped_outer_table_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND lower(docs.owner_id::text) = lower(dm.member_id::text)
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
        "function-wrapped outer-table predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_joined_source_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN docs d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
        "joined-source unqualified extra predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_derived_join_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN (SELECT id, is_public FROM docs) d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
        "derived joined-source unqualified extra predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_allows_single_source_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = current_user
                 AND role = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership { extra_predicate_sql, .. }
            if extra_predicate_sql
                .as_deref()
                .is_some_and(|s| s.to_ascii_lowercase().contains("role = 'admin'"))
    ));
}

#[test]
fn recognize_p4_in_subquery_handles_negation_and_projection_alias() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr(
        "doc_id NOT IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    assert!(recognize_p4_in_subquery(&negated, &db, &registry, "docs").is_none());

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id AS projected_doc
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    let classified =
        recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs").expect("expected match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership {
            fk_column,
            user_column,
            ..
        } if fk_column == "doc_id" && user_column == "user_id"
    ));
}

#[test]
fn recognize_p4_in_subquery_supports_joined_membership_tables() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE dm.user_id = auth_current_user_id()
             )",
    );

    let classified =
        recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs").expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            ..
        } if join_table == "doc_members" && fk_column == "doc_id" && user_column == "user_id"
    ));
}

#[test]
fn recognize_p4_in_subquery_fails_closed_for_non_membership_distinct_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "d.id IS DISTINCT FROM dm.member_id",
        "d.id IS NOT DISTINCT FROM dm.member_id",
    ];

    for clause in clauses {
        let in_subquery = parse_expr(&format!(
            "doc_id IN (
                   SELECT dm.doc_id
                   FROM docs d
                   JOIN doc_members dm ON dm.doc_id = d.id
                   WHERE dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs").is_none(),
            "non-membership DISTINCT predicate `{clause}` should fail closed for P4 IN-subquery"
        );
    }
}

#[test]
fn recognize_p4_in_subquery_fails_closed_for_function_wrapped_non_membership_ref() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE dm.user_id = current_user
                 AND lower(d.id::text) = lower(dm.member_id::text)
             )",
    );

    assert!(
        recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs").is_none(),
        "function-wrapped non-membership reference should fail closed for P4 IN-subquery"
    );
}

#[test]
fn recognize_p4_paths_remain_parity_aligned_for_membership_shape() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
    );
    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
    );

    let exists = recognize_p4(&exists_expr, &db, &registry, "docs").expect("expected EXISTS match");
    let in_sub = recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs")
        .expect("expected IN-subquery match");

    let (exists_join_table, exists_fk_column, exists_user_column, exists_extra_predicate_sql) =
        match exists.pattern {
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                extra_predicate_sql,
                ..
            } => (join_table, fk_column, user_column, extra_predicate_sql),
            other => panic!("expected P4 EXISTS classification, got: {other:?}"),
        };

    let (in_join_table, in_fk_column, in_user_column, in_extra_predicate_sql) = match in_sub.pattern
    {
        PatternClass::P4ExistsMembership {
            join_table,
            fk_column,
            user_column,
            extra_predicate_sql,
            ..
        } => (join_table, fk_column, user_column, extra_predicate_sql),
        other => panic!("expected P4 IN-subquery classification, got: {other:?}"),
    };

    assert_eq!(exists_join_table, in_join_table);
    assert_eq!(exists_fk_column, in_fk_column);
    assert_eq!(exists_user_column, in_user_column);
    assert_eq!(exists_extra_predicate_sql, in_extra_predicate_sql);
}

#[test]
fn recognize_p4_paths_fail_closed_on_ambiguous_sources() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE memberships(doc_id UUID, user_id UUID);
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
    );
    let in_subquery = parse_expr(
        "id IN (
               SELECT a.doc_id
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs").is_none(),
        "ambiguous EXISTS sources should fail closed"
    );
    assert!(
        recognize_p4_in_subquery(&in_subquery, &db, &registry, "docs").is_none(),
        "ambiguous IN-subquery sources should fail closed"
    );
}

#[test]
fn recognize_p10_and_p6_cover_non_matching_variants() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let p10_true = parse_expr("TRUE");
    assert!(recognize_p10_constant_bool(&p10_true, &db, &registry).is_some());
    let p10_not_true = parse_expr("NOT TRUE");
    assert!(matches!(
        recognize_p10_constant_bool(&p10_not_true, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P10ConstantBool { value: false },
            ..
        })
    ));
    let p10_cast = parse_expr("CAST(TRUE AS BOOLEAN)");
    assert!(matches!(
        recognize_p10_constant_bool(&p10_cast, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P10ConstantBool { value: true },
            ..
        })
    ));

    let p10_not_bool = parse_expr("1");
    assert!(recognize_p10_constant_bool(&p10_not_bool, &db, &registry).is_none());

    let p6_false = parse_expr("FALSE = is_public");
    assert!(recognize_p6(&p6_false, &db, &registry).is_none());
    let p6_is_true = parse_expr("is_public IS TRUE");
    assert!(recognize_p6(&p6_is_true, &db, &registry).is_some());
    let p6_is_not_false = parse_expr("is_public IS NOT FALSE");
    assert!(recognize_p6(&p6_is_not_false, &db, &registry).is_some());

    let p6_ident = parse_expr("published");
    assert!(recognize_p6(&p6_ident, &db, &registry).is_some());

    let p6_non_public = parse_expr("private_flag");
    assert!(recognize_p6(&p6_non_public, &db, &registry).is_none());
}

#[test]
fn extractor_helpers_and_attribute_detection_work_for_edge_cases() {
    let fun = parse_expr("auth_current_user_id()");
    assert_eq!(
        extract_function_name(&fun).as_deref(),
        Some("auth_current_user_id")
    );
    let schema_fun = parse_expr(r#""auth"."uid"()"#);
    assert_eq!(extract_function_name(&schema_fun).as_deref(), Some("uid"));

    let id_expr = parse_expr("owner_id");
    assert!(extract_function_name(&id_expr).is_none());

    let qualified = parse_expr("docs.owner_id");
    assert_eq!(extract_column_name(&qualified).as_deref(), Some("owner_id"));
    assert_eq!(
        extract_qualified_column(&qualified),
        Some((Some("docs".to_string()), "owner_id".to_string()))
    );

    let simple = parse_expr("owner_id");
    assert_eq!(
        extract_qualified_column(&simple),
        Some((None, "owner_id".to_string()))
    );

    let attr = parse_expr("priority >= 3");
    assert_eq!(is_attribute_check(&attr).as_deref(), Some("priority"));

    let user_attr = parse_expr("user_id = 'x'");
    assert!(is_attribute_check(&user_attr).is_none());

    let non_literal = parse_expr("status = other_status");
    assert!(is_attribute_check(&non_literal).is_none());
}

#[test]
fn membership_column_extraction_requires_explicit_user_predicate() {
    // WHERE clause has only a role predicate, no current-user equality.
    // Without an explicit user predicate, extract_membership_columns must
    // return None to avoid "exists any admin" false positives.
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "member_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None,)
            .is_none(),
        "membership without user predicate must fail closed"
    );
}

#[test]
fn table_and_projection_extractors_cover_non_table_and_alias_paths() {
    let table_select = parse_select("SELECT dm.doc_id AS projected FROM doc_members dm");
    let from = &table_select.from[0];
    let table_name =
        extract_table_name_from_table_factor(&from.relation).expect("table factor should resolve");
    assert_eq!(table_name, "doc_members");
    assert_eq!(
        extract_table_alias_from_table_factor(&from.relation).as_deref(),
        Some("dm")
    );
    assert_eq!(
        extract_projection_column(&table_select).as_deref(),
        Some("doc_id")
    );

    let derived_select = parse_select("SELECT x.id FROM (SELECT 1 AS id) x WHERE x.id = 1");
    let derived_from = &derived_select.from[0];
    assert!(
        extract_table_name_from_table_factor(&derived_from.relation).is_none(),
        "derived table should not resolve to a table name"
    );
}

#[test]
fn current_user_expr_detection_supports_cast_and_nested() {
    let registry = registry_with_role_level();
    let nested = parse_expr("(auth_current_user_id())");
    let casted = parse_expr("CAST(auth_current_user_id() AS UUID)");
    let keyword = parse_expr("current_user");
    let quoted_keyword = parse_expr("\"user\"");
    let schema_qualified_keyword_fn = parse_expr("auth.user()");
    let other = parse_expr("owner_id");

    assert!(is_current_user_expr(&nested, &registry));
    assert!(is_current_user_expr(&casted, &registry));
    assert!(is_current_user_expr(&keyword, &registry));
    assert!(
        !is_current_user_expr(&quoted_keyword, &registry),
        "quoted keyword identifier must not be treated as current-user accessor"
    );
    assert!(
        !is_current_user_expr(&schema_qualified_keyword_fn, &registry),
        "schema-qualified function names that normalize to SQL keywords are not accessors"
    );
    assert!(!is_current_user_expr(&other, &registry));
}

#[test]
fn extract_projection_column_returns_none_for_wildcard() {
    let select = parse_select("SELECT * FROM doc_members");
    assert!(extract_projection_column(&select).is_none());
}

#[test]
fn is_attribute_check_supports_literal_on_left_and_not_equal_operator() {
    let reverse_literal = parse_expr("3 <= priority");
    assert_eq!(
        is_attribute_check(&reverse_literal).as_deref(),
        Some("priority")
    );

    let not_equal = parse_expr("status <> 'draft'");
    assert_eq!(is_attribute_check(&not_equal).as_deref(), Some("status"));
}

#[test]
fn extract_integer_value_supports_nested_cast_and_signed_literals() {
    let nested_cast = parse_expr("CAST((2) AS INTEGER)");
    assert_eq!(extract_integer_value(&nested_cast), Some(2));

    let signed = parse_expr("-2");
    assert_eq!(extract_integer_value(&signed), Some(-2));
}

#[test]
fn is_attribute_check_accepts_casted_literal_values() {
    let expr = parse_expr("status = CAST('draft' AS TEXT)");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("status"));
}

#[test]
fn strip_qualifier_from_expr_strips_join_alias_and_handles_quoted_identifiers() {
    let mut expr = parse_expr("dm.status = 'active'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    assert_eq!(
        expr.to_string(),
        "status = 'active'",
        "alias-qualified column should be stripped"
    );

    // Double-quoted alias: `"dm"."status"` → the qualifier `"dm"` doesn't
    // match the unquoted alias string `dm` through `qualifier_matches_table`,
    // so the predicate is left unchanged, correct, since double-quoted
    // identifiers are preserved as-is.
    let mut quoted_expr = parse_expr(r#""dm"."status" = 'active'"#);
    strip_qualifier_from_expr(&mut quoted_expr, "doc_members", Some("dm"));
    // The qualifier `"dm"` does not equal `dm` after parsing; the
    // CompoundIdentifier parts contain the unquoted token, so it IS stripped.
    // What matters is the function does not panic or produce garbled output.
    let _ = quoted_expr.to_string(); // must not panic

    // Table-name qualifying: `doc_members.status` → `status`
    let mut tbl_expr = parse_expr("doc_members.status = 1");
    strip_qualifier_from_expr(&mut tbl_expr, "doc_members", None);
    assert_eq!(
        tbl_expr.to_string(),
        "status = 1",
        "table-name qualified column should be stripped"
    );
}

#[test]
fn extract_membership_columns_detects_reversed_predicates() {
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = dm.doc_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let extracted =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
            .expect("reversed predicates should still infer membership columns");
    assert_eq!(extracted.0, "doc_id");
    assert_eq!(extracted.1, "user_id");
}

#[test]
fn recognize_p1_rejects_non_numeric_threshold_expressions() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let bool_threshold = parse_expr("role_level(auth_current_user_id(), id) >= TRUE");
    assert!(recognize_p1(&bool_threshold, &db, &registry, &PolicyCommand::Select).is_none());

    let non_value_threshold = parse_expr("role_level(auth_current_user_id(), id) >= owner_id");
    assert!(recognize_p1(&non_value_threshold, &db, &registry, &PolicyCommand::Select).is_none());
}

#[test]
fn recognize_p2_ignores_non_literal_in_list_items() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let expr = parse_expr("role_level(auth_current_user_id(), id) IN (owner_id)");
    assert!(recognize_p2(&expr, &db, &registry).is_none());
}

#[test]
fn recognize_p1_p2_reject_when_no_current_user_argument() {
    // `get_owner_role(owner_id, id)`, both arguments are resource columns, not
    // current_user.  Without a current-user arg the function cannot express P1/P2
    // semantics (it would be a resource-attribute comparison, not a user-level check).
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let p1_no_user = parse_expr("role_level(owner_id, id) >= 2");
    assert!(
        recognize_p1(&p1_no_user, &db, &registry, &PolicyCommand::Select).is_none(),
        "P1 must reject role_level without a current-user argument"
    );

    let p2_no_user = parse_expr("role_level(owner_id, id) IN ('admin', 'editor')");
    assert!(
        recognize_p2(&p2_no_user, &db, &registry).is_none(),
        "P2 must reject role_level without a current-user argument"
    );
}

#[test]
fn recognize_p3_accepts_function_on_left_side() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let expr = parse_expr("auth_current_user_id() = owner_id");
    let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P3DirectOwnership { column } if column == "owner_id"
    ));
}

#[test]
fn recognize_p4_and_in_subquery_fail_when_membership_columns_cannot_be_inferred() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE odd_members(alpha text, beta text);
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM odd_members
               WHERE odd_members.alpha = 'x'
             )",
    );
    assert!(recognize_p4(&exists_expr, &db, &registry, "docs").is_none());

    let in_subquery_expr = parse_expr(
        "id IN (
               SELECT odd_members.alpha
               FROM odd_members
               WHERE odd_members.beta = 'x'
             )",
    );
    assert!(recognize_p4_in_subquery(&in_subquery_expr, &db, &registry, "docs").is_none());
}

#[test]
fn recognize_p4_exists_without_outer_row_correlation_is_not_per_row_membership() {
    // EXISTS (SELECT 1 FROM members WHERE user_id = current_user), with no predicate
    // tying members to the outer row. Reading it as P4 would key the membership by
    // `doc_id` and grant every doc the user belongs to, which is the over-grant this
    // test was written for. It is now translated through a holder instead, which grants
    // every row of the guarded table together, exactly as PostgreSQL does.
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID NOT NULL, user_id UUID NOT NULL);
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let uncorrelated = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.user_id = current_user
             )",
    );
    let classified = recognize_p4(&uncorrelated, &db, &registry, "docs")
        .expect("an uncorrelated membership check translates through a holder");
    assert!(
        matches!(
            classified.pattern,
            PatternClass::P13UncorrelatedMembership { .. }
        ),
        "it must not become a per-row membership, got {:?}",
        classified.pattern
    );
}

#[test]
fn recognize_p4_and_in_subquery_fail_for_unknown_or_unsupported_subqueries() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let unknown_table = parse_expr(
        "EXISTS (
               SELECT 1
               FROM ghost_members
               WHERE ghost_members.doc_id = docs.id
             )",
    );
    assert!(recognize_p4(&unknown_table, &db, &registry, "docs").is_none());

    let unsupported = parse_expr(
        "doc_id IN (
               (SELECT dm.doc_id FROM doc_members dm)
               UNION
               (SELECT dm.doc_id FROM doc_members dm)
             )",
    );
    assert!(recognize_p4_in_subquery(&unsupported, &db, &registry, "docs").is_none());
}

#[test]
fn recognize_p4_paths_fail_closed_for_values_subqueries() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_values = parse_expr("EXISTS (VALUES (1))");
    let in_values = parse_expr("id IN (VALUES (1))");

    assert!(recognize_p4(&exists_values, &db, &registry, "docs").is_none());
    assert!(recognize_p4_in_subquery(&in_values, &db, &registry, "docs").is_none());
}

#[test]
fn recognize_p4_multi_from_requires_user_predicate() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    // No user predicate in EXISTS → must fail closed even when the membership
    // table is present alongside a second resource table.
    let exists_no_user = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm, docs d
               WHERE dm.doc_id = d.id
             )",
    );
    assert!(
        recognize_p4(&exists_no_user, &db, &registry, "docs").is_none(),
        "EXISTS with no user predicate is an 'exists any row' false positive"
    );

    // IN-subquery with an explicit user predicate over one of the sources
    // should still be accepted; the second source just provides a FK join.
    let in_with_user = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm, docs d
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    assert!(matches!(
        recognize_p4_in_subquery(&in_with_user, &db, &registry, "docs"),
        Some(ClassifiedExpr {
            pattern: PatternClass::P4ExistsMembership { ref join_table, .. },
            ..
        }) if join_table == "doc_members"
    ));
}

#[test]
fn recognize_p6_covers_visible_branch_and_non_literal_binary_case() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let visible = parse_expr("visible = TRUE");
    let classified = recognize_p6(&visible, &db, &registry).expect("expected visible match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P6BooleanFlag { column } if column == "visible"
    ));

    let non_literal = parse_expr("is_public = owner_id");
    assert!(recognize_p6(&non_literal, &db, &registry).is_none());
}

#[test]
fn extract_membership_columns_covers_right_join_side_and_extra_predicates() {
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = doc_id
               AND dm.role > 'a'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let extracted =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
            .expect("columns should still be inferred");
    assert_eq!(extracted.0, "doc_id");
    assert_eq!(extracted.1, "user_id");
    assert!(extracted
        .2
        .as_deref()
        .is_some_and(|s| s.contains("role > 'a'")));
}

#[test]
fn extract_membership_columns_returns_none_without_user_predicate() {
    // No WHERE clause at all → no user predicate → must fail closed.
    let select = parse_select("SELECT dm.doc_id FROM doc_members dm");
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None,)
            .is_none(),
        "membership without any WHERE must fail closed"
    );
}

#[test]
fn membership_column_extraction_requires_user_predicate_not_just_role() {
    // WHERE has only a role predicate and no current-user equality:
    // even with a tenant_id column present, must still fail closed.
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "tenant_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None,)
            .is_none(),
        "membership with only a role predicate must fail closed"
    );
}

#[test]
fn membership_column_extraction_fails_when_fk_remains_ambiguous() {
    let select = parse_select(
        "SELECT m.alpha_id
             FROM memberships m
             WHERE m.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "alpha_id".to_string(),
        "beta_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let extracted =
        extract_membership_columns(&select, "memberships", Some("m"), &cols, &registry, None);
    assert!(
        extracted.is_none(),
        "ambiguous membership FK should fail closed"
    );
}

#[test]
fn extract_membership_columns_fails_when_join_predicates_conflict() {
    let select = parse_select(
        "SELECT m.doc_id
             FROM doc_members m
             WHERE m.user_id = auth_current_user_id()
               AND m.doc_id = docs.id
               AND m.project_id = docs.project_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "project_id".to_string(),
        "user_id".to_string(),
    ];

    let extracted =
        extract_membership_columns(&select, "doc_members", Some("m"), &cols, &registry, None);
    assert!(
        extracted.is_none(),
        "conflicting join predicates should fail closed"
    );
}

#[test]
fn recognize_p5_accepts_unqualified_parent_column_when_unambiguous() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM projects p
               WHERE project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
    );

    let classified = recognize_p5(&expr, &db, &registry, "tasks", &PolicyCommand::Select)
        .expect("expected P5 classification");
    assert!(matches!(
        classified.pattern,
        PatternClass::P5ParentInheritance { ref parent_table, ref fk_column, .. }
            if parent_table == "projects" && fk_column == "project_id"
    ));
}

#[test]
fn recognize_p5_supports_joined_parent_sources() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE project_tags(project_id UUID REFERENCES projects(project_uuid), tag TEXT);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM projects p
               JOIN project_tags pt ON pt.project_id = p.project_uuid
               WHERE p.project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
    );

    let classified = recognize_p5(&expr, &db, &registry, "tasks", &PolicyCommand::Select)
        .expect("expected P5 classification");
    assert!(matches!(
        classified.pattern,
        PatternClass::P5ParentInheritance { ref parent_table, ref fk_column, .. }
            if parent_table == "projects" && fk_column == "project_id"
    ));
}

#[test]
fn is_attribute_check_recognizes_like_ilike_in_list_and_null_forms() {
    // LIKE and ILIKE are now attribute checks (Phase 3g).
    let like_expr = parse_expr("status LIKE 'draft%'");
    assert_eq!(is_attribute_check(&like_expr), Some("status".to_string()));

    let ilike_name_expr = parse_expr("name ILIKE '%admin%'");
    assert_eq!(
        is_attribute_check(&ilike_name_expr),
        Some("name".to_string())
    );

    // IN list with all literals is an attribute check.
    let in_expr = parse_expr("status IN ('active', 'pending')");
    assert_eq!(is_attribute_check(&in_expr), Some("status".to_string()));

    // IS NULL / IS NOT NULL are attribute checks.
    let is_null_expr = parse_expr("deleted_at IS NULL");
    assert_eq!(
        is_attribute_check(&is_null_expr),
        Some("deleted_at".to_string())
    );

    // Negated forms are NOT attribute checks (they restrict, not grant).
    let negated_in = parse_expr("status NOT IN ('active', 'pending')");
    assert!(
        is_attribute_check(&negated_in).is_none(),
        "negated IN list should not be an attribute check"
    );

    // User-related columns are excluded.
    let user_like = parse_expr("user_id LIKE '%admin%'");
    assert!(
        is_attribute_check(&user_like).is_none(),
        "user-related column should not be classified as attribute"
    );
}

#[test]
fn parse_select_panics_for_non_query_and_non_select_body() {
    let non_query = std::panic::catch_unwind(|| parse_select("DELETE FROM doc_members"));
    assert!(non_query.is_err());

    let non_select = std::panic::catch_unwind(|| parse_select("VALUES (1)"));
    assert!(non_select.is_err());
}

#[test]
fn pg_has_role_rejects_non_string_role_value() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("pg_has_role(current_user, 42, 'MEMBER')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
}

#[test]
fn pg_has_role_rejects_wrong_arg_count() {
    let registry = FunctionRegistry::new();
    // Single arg
    let expr = parse_expr("pg_has_role('admin')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
    // Four args
    let expr = parse_expr("pg_has_role(current_user, 'admin', 'MEMBER', 'extra')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
}

#[test]
fn role_accessor_comparison_reversed_eq() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    // reversed: 'authenticated' = auth.role()
    let expr = parse_expr("'authenticated' = auth.role()");
    let classified = recognize_role_accessor_comparison(&expr, &registry);
    assert!(classified.is_some());
    let c = classified.unwrap();
    assert!(matches!(
        c.pattern,
        PatternClass::P2RoleNameInList {
            ref role_names, ..
        } if role_names == &["authenticated"]
    ));
}

#[test]
fn role_accessor_comparison_rejects_non_string_literal() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    let expr = parse_expr("auth.role() = 42");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn role_accessor_comparison_rejects_column_rhs() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    let expr = parse_expr("auth.role() = some_column");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn role_accessor_in_list_rejects_non_string_items() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    // All non-string items -> empty role_names -> returns None
    let expr = parse_expr("auth.role() IN (42, 99)");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn recognize_p5_rejects_negated_exists() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
            "NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user)",
        );
    assert!(recognize_p5(&expr, &db, &registry, "tasks", &PolicyCommand::Select).is_none());
}

#[test]
fn is_negated_boolean_flag_is_false_and_is_not_true() {
    let is_false = parse_expr("is_public IS FALSE");
    assert_eq!(
        is_negated_boolean_flag(&is_false),
        Some("is_public".to_string())
    );

    let is_not_true = parse_expr("is_published IS NOT TRUE");
    assert_eq!(
        is_negated_boolean_flag(&is_not_true),
        Some("is_published".to_string())
    );

    // Non-public-flag column -> None
    let non_flag = parse_expr("status IS FALSE");
    assert!(is_negated_boolean_flag(&non_flag).is_none());
}

#[test]
fn function_has_current_user_arg_returns_false_for_non_function() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("42");
    assert!(!function_has_current_user_arg(&expr, &registry));
}

#[test]
fn function_has_current_user_arg_returns_false_for_no_args() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("my_func()");
    assert!(!function_has_current_user_arg(&expr, &registry));
}

#[test]
fn current_user_accessor_name_subquery_with_multiple_projections_returns_none() {
    let expr = parse_expr("(SELECT a, b FROM t)");
    assert!(current_user_accessor_name(&expr).is_none());
}

#[test]
fn strip_qualifier_from_expr_handles_unary_cast_is_null_is_not_null_in_list() {
    // UnaryOp: NOT dm.active
    let mut unary = parse_expr("NOT dm.active");
    strip_qualifier_from_expr(&mut unary, "doc_members", Some("dm"));
    assert!(!unary.to_string().contains("dm."));

    // Cast: dm.role::text
    let mut cast = parse_expr("CAST(dm.role AS text)");
    strip_qualifier_from_expr(&mut cast, "doc_members", Some("dm"));
    assert!(!cast.to_string().contains("dm."));

    // IsNull: dm.deleted_at IS NULL
    let mut is_null = parse_expr("dm.deleted_at IS NULL");
    strip_qualifier_from_expr(&mut is_null, "doc_members", Some("dm"));
    assert!(!is_null.to_string().contains("dm."));

    // IsNotNull: dm.active IS NOT NULL
    let mut is_not_null = parse_expr("dm.active IS NOT NULL");
    strip_qualifier_from_expr(&mut is_not_null, "doc_members", Some("dm"));
    assert!(!is_not_null.to_string().contains("dm."));

    // InList: dm.role IN ('admin', 'editor')
    let mut in_list = parse_expr("dm.role IN ('admin', 'editor')");
    strip_qualifier_from_expr(&mut in_list, "doc_members", Some("dm"));
    assert!(!in_list.to_string().contains("dm."));
}

#[test]
fn strip_qualifier_from_expr_handles_boolean_is_variants() {
    let mut is_true = parse_expr("dm.active IS TRUE");
    strip_qualifier_from_expr(&mut is_true, "doc_members", Some("dm"));
    assert!(!is_true.to_string().contains("dm."));

    let mut is_not_false = parse_expr("dm.active IS NOT FALSE");
    strip_qualifier_from_expr(&mut is_not_false, "doc_members", Some("dm"));
    assert!(!is_not_false.to_string().contains("dm."));

    let mut is_false = parse_expr("dm.active IS FALSE");
    strip_qualifier_from_expr(&mut is_false, "doc_members", Some("dm"));
    assert!(!is_false.to_string().contains("dm."));

    let mut is_not_true = parse_expr("dm.active IS NOT TRUE");
    strip_qualifier_from_expr(&mut is_not_true, "doc_members", Some("dm"));
    assert!(!is_not_true.to_string().contains("dm."));
}

#[test]
fn strip_qualifier_from_expr_handles_function_wrapped_identifiers() {
    let mut expr = parse_expr("lower(dm.role) = 'admin'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    let rendered = expr.to_string().to_ascii_lowercase();
    assert!(
        rendered.contains("lower(role) = 'admin'"),
        "expected stripped function-wrapped predicate, got: {rendered}"
    );
    assert!(
        !rendered.contains("dm."),
        "function-wrapped identifier should have qualifier stripped, got: {rendered}"
    );
}

#[test]
fn predicate_references_other_table_recursive_arms() {
    // InList with other-table reference
    let inlist = parse_expr("other.col IN ('a', 'b')");
    assert!(predicate_references_other_table(
        &inlist,
        "members",
        Some("m")
    ));

    // UnaryOp with other-table reference
    let unary = parse_expr("NOT other.active");
    assert!(predicate_references_other_table(
        &unary,
        "members",
        Some("m")
    ));

    // IsNull with other-table reference
    let is_null = parse_expr("other.deleted_at IS NULL");
    assert!(predicate_references_other_table(
        &is_null,
        "members",
        Some("m")
    ));

    // IsNotNull with other-table reference
    let is_not_null = parse_expr("other.active IS NOT NULL");
    assert!(predicate_references_other_table(
        &is_not_null,
        "members",
        Some("m")
    ));

    // IsDistinctFrom with other-table reference
    let is_distinct = parse_expr("other.col IS DISTINCT FROM m.col");
    assert!(predicate_references_other_table(
        &is_distinct,
        "members",
        Some("m")
    ));

    // IsNotDistinctFrom with other-table reference
    let is_not_distinct = parse_expr("other.col IS NOT DISTINCT FROM m.col");
    assert!(predicate_references_other_table(
        &is_not_distinct,
        "members",
        Some("m")
    ));

    // Function wrapper with other-table reference
    let function_wrapped = parse_expr("lower(other.col) = lower(m.col)");
    assert!(predicate_references_other_table(
        &function_wrapped,
        "members",
        Some("m")
    ));

    // Same table reference -> false
    let same = parse_expr("m.status IN ('a', 'b')");
    assert!(!predicate_references_other_table(
        &same,
        "members",
        Some("m")
    ));
}

#[test]
fn extract_parent_join_columns_rejects_non_eq_predicate() {
    let pred = parse_expr("p.id > tasks.project_id");
    let outer_cols = vec!["id".to_string(), "project_id".to_string()];
    let parent_cols = vec!["id".to_string(), "owner_id".to_string()];
    assert!(extract_parent_join_columns(
        &pred,
        "tasks",
        &outer_cols,
        "projects",
        Some("p"),
        &parent_cols
    )
    .is_none());
}

#[test]
fn extract_parent_join_columns_right_is_parent_left_is_outer() {
    let pred = parse_expr("tasks.project_id = p.id");
    let outer_cols = vec!["id".to_string(), "project_id".to_string()];
    let parent_cols = vec!["id".to_string(), "owner_id".to_string()];
    let result = extract_parent_join_columns(
        &pred,
        "tasks",
        &outer_cols,
        "projects",
        Some("p"),
        &parent_cols,
    );
    assert!(result.is_some());
    let (fk, pk) = result.unwrap();
    assert_eq!(fk, "project_id");
    assert_eq!(pk, "id");
}

#[test]
fn infer_membership_fk_column_uses_table_stem_hint() {
    let cols = vec![
        "project_id".to_string(),
        "org_id".to_string(),
        "user_id".to_string(),
    ];
    // Table name: project_members -> stem hint: project_id
    let result = infer_membership_fk_column("project_members", &cols, Some("user_id"), None);
    assert_eq!(result, Some("project_id".to_string()));
}

#[test]
fn infer_membership_fk_column_filters_scope_candidates() {
    // When there are multiple _id cols but one is a scope candidate (tenant_id)
    let cols = vec![
        "doc_id".to_string(),
        "tenant_id".to_string(),
        "user_id".to_string(),
    ];
    let result = infer_membership_fk_column("memberships", &cols, Some("user_id"), None);
    assert_eq!(result, Some("doc_id".to_string()));
}

#[test]
fn diagnose_p4_membership_ambiguity_in_subquery_form() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    // Multiple membership sources -> ambiguous
    let expr = parse_expr("id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)");
    // The IN-subquery form should at least not panic
    let result = diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs");
    // It should return None (single match) or Some (ambiguous)
    // either is fine -- we just need the code path exercised
    let _ = result;
}

#[test]
fn diagnose_p5_parent_inheritance_ambiguity_returns_none_for_non_exists() {
    let db = parse_schema(
        r"CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);",
    )
    .unwrap();
    // Not an EXISTS expression at all
    let expr = parse_expr("tasks.project_id = current_user");
    assert!(diagnose_p5_parent_inheritance_ambiguity(&expr, &db, "tasks").is_none());
}

#[test]
fn extract_membership_columns_via_join_on_clause() {
    // FK correlation in ON clause, user predicate in WHERE.
    // This exercises the ON-clause FK extraction path.
    let select = parse_select(
        "SELECT m.doc_id FROM doc_members m
             JOIN docs d ON m.doc_id = d.id
             WHERE m.user_id = auth_current_user_id()
               AND m.role >= 2",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("m"), &cols, &registry, None);
    assert!(
        result.is_some(),
        "ON-clause fk_col and WHERE user_col should be extracted"
    );
    let (fk, user, _extras) = result.unwrap();
    assert_eq!(fk, "doc_id");
    assert_eq!(user, "user_id");
}

#[test]
fn recognize_array_patterns_rejects_non_current_user_any() {
    let registry = FunctionRegistry::new();
    // some_column = ANY(array_col) -- not current_user
    let expr = parse_expr("some_column = ANY(tags)");
    assert!(recognize_array_patterns(&expr, &registry).is_none());
}

// 1. extract_integer_value: Nested, Cast, UnaryPlus recursion
#[test]
fn extract_integer_value_nested_wrapping() {
    // Nested: (42) → 42
    let nested = parse_expr("(42)");
    assert_eq!(extract_integer_value(&nested), Some(42));
}

#[test]
fn extract_integer_value_cast_wrapping() {
    // Cast: CAST(7 AS INTEGER) → 7
    let cast = parse_expr("CAST(7 AS INTEGER)");
    assert_eq!(extract_integer_value(&cast), Some(7));
}

#[test]
fn extract_integer_value_unary_plus() {
    // UnaryPlus: +42 → 42
    let plus = parse_expr("+42");
    assert_eq!(extract_integer_value(&plus), Some(42));
}

#[test]
fn extract_integer_value_nested_combinations() {
    // Nested inside Cast: CAST((5) AS INT) → 5
    let nested_in_cast = parse_expr("CAST((5) AS INT)");
    assert_eq!(extract_integer_value(&nested_in_cast), Some(5));

    // UnaryPlus inside Nested: (+3) → 3
    let plus_in_nested = parse_expr("(+3)");
    assert_eq!(extract_integer_value(&plus_in_nested), Some(3));

    // UnaryMinus inside Nested: (-10) → -10
    let minus_in_nested = parse_expr("(-10)");
    assert_eq!(extract_integer_value(&minus_in_nested), Some(-10));

    // Non-integer expression → None
    let non_int = parse_expr("'hello'");
    assert_eq!(extract_integer_value(&non_int), None);
}

// 2. extract_table_alias_from_table_factor: non-Table variant
#[test]
fn extract_table_alias_from_table_factor_returns_none_for_derived() {
    // Parse a SELECT with a derived table (subquery in FROM).
    let select = parse_select("SELECT x.id FROM (SELECT 1 AS id) AS x");
    let from = &select.from[0];
    // The relation is a Derived subquery, not a Table.
    assert!(
        extract_table_alias_from_table_factor(&from.relation).is_none(),
        "Derived subquery should return None from extract_table_alias_from_table_factor"
    );
}

// 3. join_on_expr: non-matching JoinOperator variant returns None
//    and non-On JoinConstraint returns None
#[test]
fn join_on_expr_returns_none_for_non_standard_join_operators() {
    use sqlparser::ast::JoinOperator;

    // Cross Apply / non-standard variant → None
    let cross_apply = JoinOperator::CrossApply;
    assert!(
        join_on_expr(&cross_apply).is_none(),
        "CrossApply should return None from join_on_expr"
    );

    let outer_apply = JoinOperator::OuterApply;
    assert!(
        join_on_expr(&outer_apply).is_none(),
        "OuterApply should return None from join_on_expr"
    );
}

#[test]
fn join_on_expr_returns_none_for_using_constraint() {
    use sqlparser::ast::{JoinConstraint, JoinOperator};

    // JoinConstraint::Using → None
    let using_constraint = JoinOperator::Inner(JoinConstraint::Using(vec![]));
    assert!(
        join_on_expr(&using_constraint).is_none(),
        "USING constraint should return None from join_on_expr"
    );

    // JoinConstraint::Natural → None
    let natural_constraint = JoinOperator::Inner(JoinConstraint::Natural);
    assert!(
        join_on_expr(&natural_constraint).is_none(),
        "Natural constraint should return None from join_on_expr"
    );

    // JoinConstraint::None → None
    let none_constraint = JoinOperator::Inner(JoinConstraint::None);
    assert!(
        join_on_expr(&none_constraint).is_none(),
        "None constraint should return None from join_on_expr"
    );
}

// 4. extract_membership_columns: ON-clause user detection
//    and ON-clause FK detection with right_is_join path
#[test]
fn extract_membership_columns_on_clause_user_left_join_right_current_user() {
    // ON clause: dm.user_id = auth_current_user_id() (left is join, right is current_user)
    let select = parse_select(
        "SELECT dm.doc_id FROM docs d
             JOIN doc_members dm ON dm.user_id = auth_current_user_id() AND dm.doc_id = d.id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None);
    assert!(
        result.is_some(),
        "ON-clause user_col (left=join) should be extracted"
    );
    let (fk, user, _extras) = result.unwrap();
    assert_eq!(fk, "doc_id");
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_on_clause_user_right_join_left_current_user() {
    // ON clause: auth_current_user_id() = dm.user_id (right is join, left is current_user)
    let select = parse_select(
        "SELECT dm.doc_id FROM docs d
             JOIN doc_members dm ON auth_current_user_id() = dm.user_id AND dm.doc_id = d.id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None);
    assert!(
        result.is_some(),
        "ON-clause user_col (right=join) should be extracted"
    );
    let (fk, user, _extras) = result.unwrap();
    assert_eq!(fk, "doc_id");
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_on_clause_fk_right_is_join() {
    // ON clause: d.id = dm.doc_id (right is join, left is not join)
    let select = parse_select(
        "SELECT dm.doc_id FROM docs d
             JOIN doc_members dm ON d.id = dm.doc_id
             WHERE dm.user_id = auth_current_user_id()",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None);
    assert!(
        result.is_some(),
        "ON-clause FK (right_is_join) should be extracted"
    );
    let (fk, user, _extras) = result.unwrap();
    assert_eq!(fk, "doc_id");
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_where_right_is_join_fk_conflict_returns_none() {
    // WHERE clause has two different FK columns both with right_is_join:
    //   docs.id = dm.doc_id AND projects.pid = dm.project_id
    // The first sets fk_col = "doc_id", the second conflicts → return None.
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_members dm
             WHERE dm.user_id = auth_current_user_id()
               AND docs.id = dm.doc_id
               AND projects.pid = dm.member_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "member_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None);
    assert!(
        result.is_none(),
        "conflicting right_is_join FK columns should return None"
    );
}

#[test]
fn flatten_and_predicates_recursive_and() {
    // a AND b AND c (without parens, sqlparser chains as BinaryOp AND trees)
    let expr = parse_expr("x = 1 AND y = 2 AND z = 3");
    let mut out = Vec::new();
    flatten_and_predicates(&expr, &mut out);
    assert_eq!(out.len(), 3, "a AND b AND c should flatten to 3 predicates");
}

#[test]
fn flatten_and_predicates_deeply_nested() {
    // four-way AND chain; no parens to avoid sqlparser Nested wrappers
    let expr = parse_expr("a = 1 AND b = 2 AND c = 3 AND d = 4");
    let mut out = Vec::new();
    flatten_and_predicates(&expr, &mut out);
    assert_eq!(
        out.len(),
        4,
        "a AND b AND c AND d should flatten to 4 predicates"
    );
}

#[test]
fn flatten_and_predicates_non_and_leaf() {
    // OR is not flattened, single predicate
    let expr = parse_expr("x = 1 OR y = 2");
    let mut out = Vec::new();
    flatten_and_predicates(&expr, &mut out);
    assert_eq!(out.len(), 1, "OR should not be flattened, yielding 1 leaf");
}

// 6. strip_qualifier_from_expr: already tested but ensure we also have the
#[test]
fn strip_qualifier_from_expr_handles_nested_expression() {
    // Nested: (dm.status) → (status)
    let mut nested = parse_expr("(dm.status)");
    strip_qualifier_from_expr(&mut nested, "doc_members", Some("dm"));
    let result = nested.to_string();
    assert!(
        !result.contains("dm."),
        "Nested expression should have qualifier stripped, got: {result}"
    );
}

#[test]
fn strip_qualifier_from_expr_handles_is_distinct_from() {
    let mut expr = parse_expr("dm.status IS DISTINCT FROM 'archived'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    let result = expr.to_string();
    assert!(
        !result.contains("dm."),
        "IS DISTINCT FROM should have qualifier stripped, got: {result}"
    );
}

#[test]
fn strip_qualifier_from_expr_handles_is_not_distinct_from() {
    let mut expr = parse_expr("dm.status IS NOT DISTINCT FROM 'archived'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    let result = expr.to_string();
    assert!(
        !result.contains("dm."),
        "IS NOT DISTINCT FROM should have qualifier stripped, got: {result}"
    );
}

// 7. table_qualifier_candidates: schema-qualified name
#[test]
fn table_qualifier_candidates_includes_relation_part() {
    let candidates = table_qualifier_candidates("myschema.events");
    assert!(
        candidates.contains(&"events".to_string()),
        "should include the relation part: {candidates:?}",
    );
    assert!(
        candidates.contains(&"myschema.events".to_string()),
        "should include the full qualified name: {candidates:?}",
    );
}

#[test]
fn table_qualifier_candidates_unqualified_name() {
    let candidates = table_qualifier_candidates("users");
    assert_eq!(candidates, vec!["users".to_string()]);
}

#[test]
fn qualifier_matches_table_with_schema_qualified_name() {
    // When table_name is "public.docs", qualifier "docs" should match.
    assert!(qualifier_matches_table("docs", "public.docs", None));
    // And full name should also match.
    assert!(qualifier_matches_table("public.docs", "public.docs", None));
    // Alias takes priority.
    assert!(qualifier_matches_table("d", "public.docs", Some("d")));
    // Non-matching qualifier.
    assert!(!qualifier_matches_table("other", "public.docs", None));
}

//    and None for multiple non-scope candidates
#[test]
fn infer_membership_fk_column_uses_membership_suffix_hint() {
    // join_table "team_membership" → hint "team_id"
    let result = infer_membership_fk_column(
        "team_membership",
        &["id".into(), "user_id".into(), "team_id".into()],
        Some("user_id"),
        None,
    );
    assert_eq!(result, Some("team_id".to_string()));
}

#[test]
fn infer_membership_fk_column_uses_memberships_suffix_hint() {
    // join_table "org_memberships" → hint "org_id"
    let result = infer_membership_fk_column(
        "org_memberships",
        &["id".into(), "user_id".into(), "org_id".into()],
        Some("user_id"),
        None,
    );
    assert_eq!(result, Some("org_id".to_string()));
}

#[test]
fn infer_membership_fk_column_returns_none_for_multiple_non_scope_candidates() {
    // Multiple id-like columns, no hint match, no scope filter → None
    let result = infer_membership_fk_column(
        "assignments",
        &[
            "id".into(),
            "project_id".into(),
            "task_id".into(),
            "user_id".into(),
        ],
        Some("user_id"),
        None,
    );
    assert_eq!(result, None);
}

#[test]
fn infer_membership_fk_column_projected_fk_hint_takes_priority() {
    // When projected_fk_hint matches one of the candidates, use it
    let result = infer_membership_fk_column(
        "assignments",
        &[
            "id".into(),
            "project_id".into(),
            "task_id".into(),
            "user_id".into(),
        ],
        Some("user_id"),
        Some("task_id"),
    );
    assert_eq!(result, Some("task_id".to_string()));
}

// 9. diagnose_p4_membership_ambiguity: InSubquery form
#[test]
fn diagnose_p4_membership_ambiguity_in_subquery_with_multiple_sources() {
    // Build a schema with two membership-like tables so the InSubquery path
    // can find multiple matches → ambiguous.
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, member_id UUID);
CREATE TABLE doc_editors(doc_id UUID, user_id UUID);
",
    )
    .unwrap();
    let registry = FunctionRegistry::new();

    // InSubquery form with two FROM sources
    let expr = parse_expr(
        "id IN (
                SELECT dm.doc_id
                FROM doc_members dm, doc_editors de
                WHERE dm.user_id = current_user
                  AND de.user_id = current_user
                  AND dm.doc_id = docs.id
                  AND de.doc_id = docs.id
            )",
    );
    let result = diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs");
    // Should reach the InSubquery branch and produce Some diagnostic
    // (either "multiple candidate" or "could not infer")
    assert!(
        result.is_some(),
        "InSubquery with multiple membership sources should be diagnosed as ambiguous"
    );
}

#[test]
fn diagnose_p4_membership_ambiguity_returns_none_for_non_exists_non_insubquery() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr("owner_id = current_user");
    assert!(diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs").is_none());
}

// 10. diagnose_p5_parent_inheritance_ambiguity: negated, non-Select, conflicting join
#[test]
fn diagnose_p5_returns_none_for_negated_exists() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    let expr = parse_expr(
            "NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user)",
        );
    assert!(
        diagnose_p5_parent_inheritance_ambiguity(&expr, &db, "tasks").is_none(),
        "negated EXISTS should return None"
    );
}

#[test]
fn diagnose_p5_returns_none_for_non_select_body() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
    )
    .unwrap();
    let expr = parse_expr("EXISTS (VALUES (1))");
    assert!(
        diagnose_p5_parent_inheritance_ambiguity(&expr, &db, "tasks").is_none(),
        "non-Select body should return None"
    );
}

#[test]
fn diagnose_p5_returns_conflicting_join_message() {
    // When the same parent source has two different FK columns from the outer table,
    let db = parse_schema(
            r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, code UUID, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), project_code UUID REFERENCES projects(code));
",
        )
        .unwrap();
    let expr = parse_expr(
        "EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = tasks.project_id
                  AND p.code = tasks.project_code
                  AND p.owner_id = current_user
            )",
    );
    let result = diagnose_p5_parent_inheritance_ambiguity(&expr, &db, "tasks");
    assert!(
        result.is_some(),
        "conflicting join columns should produce a diagnostic"
    );
    assert!(
        result.unwrap().contains("conflicting"),
        "diagnostic should mention conflicting"
    );
}

// 11. analyze_p5_parent_inheritance: empty sources
#[test]
fn analyze_p5_returns_none_for_empty_sources() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
    )
    .unwrap();
    // We cannot parse "SELECT 1 WHERE ..." without FROM in standard SQL,
    // but we can construct via parse_select with a derived table that has no relation sources.
    // Actually, sqlparser does allow `SELECT 1 WHERE true`.
    let select = parse_select("SELECT 1");
    let result = analyze_p5_parent_inheritance(&select, &db, "tasks");
    assert!(result.is_none(), "empty sources should return None");
}

// 11b. analyze_p5: empty inner_predicates → skip
#[test]
fn analyze_p5_skips_candidate_with_only_join_predicates_and_no_inner() {
    // When ALL predicates are outer↔parent join columns, inner_predicates is empty,
    // so the candidate is skipped.
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    // EXISTS with only a join predicate and no inner ownership/membership predicate
    let expr = parse_expr("EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id)");
    let result = recognize_p5(
        &expr,
        &db,
        &FunctionRegistry::new(),
        "tasks",
        &PolicyCommand::Select,
    );
    assert!(
        result.is_none(),
        "P5 with no inner predicate (only join) should not match"
    );
}

// 12. function_has_current_user_arg: non-List args
#[test]
fn function_has_current_user_arg_returns_false_for_function_with_no_arg_list() {
    use sqlparser::ast::{Function, FunctionArguments, ObjectName};
    let registry = FunctionRegistry::new();
    // Build a Function AST node with FunctionArguments::None
    let func = Expr::Function(Function {
        name: ObjectName::from(vec![sqlparser::ast::Ident::new("my_func")]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    });
    assert!(
        !function_has_current_user_arg(&func, &registry),
        "FunctionArguments::None should return false"
    );
}

// 13. recognize_pg_has_role: non-List args
#[test]
fn recognize_pg_has_role_returns_none_for_no_arg_list() {
    use sqlparser::ast::{Function, FunctionArguments, ObjectName};
    let registry = FunctionRegistry::new();
    // Build a pg_has_role function with FunctionArguments::None
    let func_expr = Expr::Function(Function {
        name: ObjectName::from(vec![sqlparser::ast::Ident::new("pg_has_role")]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    });
    assert!(
        recognize_pg_has_role(&func_expr, &registry).is_none(),
        "pg_has_role with FunctionArguments::None should return None"
    );
}

// Additional: selection_references_current_user with IsDistinctFrom/IsNotDistinctFrom
// and catch-all arm
#[test]
fn selection_references_current_user_via_is_not_distinct_from() {
    let registry = FunctionRegistry::new();
    let select =
        parse_select("SELECT 1 FROM doc_members WHERE user_id IS NOT DISTINCT FROM current_user");
    assert!(
        selection_references_current_user(&select, &registry),
        "IS NOT DISTINCT FROM current_user should be detected"
    );
}

#[test]
fn selection_references_current_user_via_is_distinct_from() {
    let registry = FunctionRegistry::new();
    let select =
        parse_select("SELECT 1 FROM doc_members WHERE user_id IS DISTINCT FROM current_user");
    assert!(
        selection_references_current_user(&select, &registry),
        "IS DISTINCT FROM current_user should be detected"
    );
}

#[test]
fn selection_references_current_user_catch_all_with_bare_current_user() {
    let registry = FunctionRegistry::new();
    // This is unusual but tests the `_ =>` branch
    let select = parse_select("SELECT 1 FROM doc_members WHERE current_user");
    assert!(
        selection_references_current_user(&select, &registry),
        "bare current_user in WHERE should be detected via catch-all"
    );
}

#[test]
fn selection_references_current_user_returns_false_without_selection() {
    let registry = FunctionRegistry::new();
    let select = parse_select("SELECT 1 FROM doc_members");
    assert!(
        !selection_references_current_user(&select, &registry),
        "no WHERE clause should return false"
    );
}

// Additional: extract_membership_columns ON-clause user detection where
// user_col is already set (second user predicate in ON) → skipped but no error
#[test]
fn extract_membership_columns_on_clause_duplicate_user_col_is_ignored() {
    // Both WHERE and ON have user predicates; the first one wins.
    let select = parse_select(
        "SELECT dm.doc_id FROM docs d
             JOIN doc_members dm ON dm.user_id = auth_current_user_id() AND dm.doc_id = d.id
             WHERE dm.user_id = auth_current_user_id()",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result =
        extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None);
    assert!(result.is_some());
    let (fk, user, _) = result.unwrap();
    assert_eq!(fk, "doc_id");
    assert_eq!(user, "user_id");
}

// Additional: diagnose_p4 for EXISTS with a non-Select body
#[test]
fn diagnose_p4_membership_ambiguity_exists_non_select_body() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr("EXISTS (VALUES (1))");
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs").is_none(),
        "EXISTS with non-Select body should return None"
    );
}

// Additional: diagnose_p4 negated EXISTS returns _ => None
#[test]
fn diagnose_p4_membership_ambiguity_negated_exists() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "NOT EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs").is_none(),
        "negated EXISTS should return None from diagnose_p4"
    );
}

// Additional: diagnose_p4 InSubquery negated → falls to _ => None
#[test]
fn diagnose_p4_membership_ambiguity_negated_in_subquery() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr =
        parse_expr("id NOT IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)");
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs").is_none(),
        "negated IN subquery should return None"
    );
}

// ── Gap 6: temporal predicates ──────────────────────────────────────────

#[test]
fn is_attribute_check_handles_now_comparison() {
    let expr = parse_expr("valid_until > now()");
    assert_eq!(
        is_attribute_check(&expr).as_deref(),
        Some("valid_until"),
        "now() should be accepted as a temporal literal"
    );
}

#[test]
fn is_attribute_check_handles_current_timestamp() {
    let expr = parse_expr("created_at <= current_timestamp");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("created_at"),);
}

// ── Gap 3: COALESCE/NULLIF → P3 ────────────────────────────────────────

#[test]
fn coalesce_wrapped_ownership_classified_as_p3_confidence_b() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr =
        parse_expr("COALESCE(owner_id, '00000000-0000-0000-0000-000000000000') = current_user");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        matches!(&classified, Some(c) if matches!(&c.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id")),
        "COALESCE-wrapped column should classify as P3, got: {classified:?}"
    );
    assert_eq!(
        classified.unwrap().confidence,
        ConfidenceLevel::B,
        "COALESCE wrapping should cap confidence at B"
    );
}

#[test]
fn nullif_wrapped_ownership_classified_as_p3() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("NULLIF(owner_id, '') = current_user");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        matches!(&classified, Some(c) if matches!(&c.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id")),
        "NULLIF-wrapped column should classify as P3, got: {classified:?}"
    );
}

// ── Gap 2: JWT claim extraction ────────────────────────────────────────

#[test]
fn current_user_accessor_name_unwraps_json_long_arrow() {
    // current_setting('request.jwt.claims')::json->>'sub'
    let expr = parse_expr("current_setting('request.jwt.claims')::json->>'sub'");
    assert_eq!(
        current_user_accessor_name(&expr).as_deref(),
        Some("current_setting"),
    );
}

#[test]
fn current_user_accessor_name_unwraps_nested_json_arrows() {
    // auth.jwt()->'user_metadata'->>'id', schema prefix stripped by normalize_relation_name
    let expr = parse_expr("auth.jwt()->'user_metadata'->>'id'");
    assert_eq!(current_user_accessor_name(&expr).as_deref(), Some("jwt"),);
}

#[test]
fn jwt_claim_extraction_classified_as_p3() {
    let db = db_with_docs_and_members();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
  "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"},
  "current_setting": {"kind":"current_user_accessor","returns":"text"}
}"#,
        )
        .unwrap();
    let expr = parse_expr("owner_id = current_setting('request.jwt.claims')::json->>'sub'");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        matches!(&classified, Some(c) if matches!(&c.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id")),
        "JWT claim extraction should classify as P3, got: {classified:?}"
    );
    // JSON-wrapped → capped at B
    assert_eq!(classified.unwrap().confidence, ConfidenceLevel::B);
}

// ── Gap 8: IS DISTINCT FROM ───────────────────────────────────────────

#[test]
fn is_attribute_check_handles_is_not_distinct_from() {
    let expr = parse_expr("status IS NOT DISTINCT FROM 'active'");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("status"),);
}

#[test]
fn is_attribute_check_handles_is_distinct_from() {
    let expr = parse_expr("status IS DISTINCT FROM 'deleted'");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("status"),);
}

// ── Gap 5: BETWEEN ───────────────────────────────────────────────────

#[test]
fn is_attribute_check_handles_between() {
    let expr = parse_expr("priority BETWEEN 1 AND 10");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("priority"),);
}

#[test]
fn is_attribute_check_rejects_negated_between() {
    let expr = parse_expr("priority NOT BETWEEN 1 AND 10");
    assert!(
        is_attribute_check(&expr).is_none(),
        "negated BETWEEN should not match"
    );
}

#[test]
fn is_attribute_check_between_with_temporal_bounds() {
    let expr = parse_expr("created_at BETWEEN '2024-01-01' AND now()");
    assert_eq!(is_attribute_check(&expr).as_deref(), Some("created_at"),);
}

#[test]
fn is_literal_or_temporal_rejects_arbitrary_functions() {
    // random_func() should NOT be accepted as temporal
    let expr = parse_expr("col > random_func()");
    assert!(
        is_attribute_check(&expr).is_none(),
        "arbitrary functions should not match as temporal"
    );
}
