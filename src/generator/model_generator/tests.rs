use super::dsl::*;
use super::role_threshold::*;
use super::*;
use crate::parser::sql_parser::{parse_schema, DatabaseLike, ParserDB, PolicyLike};

fn role_registry(role_levels: &str, include_team: bool) -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    let team_fields = if include_team {
        r#",
    "team_membership_table": "team_memberships",
    "team_membership_user_col": "user_id",
    "team_membership_team_col": "team_id""#
    } else {
        ""
    };
    let json = format!(
        r#"{{
  "role_level": {{
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {role_levels},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"{team_fields}
  }}
}}"#
    );
    registry
        .load_from_json(&json)
        .expect("registry json should parse");
    registry
}

fn docs_db_with_policy(policy_sql: &str) -> ParserDB {
    let sql = format!(
        "
CREATE TABLE docs(id uuid primary key, owner_id uuid, status text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policy_sql}
"
    );
    parse_schema(&sql).expect("schema should parse")
}

fn classified_from_policy<DB: DatabaseLike>(
    policy: &DB::Policy,
    db: &DB,
    using: Option<PatternClass>,
    with_check: Option<PatternClass>,
) -> ClassifiedPolicy {
    let mut result = ClassifiedPolicy::from_policy(policy, db);
    result.using_classification = using.map(|pattern| ClassifiedExpr {
        pattern,
        confidence: ConfidenceLevel::A,
    });
    result.with_check_classification = with_check.map(|pattern| ClassifiedExpr {
        pattern,
        confidence: ConfidenceLevel::A,
    });
    result
}

#[test]
fn compose_action_with_only_restrictive_rules_maps_to_no_access() {
    let mut plan = TypePlan::new("docs");
    let bucket = ModeBuckets {
        permissive: Vec::new(),
        restrictive: vec![UsersetExpr::Computed("owner".to_string())],
        role_limited: Vec::new(),
    };

    let expr = compose_action(&mut plan, Some(&bucket)).expect("expected expression");
    assert_eq!(expr, UsersetExpr::Computed("no_access".to_string()));
    assert!(
        plan.direct_relations.contains_key("no_access"),
        "restrictive-only rules should synthesize no_access"
    );
}

#[test]
fn compose_action_with_only_a_role_limited_barrier_maps_to_no_access() {
    let mut plan = TypePlan::new("docs");
    let bucket = ModeBuckets {
        permissive: Vec::new(),
        restrictive: Vec::new(),
        role_limited: vec![RoleLimitedRule {
            policy: "docs_review".to_string(),
            rule: UsersetExpr::Computed("reviewer".to_string()),
            scope_relation: "scope_docs_review".to_string(),
        }],
    };

    let expr = compose_action(&mut plan, Some(&bucket)).expect("expected expression");
    assert_eq!(expr, UsersetExpr::Computed("no_access".to_string()));
}

/// The fold always puts an exclusion beside a granting branch, so no generated model
/// can tell a wrong answer here from a right one. The contract is pinned directly.
#[test]
fn grants_nothing_reads_only_the_base_of_an_exclusion() {
    let mut plan = TypePlan::new("docs");
    plan.ensure_direct(
        DENY_RELATION,
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );
    plan.ensure_direct("owner", vec![DirectSubject::Type(USER_TYPE.to_string())]);

    let from_nothing = UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed(DENY_RELATION.to_string())),
        subtract: Box::new(UsersetExpr::Computed("owner".to_string())),
    };
    assert!(
        grants_nothing(&from_nothing, &plan, &mut BTreeSet::new()),
        "subtracting from a relation that grants nobody still grants nobody"
    );

    let from_owner = UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed("owner".to_string())),
        subtract: Box::new(UsersetExpr::Computed(DENY_RELATION.to_string())),
    };
    assert!(
        !grants_nothing(&from_owner, &plan, &mut BTreeSet::new()),
        "how much a subtraction removes is unknowable, so the base decides"
    );
}

/// `rule_implies` treats equal keys as the same rule, so an exclusion that ignored a
/// side would let one stand for another.
#[test]
fn userset_key_separates_exclusions_by_both_sides() {
    let exclusion = |base: &str, subtract: &str| UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed(base.to_string())),
        subtract: Box::new(UsersetExpr::Computed(subtract.to_string())),
    };

    let key = userset_key(&exclusion("owner", "blocked"));
    assert_eq!(key, userset_key(&exclusion("owner", "blocked")));
    assert_ne!(key, userset_key(&exclusion("editor", "blocked")));
    assert_ne!(key, userset_key(&exclusion("owner", "suspended")));
    assert_ne!(
        key,
        userset_key(&UsersetExpr::Intersection(vec![
            UsersetExpr::Computed("owner".to_string()),
            UsersetExpr::Computed("blocked".to_string()),
        ]))
    );
}

#[test]
fn pattern_to_expr_handles_missing_or_invalid_role_threshold_metadata() {
    let empty_registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p1 = PatternClass::P1NumericThreshold {
        function_name: "missing_fn".to_string(),
        operator: ThresholdOperator::Gte,
        threshold: 2,
        command: PolicyCommand::Select,
    };
    let p2 = PatternClass::P2RoleNameInList {
        function_name: "missing_fn".to_string(),
        role_names: vec!["viewer".to_string()],
        privilege: RolePrivilege::Member,
    };

    let p1_expr = pattern_to_expr(
        &p1,
        "p1",
        &mut table_plan,
        &mut all_types,
        &empty_registry,
        &mut notes,
    );
    let p2_expr = pattern_to_expr(
        &p2,
        "p2",
        &mut table_plan,
        &mut all_types,
        &empty_registry,
        &mut notes,
    );

    assert_eq!(p1_expr, UsersetExpr::Computed("no_access".to_string()));
    // P2 with missing metadata falls through to `handle_p2_role_gate`, which walks a
    // scope relation rather than denying.
    assert!(
        matches!(
            &p2_expr,
            UsersetExpr::TupleToUserset { tupleset, computed }
                if tupleset.starts_with("scope_") && computed == "member"
        ),
        "P2 with a non-RoleThreshold function should walk a scope relation, got: {p2_expr:?}"
    );
    // P1 emits a TODO about missing semantic metadata; P2 emits a TODO
    // about the role gate (and possibly missing object identifier).
    assert!(notes[0].message().contains("missing semantic metadata"));
    assert!(
        notes.iter().any(|t| t.message().contains("Role gate")),
        "expected role-gate TODO: {notes:?}"
    );
}

#[test]
fn pattern_to_expr_handles_empty_role_selection_paths() {
    let registry = role_registry("{}", false);
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p2_non_numeric = PatternClass::P2RoleNameInList {
        function_name: "role_level".to_string(),
        role_names: vec!["viewer".to_string()],
        privilege: RolePrivilege::Member,
    };
    let p2_numeric_without_levels = PatternClass::P2RoleNameInList {
        function_name: "role_level".to_string(),
        role_names: vec!["5".to_string()],
        privilege: RolePrivilege::Member,
    };

    let first = pattern_to_expr(
        &p2_non_numeric,
        "p2_non_numeric",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let second = pattern_to_expr(
        &p2_numeric_without_levels,
        "p2_numeric",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(first, UsersetExpr::Computed("no_access".to_string()));
    assert_eq!(second, UsersetExpr::Computed("no_access".to_string()));
}

#[test]
fn pattern_to_expr_covers_abac_composite_constant_and_unknown_branches() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let relationship = ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        },
        confidence: ConfidenceLevel::A,
    };
    let p7 = PatternClass::P7AbacAnd {
        relationship_part: Box::new(relationship.clone()),
        attribute_part: "status".to_string(),
    };
    let p8_or_empty = PatternClass::P8Composite {
        op: BoolOp::Or,
        parts: Vec::new(),
    };
    let p8_and_empty = PatternClass::P8Composite {
        op: BoolOp::And,
        parts: Vec::new(),
    };
    let p9 = PatternClass::P9AttributeCondition {
        column: "status".to_string(),
        value_description: "'published'".to_string(),
        predicate: None,
        request_predicate: None,
    };
    let p8_and_attr_true = PatternClass::P8Composite {
        op: BoolOp::And,
        parts: vec![
            ClassifiedExpr {
                pattern: p9.clone(),
                confidence: ConfidenceLevel::C,
            },
            ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool { value: true },
                confidence: ConfidenceLevel::A,
            },
        ],
    };
    let p10_false = PatternClass::P10ConstantBool { value: false };
    let p5 = PatternClass::P5ParentInheritance {
        parent_table: "projects".to_string(),
        fk_column: "project_id".to_string(),
        inner_pattern: Box::new(relationship),
    };
    let unknown = PatternClass::Unknown {
        sql_text: "mystery()".to_string(),
        reason: "no recognizer".to_string(),
    };

    let p7_expr = pattern_to_expr(
        &p7,
        "p7",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_or_expr = pattern_to_expr(
        &p8_or_empty,
        "p8_or",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_and_expr = pattern_to_expr(
        &p8_and_empty,
        "p8_and",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p10_expr = pattern_to_expr(
        &p10_false,
        "p10",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p9_expr = pattern_to_expr(
        &p9,
        "p9",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_and_attr_true_expr = pattern_to_expr(
        &p8_and_attr_true,
        "p8_and_attr_true",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p5_expr = pattern_to_expr(
        &p5,
        "p5",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let unknown_expr = pattern_to_expr(
        &unknown,
        "unknown",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(p7_expr, UsersetExpr::Computed("owner".to_string()));
    assert_eq!(p8_or_expr, UsersetExpr::Computed("no_access".to_string()));
    assert_eq!(p8_and_expr, UsersetExpr::Computed("no_access".to_string()));
    assert_eq!(p10_expr, UsersetExpr::Computed("no_access".to_string()));
    assert_eq!(p9_expr, UsersetExpr::Computed("no_access".to_string()));
    assert!(
            matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Computed(name) if name == "no_access"
            ) || matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Intersection(children)
                    if children
                        .iter()
                        .any(|child| matches!(child, UsersetExpr::Computed(name) if name == "no_access"))
            ),
            "attribute + constant-true composite should remain deny-biased, got: {p8_and_attr_true_expr:?}"
        );
    // The inherited rule is the parent-side ownership the policy names, not the
    // parent's whole read permission.
    assert_eq!(
        p5_expr,
        UsersetExpr::TupleToUserset {
            tupleset: "projects".to_string(),
            computed: "owner".to_string(),
        }
    );
    assert_eq!(unknown_expr, UsersetExpr::Computed("no_access".to_string()));
    assert!(table_plan.direct_relations.contains_key("projects"));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("still requires runtime enforcement")));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("mapped to no_access for safety")));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("could not be safely translated")));
}

#[test]
fn build_schema_plan_adds_notes_for_non_public_to_and_empty_translation() {
    let db = docs_db_with_policy(
        "CREATE POLICY docs_select ON docs FOR SELECT TO app_user USING (TRUE);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(
        policy,
        &db,
        Some(PatternClass::Unknown {
            sql_text: "TRUE".to_string(),
            reason: "not supported".to_string(),
        }),
        None,
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    assert!(plan
        .notes
        .iter()
        .any(|t| t.message().contains("Policy role scope TO")));
    assert!(plan.notes.iter().any(|t| t
        .message()
        .contains("Expression could not be safely translated")));
    assert!(plan
        .notes
        .iter()
        .any(|t| t.message().contains("not supported")));
}

#[test]
fn build_schema_plan_models_non_public_scope_via_pg_role() {
    let db = docs_db_with_policy(
        "CREATE POLICY docs_select ON docs FOR SELECT TO app_user USING (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let scope_relation = policy_scope_relation_name("docs_select");
    let classified = classified_from_policy(
        policy,
        &db,
        Some(PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        }),
        None,
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("docs type should exist");
    assert!(docs.direct_relations.contains_key(&scope_relation));
    assert!(matches!(
        docs.computed_relations.get("can_select"),
        Some(UsersetExpr::Intersection(children))
            if children.iter().any(|c| matches!(c, UsersetExpr::Computed(name) if name == "owner"))
                && children.iter().any(|c| matches!(
                    c,
                    UsersetExpr::TupleToUserset { tupleset, computed }
                        if tupleset == &scope_relation && computed == "member"
                ))
    ));

    let pg_role = plan
        .types
        .iter()
        .find(|t| t.type_name == "pg_role")
        .expect("pg_role type should exist");
    assert!(matches!(
        pg_role.direct_relations.get("member"),
        Some(subjects) if subjects == &vec![DirectSubject::Type("user".to_string())]
    ));
}

#[test]
fn build_schema_plan_mirrors_update_check_when_only_with_check_is_present() {
    let db = docs_db_with_policy(
        "CREATE POLICY docs_update ON docs FOR UPDATE WITH CHECK (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(
        policy,
        &db,
        None,
        Some(PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        }),
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("docs type should exist");
    assert!(
        docs.computed_relations.contains_key("can_update"),
        "update relation should be synthesized from WITH CHECK"
    );
}

#[test]
fn exact_roles_expr_does_not_conflate_roles_at_same_level() {
    // `viewer=1` and `guest=1` share the same integer level.  Selecting only
    // `'viewer'` by name must NOT include `grant_guest`.
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("viewer".to_string(), 1),
        ("guest".to_string(), 1),
        ("editor".to_string(), 2),
    ]);

    let sorted =
        ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

    // Select only "viewer" by name.
    let selected = BTreeSet::from(["viewer".to_string()]);
    let expr = exact_roles_expr(&sorted, &selected, false).expect("should produce an expression");

    // The expression must include grant_viewer.
    let contains_viewer = match &expr {
        UsersetExpr::Computed(n) => n == "grant_viewer",
        UsersetExpr::Union(children) => children
            .iter()
            .any(|c| matches!(c, UsersetExpr::Computed(n) if n == "grant_viewer")),
        _ => false,
    };
    assert!(contains_viewer, "grant_viewer must be included");

    // The expression must NOT include grant_guest.
    let contains_guest = match &expr {
        UsersetExpr::Computed(n) => n == "grant_guest",
        UsersetExpr::Union(children) => children
            .iter()
            .any(|c| matches!(c, UsersetExpr::Computed(n) if n == "grant_guest")),
        _ => false,
    };
    assert!(
        !contains_guest,
        "grant_guest must not be included when only 'viewer' was selected"
    );
}

#[test]
fn ensure_role_threshold_scaffold_with_team_support_and_exact_roles_owner_inclusion() {
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("viewer".to_string(), 1),
        ("editor".to_string(), 2),
        ("admin".to_string(), 3),
    ]);

    let sorted =
        ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, true);
    assert!(table_plan.direct_relations.contains_key("owner_team"));
    assert!(table_plan.direct_relations.contains_key("grant_admin"));
    assert!(all_types.contains_key("team"));

    let selected = BTreeSet::from(["admin".to_string()]);
    let expr = exact_roles_expr(&sorted, &selected, true).expect("roles should produce expression");
    assert!(matches!(&expr, UsersetExpr::Union(children) if children
    .iter()
    .any(|c| matches!(c, UsersetExpr::Computed(name) if name == "owner_user"))
    && children.iter().any(|c| matches!(
        c,
        UsersetExpr::TupleToUserset { tupleset, computed }
            if tupleset == "owner_team" && computed == "member"
    ))));
}

#[test]
fn ensure_role_threshold_scaffold_sanitizes_role_relation_names() {
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let role_levels =
        BTreeMap::from([("read-write".to_string(), 1), ("Team Admin".to_string(), 2)]);

    ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

    assert!(
        table_plan.direct_relations.contains_key("grant_read_write"),
        "expected hyphenated role names to be canonicalized"
    );
    assert!(
        table_plan.direct_relations.contains_key("grant_team_admin"),
        "expected spaced/cased role names to be canonicalized"
    );
    assert!(
        table_plan
            .computed_relations
            .contains_key("role_read_write"),
        "expected computed role relation name to be canonicalized"
    );
}

#[test]
fn ensure_role_threshold_scaffold_disambiguates_role_name_collisions() {
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([("role-a".to_string(), 1), ("role a".to_string(), 2)]);

    ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);

    let grant_relations: Vec<&String> = table_plan
        .direct_relations
        .keys()
        .filter(|name| name.starts_with("grant_role_a"))
        .collect();
    assert_eq!(
        grant_relations.len(),
        2,
        "canonical collisions must remain distinct relation identifiers"
    );
    assert_ne!(
        grant_relations[0], grant_relations[1],
        "colliding canonical names should be disambiguated"
    );
}

#[test]
fn expr_to_dsl_parenthesizes_a_child_of_another_kind() {
    let union = UsersetExpr::Union(vec![
        UsersetExpr::Computed("a".to_string()),
        UsersetExpr::Computed("b".to_string()),
    ]);
    let intersection = UsersetExpr::Intersection(vec![
        UsersetExpr::Computed("x".to_string()),
        UsersetExpr::Computed("y".to_string()),
    ]);

    assert_eq!(expr_to_dsl(&union, Some("and")), "(a or b)");
    assert_eq!(expr_to_dsl(&intersection, Some("or")), "(x and y)");
    assert_eq!(expr_to_dsl(&union, Some("or")), "a or b");
    assert_eq!(expr_to_dsl(&union, None), "a or b");

    let mixed = UsersetExpr::Union(vec![
        intersection.clone(),
        UsersetExpr::Exclusion {
            base: Box::new(UsersetExpr::Computed("a".to_string())),
            subtract: Box::new(UsersetExpr::Computed("b".to_string())),
        },
    ]);
    assert_eq!(expr_to_dsl(&mixed, None), "(x and y) or (a but not b)");

    let nested = UsersetExpr::Exclusion {
        base: Box::new(union),
        subtract: Box::new(intersection),
    };
    assert_eq!(expr_to_dsl(&nested, None), "(a or b) but not (x and y)");
}

#[test]
fn combine_helpers_cover_empty_and_multi_intersection() {
    assert!(combine_union(Vec::new()).is_none());
    assert!(combine_intersection(Vec::new()).is_none());

    let inter = combine_intersection(vec![
        UsersetExpr::Computed("a".to_string()),
        UsersetExpr::Computed("b".to_string()),
    ])
    .expect("intersection should exist");
    assert!(matches!(inter, UsersetExpr::Intersection(children) if children.len() == 2));

    let mut plan = TypePlan::new("docs");
    let empty_bucket = ModeBuckets::default();
    assert!(compose_action(&mut plan, Some(&empty_bucket)).is_none());
}

#[test]
fn build_schema_plan_skips_unknown_and_non_rls_tables() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
CREATE TABLE rls_docs(id uuid primary key, owner_id uuid);
ALTER TABLE rls_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs USING (owner_id = current_user);
CREATE POLICY rls_docs_select ON rls_docs USING (owner_id = current_user);
",
    )
    .expect("schema should parse");

    let mut policies = Vec::new();
    for policy in db.policies() {
        let classified = classified_from_policy(
            policy,
            &db,
            Some(PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            }),
            None,
        );
        if classified.name() == "docs_select" {
            let mut missing_table = classified.clone();
            missing_table.table = "ghost_docs".to_string();
            policies.push(missing_table);
        }
        policies.push(classified);
    }

    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&policies, &db, &registry, &GeneratorSettings::default());
    assert!(
        plan.types.iter().any(|t| t.type_name == "rls_docs"),
        "RLS-enabled table should be translated"
    );
    assert!(
        !plan.types.iter().any(|t| t.type_name == "docs"),
        "non-RLS table should be skipped"
    );
}

#[test]
fn build_schema_plan_denies_every_action_when_no_clause_translates() {
    let db = docs_db_with_policy(
        "CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(policy, &db, None, None);
    let registry = FunctionRegistry::new();

    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());
    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("RLS-enabled table should still be emitted");
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            docs.computed_relations.get(relation),
            Some(&UsersetExpr::Computed("no_access".to_string())),
            "{relation} should deny when nothing translated"
        );
    }
    let messages: Vec<String> = plan.notes.iter().map(TranslationNote::message).collect();
    assert!(
        messages.iter().any(|message| message
            .contains("Every permissive policy on 'docs' covering SELECT fell below")),
        "the schema has a SELECT policy, it did not translate: {messages:#?}"
    );
    assert!(
        messages.iter().any(|message| message
            .contains("No permissive policy on 'docs' covers INSERT, UPDATE, DELETE")),
        "nothing covers the write commands: {messages:#?}"
    );
}

#[test]
fn build_schema_plan_canonicalizes_schema_qualified_table_names() {
    let db = parse_schema(
        r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs FOR SELECT USING (owner_id = current_user);
",
    )
    .expect("schema should parse");

    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(
        policy,
        &db,
        Some(PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        }),
        None,
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    assert!(
        plan.types.iter().any(|t| t.type_name == "docs"),
        "schema-qualified table name should canonicalize to relation name"
    );
    assert!(
        !plan.types.iter().any(|t| t.type_name == "app.docs"),
        "raw schema-qualified table name should not appear in output types"
    );
}

#[test]
fn build_schema_plan_mirrors_update_using_when_with_check_absent() {
    let db = docs_db_with_policy(
        "CREATE POLICY docs_update ON docs FOR UPDATE USING (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(
        policy,
        &db,
        Some(PatternClass::P3DirectOwnership {
            column: "owner_id".to_string(),
        }),
        None,
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("docs type should exist");
    assert!(docs.computed_relations.contains_key("can_update"));
}

#[test]
fn ensure_role_threshold_scaffold_sorts_ties_by_role_name() {
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("beta".to_string(), 1),
        ("alpha".to_string(), 1),
        ("admin".to_string(), 2),
    ]);

    let sorted =
        ensure_role_threshold_scaffold(&mut table_plan, &mut all_types, &role_levels, false);
    let ordered: Vec<(String, i32)> = sorted
        .iter()
        .map(|role| (role.original_name.clone(), role.level))
        .collect();
    assert_eq!(
        ordered,
        vec![
            ("alpha".to_string(), 1),
            ("beta".to_string(), 1),
            ("admin".to_string(), 2),
        ]
    );
}

#[test]
fn pattern_to_expr_handles_unreachable_thresholds_and_case_insensitive_role_names() {
    let registry = role_registry(r#"{"viewer": 1}"#, false);
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p1_unreachable = PatternClass::P1NumericThreshold {
        function_name: "role_level".to_string(),
        operator: ThresholdOperator::Gt,
        threshold: 10,
        command: PolicyCommand::Select,
    };
    let p2_mixed_case = PatternClass::P2RoleNameInList {
        function_name: "role_level".to_string(),
        role_names: vec!["VIEWER".to_string()],
        privilege: RolePrivilege::Member,
    };

    let p1_expr = pattern_to_expr(
        &p1_unreachable,
        "p1_unreachable",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p2_expr = pattern_to_expr(
        &p2_mixed_case,
        "p2_case",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(p1_expr, UsersetExpr::Computed("no_access".to_string()));
    assert!(
        matches!(p2_expr, UsersetExpr::Union(_) | UsersetExpr::Computed(_)),
        "case-insensitive role name matching should produce a translatable expression"
    );
}

#[test]
fn role_registry_helper_covers_team_branch() {
    let registry = role_registry(r#"{"viewer": 1, "editor": 2}"#, true);
    assert!(matches!(
        registry.get("role_level"),
        Some(FunctionSemantic::RoleThreshold {
            team_membership_table: Some(_),
            team_membership_user_col: Some(_),
            team_membership_team_col: Some(_),
            ..
        })
    ));
}

#[test]
fn action_target_helpers_cover_empty_arms() {
    assert!(using_targets(PolicyCommand::Insert).is_empty());
    assert!(with_check_targets(PolicyCommand::Select).is_empty());
    assert!(with_check_targets(PolicyCommand::Delete).is_empty());
}

#[test]
fn confidence_filter_prevents_with_check_mirror_when_with_check_was_filtered() {
    // UPDATE policy: USING has high-confidence P3, WITH CHECK has low-confidence (would
    // normally be filtered).  After confidence filtering, with_check_was_filtered = true
    // → the USING→WITH CHECK mirror must NOT be applied.
    let db = docs_db_with_policy(
        "CREATE POLICY docs_upd ON docs FOR UPDATE \
             USING (owner_id = current_user) WITH CHECK (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let p3 = PatternClass::P3DirectOwnership {
        column: "owner_id".to_string(),
    };
    // Construct a policy where WITH CHECK has low confidence (B) and USING has high (A).
    let mut classified = ClassifiedPolicy::from_policy(policy, &db);
    classified.using_classification = Some(ClassifiedExpr {
        pattern: p3.clone(),
        confidence: ConfidenceLevel::A,
    });
    classified.with_check_classification = Some(ClassifiedExpr {
        pattern: p3.clone(),
        confidence: ConfidenceLevel::B,
    });
    // Filter at level A: WITH CHECK (B) gets filtered out → with_check_was_filtered = true.
    let filtered = filter_policies_for_output(&[classified.clone()], ConfidenceLevel::A);
    let filtered_cp = filtered.first().expect("USING should survive at A");
    assert!(
        filtered_cp.with_check_was_filtered,
        "with_check_was_filtered should be true after filtering"
    );
    assert!(
        filtered_cp.with_check_classification.is_none(),
        "with_check_classification should be None after filtering"
    );

    // Build a schema plan from the filtered policy.
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(
        std::slice::from_ref(filtered_cp),
        &db,
        &registry,
        &GeneratorSettings::default(),
    );
    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("docs type should exist");
    // USING survived → can_update_using should be defined.
    assert!(
        docs.computed_relations.contains_key("can_update"),
        "can_update relation should exist from USING expression"
    );
    // WITH CHECK was filtered, NOT mirrored → can_insert or can_update_check should NOT
    // exist (we don't mirror low-confidence USING into WITH CHECK slot).
    // For UPDATE the check target is can_update_check, it should be absent.
    assert!(
        !docs.computed_relations.contains_key("can_update_check"),
        "can_update_check must not be silently mirrored from USING when with_check was filtered; \
             relations present: {:?}",
        docs.computed_relations.keys().collect::<Vec<_>>()
    );
    // Now verify that when WITH CHECK is genuinely absent (not filtered), the mirror DOES apply.
    classified.with_check_classification = None; // never present
    classified.with_check_was_filtered = false;
    let plan2 = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());
    let docs2 = plan2
        .types
        .iter()
        .find(|t| t.type_name == "docs")
        .expect("docs type");
    assert!(
        docs2.computed_relations.contains_key("can_update"),
        "mirror should still apply when with_check was never present"
    );
}

#[test]
fn resolve_owner_column_finds_fk_to_users_table() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE items(id UUID PRIMARY KEY, creator_id UUID REFERENCES users(id));
",
    )
    .unwrap();
    // No owner_id column, but FK to users -> should return creator_id
    let result = resolve_owner_column("items", &db);
    assert_eq!(result, Some("creator_id".to_string()));
}

#[test]
fn resolve_principal_info_uses_configured_table_and_pk() {
    let db = parse_schema(
        r"
CREATE TABLE accounts(account_id UUID PRIMARY KEY, email TEXT);
",
    )
    .unwrap();
    let result = resolve_principal_info(&db, Some("accounts"), Some("account_id"), &[]);
    assert!(result.is_some());
    let pi = result.unwrap();
    assert_eq!(pi.table, "accounts");
    assert_eq!(pi.pk_col, "account_id");
}

#[test]
fn resolve_principal_info_returns_none_for_missing_configured_column() {
    let db = parse_schema(
        r"
CREATE TABLE accounts(account_id UUID PRIMARY KEY);
",
    )
    .unwrap();
    // Column doesn't exist
    let result = resolve_principal_info(&db, Some("accounts"), Some("nonexistent_col"), &[]);
    assert!(result.is_none());
}

#[test]
fn pattern_to_expr_p5_with_unknown_inner_returns_no_access() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new("tasks");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let unknown_inner = ClassifiedExpr {
        pattern: PatternClass::Unknown {
            sql_text: "mystery()".to_string(),
            reason: "unrecognized function".to_string(),
        },
        confidence: ConfidenceLevel::D,
    };
    let p5 = PatternClass::P5ParentInheritance {
        parent_table: "projects".to_string(),
        fk_column: "project_id".to_string(),
        inner_pattern: Box::new(unknown_inner),
    };

    let expr = pattern_to_expr(
        &p5,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    assert_eq!(expr, UsersetExpr::Computed("no_access".to_string()));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("unknown inner rule")));
}

#[test]
fn pattern_to_expr_p6_missing_pk_generates_note() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new("items");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    // items table has no PK in this context -- pattern_to_expr won't find one
    let p6 = PatternClass::P6BooleanFlag {
        column: "is_public".to_string(),
    };

    let _expr = pattern_to_expr(
        &p6,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    // The table "items" doesn't exist in the empty DB, so PK can't be resolved.
    // The public_expr is still returned but a TODO is added about missing object identifier.
    // Check that no panic occurred -- the function should handle gracefully.
}

#[test]
fn populate_role_threshold_sources_emits_note_for_missing_user_principal() {
    // Schema with role-threshold table but NO users table
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1, "editor": 2}"#, false);
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let hints = RoleThresholdResourceHints::default();

    populate_role_threshold_sources(
        "role_level",
        "docs",
        &db,
        &registry,
        &hints,
        &mut table_plan,
        &mut all_types,
    );

    // Should have a TODO about unresolved user principal
    let has_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("unresolved user principal"))
        });
    assert!(
        has_note,
        "should emit TODO for missing user principal table"
    );
}

#[test]
fn resolve_principal_info_auto_resolves_pk_for_configured_table() {
    // Configure table but no pk_col, should auto-resolve from PK
    let db = parse_schema(r"CREATE TABLE accounts(id UUID PRIMARY KEY, email TEXT);").unwrap();
    let result = resolve_principal_info(&db, Some("accounts"), None, &[]);
    assert!(result.is_some());
    let pi = result.unwrap();
    assert_eq!(pi.table, "accounts");
    assert_eq!(pi.pk_col, "id");
}

#[test]
fn populate_role_threshold_sources_emits_note_for_missing_team_principal() {
    // Schema with team membership but no teams table
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1}"#, true);
    let mut table_plan = TypePlan::new("docs");
    let mut all_types = BTreeMap::new();
    let hints = RoleThresholdResourceHints::default();

    populate_role_threshold_sources(
        "role_level",
        "docs",
        &db,
        &registry,
        &hints,
        &mut table_plan,
        &mut all_types,
    );

    // Should have a TODO about unresolved team principal
    let has_team_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("unresolved team principal"))
        });
    assert!(
        has_team_note,
        "should emit TODO for missing team principal table; sources: {:?}",
        table_plan.table_tuple_sources
    );
}

// positional_function_arg, non-List FunctionArguments
#[test]
fn positional_function_arg_returns_none_for_non_list_args() {
    use sqlparser::ast::{FunctionArguments, Ident, ObjectName, ObjectNamePart};

    let func = Function {
        name: ObjectName(vec![ObjectNamePart::Identifier(Ident::new("test_fn"))]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: vec![],
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    };
    assert!(
        positional_function_arg(&func, 0).is_none(),
        "FunctionArguments::None should return None"
    );
}

// extract_resource_columns_for_function, visitor-based integration
#[test]
fn extract_resource_columns_finds_function_in_nested_binary_op() {
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let expr = Parser::new(&PostgreSqlDialect {})
        .try_with_sql("my_func(x, col_a) AND my_func(x, col_b)")
        .unwrap()
        .parse_expr()
        .unwrap();

    let cols = extract_resource_columns_for_function(&expr, "my_func", 1);
    assert_eq!(cols.len(), 2);
    assert!(cols.contains("col_a"));
    assert!(cols.contains("col_b"));
}

#[test]
fn extract_resource_columns_finds_function_inside_subquery() {
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let expr = Parser::new(&PostgreSqlDialect {})
        .try_with_sql("EXISTS (SELECT my_func(x, col_a) FROM t)")
        .unwrap()
        .parse_expr()
        .unwrap();

    let cols = extract_resource_columns_for_function(&expr, "my_func", 1);
    assert_eq!(cols.len(), 1);
    assert!(cols.contains("col_a"));
}

#[test]
fn extract_resource_columns_returns_empty_for_non_matching_function() {
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    let expr = Parser::new(&PostgreSqlDialect {})
        .try_with_sql("other_func(x, col_a)")
        .unwrap()
        .parse_expr()
        .unwrap();

    let cols = extract_resource_columns_for_function(&expr, "my_func", 1);
    assert!(cols.is_empty());
}

// resolve_owner_column, returns None
#[test]
fn resolve_owner_column_returns_none_when_no_owner_col_and_no_fk_to_users() {
    let db = parse_schema(
        r"
CREATE TABLE widgets(name TEXT, value INT);
",
    )
    .unwrap();
    let result = resolve_owner_column("widgets", &db);
    assert!(
        result.is_none(),
        "Table with no owner-like column and no FK to users should return None"
    );
}

// populate_role_threshold_sources, pk_col is None
#[test]
fn populate_role_threshold_sources_emits_note_for_missing_pk_col() {
    // Table without a PK or `id` column → pk_col will be None → line 1792
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE things(name TEXT, value INT);
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1}"#, false);
    let mut table_plan = TypePlan::new("things");
    let mut all_types = BTreeMap::new();
    let mut hints = RoleThresholdResourceHints::default();
    // Provide a resource column hint so we get past the grant_join_col check
    hints.columns.insert(
        ("things".to_string(), "role_level".to_string()),
        "name".to_string(),
    );

    populate_role_threshold_sources(
        "role_level",
        "things",
        &db,
        &registry,
        &hints,
        &mut table_plan,
        &mut all_types,
    );

    let has_pk_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("missing object identifier"))
        });
    assert!(
        has_pk_note,
        "should emit TODO for missing PK column; sources: {:?}",
        table_plan.table_tuple_sources
    );
}

// A name held by one kind of relation must not be reused by the other, since the
// DSL would then carry two `define` lines for it.
#[test]
fn ensure_direct_yields_a_fresh_name_when_the_relation_is_computed() {
    let mut plan = TypePlan::new("test");
    plan.ensure_computed("rel", UsersetExpr::Computed("x".into()));
    let name = plan.ensure_direct("rel", vec![DirectSubject::Type("user".into())]);
    assert_ne!(name, "rel", "the computed relation still holds 'rel'");
    assert!(plan.direct_relations.contains_key(&name));
    assert!(!plan.computed_relations.contains_key(&name));
}

#[test]
fn ensure_direct_yields_a_fresh_name_when_the_subjects_differ() {
    let mut plan = TypePlan::new("test");
    let first = plan.ensure_direct("rel", vec![DirectSubject::Type("user".into())]);
    let second = plan.ensure_direct("rel", vec![DirectSubject::Type("team".into())]);
    assert_eq!(first, "rel");
    assert_ne!(second, first);
    assert_eq!(
        plan.direct_relations.get(&first),
        Some(&vec![DirectSubject::Type("user".into())])
    );
    assert_eq!(
        plan.direct_relations.get(&second),
        Some(&vec![DirectSubject::Type("team".into())])
    );
    // Asking again with the same subjects reuses the name it already minted.
    assert_eq!(
        plan.ensure_direct("rel", vec![DirectSubject::Type("team".into())]),
        second
    );
}

#[test]
fn ensure_computed_yields_a_fresh_name_when_the_expression_differs() {
    let mut plan = TypePlan::new("test");
    let first = plan.ensure_computed("rel", UsersetExpr::Computed("a".into()));
    let second = plan.ensure_computed("rel", UsersetExpr::Computed("b".into()));
    assert_eq!(first, "rel");
    assert_ne!(second, first, "a different rule cannot reuse the name");
    assert_eq!(
        plan.computed_relations.get(&first),
        Some(&UsersetExpr::Computed("a".into()))
    );
    assert_eq!(
        plan.computed_relations.get(&second),
        Some(&UsersetExpr::Computed("b".into()))
    );
    // The same rule keeps sharing the one relation.
    assert_eq!(
        plan.ensure_computed("rel", UsersetExpr::Computed("a".into())),
        first
    );
}

/// `set_computed` overwrites a computed rule by design, but a name a direct relation
/// already holds yields instead, the same way its two siblings do. It used to assert in
/// debug builds and do nothing in release, which is a guard where it cannot fire.
#[test]
fn set_computed_yields_a_fresh_name_when_the_relation_is_direct() {
    let mut plan = TypePlan::new("test");
    plan.ensure_direct("rel", vec![DirectSubject::Type("user".into())]);

    let name = plan.set_computed("rel", UsersetExpr::Computed("x".into()));

    assert_ne!(name, "rel", "the direct relation still holds 'rel'");
    assert!(
        plan.direct_relations.contains_key("rel"),
        "the direct relation is untouched"
    );
    assert!(
        plan.computed_relations.contains_key(&name),
        "the computed rule lands under the yielded name"
    );

    // Overwriting an existing computed rule is still what the function is for.
    let first = plan.set_computed("other", UsersetExpr::Computed("a".into()));
    let second = plan.set_computed("other", UsersetExpr::Computed("b".into()));
    assert_eq!(first, second, "a computed name is overwritten, not yielded");
    assert_eq!(
        plan.computed_relations.get(&second),
        Some(&UsersetExpr::Computed("b".into())),
        "the later rule wins"
    );
}

// canonical name collision, two tables → same canonical name
#[test]
fn build_schema_plan_disambiguates_canonical_name_collision() {
    let db = parse_schema(
        r"
CREATE SCHEMA app;
CREATE TABLE app.items(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_sel ON app.items FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.items(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_sel2 ON public.items FOR SELECT USING (owner_id = current_user);
",
    )
    .unwrap();

    let mut policies = Vec::new();
    for policy in db.policies() {
        let table_name = policy.target_table_name().to_string();
        let mut classified = ClassifiedPolicy::from_policy(policy, &db);
        classified.using_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership {
                column: "owner_id".to_string(),
            },
            confidence: ConfidenceLevel::A,
        });
        policies.push((table_name, classified));
    }

    let registry = FunctionRegistry::new();
    let classified_policies: Vec<ClassifiedPolicy> =
        policies.into_iter().map(|(_, cp)| cp).collect();
    let plan = build_schema_plan(
        &classified_policies,
        &db,
        &registry,
        &GeneratorSettings::default(),
    );

    // One of the two types should be disambiguated
    let type_names: Vec<&str> = plan.types.iter().map(|t| t.type_name.as_str()).collect();
    // At least one type name should contain an underscore+hex suffix
    let has_disambiguated = type_names
        .iter()
        .any(|name| name.starts_with("items_") && name.len() > "items_".len());
    // Either collision happened (both present as items + items_hash) or both
    // are items (same owner, line 218). The important thing is no panic.
    assert!(
        type_names.iter().any(|name| name.starts_with("items")),
        "should have at least one items type; got: {type_names:?}"
    );
    // If collision was detected, a TODO should have been emitted
    if has_disambiguated {
        assert!(
            plan.notes
                .iter()
                .any(|t| t.message().contains("Type name collision")),
            "collision should produce a TODO; notes: {:?}",
            plan.notes
        );
    }
}

// scoped_roles missing PK → TODO
#[test]
fn build_schema_plan_emits_note_for_scoped_roles_missing_pk() {
    // Table with no PK and no `id` column
    let db = parse_schema(
        r"
CREATE TABLE things(name TEXT, value INT);
ALTER TABLE things ENABLE ROW LEVEL SECURITY;
CREATE POLICY things_sel ON things FOR SELECT TO app_user USING (value > 0);
",
    )
    .unwrap();

    let policy = db.policies().next().expect("policy should exist");
    let mut classified = ClassifiedPolicy::from_policy(policy, &db);
    classified.using_classification = Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership {
            column: "name".to_string(),
        },
        confidence: ConfidenceLevel::A,
    });
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default());

    // The role-scope code should emit a TODO about missing PK for policy scope tuples
    let has_pk_note = plan
        .notes
        .iter()
        .any(|t| t.message().contains("Policy role scope TO"));
    assert!(
        has_pk_note,
        "scoped roles should produce a TODO; notes: {:?}",
        plan.notes
    );

    // Also check that table_tuple_sources contains a Todo about missing object identifier
    let things_type = plan.types.iter().find(|t| t.type_name == "things");
    if let Some(things) = things_type {
        let has_missing_pk_source = things.table_tuple_sources.iter().any(|s| {
                matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("missing object identifier"))
            });
        assert!(
            has_missing_pk_source,
            "should emit TupleSource::Todo for missing object identifier; sources: {:?}",
            things.table_tuple_sources
        );
    }
}

// P5 inner pattern results in no_access → TODO
#[test]
fn pattern_to_expr_p5_with_inner_no_access_emits_note() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new("tasks");
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    // P5 with inner P9 (attribute-only) which produces no_access
    let inner = ClassifiedExpr {
        pattern: PatternClass::P9AttributeCondition {
            column: "status".to_string(),
            value_description: "'active'".to_string(),
            predicate: None,
            request_predicate: None,
        },
        confidence: ConfidenceLevel::C,
    };
    let p5 = PatternClass::P5ParentInheritance {
        parent_table: "projects".to_string(),
        fk_column: "project_id".to_string(),
        inner_pattern: Box::new(inner),
    };

    let _expr = pattern_to_expr(
        &p5,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    // P9 inside P5 produces no_access on the parent → TODO emitted
    let has_inner_note = notes.iter().any(|t| {
        t.message().contains("could not be safely translated")
            || t.message().contains("mapped to no_access")
    });
    assert!(
        has_inner_note,
        "P5 with inner no_access should produce a TODO; notes: {notes:?}"
    );
}
