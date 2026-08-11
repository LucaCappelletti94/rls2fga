//! Emission for the patterns a role decides, and the scaffolding they need.
//!
//! A numeric threshold, a role-name list, the `pg_role` scope a `TO` clause narrows by, and the
//! grant relations a role-threshold function implies.

use super::*;

/// The scope a `TO` clause narrows by, described in one value.
///
/// Five of these travelled as separate arguments and are one description: the relation to
/// declare, the `pg_role` relation the caller's walk reads, the roles admitted, the note to
/// raise, and what to say went unfilled when no tuple can name the row.
pub(crate) struct RoleScopeSpec<'a> {
    /// Relation to declare on the guarded type.
    pub(crate) scope_relation: &'a RelationName,
    /// The `pg_role` relation the caller's walk reads. Declared here so the walk and the
    /// relation the operator loads cannot drift apart.
    pub(crate) walked: &'a RelationName,
    /// Roles the clause admits.
    pub(crate) role_names: &'a [String],
    /// Note raised once the scope is declared.
    pub(crate) scope_note: TranslationNote,
    /// What went unfilled, for the note raised when no tuple can name the row.
    pub(crate) missing_object_what: &'a str,
}

/// Declare the `pg_role` scope a policy's `TO` clause narrows by, and load it.
///
/// Returns whether a tuple can name a row of the table. Where none can, the scope is
/// left unminted rather than declared empty: a scope relation nothing can fill asks the
/// operator for `pg_role` memberships no rule reads, and a caller whose whole grant
/// rides on the scope falls closed on the answer.
pub(crate) fn register_pg_role_scope<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    source_table: &str,
    policy_name: &str,
    db: &DB,
    spec: RoleScopeSpec<'_>,
) -> bool {
    let RoleScopeSpec {
        scope_relation,
        walked,
        role_names,
        scope_note,
        missing_object_what,
    } = spec;
    if let Some(pk_cols) = resolve_pk_columns(source_table, db) {
        ensure_pg_role_relation(all_types, walked);
        table_plan.ensure_direct(
            scope_relation.clone(),
            vec![DirectSubject::Type(PG_ROLE_TYPE.to_string())],
        );
        notes.push(scope_note);
        for role in role_names {
            let pg_role = canonical_fga_type_name(role);
            // A quoted role can rewrite onto a different existing role, which
            // changes who the policy admits.
            if normalize_identifier(role) != pg_role {
                notes.push(TranslationNote::RoleNameRewritten {
                    policy: policy_name.to_string(),
                    role: role.clone(),
                    pg_role: pg_role.clone(),
                });
            }
            table_plan.add_source(TupleSource::PolicyScope {
                table: source_table.to_string(),
                pk_cols: pk_cols.clone(),
                scope_relation: scope_relation.clone(),
                pg_role,
            });
        }
        true
    } else {
        skip_source_without_row_identity(table_plan, source_table, missing_object_what, db);
        false
    }
}

/// Handle `P2RoleNameInList` when the function is *not* a `RoleThreshold` (e.g.
/// `pg_has_role()` or Supabase `auth.role()`).  Creates scope-style direct
/// relations per role name and emits `PolicyScope` tuple sources, mirroring the
/// pattern used for policy-level `TO` role scoping.
pub(crate) fn handle_p2_role_gate<DB: DatabaseLike>(
    role_names: &[String],
    privilege: RolePrivilege,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    let db = ctx.db;
    if role_names.is_empty() {
        return deny_expr(table_plan);
    }

    let scope_relation = policy_scope_relation_name(policy_name);
    let held_by = privilege.relation_name();
    let scope_can_be_filled = register_pg_role_scope(
        table_plan,
        all_types,
        notes,
        source_table,
        policy_name,
        db,
        RoleScopeSpec {
            scope_relation: &scope_relation,
            walked: &held_by,
            role_names,
            scope_note: TranslationNote::RoleGateScope {
                policy: policy_name.to_string(),
                roles: role_names.to_vec(),
                relation: scope_relation.clone(),
                held_by: held_by.to_string(),
            },
            missing_object_what: "role gate tuples",
        },
    );
    // The whole grant is the scope, so an unfillable one is a permission nothing can
    // satisfy rather than a narrower one.
    if !scope_can_be_filled {
        return deny_expr(table_plan);
    }

    // The scope relation holds `[pg_role]` subjects, so a `user:` subject can never satisfy
    // it directly. Walking it to the role's holders is what admits them, and it is what
    // makes the relation survive the pruner.
    UsersetExpr::TupleToUserset {
        tupleset: scope_relation,
        computed: held_by,
    }
}

/// The relation a numeric role threshold admits, or a denial when no role reaches it.
pub(crate) fn emit_numeric_threshold<DB: DatabaseLike>(
    numeric_threshold: &NumericThreshold,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let NumericThreshold {
        function_name,
        operator,
        threshold,
        ..
    } = numeric_threshold;
    let Some(prepared) = prepare_role_threshold_translation(
        function_name,
        "Role-threshold",
        ctx,
        table_plan,
        all_types,
        notes,
    ) else {
        return deny_expr(table_plan);
    };
    if !prepared.rows_can_be_named {
        return deny_expr(table_plan);
    }

    let min_level = match operator {
        ThresholdOperator::Gte => *threshold,
        ThresholdOperator::Gt => threshold.saturating_add(1),
    };

    if let Some(role_relation) = role_for_level(&prepared.sorted_roles, min_level) {
        UsersetExpr::Computed(role_relation)
    } else {
        deny_expr(table_plan)
    }
}

/// The relations a role-name list admits, whether the function is a role threshold or a plain role accessor.
pub(crate) fn emit_role_name_in_list<DB: DatabaseLike>(
    role_name_in_list: &RoleNameInList,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let RoleNameInList {
        function_name,
        role_names,
        privilege,
    } = role_name_in_list;
    let Some(prepared) = prepare_role_threshold_translation(
        function_name,
        "Role-list",
        ctx,
        table_plan,
        all_types,
        notes,
    ) else {
        // Non-RoleThreshold function (e.g. pg_has_role, auth.role()) ,
        // fall back to scope-style direct relations per role name.
        return handle_p2_role_gate(role_names, *privilege, ctx, table_plan, all_types, notes);
    };
    if !prepared.rows_can_be_named {
        return deny_expr(table_plan);
    }

    // Matched by name, not by level, so `viewer=1` and `guest=1` stay
    // distinct. A numeric item means every role at that level.
    let mut selected_names: BTreeSet<String> = BTreeSet::new();
    for role in role_names {
        if let Ok(level) = role.parse::<i32>() {
            // Numeric string → expand to all role names at this level.
            for r in &prepared.sorted_roles {
                if r.level == level {
                    selected_names.insert(r.original_name.to_lowercase());
                }
            }
            continue;
        }
        // Role name string → insert directly (case-insensitive).
        selected_names.insert(role.to_lowercase());
    }

    if selected_names.is_empty() {
        return deny_expr(table_plan);
    }

    if let Some(expr) = exact_roles_expr(
        &prepared.sorted_roles,
        &selected_names,
        prepared.has_team_support,
    ) {
        expr
    } else {
        deny_expr(table_plan)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RoleThresholdPrepared {
    sorted_roles: Vec<RoleRelationName>,
    has_team_support: bool,
    /// Whether a tuple can name a row of the guarded table. Every grant a role
    /// threshold mints is keyed on one, so without it the whole rule falls closed.
    rows_can_be_named: bool,
}

pub(crate) fn prepare_role_threshold_translation<DB: DatabaseLike>(
    function_name: &str,
    function_kind_label: &str,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> Option<RoleThresholdPrepared> {
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    let registry = ctx.registry;
    let hints = ctx.hints;
    let db = ctx.db;
    let Some(FunctionSemantic::RoleThreshold {
        role_levels,
        team_membership_table,
        ..
    }) = registry.get(function_name)
    else {
        notes.push(TranslationNote::FunctionMissingMetadata {
            policy: policy_name.to_string(),
            function_kind: function_kind_label.to_string(),
            function: function_name.to_string(),
        });
        return None;
    };

    let has_team_support = team_membership_table.is_some();
    let sorted_roles =
        ensure_role_threshold_scaffold(table_plan, all_types, role_levels, has_team_support);
    populate_role_threshold_sources(
        function_name,
        source_table,
        db,
        registry,
        hints,
        table_plan,
        all_types,
    );

    Some(RoleThresholdPrepared {
        sorted_roles,
        has_team_support,
        rows_can_be_named: resolve_pk_columns(source_table, db).is_some(),
    })
}

pub(crate) fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    role_levels: &BTreeMap<String, i32>,
    has_team_support: bool,
) -> Vec<RoleRelationName> {
    let sorted_roles = sorted_role_relation_names(role_levels);

    table_plan.ensure_direct(
        owner_user_relation(),
        vec![DirectSubject::Type(USER_TYPE.to_string())],
    );

    if has_team_support {
        table_plan.ensure_direct(
            owner_team_relation(),
            vec![DirectSubject::Type(TEAM_TYPE.to_string())],
        );
        ensure_member_type(all_types, TEAM_TYPE);
    }

    let grant_subjects = if has_team_support {
        vec![
            DirectSubject::Type(USER_TYPE.to_string()),
            DirectSubject::Type(TEAM_TYPE.to_string()),
        ]
    } else {
        vec![DirectSubject::Type(USER_TYPE.to_string())]
    };

    for role in &sorted_roles {
        table_plan.ensure_direct(role.grant_relation(), grant_subjects.clone());
    }

    let mut descending = sorted_roles.clone();
    descending.reverse();

    for (idx, role) in descending.iter().enumerate() {
        let mut children = Vec::new();

        if idx == 0 {
            children.push(UsersetExpr::Computed(owner_user_relation()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: owner_team_relation(),
                    computed: member_relation(),
                });
            }
        } else if let Some(prev) = descending.get(idx - 1) {
            children.push(UsersetExpr::Computed(prev.role_relation()));
        }

        let grant_name = role.grant_relation();
        children.push(UsersetExpr::Computed(grant_name.clone()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: grant_name,
                computed: member_relation(),
            });
        }

        if let Some(expr) = combine_union(children) {
            table_plan.ensure_computed(role.role_relation(), expr);
        }
    }

    sorted_roles
}

pub(crate) fn role_for_level(
    sorted_roles: &[RoleRelationName],
    min_level: i32,
) -> Option<RelationName> {
    sorted_roles
        .iter()
        .find(|role| role.level >= min_level)
        .map(RoleRelationName::role_relation)
}

/// Userset for a P2 role-name-in-list policy.
///
/// Keyed on the listed role names, so a same-level role with a different name
/// (`guest=1` beside `viewer=1`) is not admitted.
pub(crate) fn exact_roles_expr(
    sorted_roles: &[RoleRelationName],
    selected_names: &BTreeSet<String>,
    has_team_support: bool,
) -> Option<UsersetExpr> {
    let mut children = Vec::new();

    for role in sorted_roles {
        if selected_names.contains(&role.original_name.to_lowercase()) {
            let grant_name = role.grant_relation();
            children.push(UsersetExpr::Computed(grant_name.clone()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: grant_name,
                    computed: member_relation(),
                });
            }
        }
    }

    // Include owner_user / owner_team when the highest-level role is selected.
    let max_level = sorted_roles.iter().map(|role| role.level).max();
    if let Some(max) = max_level {
        let max_is_selected = sorted_roles
            .iter()
            .any(|r| r.level == max && selected_names.contains(&r.original_name.to_lowercase()));
        if max_is_selected {
            children.push(UsersetExpr::Computed(owner_user_relation()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: owner_team_relation(),
                    computed: member_relation(),
                });
            }
        }
    }

    combine_union(children)
}
