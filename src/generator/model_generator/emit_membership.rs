//! Emission for the patterns that reach through another row.
//!
//! Membership through a join table, a membership naming no column of the guarded table, a
//! parent rule through a foreign key, and the two shapes that combine other patterns.

use super::*;

/// A membership naming no column of the guarded table, which admits every row at once through a holder.
pub(crate) fn emit_uncorrelated_membership<DB: DatabaseLike>(
    uncorrelated_membership: &UncorrelatedMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let UncorrelatedMembership {
        member_table,
        user_column,
        extra_predicates,
    } = uncorrelated_membership;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    // Reading the member table is still reading it as the caller, so its own
    // RLS decides which membership rows count, exactly as for P4.
    match join_table_readability(member_table, db, readability) {
        JoinTableReadability::Unreadable => {
            notes.push(TranslationNote::MembershipTableGrantsNoReads {
                policy: policy_name.to_string(),
                join_table: member_table.clone(),
            });
            return deny_expr(table_plan);
        }
        JoinTableReadability::Guarded { .. } => {
            notes.push(TranslationNote::MembershipTableGuarded {
                policy: policy_name.to_string(),
                join_table: member_table.clone(),
            });
        }
        JoinTableReadability::Open => {}
    }
    // Before any note or any minting: the grant hangs off a bridge from this row
    // to the holder, so with no row identity there is nothing to hang it on, a
    // holder type minted here would outlive the expression that justified it,
    // and advice about the tuple SQL names a query nothing will emit.
    let Some(pk_cols) = resolve_pk_columns(source_table, db) else {
        skip_source_without_row_identity(table_plan, source_table, "membership holder tuples", db);
        return deny_expr(table_plan);
    };

    // Temporal comparisons on the member row move into the condition its member tuple
    // names. Declared on this plan, referenced by name from the holder's member relation.
    let gate = declare_temporal_condition(
        extra_predicates,
        member_table,
        policy_name,
        table_plan,
        &ctx.settings.request_time_parameter,
        db,
    )
    .map(|(condition, context)| MembershipGate {
        condition,
        context,
        aggregate: !row_uniquely_keys(member_table, &[user_column], db),
    });

    let announced = if gate.is_some() {
        extra_predicates.sql_excluding_requests()
    } else {
        extra_predicates.sql()
    };
    if let Some(extra) = announced {
        notes.push(TranslationNote::MembershipExtraPredicate {
            policy: policy_name.to_string(),
            predicate: extra,
        });
    }

    // One holder per member source, never per table and never per policy: two
    // policies reading the same table may share, and two reading different
    // ones must not pool their members.
    let holder_type = holder_type_name(member_table, table_types);
    ensure_member_type(all_types, &holder_type, &table_plan.well_known);
    if let (Some(gate), Some(holder_plan)) = (&gate, all_types.get_mut(&holder_type)) {
        holder_plan.add_direct_subject(
            &member_relation(),
            DirectSubject::ConditionalType {
                type_name: table_plan.well_known.user.clone(),
                condition: gate.condition.clone(),
            },
        );
    }
    // Named after the type it points at, as the parent link is.
    let holder_relation = table_plan.ensure_direct(
        clamp_relation_name(holder_type.clone()),
        vec![DirectSubject::Type(holder_type.clone())],
    );
    table_plan.add_source(TupleSource::HolderMembers {
        holder_type: holder_type.clone(),
        member_table: member_table.clone(),
        user_col: user_column.clone(),
        extra_predicates: extra_predicates.clone(),
        gate: gate.clone(),
    });
    if let Some(holder_plan) = all_types.get_mut(&holder_type) {
        holder_plan.add_source(TupleSource::HolderMembers {
            holder_type: holder_type.clone(),
            member_table: member_table.clone(),
            user_col: user_column.clone(),
            extra_predicates: extra_predicates.clone(),
            gate: gate.clone(),
        });
    }
    table_plan.add_source(TupleSource::HolderBridge {
        table: source_table.to_string(),
        pk_cols,
        relation: holder_relation.clone(),
        holder_type,
    });
    UsersetExpr::TupleToUserset {
        tupleset: holder_relation,
        computed: member_relation(),
    }
}

/// Membership through a join table, bridged on the column the policy correlates.
pub(crate) fn emit_exists_membership<DB: DatabaseLike>(
    exists_membership: &ExistsMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let ExistsMembership {
        join_table,
        fk_column,
        outer_column,
        user_column,
        extra_predicates,
    } = exists_membership;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    // The subquery reads `join_table` as the user, so its own RLS decides which
    // membership rows count.
    let read_scope_roles = match join_table_readability(join_table, db, readability) {
        JoinTableReadability::Unreadable => {
            notes.push(TranslationNote::MembershipTableGrantsNoReads {
                policy: policy_name.to_string(),
                join_table: join_table.clone(),
            });
            return deny_expr(table_plan);
        }
        JoinTableReadability::Guarded { roles } => {
            notes.push(TranslationNote::MembershipTableGuarded {
                policy: policy_name.to_string(),
                join_table: join_table.clone(),
            });
            roles
        }
        JoinTableReadability::Open => Vec::new(),
    };

    // Prefer the table that fk_column actually references (e.g. "teams"
    // for team_members.team_id → teams.id).  Fall back to the FK-column
    // name heuristic when no FK constraint metadata is available
    // (e.g. "doc_id" → "doc" for an undeclared reference).
    let parent_type = referenced_table_for_fk_col(db, join_table, fk_column).map_or_else(
        || parent_type_from_fk_column(fk_column.as_str()),
        |referenced| table_types.resolve(db, referenced),
    );

    // Before anything is minted: the grant hangs off a bridge from this row to
    // its parent object, so with no bridge there is nothing to hang it on and a
    // parent type minted here would outlive the expression justifying it.
    if !bridge_is_buildable(table_plan, source_table, outer_column, &parent_type, db) {
        return deny_expr(table_plan);
    }

    // A temporal comparison such as `expires_at > now()` is completed by the request, so
    // it rides the member tuple as a condition rather than filtering the query. Declared on
    // this plan and referenced by name from the member relation, wherever that lives.
    let gate = declare_temporal_condition(
        extra_predicates,
        join_table,
        policy_name,
        table_plan,
        &ctx.settings.request_time_parameter,
        db,
    );
    let conditional_member = gate
        .as_ref()
        .map(|(condition, _)| DirectSubject::ConditionalType {
            type_name: table_plan.well_known.user.clone(),
            condition: condition.clone(),
        });

    // The relation is named after the parent type, but relation names have a
    // tighter length limit, so use the name the plan actually registered.
    let parent_relation = table_plan.ensure_direct(
        parent_type.clone(),
        vec![DirectSubject::Type(parent_type.clone())],
    );
    // This plan is outside `all_types` until the table build finishes, so a
    // self-referential membership registers `member` here before the post-pass trims it.
    if parent_type == table_plan.type_name.as_str() {
        table_plan.ensure_direct(
            member_relation(),
            vec![DirectSubject::Type(table_plan.well_known.user.clone())],
        );
        if let Some(subject) = &conditional_member {
            table_plan.add_direct_subject(&member_relation(), subject.clone());
        }
    } else {
        ensure_member_type(all_types, &parent_type, &table_plan.well_known);
        if let (Some(subject), Some(parent_plan)) =
            (&conditional_member, all_types.get_mut(&parent_type))
        {
            parent_plan.add_direct_subject(&member_relation(), subject.clone());
        }
        // Only a declared reference names a table. The fallback derives the type
        // from the column's name, and no row of any table is named by it.
        if let Some(referenced) = referenced_table_for_fk_col(db, join_table, fk_column) {
            bind_row_source(all_types, &parent_type, referenced, db);
        }
    }

    // The clock moved into the condition, so only what remains needs announcing.
    let announced = if gate.is_some() {
        extra_predicates.sql_excluding_requests()
    } else {
        extra_predicates.sql()
    };
    if let Some(extra) = announced {
        notes.push(TranslationNote::MembershipExtraPredicate {
            policy: policy_name.to_string(),
            predicate: extra,
        });
    }

    // Membership rows: add to table_plan first (for correct ordering in IR renderer),
    // then also to the parent type's plan for semantic correctness (deduplicated).
    let membership_source = TupleSource::ExistsMembership {
        join_table: join_table.clone(),
        fk_col: fk_column.clone(),
        user_col: user_column.clone(),
        parent_type: parent_type.clone(),
        extra_predicates: extra_predicates.clone(),
        gate: gate.map(|(condition, context)| MembershipGate {
            condition,
            context,
            aggregate: !row_uniquely_keys(join_table, &[fk_column, user_column], db),
        }),
    };
    table_plan.add_source(membership_source.clone());
    if let Some(parent_plan) = all_types.get_mut(&parent_type) {
        parent_plan.add_source(membership_source);
    }

    // Bridge rows link each source-table row to its parent, through the column
    // the policy compares. The pk column is resolved again at render time by
    // `resolve_bridge_columns`.
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.to_string(),
        fk_col: outer_column.clone(),
        parent_type: parent_type.clone(),
        relation: parent_relation.clone(),
    });

    let membership = UsersetExpr::TupleToUserset {
        tupleset: parent_relation,
        computed: member_relation(),
    };
    if read_scope_roles.is_empty() {
        return membership;
    }

    // Only those roles can read the membership rows, so only they inherit
    // the grant.
    let scope_relation = membership_read_scope_relation_name(join_table);
    register_pg_role_scope(
        table_plan,
        all_types,
        notes,
        source_table,
        policy_name,
        db,
        RoleScopeSpec {
            scope_relation: &scope_relation,
            walked: &RolePrivilege::Usage.relation_name(),
            role_names: &read_scope_roles,
            scope_note: TranslationNote::MembershipReadScope {
                policy: policy_name.to_string(),
                join_table: join_table.clone(),
                roles: read_scope_roles.clone(),
                relation: scope_relation.clone(),
            },
            missing_object_what: "membership read scope tuples",
        },
    );
    scoped_policy_expr(membership, &scope_relation)
}

/// A parent's rule reached through a foreign key, gated by the parent's own read.
pub(crate) fn emit_parent_inheritance<DB: DatabaseLike>(
    parent_inheritance: &ParentInheritance,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let ParentInheritance {
        parent_table,
        fk_column,
        inner_pattern,
    } = parent_inheritance;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;

    let parent_type = table_types.resolve(db, parent_table);

    // The relation is named after the parent type, but relation names have a
    // tighter length limit, so use the name the plan actually registered.
    let parent_relation = table_plan.ensure_direct(
        parent_type.clone(),
        vec![DirectSubject::Type(parent_type.clone())],
    );
    // The inner rule has to land on the parent's plan. When the parent is the
    // table being built, that plan is `table_plan`, held here rather than in
    // `all_types`, so writing it there would be dropped by the re-insert at
    // the end of the table loop.
    let inherits_from_self = parent_type == table_plan.type_name.as_str();
    // A bare delegation adds nothing to the parent's own read rule, so the gate
    // below is the whole rule. Translating the constant would mint a
    // `public_viewer` relation on the parent and ask an operator for a tuple per
    // parent row that no rule reads.
    let bare_delegation = matches!(
        &inner_pattern.pattern,
        PatternClass::P10ConstantBool(ConstantBool { value: true })
    );
    let inner_expr = if bare_delegation {
        UsersetExpr::Computed(can_select_relation())
    } else if inherits_from_self {
        translate_pattern(
            &inner_pattern.pattern,
            &ctx.for_table(parent_table),
            table_plan,
            all_types,
            notes,
            readability,
        )
    } else {
        let parent_plan = all_types
            .entry(parent_type.clone())
            .or_insert_with(|| TypePlan::new_with_well_known(&parent_type, &table_plan.well_known));
        let mut parent_plan_owned = core::mem::replace(
            parent_plan,
            TypePlan::new_with_well_known(&parent_type, &table_plan.well_known),
        );
        let expr = translate_pattern(
            &inner_pattern.pattern,
            &ctx.for_table(parent_table),
            &mut parent_plan_owned,
            all_types,
            notes,
            readability,
        );
        *all_types
            .entry(parent_type.clone())
            .or_insert_with(|| TypePlan::new(&parent_type)) = parent_plan_owned;
        bind_row_source(all_types, &parent_type, parent_table, db);
        expr
    };

    // The policy requires this specific parent-side rule. Pointing at the
    // parent's `can_select` instead would import every other permissive
    // policy the parent has.
    let rule_is_denial =
        matches!(&inner_expr, UsersetExpr::Computed(name) if *name == deny_relation());
    // A row the parent hides cannot satisfy the rule, self references included.
    // Gating narrows the rule, so an unreadable RLS state gates.
    let gate_on_parent = !rule_is_denial
        && !bare_delegation
        && lookup_table(db, parent_table)
            .is_some_and(|table| table.has_row_level_security(db) != Ok(false));
    let rule_expr = if gate_on_parent {
        UsersetExpr::Intersection(vec![
            inner_expr,
            UsersetExpr::Computed(can_select_relation()),
        ])
    } else {
        inner_expr
    };
    let inherited = match rule_expr {
        UsersetExpr::Computed(name) => name,
        expr => {
            // Named after the rule, so children share it and a policy rename
            // leaves the parent alone.
            let name = clamp_relation_name(format!(
                "{INHERITED_RELATION_PREFIX}{}",
                stable_hex_suffix(userset_key(&expr).as_str())
            ));
            if inherits_from_self {
                table_plan.ensure_computed(name, expr)
            } else {
                all_types
                    .entry(parent_type.clone())
                    .or_insert_with(|| {
                        TypePlan::new_with_well_known(&parent_type, &table_plan.well_known)
                    })
                    .ensure_computed(name, expr)
            }
        }
    };

    if rule_is_denial {
        notes.push(TranslationNote::ParentRuleUntranslated {
            policy: policy_name.to_string(),
            parent_table: parent_table.clone(),
        });
    }

    if !bridge_is_buildable(table_plan, source_table, fk_column, &parent_type, db) {
        return deny_expr(table_plan);
    }
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.to_string(),
        fk_col: fk_column.clone(),
        parent_type: parent_type.clone(),
        relation: parent_relation.clone(),
    });

    UsersetExpr::TupleToUserset {
        tupleset: parent_relation,
        computed: inherited,
    }
}

/// The relationship half of a hybrid clause, with the attribute half handed to the caller.
pub(crate) fn emit_abac_and<DB: DatabaseLike>(
    abac_and: &AbacAnd,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let AbacAnd {
        relationship_part,
        attribute_part,
    } = abac_and;
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    notes.push(TranslationNote::AttributeNeedsRuntimeEnforcement {
        policy: policy_name.to_string(),
        attribute: attribute_part.clone(),
    });
    // Recurse first so relationship sources appear before the attribute Todo
    // in table_tuple_sources (matching old generate_tuple_queries ordering).
    let result = translate_pattern(
        &relationship_part.pattern,
        ctx,
        table_plan,
        all_types,
        notes,
        readability,
    );
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::AttributeRuntimeEnforcement {
            table: source_table.to_string(),
            attribute: attribute_part.clone(),
        },
    });
    result
}

/// A union or intersection of the parts a composite clause combines.
pub(crate) fn emit_composite<DB: DatabaseLike>(
    composite: &Composite,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<String, JoinTableReadability>,
) -> UsersetExpr {
    let Composite { op, parts } = composite;
    let mut child_exprs = Vec::new();
    for part in parts {
        child_exprs.push(translate_pattern(
            &part.pattern,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
        ));
    }
    match op {
        BoolOp::Or => combine_union(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
        BoolOp::And => combine_intersection(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
    }
}
