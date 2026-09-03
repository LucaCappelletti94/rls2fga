//! Emission for the patterns that reach through another row.
//!
//! Membership through a join table, a membership naming no column of the guarded table, a
//! parent rule through a foreign key, and the two shapes that combine other patterns.

use super::*;

use crate::classifier::recognizers::{resolve_membership_pairing, MembershipPairing};

/// A membership naming no column of the guarded table, which admits every row at once through a holder.
pub(crate) fn emit_uncorrelated_membership<DB: DatabaseLike>(
    uncorrelated_membership: &UncorrelatedMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<String, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
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
    if noted_membership_read_scope(member_table, ctx, readability, notes).is_none() {
        return deny_expr(table_plan);
    }
    // Before any note or any minting: the grant hangs off a bridge from this row
    // to the holder, so with no row identity there is nothing to hang it on, a
    // holder type minted here would outlive the expression that justified it,
    // and advice about the tuple SQL names a query nothing will emit.
    let Some(source_identity_cols) = resolve_row_identity(source_table, db) else {
        skip_source_without_row_identity(table_plan, source_table, "membership holder tuples", db);
        return deny_expr(table_plan);
    };

    // Temporal comparisons on the member row move into the condition its member tuple
    // names. Declared on this plan, referenced by name from wherever the member lives.
    let gate = declare_temporal_condition(
        extra_predicates,
        member_table,
        policy_name,
        table_plan,
        &ctx.settings.request_time_parameter,
        ctx.condition_parameters,
        db,
    );
    // Several member rows per user only where the user column covers no declared
    // identity, and then the clock must be evaluated per row.
    let rows_unique = row_uniquely_keys(member_table, &[user_column], db);
    let witness = match &gate {
        Some((condition, context)) if !rows_unique => {
            if let Some(identity_cols) = resolve_row_identity(member_table, db) {
                Some((condition.clone(), context.clone(), identity_cols))
            } else if context.len() == 1 {
                // A single carried value is a real row's value, so compressing the
                // rows stays sound and at worst incomplete.
                None
            } else {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the rows of '{member_table}' have no declared identity, and \
                         several clock comparisons cannot be compressed into one \
                         fact without mixing rows"
                    ),
                });
                return deny_expr(table_plan);
            }
        }
        _ => None,
    };

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
    // Named after the type it points at, as the parent link is.
    let holder_relation = table_plan.ensure_direct(
        clamp_relation_name(holder_type.clone()),
        vec![DirectSubject::Type(holder_type.clone())],
    );
    if let Some((condition, context, identity_cols)) = witness {
        let share_type = share_type_name(member_table, table_types);
        let member_rel = {
            let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
                TypePlan::new_with_well_known(&share_type, &table_plan.well_known)
            });
            share_plan.ensure_direct(
                member_relation(),
                vec![DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.to_string(),
                    condition: condition.clone(),
                }],
            )
        };
        let share_source = TupleSource::MembershipShareMembers {
            join_table: member_table.clone(),
            identity_cols: identity_cols.clone(),
            user_col: user_column.clone(),
            share_type: share_type.clone(),
            relation: member_rel.clone(),
            condition,
            extra_predicates: extra_predicates.clone(),
            context,
        };
        table_plan.add_source(share_source.clone());
        if let Some(share_plan) = all_types.get_mut(&share_type) {
            share_plan.add_source(share_source);
        }
        let holder_plan = all_types
            .entry(holder_type.clone())
            .or_insert_with(|| TypePlan::new_with_well_known(&holder_type, &table_plan.well_known));
        let link = holder_plan.ensure_direct(
            clamp_relation_name(share_type.clone()),
            vec![DirectSubject::Type(share_type.clone())],
        );
        let witness_member = holder_plan.ensure_computed(
            format!("{share_type}_member"),
            UsersetExpr::TupleToUserset {
                tupleset: link.clone(),
                computed: member_rel,
            },
        );
        holder_plan.add_source(TupleSource::HolderShares {
            member_table: member_table.clone(),
            identity_cols,
            holder_type: holder_type.clone(),
            share_type,
            relation: link,
        });
        table_plan.add_source(TupleSource::HolderBridge {
            table: source_table.clone(),
            identity_cols: source_identity_cols,
            relation: holder_relation.clone(),
            holder_type,
        });
        return UsersetExpr::TupleToUserset {
            tupleset: holder_relation,
            computed: witness_member,
        };
    }
    let gate = gate.map(|(condition, context)| MembershipGate {
        condition,
        context,
        aggregate: !rows_unique,
    });
    ensure_member_type(all_types, &holder_type, &table_plan.well_known);
    if let (Some(gate), Some(holder_plan)) = (&gate, all_types.get_mut(&holder_type)) {
        holder_plan.add_direct_subject(
            &member_relation(),
            DirectSubject::ConditionalType {
                type_name: table_plan.well_known.user.to_string(),
                condition: gate.condition.clone(),
            },
        );
    }
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
            gate,
        });
    }
    table_plan.add_source(TupleSource::HolderBridge {
        table: source_table.clone(),
        identity_cols: source_identity_cols,
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
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
) -> UsersetExpr {
    let ExistsMembership {
        join_table,
        pairs,
        user_column,
        extra_predicates,
    } = exists_membership;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    // The subquery reads `join_table` as the user, so its own RLS decides which
    // membership rows count.
    let Some(read_scope_roles) = noted_membership_read_scope(join_table, ctx, readability, notes)
    else {
        return deny_expr(table_plan);
    };

    // The classifier's own resolver, so an oracle-supplied pairing obeys the same
    // rules and an unkeyed one falls closed with its reason rather than keying a
    // grant on a subset of its columns.
    let (pairs, pairing) =
        match resolve_membership_pairing(pairs.clone(), join_table, source_table, db) {
            Ok(resolved) => resolved,
            Err(reason) => {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason,
                });
                return deny_expr(table_plan);
            }
        };
    let parent_type = match (&pairing, pairs.as_slice()) {
        // Prefer the table the column actually references (e.g. "teams" for
        // team_members.team_id → teams.id). Fall back to the FK-column name
        // heuristic when no FK constraint metadata is available (e.g. "doc_id" →
        // "doc" for an undeclared reference). Single-column only: no name says
        // what two columns point at.
        (MembershipPairing::Single, [pair]) => {
            referenced_table_for_fk_col(db, join_table, &pair.join_column).map_or_else(
                || parent_type_from_fk_column(pair.join_column.as_str()),
                |referenced| table_types.resolve(&referenced),
            )
        }
        // The resolver never yields `Single` with any other width, so this arm
        // exists only to fall closed rather than panic.
        (MembershipPairing::Single, _) => return deny_expr(table_plan),
        (MembershipPairing::ForeignKey { parent_table }, _) => table_types.resolve(parent_table),
        // The outer columns are the guarded key, so the parent is the row itself.
        (MembershipPairing::SelfKeyed, _) => table_plan.type_name.to_string(),
    };
    let outer_cols: Vec<ColumnName> = pairs.iter().map(|pair| pair.outer_column.clone()).collect();

    // Before anything is minted: the grant hangs off a bridge from this row to
    // its parent object, so with no bridge there is nothing to hang it on and a
    // parent type minted here would outlive the expression justifying it.
    if !bridge_is_buildable(table_plan, source_table, &outer_cols, &parent_type, db) {
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
        ctx.condition_parameters,
        db,
    );
    // Several rows can key one (parent, user) only where no declared identity of the
    // join table is covered by the correlation, and then the clock must be evaluated
    // per row: one witness object per membership row, exactly as `EXISTS` is.
    let correlation_cols: Vec<&ColumnName> = pairs
        .iter()
        .map(|pair| &pair.join_column)
        .chain([user_column])
        .collect();
    let rows_unique = row_uniquely_keys(join_table, &correlation_cols, db);
    let witness = match &gate {
        Some((condition, context)) if !rows_unique => {
            if let Some(identity_cols) = resolve_row_identity(join_table, db) {
                Some((condition.clone(), context.clone(), identity_cols))
            } else if context.len() == 1 {
                // A single carried value is a real row's value, so compressing the
                // rows stays sound and at worst incomplete.
                None
            } else {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the rows of '{join_table}' have no declared identity, and \
                         several clock comparisons cannot be compressed into one \
                         fact without mixing rows"
                    ),
                });
                return deny_expr(table_plan);
            }
        }
        _ => None,
    };
    let conditional_member = match &gate {
        Some((condition, _)) if witness.is_none() => Some(DirectSubject::ConditionalType {
            type_name: table_plan.well_known.user.to_string(),
            condition: condition.clone(),
        }),
        _ => None,
    };

    // The relation is named after the parent type, but relation names have a
    // tighter length limit, so use the name the plan actually registered.
    let parent_relation = table_plan.ensure_direct(
        parent_type.clone(),
        vec![DirectSubject::Type(parent_type.clone())],
    );
    // This plan is outside `all_types` until the table build finishes, so a
    // self-referential membership registers `member` here before the post-pass trims it.
    // The witness route registers no direct member: its access relation is computed
    // over the share link, and a direct grant surface would sit unused.
    if parent_type == table_plan.type_name.as_str() {
        if witness.is_none() {
            table_plan.ensure_direct(
                member_relation(),
                vec![DirectSubject::Type(table_plan.well_known.user.to_string())],
            );
            if let Some(subject) = &conditional_member {
                table_plan.add_direct_subject(&member_relation(), subject.clone());
            }
        }
    } else {
        if witness.is_none() {
            ensure_member_type(all_types, &parent_type, &table_plan.well_known);
            if let (Some(subject), Some(parent_plan)) =
                (&conditional_member, all_types.get_mut(&parent_type))
            {
                parent_plan.add_direct_subject(&member_relation(), subject.clone());
            }
        } else {
            all_types.entry(parent_type.clone()).or_insert_with(|| {
                TypePlan::new_with_well_known(&parent_type, &table_plan.well_known)
            });
        }
        // Only a declared reference names a table: the single-column fallback
        // derives the type from the column's name, and no row of any table is
        // named by it. The self route binds nothing, since the guarded type's
        // own rows already name its objects.
        match &pairing {
            MembershipPairing::Single => {
                if let Some(referenced) = pairs
                    .first()
                    .and_then(|pair| referenced_table_for_fk_col(db, join_table, &pair.join_column))
                {
                    bind_row_source(all_types, &parent_type, &referenced, db);
                }
            }
            MembershipPairing::ForeignKey { parent_table } => {
                bind_row_source(all_types, &parent_type, parent_table, db);
            }
            MembershipPairing::SelfKeyed => {}
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

    if let Some((condition, context, identity_cols)) = witness {
        let share_type = share_type_name(join_table, table_types);
        let member_rel = {
            let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
                TypePlan::new_with_well_known(&share_type, &table_plan.well_known)
            });
            share_plan.ensure_direct(
                member_relation(),
                vec![DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.to_string(),
                    condition: condition.clone(),
                }],
            )
        };
        let share_source = TupleSource::MembershipShareMembers {
            join_table: join_table.clone(),
            identity_cols: identity_cols.clone(),
            user_col: user_column.clone(),
            share_type: share_type.clone(),
            relation: member_rel.clone(),
            condition,
            extra_predicates: extra_predicates.clone(),
            context,
        };
        table_plan.add_source(share_source.clone());
        if let Some(share_plan) = all_types.get_mut(&share_type) {
            share_plan.add_source(share_source);
        }
        let fk_cols: Vec<ColumnName> = pairs.iter().map(|pair| pair.join_column.clone()).collect();
        let (shares_link, witness_member) = if parent_type == table_plan.type_name.as_str() {
            let link = table_plan.ensure_direct(
                clamp_relation_name(share_type.clone()),
                vec![DirectSubject::Type(share_type.clone())],
            );
            let witness_member = table_plan.ensure_computed(
                format!("{share_type}_member"),
                UsersetExpr::TupleToUserset {
                    tupleset: link.clone(),
                    computed: member_rel.clone(),
                },
            );
            (link, witness_member)
        } else {
            let Some(parent_plan) = all_types.get_mut(&parent_type) else {
                return deny_expr(table_plan);
            };
            let link = parent_plan.ensure_direct(
                clamp_relation_name(share_type.clone()),
                vec![DirectSubject::Type(share_type.clone())],
            );
            let witness_member = parent_plan.ensure_computed(
                format!("{share_type}_member"),
                UsersetExpr::TupleToUserset {
                    tupleset: link.clone(),
                    computed: member_rel.clone(),
                },
            );
            (link, witness_member)
        };
        let bridge = TupleSource::ShareBridge {
            join_table: join_table.clone(),
            identity_cols,
            object_cols: fk_cols,
            guarded_type: parent_type.clone(),
            share_type,
            relation: shares_link,
        };
        // Attach the source to the plan that defines its guarded relation.
        if parent_type == table_plan.type_name.as_str() {
            table_plan.add_source(bridge);
        } else if let Some(parent_plan) = all_types.get_mut(&parent_type) {
            parent_plan.add_source(bridge);
        }
        table_plan.add_source(TupleSource::ParentBridge {
            table: source_table.clone(),
            fk_cols: outer_cols,
            parent_type: parent_type.clone(),
            relation: parent_relation.clone(),
        });
        let membership = UsersetExpr::TupleToUserset {
            tupleset: parent_relation,
            computed: witness_member,
        };
        if read_scope_roles.is_empty() {
            return membership;
        }
        let scope_relation =
            membership_read_scope_relation_name(&ctx.table_types.resolve(join_table));
        register_pg_role_scope(
            table_plan,
            all_types,
            notes,
            source_table,
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
        return scoped_policy_expr(membership, &scope_relation);
    }

    // Membership rows: add to table_plan first (for correct ordering in IR renderer),
    // then also to the parent type's plan for semantic correctness (deduplicated).
    let membership_source = TupleSource::ExistsMembership {
        join_table: join_table.clone(),
        fk_cols: pairs.iter().map(|pair| pair.join_column.clone()).collect(),
        user_col: user_column.clone(),
        parent_type: parent_type.clone(),
        extra_predicates: extra_predicates.clone(),
        gate: gate.map(|(condition, context)| MembershipGate {
            condition,
            context,
            aggregate: !rows_unique,
        }),
    };
    table_plan.add_source(membership_source.clone());
    if let Some(parent_plan) = all_types.get_mut(&parent_type) {
        parent_plan.add_source(membership_source);
    }

    // Bridge rows link each source-table row to its parent, through the columns
    // the policy compares. The pk columns are resolved again at render time by
    // `resolve_bridge_columns`.
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.clone(),
        fk_cols: outer_cols,
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
    let scope_relation = membership_read_scope_relation_name(&ctx.table_types.resolve(join_table));
    register_pg_role_scope(
        table_plan,
        all_types,
        notes,
        source_table,
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
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
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

    let parent_type = table_types.resolve(parent_table);

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
        && lookup_table_id(db, parent_table)
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

    if !bridge_is_buildable(
        table_plan,
        source_table,
        core::slice::from_ref(fk_column),
        &parent_type,
        db,
    ) {
        return deny_expr(table_plan);
    }
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.clone(),
        fk_cols: vec![fk_column.clone()],
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
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
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
            table: source_table.clone(),
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
    readability: &mut BTreeMap<TableId, JoinTableReadability>,
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
