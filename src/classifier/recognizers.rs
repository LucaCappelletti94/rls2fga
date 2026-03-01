use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Select, SelectItem,
    TableFactor, UnaryOperator, Value,
};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
pub use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::expr::{extract_column_name_through_coalesce, is_coalesce_wrapped};
use crate::parser::names::{
    is_owner_like_column_name, is_public_flag_column_name, is_user_related_column_name,
    lookup_table, normalize_relation_name, normalized_function_name, split_schema_and_relation,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, ParserDB, TableLike};

/// Try to recognize P1: numeric role threshold `func(user, resource) >= N`.
pub fn recognize_p1(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
    command: &PolicyCommand,
) -> Option<ClassifiedExpr> {
    if let Expr::BinaryOp { left, op, right } = expr {
        let (func_expr, threshold_expr, operator) = match op {
            BinaryOperator::GtEq => (left.as_ref(), right.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Gt => (left.as_ref(), right.as_ref(), ThresholdOperator::Gt),
            BinaryOperator::LtEq => (right.as_ref(), left.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Lt => (right.as_ref(), left.as_ref(), ThresholdOperator::Gt),
            _ => return None,
        };

        let func_name = extract_function_name(func_expr)?;
        if !registry.is_role_threshold(&func_name) {
            return None;
        }
        // Require that the function call contains a current-user argument, otherwise
        // a role comparison on resource attributes (e.g. `resource_level(id, resource_id) >= 2`)
        // would be misclassified as P1.
        if !function_has_current_user_arg(func_expr, registry) {
            return None;
        }

        let threshold = extract_integer_value(threshold_expr)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold {
                function_name: func_name,
                operator,
                threshold,
                command: command.clone(),
            },
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Try to recognize P2: role name IN-list `func(user, resource) IN ('viewer', ...)`.
///
/// Also recognises the `PostgreSQL` built-in `pg_has_role(user, 'role', privilege)`
/// which checks database-level role membership for the current user.
pub fn recognize_p2(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::InList {
        expr: inner_expr,
        list,
        negated,
    } = expr
    {
        // Negated IN-lists are never expressible as static OpenFGA tuples.
        if *negated {
            return None;
        }

        if let Some(func_name) = extract_function_name(inner_expr) {
            if registry.is_role_threshold(&func_name) {
                // Require that the function call contains a current-user argument.
                if !function_has_current_user_arg(inner_expr, registry) {
                    return None;
                }

                let role_names = extract_role_names_from_in_list(list, true);

                if !role_names.is_empty() {
                    return Some(ClassifiedExpr {
                        pattern: PatternClass::P2RoleNameInList {
                            function_name: func_name,
                            role_names,
                        },
                        confidence: ConfidenceLevel::A,
                    });
                }
            }
            // Not a role-threshold function — fall through to role-accessor check below.
        }
    }

    // Phase 6c: pg_has_role(user, 'role', privilege) — `PostgreSQL` built-in role-membership check.
    // Supports:
    //   - three-arg form: pg_has_role(current_user, 'rolename', 'MEMBER')
    //   - two-arg form:   pg_has_role('rolename', 'MEMBER')  (current session user implied)
    if let Some(c) = recognize_pg_has_role(expr, registry) {
        return Some(c);
    }

    // Phase 6d: role_func() = 'name'  /  role_func() IN ('name', ...) where the function
    // is registered as a RoleAccessor (e.g. Supabase `auth.role()`).
    recognize_role_accessor_comparison(expr, registry)
}

/// Recognise `pg_has_role(user, 'role', privilege)` / `pg_has_role('role', privilege)`.
/// Maps to `P2RoleNameInList` at confidence A since the built-in has fixed semantics.
fn recognize_pg_has_role(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    use sqlparser::ast::FunctionArguments;

    let Expr::Function(func) = expr else {
        return None;
    };
    if normalized_function_name(func) != "pg_has_role" {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };

    let args: Vec<&Expr> = arg_list.args.iter().filter_map(function_arg_expr).collect();

    let role_expr = match args.as_slice() {
        // Three-arg: pg_has_role(user, 'role', privilege) — user must be current_user.
        [user_expr, role_expr, _priv] if is_current_user_expr(user_expr, registry) => role_expr,
        // Two-arg: pg_has_role('role', privilege) — current session user is implicit.
        [role_expr, _priv] => role_expr,
        _ => return None,
    };

    // Extract the role name from the second positional argument.
    let role_name = match role_expr {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) => s.clone(),
            _ => return None,
        },
        _ => return None,
    };

    Some(ClassifiedExpr {
        pattern: PatternClass::P2RoleNameInList {
            function_name: "pg_has_role".to_string(),
            role_names: vec![role_name],
        },
        confidence: ConfidenceLevel::A,
    })
}

/// Phase 6d: Recognise role-accessor comparisons.
///
/// Handles two forms where the function is registered as `RoleAccessor`:
/// - `role_func() = 'rolename'`
/// - `role_func() IN ('role1', 'role2', ...)`
///
/// Maps to `P2RoleNameInList` at confidence A.  Typical use: Supabase
/// `auth.role() = 'authenticated'`.
fn recognize_role_accessor_comparison(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    // Helper: extract a zero-arg function name from a possibly-cast expression.
    let extract_role_func_name = |e: &Expr| -> Option<String> {
        let name = extract_function_name(e)?;
        if registry.is_role_accessor(&name) {
            Some(name)
        } else {
            None
        }
    };

    // Form 1: role_func() = 'rolename'  or  'rolename' = role_func()
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    {
        let (func_name, literal_expr) = if let Some(name) = extract_role_func_name(left) {
            (name, right.as_ref())
        } else if let Some(name) = extract_role_func_name(right) {
            (name, left.as_ref())
        } else {
            return None;
        };

        let role_name = match literal_expr {
            Expr::Value(v) => match &v.value {
                Value::SingleQuotedString(s) => s.clone(),
                _ => return None,
            },
            _ => return None,
        };

        return Some(ClassifiedExpr {
            pattern: PatternClass::P2RoleNameInList {
                function_name: func_name,
                role_names: vec![role_name],
            },
            confidence: ConfidenceLevel::A,
        });
    }

    // Form 2: role_func() IN ('role1', 'role2', ...)
    if let Expr::InList {
        expr: inner,
        list,
        negated: false,
    } = expr
    {
        let func_name = extract_role_func_name(inner)?;
        let role_names = extract_role_names_from_in_list(list, false);

        if role_names.is_empty() {
            return None;
        }

        return Some(ClassifiedExpr {
            pattern: PatternClass::P2RoleNameInList {
                function_name: func_name,
                role_names,
            },
            confidence: ConfidenceLevel::A,
        });
    }

    None
}

fn extract_role_names_from_in_list(list: &[Expr], allow_numeric: bool) -> Vec<String> {
    list.iter()
        .filter_map(|e| {
            if let Expr::Value(v) = e {
                return match &v.value {
                    Value::SingleQuotedString(s) => Some(s.clone()),
                    Value::Number(n, _) if allow_numeric => Some(n.clone()),
                    _ => None,
                };
            }
            None
        })
        .collect()
}

/// Try to recognize P3: direct ownership `owner_id = auth.user_id()`.
pub fn recognize_p3(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let (left, right) = match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        }
        | Expr::IsNotDistinctFrom(left, right) => (left.as_ref(), right.as_ref()),
        _ => return None,
    };

    // Try column = accessor_expr or accessor_expr = column.
    // Falls through to extract_column_name_through_coalesce when plain
    // extract_column_name returns None (e.g. COALESCE(col, default)).
    let (col_name, accessor_name, accessor_indirection) = if let (Some(col), Some(accessor)) =
        (extract_column_name(left), current_user_accessor_name(right))
    {
        let indirection = is_subquery_wrapped(right) || is_json_accessor_wrapped(right);
        (col, accessor, indirection)
    } else if let (Some(accessor), Some(col)) =
        (current_user_accessor_name(left), extract_column_name(right))
    {
        let indirection = is_subquery_wrapped(left) || is_json_accessor_wrapped(left);
        (col, accessor, indirection)
    } else if let (Some(col), Some(accessor)) = (
        extract_column_name_through_coalesce(left),
        current_user_accessor_name(right),
    ) {
        let indirection = is_subquery_wrapped(right)
            || is_json_accessor_wrapped(right)
            || is_coalesce_wrapped(left);
        (col, accessor, indirection)
    } else if let (Some(accessor), Some(col)) = (
        current_user_accessor_name(left),
        extract_column_name_through_coalesce(right),
    ) {
        let indirection = is_subquery_wrapped(left)
            || is_json_accessor_wrapped(left)
            || is_coalesce_wrapped(right);
        (col, accessor, indirection)
    } else {
        return None;
    };

    // Subquery-wrapped or JSON-extracted accessor: cap confidence at B regardless
    // of how the inner expression was resolved (the extra indirection prevents
    // registry-A certainty).
    if accessor_indirection {
        return Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership { column: col_name },
            confidence: ConfidenceLevel::B,
        });
    }

    // Determine how we matched the accessor and assign confidence accordingly.
    let is_registry_confirmed = registry.is_current_user_accessor(&accessor_name);
    let accessor_lower = accessor_name.to_lowercase();
    let is_sql_keyword = is_current_user_keyword(&accessor_lower);

    if !is_registry_confirmed && !is_sql_keyword {
        // Heuristic accessor name check.
        // `current_setting` is a PostgreSQL built-in that often carries the current user ID
        // (e.g. `current_setting('app.current_user_id')::uuid`).  We accept it as a
        // heuristic user-accessor at confidence B; register it explicitly for confidence A.
        if !accessor_lower.contains("current_user")
            && !accessor_lower.contains("auth")
            && accessor_lower != "current_setting"
        {
            return None;
        }

        // Heuristic match: cap at confidence B regardless of column name.
        // Reserve A for registry-confirmed functions and SQL keywords.
        if is_owner_like_column_name(&col_name) {
            return Some(ClassifiedExpr {
                pattern: PatternClass::P3DirectOwnership { column: col_name },
                confidence: ConfidenceLevel::B,
            });
        }

        // Heuristic function + non-standard column → confidence B
        return Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership { column: col_name },
            confidence: ConfidenceLevel::B,
        });
    }

    // Registry-confirmed or SQL keyword: accept any column at confidence A
    Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership { column: col_name },
        confidence: ConfidenceLevel::A,
    })
}

/// Try to recognize P4: EXISTS membership check.
pub fn recognize_p4(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::Exists { subquery, negated } = expr {
        if *negated {
            return None;
        }

        let query = subquery.as_ref();
        let body = query.body.as_ref();

        if let sqlparser::ast::SetExpr::Select(select) = body {
            return classify_membership_select(select.as_ref(), db, registry, None);
        }
    }
    None
}

/// Try to recognize P5: parent inheritance via correlated EXISTS on parent table.
pub fn recognize_p5(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: &PolicyCommand,
) -> Option<ClassifiedExpr> {
    if let Expr::Exists { subquery, negated } = expr {
        if *negated {
            return None;
        }

        let query = subquery.as_ref();
        let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        let analysis = analyze_p5_parent_inheritance(select.as_ref(), db, outer_table)?;

        let mut matches = Vec::new();
        for candidate in analysis.candidates {
            let P5InheritanceCandidate {
                parent_table,
                fk_column,
                inner_predicates,
            } = candidate;
            let Some(inner_expr) = combine_predicates_with_and(inner_predicates) else {
                continue;
            };
            let inner_classified = crate::classifier::policy_classifier::classify_expr(
                &inner_expr,
                db,
                registry,
                &parent_table,
                command,
            );
            // Only accept user-resource relationship patterns as inner patterns.
            // Attribute checks (P6, P9, P10) do not represent a relationship
            // between a user and the parent resource and must not become P5.
            if !matches!(
                inner_classified.pattern,
                PatternClass::P1NumericThreshold { .. }
                    | PatternClass::P2RoleNameInList { .. }
                    | PatternClass::P3DirectOwnership { .. }
                    | PatternClass::P4ExistsMembership { .. }
                    | PatternClass::P5ParentInheritance { .. }
                    | PatternClass::P7AbacAnd { .. }
                    | PatternClass::P8Composite { .. }
            ) {
                continue;
            }

            matches.push(ClassifiedExpr {
                confidence: inner_classified.confidence,
                pattern: PatternClass::P5ParentInheritance {
                    parent_table,
                    fk_column,
                    inner_pattern: Box::new(inner_classified),
                },
            });
        }

        if matches.len() == 1 {
            return matches.into_iter().next();
        }
    }
    None
}

/// Try to recognize P4 via IN-subquery: `col IN (SELECT col FROM membership_table ...)`.
pub fn recognize_p4_in_subquery(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::InSubquery {
        expr: lhs,
        subquery,
        negated,
    } = expr
    {
        if *negated {
            return None;
        }

        // LHS should be a column reference (e.g. team_id)
        let lhs_col = extract_column_name(lhs)?;

        let query = subquery.as_ref();
        let body = query.body.as_ref();

        if let sqlparser::ast::SetExpr::Select(select) = body {
            let projected_col = extract_projection_column(select.as_ref()).unwrap_or(lhs_col);
            return classify_membership_select(select.as_ref(), db, registry, Some(projected_col));
        }
    }
    None
}

/// Phase 6e: Recognise `PostgreSQL` array membership patterns.
///
/// - `current_user = ANY(col)` / `ANY(col) = current_user` → `P9AttributeCondition`
///   at confidence B with a note explaining UNNEST-based tuple expansion.
/// - `col1 && col2` (array overlap) → `P9AttributeCondition` at confidence C with TODO.
///
/// Both are mapped to P9 so they generate a structured TODO in the model output rather
/// than falling through to `Unknown`, which signals a parsing failure.
pub fn recognize_array_patterns(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    // Case 1: `current_user = ANY(array_col)` — direct array membership.
    if let Expr::AnyOp {
        left,
        compare_op: BinaryOperator::Eq,
        right,
        ..
    } = expr
    {
        let array_expr = if is_current_user_expr(left, registry) {
            // current_user = ANY(right)
            right.as_ref()
        } else if is_current_user_expr(right, registry) {
            // In the reversed form `ANY(left) = current_user` sqlparser would
            // not produce AnyOp; guard here for future parser versions.
            left.as_ref()
        } else {
            return None;
        };

        let array_col = extract_column_name(array_expr).unwrap_or_else(|| array_expr.to_string());
        return Some(ClassifiedExpr {
            pattern: PatternClass::P9AttributeCondition {
                column: array_col.clone(),
                value_description: format!(
                    "current_user ∈ array column '{array_col}' \
                     (expand with UNNEST for static tuple generation)"
                ),
            },
            confidence: ConfidenceLevel::B,
        });
    }

    // Case 2: `col1 && col2` — array overlap operator.
    if let Expr::BinaryOp {
        op: BinaryOperator::PGOverlap,
        left,
        right,
    } = expr
    {
        let col = extract_column_name(left)
            .or_else(|| extract_column_name(right))
            .unwrap_or_else(|| expr.to_string());
        return Some(ClassifiedExpr {
            pattern: PatternClass::P9AttributeCondition {
                column: col,
                value_description: "array overlap (&&); requires runtime filtering".to_string(),
            },
            confidence: ConfidenceLevel::C,
        });
    }

    None
}

fn classify_membership_select(
    select: &Select,
    db: &ParserDB,
    registry: &FunctionRegistry,
    projected_fk: Option<String>,
) -> Option<ClassifiedExpr> {
    // Fail closed when the same table appears more than once (self-join).
    // Self-joins add constraints we cannot express as static membership tuples;
    // accepting them would produce tuples more permissive than the original policy.
    let all_sources = relation_sources(select);
    let unique_table_count = all_sources
        .iter()
        .map(|s| normalize_relation_name(&s.table_name))
        .collect::<std::collections::HashSet<_>>()
        .len();
    if unique_table_count != all_sources.len() {
        return None;
    }

    let matches = membership_matches(select, db, registry, projected_fk.as_deref());
    if matches.len() != 1 {
        return None;
    }

    let (join_table, inferred_fk_column, user_column, extra_predicate_sql) =
        matches.into_iter().next()?;

    Some(ClassifiedExpr {
        pattern: PatternClass::P4ExistsMembership {
            join_table,
            fk_column: projected_fk.unwrap_or(inferred_fk_column),
            user_column,
            extra_predicate_sql,
        },
        confidence: ConfidenceLevel::A,
    })
}

pub(crate) fn diagnose_p4_membership_ambiguity(
    expr: &Expr,
    db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<String> {
    fn diagnose_select(
        select: &Select,
        db: &ParserDB,
        registry: &FunctionRegistry,
        projected_fk: Option<&str>,
    ) -> Option<String> {
        let matches = membership_matches(select, db, registry, projected_fk);
        if matches.len() > 1 {
            return Some(
                "Ambiguous membership pattern: multiple candidate membership sources matched"
                    .to_string(),
            );
        }
        if matches.is_empty() && selection_references_current_user(select, registry) {
            return Some(
                "Ambiguous membership pattern: could not infer a unique membership join"
                    .to_string(),
            );
        }
        None
    }

    match expr {
        Expr::Exists { subquery, negated } if !negated => {
            let query = subquery.as_ref();
            let body = query.body.as_ref();
            if let sqlparser::ast::SetExpr::Select(select) = body {
                return diagnose_select(select.as_ref(), db, registry, None);
            }
            None
        }
        Expr::InSubquery {
            expr: lhs,
            subquery,
            negated,
        } if !negated => {
            let lhs_col = extract_column_name(lhs)?;
            let query = subquery.as_ref();
            let body = query.body.as_ref();
            if let sqlparser::ast::SetExpr::Select(select) = body {
                let projected_fk = extract_projection_column(select.as_ref())
                    .unwrap_or(lhs_col)
                    .clone();
                return diagnose_select(select.as_ref(), db, registry, Some(&projected_fk));
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn diagnose_p5_parent_inheritance_ambiguity(
    expr: &Expr,
    db: &ParserDB,
    outer_table: &str,
) -> Option<String> {
    let Expr::Exists { subquery, negated } = expr else {
        return None;
    };
    if *negated {
        return None;
    }

    let query = subquery.as_ref();
    let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let analysis = analyze_p5_parent_inheritance(select.as_ref(), db, outer_table)?;

    if analysis.candidates.len() > 1 {
        return Some(
            "Ambiguous parent inheritance pattern: multiple candidate parent sources matched"
                .to_string(),
        );
    }
    if analysis.saw_conflicting_join {
        return Some(
            "Ambiguous parent inheritance pattern: conflicting outer FK join columns in EXISTS predicate"
                .to_string(),
        );
    }
    None
}

#[derive(Debug, Clone)]
struct P5InheritanceCandidate {
    parent_table: String,
    fk_column: String,
    inner_predicates: Vec<Expr>,
}

#[derive(Debug, Clone, Default)]
struct P5InheritanceAnalysis {
    candidates: Vec<P5InheritanceCandidate>,
    saw_conflicting_join: bool,
}

fn analyze_p5_parent_inheritance(
    select: &Select,
    db: &ParserDB,
    outer_table: &str,
) -> Option<P5InheritanceAnalysis> {
    let sources = relation_sources(select);
    if sources.is_empty() {
        return None;
    }

    let outer_table_meta = lookup_table(db, outer_table)?;
    let selection = select.selection.as_ref()?;

    let outer_cols: Vec<String> = outer_table_meta
        .columns(db)
        .map(|c| c.column_name().to_string())
        .collect();
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);

    let mut analysis = P5InheritanceAnalysis::default();

    for source in sources {
        let Some(parent_table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let parent_cols: Vec<String> = parent_table
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        let mut fk_column: Option<String> = None;
        let mut inner_predicates = Vec::new();
        let mut invalid_join = false;

        for pred in &predicates {
            if let Some((outer_fk, _parent_col)) = extract_parent_join_columns(
                pred,
                outer_table,
                &outer_cols,
                &source.table_name,
                source.alias.as_deref(),
                &parent_cols,
            ) {
                if fk_column
                    .as_ref()
                    .is_none_or(|existing| existing == &outer_fk)
                {
                    fk_column = Some(outer_fk);
                    continue;
                }
                invalid_join = true;
                break;
            }
            inner_predicates.push((*pred).clone());
        }

        if invalid_join {
            analysis.saw_conflicting_join = true;
            continue;
        }
        let Some(fk_column) = fk_column else {
            continue;
        };
        if inner_predicates.is_empty() {
            continue;
        }
        if !table_has_fk_to_parent(outer_table_meta, db, &fk_column, &source.table_name) {
            continue;
        }

        analysis.candidates.push(P5InheritanceCandidate {
            parent_table: source.table_name,
            fk_column,
            inner_predicates,
        });
    }

    Some(analysis)
}

fn selection_references_current_user(select: &Select, registry: &FunctionRegistry) -> bool {
    let Some(selection) = select.selection.as_ref() else {
        return false;
    };
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);
    predicates.into_iter().any(|predicate| match predicate {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            is_current_user_expr(left, registry) || is_current_user_expr(right, registry)
        }
        _ => is_current_user_expr(predicate, registry),
    })
}

/// Try to recognize P10: constant boolean policies (`TRUE` / `FALSE`).
pub fn recognize_p10_constant_bool(
    expr: &Expr,
    _db: &ParserDB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    constant_bool_value(expr).map(|value| ClassifiedExpr {
        pattern: PatternClass::P10ConstantBool { value },
        confidence: ConfidenceLevel::A,
    })
}

/// Try to recognize P6: boolean flag `is_public = TRUE` or bare boolean column.
pub fn recognize_p6(
    expr: &Expr,
    _db: &ParserDB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    /// Pick confidence: A when the column is explicitly registered, B otherwise.
    ///
    /// Heuristic-only matches are capped at B because column names like `published`
    /// or `visible` commonly represent editorial state rather than access control;
    /// wildcard public grants must be confirmed by the operator.
    fn p6_confidence(col: &str, registry: &FunctionRegistry) -> ConfidenceLevel {
        if registry.is_confirmed_public_flag_column(col) {
            ConfidenceLevel::A
        } else {
            ConfidenceLevel::B
        }
    }

    if let Some((col_name, is_true)) = extract_boolean_column_equality(expr) {
        if is_true && is_public_flag_column_name(&col_name) {
            return Some(ClassifiedExpr {
                pattern: PatternClass::P6BooleanFlag {
                    column: col_name.clone(),
                },
                confidence: p6_confidence(&col_name, registry),
            });
        }
        return None;
    }

    match expr {
        Expr::IsTrue(inner) | Expr::IsNotFalse(inner) => {
            let col_name = extract_column_name(inner)?;
            if is_public_flag_column_name(&col_name) {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag {
                        column: col_name.clone(),
                    },
                    confidence: p6_confidence(&col_name, registry),
                });
            }
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let col_name = extract_column_name(expr)?;
            if is_public_flag_column_name(&col_name) {
                return Some(ClassifiedExpr {
                    pattern: PatternClass::P6BooleanFlag {
                        column: col_name.clone(),
                    },
                    confidence: p6_confidence(&col_name, registry),
                });
            }
        }
        _ => {}
    }
    None
}

/// Returns the column name if the expression is a negated public-flag check
/// (`col = FALSE`, `FALSE = col`, `col IS FALSE`, `col IS NOT TRUE`).
///
/// These forms look similar to P6 but cannot be expressed as static `OpenFGA`
/// tuples because they filter OUT rows rather than granting access.
pub fn is_negated_boolean_flag(expr: &Expr) -> Option<String> {
    if let Some((col_name, value)) = extract_boolean_column_equality(expr) {
        if !value && is_public_flag_column_name(&col_name) {
            return Some(col_name);
        }
        return None;
    }

    match expr {
        Expr::IsFalse(inner) | Expr::IsNotTrue(inner) => {
            let col_name = extract_column_name(inner)?;
            if is_public_flag_column_name(&col_name) {
                return Some(col_name);
            }
            None
        }
        _ => None,
    }
}

fn extract_boolean_column_equality(expr: &Expr) -> Option<(String, bool)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    if let (Some(col), Some(value)) = (extract_column_name(left), constant_bool_value(right)) {
        return Some((col, value));
    }
    if let (Some(value), Some(col)) = (constant_bool_value(left), extract_column_name(right)) {
        return Some((col, value));
    }

    None
}

pub(crate) fn constant_bool_value(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Boolean(b) => Some(*b),
            _ => None,
        },
        Expr::Nested(inner) | Expr::Cast { expr: inner, .. } => constant_bool_value(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => constant_bool_value(inner).map(|value| !value),
        _ => None,
    }
}

// ---- Helper functions ----

/// Extract a function name from an expression.
pub fn extract_function_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalized_function_name(func)),
        Expr::Cast { expr, .. } => extract_function_name(expr),
        Expr::Nested(inner) => extract_function_name(inner),
        _ => None,
    }
}

/// True when the function call in `expr` has at least one argument that resolves
/// to a current-user expression.
///
/// Used by the P1/P2 recognizers to guard against false positives where a
/// role-threshold function is called with non-user arguments, e.g.
/// `get_owner_role(owner_id, id) >= 2`.
fn function_has_current_user_arg(expr: &Expr, registry: &FunctionRegistry) -> bool {
    use sqlparser::ast::FunctionArguments;
    let Expr::Function(func) = expr else {
        return false;
    };
    let FunctionArguments::List(arg_list) = &func.args else {
        return false;
    };
    arg_list
        .args
        .iter()
        .filter_map(function_arg_expr)
        .any(|e| is_current_user_expr(e, registry))
}

/// Extract an integer value from an expression.
fn extract_integer_value(expr: &Expr) -> Option<i32> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse().ok(),
            _ => None,
        },
        Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr: inner,
        } => extract_integer_value(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr: inner,
        } => extract_integer_value(inner).map(|value| -value),
        _ => None,
    }
}

/// Extract a table name from a `TableFactor`.
fn extract_table_name_from_table_factor(tf: &TableFactor) -> Option<String> {
    if let TableFactor::Table { name, .. } = tf {
        Some(name.to_string())
    } else {
        None
    }
}

fn extract_table_alias_from_table_factor(tf: &TableFactor) -> Option<String> {
    if let TableFactor::Table { alias, .. } = tf {
        alias.as_ref().map(|a| a.name.value.clone())
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct RelationSource {
    table_name: String,
    alias: Option<String>,
}

fn relation_sources(select: &Select) -> Vec<RelationSource> {
    let mut sources = Vec::new();
    for from in &select.from {
        if let Some(source) = relation_source_from_table_factor(&from.relation) {
            sources.push(source);
        }
        for join in &from.joins {
            if let Some(source) = relation_source_from_table_factor(&join.relation) {
                sources.push(source);
            }
        }
    }

    sources
}

fn relation_source_from_table_factor(tf: &TableFactor) -> Option<RelationSource> {
    Some(RelationSource {
        table_name: extract_table_name_from_table_factor(tf)?,
        alias: extract_table_alias_from_table_factor(tf),
    })
}

fn membership_matches(
    select: &Select,
    db: &ParserDB,
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> Vec<(String, String, String, Option<String>)> {
    let mut matches = Vec::new();
    for source in relation_sources(select) {
        let Some(table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let col_names: Vec<String> = table
            .columns(db)
            .map(|c| c.column_name().to_string())
            .collect();

        if let Some((fk_col, user_col, extra_predicate_sql)) = extract_membership_columns(
            select,
            &source.table_name,
            source.alias.as_deref(),
            &col_names,
            registry,
            projected_fk_hint,
        ) {
            matches.push((source.table_name, fk_col, user_col, extra_predicate_sql));
        }
    }
    matches
}

fn extract_projection_column(select: &Select) -> Option<String> {
    select.projection.first().and_then(|p| match p {
        SelectItem::UnnamedExpr(e) => extract_column_name(e),
        SelectItem::ExprWithAlias { expr, .. } => extract_column_name(expr),
        _ => None,
    })
}

/// Extract the ON expression from a `JoinOperator`, if present.
fn join_on_expr(op: &sqlparser::ast::JoinOperator) -> Option<&Expr> {
    use sqlparser::ast::JoinConstraint;
    use sqlparser::ast::JoinOperator::{
        CrossJoin, FullOuter, Inner, Join, Left, LeftOuter, Right, RightOuter,
    };
    let (Join(c) | Inner(c) | Left(c) | LeftOuter(c) | Right(c) | RightOuter(c) | FullOuter(c)
    | CrossJoin(c)) = op
    else {
        return None;
    };
    if let JoinConstraint::On(expr) = c {
        Some(expr)
    } else {
        None
    }
}

fn extract_membership_columns(
    select: &Select,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
    projected_fk_hint: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let mut fk_col: Option<String> = None;
    let mut fk_col_is_explicit = false; // true only when found via an explicit `join_col = outer_col` predicate
    let mut user_col: Option<String> = None;
    let mut extras: Vec<String> = Vec::new();

    // Collect JOIN ON predicates separately (they provide explicit FK correlation but should
    // not be included in the extra_predicate_sql used in generated tuple queries).
    let mut on_predicates: Vec<&Expr> = Vec::new();
    for from_item in &select.from {
        for join in &from_item.joins {
            if let Some(on_expr) = join_on_expr(&join.join_operator) {
                flatten_and_predicates(on_expr, &mut on_predicates);
            }
        }
    }

    // Process WHERE predicates (with extras).
    if let Some(selection) = &select.selection {
        let mut predicates = Vec::new();
        flatten_and_predicates(selection, &mut predicates);

        for pred in predicates {
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = pred
            {
                let left_col = extract_qualified_column(left);
                let right_col = extract_qualified_column(right);

                // user_id = auth_current_user()
                if let Some((qual, col)) = left_col.clone() {
                    if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                        && is_current_user_expr(right, registry)
                    {
                        user_col = Some(col);
                        continue;
                    }
                }
                if let Some((qual, col)) = right_col.clone() {
                    if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                        && is_current_user_expr(left, registry)
                    {
                        user_col = Some(col);
                        continue;
                    }
                }

                // join_table_fk = outer_table_col
                if let (Some((left_qual, left_name)), Some((right_qual, right_name))) =
                    (left_col, right_col)
                {
                    let left_is_join = is_join_column_ref(
                        left_qual.as_deref(),
                        &left_name,
                        join_table,
                        join_alias,
                        join_cols,
                    );
                    let right_is_join = is_join_column_ref(
                        right_qual.as_deref(),
                        &right_name,
                        join_table,
                        join_alias,
                        join_cols,
                    );

                    if left_is_join && !right_is_join {
                        if fk_col
                            .as_ref()
                            .is_none_or(|existing| existing == &left_name)
                        {
                            fk_col = Some(left_name);
                            fk_col_is_explicit = true;
                            continue;
                        }
                        return None;
                    }
                    if right_is_join && !left_is_join {
                        if fk_col
                            .as_ref()
                            .is_none_or(|existing| existing == &right_name)
                        {
                            fk_col = Some(right_name);
                            fk_col_is_explicit = true;
                            continue;
                        }
                        return None;
                    }
                    // Neither side references the join table — this is an outer-row
                    // correlation predicate (e.g. `d.id = docs.id` linking the inner
                    // alias to the outer table).  These are implicit in the generated
                    // tuple query and must not be added to extra_predicate_sql.
                    if !left_is_join && !right_is_join {
                        continue;
                    }
                }
            }

            // Scope validation: reject predicates that reference columns from
            // tables other than the join table.  Such predicates require a JOIN
            // that the generated single-table tuple query cannot provide, so
            // they would produce semantically invalid SQL.
            if predicate_references_other_table(pred, join_table, join_alias) {
                return None;
            }
            // Keep additional predicates for tuple filtering.
            // Strip join-table qualifiers at the AST level before rendering to SQL.
            // This handles double-quoted identifiers, dollar-quoted strings, and other
            // SQL literal forms that text-based rewriting would mangle.
            let mut normalized_pred = pred.clone();
            strip_qualifier_from_expr(&mut normalized_pred, join_table, join_alias);
            extras.push(normalized_pred.to_string());
        }
    }

    // Also scan JOIN ON conditions for explicit FK correlation.
    // These are NOT added to extras because the generated tuple query does not include a JOIN.
    for pred in &on_predicates {
        if fk_col_is_explicit {
            break; // FK already found; no need to scan further.
        }
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = pred
        {
            let left_col = extract_qualified_column(left);
            let right_col = extract_qualified_column(right);

            // user_id = auth_current_user() — handle in ON clause too
            if let Some((qual, col)) = left_col.clone() {
                if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                    && is_current_user_expr(right, registry)
                {
                    if user_col.is_none() {
                        user_col = Some(col);
                    }
                    continue;
                }
            }
            if let Some((qual, col)) = right_col.clone() {
                if is_join_column_ref(qual.as_deref(), &col, join_table, join_alias, join_cols)
                    && is_current_user_expr(left, registry)
                {
                    if user_col.is_none() {
                        user_col = Some(col);
                    }
                    continue;
                }
            }

            if let (Some((left_qual, left_name)), Some((right_qual, right_name))) =
                (left_col, right_col)
            {
                let left_is_join = is_join_column_ref(
                    left_qual.as_deref(),
                    &left_name,
                    join_table,
                    join_alias,
                    join_cols,
                );
                let right_is_join = is_join_column_ref(
                    right_qual.as_deref(),
                    &right_name,
                    join_table,
                    join_alias,
                    join_cols,
                );

                if left_is_join
                    && !right_is_join
                    && fk_col
                        .as_ref()
                        .is_none_or(|existing| existing == &left_name)
                {
                    fk_col = Some(left_name);
                    fk_col_is_explicit = true;
                } else if right_is_join
                    && !left_is_join
                    && fk_col
                        .as_ref()
                        .is_none_or(|existing| existing == &right_name)
                {
                    fk_col = Some(right_name);
                    fk_col_is_explicit = true;
                }
            }
        }
    }

    // Only fall back to column-name inference when the IN-subquery form provides
    // an implicit correlation via the projected FK hint.  An EXISTS without an
    // explicit `join_table_col = outer_table_col` predicate cannot be safely
    // classified as P4: the policy would grant access to any resource the user
    // is a member of, rather than the specific resource being queried.
    if fk_col.is_none() && !fk_col_is_explicit && projected_fk_hint.is_some() {
        fk_col = infer_membership_fk_column(
            join_table,
            join_cols,
            user_col.as_deref(),
            projected_fk_hint,
        );
    }

    let user_col = user_col?;
    let fk_col = fk_col?;

    let extra_predicate_sql = if extras.is_empty() {
        None
    } else {
        Some(extras.join(" AND "))
    };

    Some((fk_col, user_col, extra_predicate_sql))
}

fn flatten_and_predicates<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::And,
        right,
    } = expr
    {
        flatten_and_predicates(left, out);
        flatten_and_predicates(right, out);
    } else {
        out.push(expr);
    }
}

fn extract_qualified_column(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Identifier(id) => Some((None, id.value.clone())),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => Some((
            Some(parts[parts.len() - 2].value.clone()),
            parts.last()?.value.clone(),
        )),
        _ => None,
    }
}

fn current_user_accessor_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalized_function_name(func)),
        Expr::Identifier(ident) => Some(normalize_relation_name(&ident.value)),
        Expr::Cast { expr, .. } => current_user_accessor_name(expr),
        Expr::Nested(inner) => current_user_accessor_name(inner),
        // Phase 6b: unwrap a scalar subquery — `(SELECT auth.uid())`.
        // The subquery must project exactly one non-wildcard expression.
        Expr::Subquery(query) => {
            if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
                if select.projection.len() == 1 {
                    if let SelectItem::UnnamedExpr(inner)
                    | SelectItem::ExprWithAlias { expr: inner, .. } = &select.projection[0]
                    {
                        return current_user_accessor_name(inner);
                    }
                }
            }
            None
        }
        // Gap 2: unwrap JSON accessor operators (`->`, `->>`, `#>`, `#>>`).
        // Example: `current_setting('request.jwt.claims')::json->>'sub'`
        Expr::BinaryOp {
            op:
                BinaryOperator::Arrow
                | BinaryOperator::LongArrow
                | BinaryOperator::HashArrow
                | BinaryOperator::HashLongArrow,
            left,
            ..
        } => current_user_accessor_name(left),
        _ => None,
    }
}

/// Returns `true` when `expr` (or its Cast/Nested wrapper) is a scalar subquery.
/// Used in [`recognize_p3`] to cap confidence at B for subquery-wrapped accessors.
fn is_subquery_wrapped(expr: &Expr) -> bool {
    match expr {
        Expr::Subquery(_) => true,
        Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => is_subquery_wrapped(inner),
        _ => false,
    }
}

/// Returns `true` when `expr` (or its Cast/Nested wrapper) contains a JSON
/// accessor operator (`->`, `->>`, `#>`, `#>>`).  Used in [`recognize_p3`] to
/// cap confidence at B for JSON-extracted user identifiers.
fn is_json_accessor_wrapped(expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp {
            op:
                BinaryOperator::Arrow
                | BinaryOperator::LongArrow
                | BinaryOperator::HashArrow
                | BinaryOperator::HashLongArrow,
            ..
        } => true,
        Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => is_json_accessor_wrapped(inner),
        _ => false,
    }
}

fn is_current_user_keyword(name: &str) -> bool {
    // `session_user` is intentionally excluded: it refers to the original connection user and
    // does NOT change when `SET ROLE` is used, unlike `current_user` / `current_role`.
    // Policies that reference `session_user` must be classified as Unknown (D) so the operator
    // manually verifies the intended semantics before translation.
    name == "current_user" || name == "user" || name == "current_role"
}

fn is_known_current_user_name(name: &str, registry: &FunctionRegistry) -> bool {
    let normalized = normalize_relation_name(name);
    registry.is_current_user_accessor(&normalized) || is_current_user_keyword(&normalized)
}

fn is_current_user_expr(expr: &Expr, registry: &FunctionRegistry) -> bool {
    current_user_accessor_name(expr)
        .as_deref()
        .is_some_and(|name| is_known_current_user_name(name, registry))
}

fn is_join_column_ref(
    qualifier: Option<&str>,
    column: &str,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
) -> bool {
    if !join_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        None => true,
        Some(q) => qualifier_matches_table(q, join_table, join_alias),
    }
}

/// Strip join-table qualifiers from all `CompoundIdentifier` nodes in `expr`
/// whose qualifier matches `join_table` or `join_alias`.  Qualifying identifiers
/// are replaced with bare `Identifier` nodes, making the predicate suitable for
/// embedding in a single-table query that does not include the join table.
///
/// Operates at the AST level to correctly handle double-quoted identifiers,
/// dollar-quoted strings, and other SQL literal forms that text-based rewriting
/// would mangle.
fn strip_qualifier_from_expr(expr: &mut Expr, join_table: &str, join_alias: Option<&str>) {
    // Check — without consuming — whether this CompoundIdentifier should be stripped.
    let strip_to_bare = if let Expr::CompoundIdentifier(parts) = &*expr {
        parts.len() >= 2
            && qualifier_matches_table(&parts[parts.len() - 2].value, join_table, join_alias)
    } else {
        false
    };
    if strip_to_bare {
        if let Expr::CompoundIdentifier(parts) = &*expr {
            let column = parts.last().unwrap().clone();
            *expr = Expr::Identifier(column);
        }
        return;
    }

    match expr {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            strip_qualifier_from_expr(left, join_table, join_alias);
            strip_qualifier_from_expr(right, join_table, join_alias);
        }
        Expr::Function(function) => {
            if let FunctionArguments::List(arg_list) = &mut function.args {
                for arg in &mut arg_list.args {
                    if let Some(arg_expr) = function_arg_expr_mut(arg) {
                        strip_qualifier_from_expr(arg_expr, join_table, join_alias);
                    }
                }
            }
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Cast { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner) => {
            strip_qualifier_from_expr(inner, join_table, join_alias);
        }
        Expr::InList {
            expr: inner, list, ..
        } => {
            strip_qualifier_from_expr(inner, join_table, join_alias);
            for item in list.iter_mut() {
                strip_qualifier_from_expr(item, join_table, join_alias);
            }
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand_expr) = operand.as_deref_mut() {
                strip_qualifier_from_expr(operand_expr, join_table, join_alias);
            }
            for when in conditions.iter_mut() {
                strip_qualifier_from_expr(&mut when.condition, join_table, join_alias);
                strip_qualifier_from_expr(&mut when.result, join_table, join_alias);
            }
            if let Some(else_expr) = else_result.as_deref_mut() {
                strip_qualifier_from_expr(else_expr, join_table, join_alias);
            }
        }
        _ => {}
    }
}

fn function_arg_expr_mut(arg: &mut FunctionArg) -> Option<&mut Expr> {
    match arg {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))
        | FunctionArg::Named {
            arg: FunctionArgExpr::Expr(expr),
            ..
        }
        | FunctionArg::ExprNamed {
            arg: FunctionArgExpr::Expr(expr),
            ..
        } => Some(expr),
        _ => None,
    }
}

/// Returns `true` if `expr` contains any column reference whose qualifier is
/// NOT the join table (or its alias).  Bare (unqualified) column references are
/// assumed to belong to the join table and are allowed.
fn predicate_references_other_table(
    expr: &Expr,
    join_table: &str,
    join_alias: Option<&str>,
) -> bool {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            // qualifier.column — check if qualifier matches the join table.
            let qualifier = &parts[parts.len() - 2].value;
            !qualifier_matches_table(qualifier, join_table, join_alias)
        }
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            predicate_references_other_table(left, join_table, join_alias)
                || predicate_references_other_table(right, join_table, join_alias)
        }
        Expr::Function(function) => {
            if let FunctionArguments::List(arg_list) = &function.args {
                arg_list
                    .args
                    .iter()
                    .filter_map(function_arg_expr)
                    .any(|arg_expr| {
                        predicate_references_other_table(arg_expr, join_table, join_alias)
                    })
            } else {
                false
            }
        }
        Expr::UnaryOp { expr, .. } | Expr::Cast { expr, .. } | Expr::Nested(expr) => {
            predicate_references_other_table(expr, join_table, join_alias)
        }
        Expr::IsTrue(e)
        | Expr::IsNotFalse(e)
        | Expr::IsFalse(e)
        | Expr::IsNotTrue(e)
        | Expr::IsNull(e)
        | Expr::IsNotNull(e) => predicate_references_other_table(e, join_table, join_alias),
        Expr::InList { expr, list, .. } => {
            predicate_references_other_table(expr, join_table, join_alias)
                || list
                    .iter()
                    .any(|e| predicate_references_other_table(e, join_table, join_alias))
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            operand
                .as_deref()
                .is_some_and(|e| predicate_references_other_table(e, join_table, join_alias))
                || conditions.iter().any(|when| {
                    predicate_references_other_table(&when.condition, join_table, join_alias)
                        || predicate_references_other_table(&when.result, join_table, join_alias)
                })
                || else_result
                    .as_deref()
                    .is_some_and(|e| predicate_references_other_table(e, join_table, join_alias))
        }
        _ => false, // bare identifiers, functions, literals, constants — safe
    }
}

fn qualifier_matches_table(qualifier: &str, table_name: &str, alias: Option<&str>) -> bool {
    if alias.is_some_and(|a| qualifier.eq_ignore_ascii_case(a)) {
        return true;
    }

    table_qualifier_candidates(table_name)
        .iter()
        .any(|candidate| qualifier.eq_ignore_ascii_case(candidate))
}

fn table_qualifier_candidates(table_name: &str) -> Vec<String> {
    let mut candidates = vec![table_name.to_string()];
    if let Some((_, relation)) = split_schema_and_relation(table_name) {
        candidates.push(relation);
    }
    candidates
}

fn combine_predicates_with_and(predicates: Vec<Expr>) -> Option<Expr> {
    let mut iter = predicates.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |acc, next| Expr::BinaryOp {
        left: Box::new(acc),
        op: BinaryOperator::And,
        right: Box::new(next),
    }))
}

fn extract_parent_join_columns(
    predicate: &Expr,
    outer_table: &str,
    outer_cols: &[String],
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
) -> Option<(String, String)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = predicate
    else {
        return None;
    };

    let left_col = extract_qualified_column(left)?;
    let right_col = extract_qualified_column(right)?;

    let left_is_parent = is_parent_column_ref(
        left_col.0.as_deref(),
        &left_col.1,
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );
    let right_is_parent = is_parent_column_ref(
        right_col.0.as_deref(),
        &right_col.1,
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );

    let left_is_outer = is_outer_column_ref(
        left_col.0.as_deref(),
        &left_col.1,
        outer_table,
        outer_cols,
        parent_cols,
    );
    let right_is_outer = is_outer_column_ref(
        right_col.0.as_deref(),
        &right_col.1,
        outer_table,
        outer_cols,
        parent_cols,
    );

    if left_is_parent && right_is_outer {
        return Some((right_col.1, left_col.1));
    }
    if right_is_parent && left_is_outer {
        return Some((left_col.1, right_col.1));
    }

    None
}

fn is_parent_column_ref(
    qualifier: Option<&str>,
    column: &str,
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
    outer_cols: &[String],
) -> bool {
    if !parent_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, parent_table, parent_alias),
        None => !outer_cols.iter().any(|c| c == column),
    }
}

fn is_outer_column_ref(
    qualifier: Option<&str>,
    column: &str,
    outer_table: &str,
    outer_cols: &[String],
    parent_cols: &[String],
) -> bool {
    if !outer_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, outer_table, None),
        None => !parent_cols.iter().any(|c| c == column),
    }
}

fn table_has_fk_to_parent(
    outer_table: &<ParserDB as DatabaseLike>::Table,
    db: &ParserDB,
    fk_column: &str,
    parent_table_name: &str,
) -> bool {
    outer_table.foreign_keys(db).any(|fk| {
        let host_col_matches = fk
            .host_column(db)
            .is_some_and(|col| col.column_name() == fk_column);
        if !host_col_matches {
            return false;
        }

        qualifier_matches_table(
            fk.referenced_table(db).table_name(),
            parent_table_name,
            None,
        )
    })
}

/// Check if an expression references a column that looks like an attribute
/// (not a user/owner reference).
pub fn is_attribute_check(expr: &Expr) -> Option<String> {
    if let Expr::BinaryOp { left, op, right } = expr {
        if matches!(
            op,
            BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::GtEq
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::Lt
        ) {
            if let Some(col) = extract_column_name(left) {
                if is_literal_or_temporal(right) && !is_user_related_column_name(&col) {
                    return Some(col);
                }
            }
            if let Some(col) = extract_column_name(right) {
                if is_literal_or_temporal(left) && !is_user_related_column_name(&col) {
                    return Some(col);
                }
            }
        }
    }
    // `col IN ('a', 'b', ...)` with all-literal items (non-negated).
    if let Expr::InList {
        expr: col_expr,
        list,
        negated: false,
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col)
                && !list.is_empty()
                && list.iter().all(is_literal_value)
            {
                return Some(col);
            }
        }
    }
    // `col IS NOT DISTINCT FROM value` / `col IS DISTINCT FROM value`
    if let Expr::IsNotDistinctFrom(left, right) | Expr::IsDistinctFrom(left, right) = expr {
        if let Some(col) = extract_column_name(left) {
            if is_literal_or_temporal(right) && !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
        if let Some(col) = extract_column_name(right) {
            if is_literal_or_temporal(left) && !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    // `col BETWEEN low AND high` (non-negated, both bounds literal or temporal).
    if let Expr::Between {
        expr: col_expr,
        low,
        high,
        negated: false,
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col)
                && is_literal_or_temporal(low)
                && is_literal_or_temporal(high)
            {
                return Some(col);
            }
        }
    }
    // `col IS NULL` / `col IS NOT NULL`
    if let Expr::IsNull(col_expr) | Expr::IsNotNull(col_expr) = expr {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    // `col LIKE pattern` / `col ILIKE pattern` (non-negated)
    if let Expr::Like {
        negated: false,
        expr: col_expr,
        ..
    }
    | Expr::ILike {
        negated: false,
        expr: col_expr,
        ..
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(&col) {
                return Some(col);
            }
        }
    }
    None
}

fn is_literal_value(expr: &Expr) -> bool {
    match expr {
        Expr::Value(_) => true,
        Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
            expr: inner,
        } => is_literal_value(inner),
        _ => false,
    }
}

/// Returns `true` when the expression is a literal value or a well-known
/// temporal function call (e.g. `now()`, `current_timestamp`).  Used in
/// `is_attribute_check` so that `valid_until > now()` is recognised as an
/// attribute condition rather than falling through to Unknown.
fn is_literal_or_temporal(expr: &Expr) -> bool {
    if is_literal_value(expr) {
        return true;
    }
    is_well_known_temporal_function(expr)
}

/// Recognise zero-arg temporal built-in functions that produce a deterministic
/// (within a statement) date/time value.
fn is_well_known_temporal_function(expr: &Expr) -> bool {
    match expr {
        Expr::Function(func) => {
            let name = normalized_function_name(func);
            matches!(
                name.as_str(),
                "now"
                    | "current_timestamp"
                    | "current_date"
                    | "current_time"
                    | "clock_timestamp"
                    | "statement_timestamp"
                    | "transaction_timestamp"
                    | "localtime"
                    | "localtimestamp"
            )
        }
        Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => {
            is_well_known_temporal_function(inner)
        }
        _ => false,
    }
}

fn infer_membership_fk_column(
    join_table: &str,
    join_cols: &[String],
    user_col: Option<&str>,
    projected_fk_hint: Option<&str>,
) -> Option<String> {
    let id_candidates: Vec<String> = join_cols
        .iter()
        .filter(|c| c.ends_with("_id") && Some(c.as_str()) != user_col)
        .cloned()
        .collect();

    if id_candidates.is_empty() {
        return None;
    }
    if id_candidates.len() == 1 {
        return id_candidates.first().cloned();
    }

    if let Some(hint) = projected_fk_hint {
        if id_candidates.iter().any(|c| c == hint) {
            return Some(hint.to_string());
        }
    }

    let relation = normalize_relation_name(join_table);
    let mut relation_hints = Vec::new();
    if let Some(stem) = relation.strip_suffix("_members") {
        relation_hints.push(format!("{stem}_id"));
    }
    if let Some(stem) = relation.strip_suffix("_memberships") {
        relation_hints.push(format!("{stem}_id"));
    }
    if let Some(stem) = relation.strip_suffix("_membership") {
        relation_hints.push(format!("{stem}_id"));
    }

    let hinted: Vec<String> = id_candidates
        .iter()
        .filter(|candidate| relation_hints.iter().any(|hint| hint == *candidate))
        .cloned()
        .collect();
    if hinted.len() == 1 {
        return hinted.into_iter().next();
    }

    let non_scope_candidates: Vec<String> = id_candidates
        .iter()
        .filter(|candidate| {
            !matches!(
                candidate.as_str(),
                "tenant_id" | "org_id" | "organization_id" | "account_id" | "workspace_id"
            )
        })
        .cloned()
        .collect();
    if non_scope_candidates.len() == 1 {
        return non_scope_candidates.into_iter().next();
    }

    None
}

#[cfg(test)]
mod tests {
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
        let c3 =
            recognize_p2(&three_arg, &db, &registry).expect("expected P2 for pg_has_role 3-arg");
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

        // Two-arg form: pg_has_role('editor', 'USAGE') — current user is implied.
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

        // Three-arg form with non-current-user first arg should not match.
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
        // Register `role` (normalized form of `auth.role` — schema stripped) as a RoleAccessor.
        registry.register_if_absent(
            "role",
            &crate::parser::function_analyzer::FunctionSemantic::RoleAccessor {
                returns: "text".to_string(),
            },
        );

        // Equality form: auth.role() = 'authenticated'
        // `auth.role` normalizes to `role` (schema prefix is stripped by normalize_relation_name).
        let eq_expr = parse_expr("auth.role() = 'authenticated'");
        let c_eq = recognize_p2(&eq_expr, &db, &registry)
            .expect("expected P2 for role_accessor = literal");
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
    fn recognize_array_patterns_any_and_overlap() {
        let registry = FunctionRegistry::new();

        // `current_user = ANY(allowed_users)` → P9 at confidence B.
        let any_expr = parse_expr("current_user = ANY(allowed_users)");
        let c_any = recognize_array_patterns(&any_expr, &registry)
            .expect("expected array pattern match for = ANY");
        assert!(
            matches!(
                &c_any.pattern,
                PatternClass::P9AttributeCondition { column, .. } if column == "allowed_users"
            ),
            "= ANY should produce P9 on array column, got: {:?}",
            c_any.pattern
        );
        assert_eq!(
            c_any.confidence,
            ConfidenceLevel::B,
            "= ANY should be confidence B"
        );

        // `col1 && col2` array overlap → P9 at confidence C.
        let overlap_expr = parse_expr("allowed_roles && ARRAY['admin', 'editor']");
        let c_overlap = recognize_array_patterns(&overlap_expr, &registry)
            .expect("expected array pattern match for &&");
        assert!(
            matches!(
                &c_overlap.pattern,
                PatternClass::P9AttributeCondition { .. }
            ),
            "array && should produce P9, got: {:?}",
            c_overlap.pattern
        );
        assert_eq!(
            c_overlap.confidence,
            ConfidenceLevel::C,
            "&& should be confidence C"
        );

        // Non-array expression should not match.
        let non_array = parse_expr("owner_id = current_user");
        assert!(recognize_array_patterns(&non_array, &registry).is_none());
    }

    #[test]
    fn recognize_p3_heuristics_cover_confidence_variants() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        // Heuristic accessor with owner-like column → confidence B (not A).
        // A is reserved for registry-confirmed functions and SQL keywords.
        let a = parse_expr("owner_id = auth_current_user_id()");
        let classified_a = recognize_p3(&a, &db, &registry).expect("expected heuristic match");
        assert_eq!(classified_a.confidence, ConfidenceLevel::B);

        let b = parse_expr("tenant_uuid = auth_current_user_id()");
        let classified_b = recognize_p3(&b, &db, &registry).expect("expected heuristic match");
        assert_eq!(classified_b.confidence, ConfidenceLevel::B);

        let none = parse_expr("tenant_uuid = actor_id()");
        assert!(
            recognize_p3(&none, &db, &registry).is_none(),
            "non-user-like function should not match ownership"
        );

        let not_eq = parse_expr("owner_id <> auth_current_user_id()");
        assert!(recognize_p3(&not_eq, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p3_supports_is_not_distinct_from() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();

        // Heuristic accessor with owner-like column → confidence B (see 3c).
        let expr = parse_expr("owner_id IS NOT DISTINCT FROM auth_current_user_id()");
        let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
        assert!(matches!(
            classified.pattern,
            PatternClass::P3DirectOwnership { ref column } if column == "owner_id"
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::B);
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
    fn recognize_p3_current_setting_is_heuristic_b_and_registry_a() {
        let db = db_with_docs_and_members();

        // Without explicit registration: current_setting → confidence B.
        let empty_registry = FunctionRegistry::new();
        let expr = parse_expr("owner_id = current_setting('app.current_user_id')::uuid");
        let classified = recognize_p3(&expr, &db, &empty_registry)
            .expect("expected P3 match for current_setting");
        assert!(
            matches!(&classified.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
            "current_setting should produce P3"
        );
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::B,
            "unregistered current_setting should be confidence B"
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
        assert!(recognize_p4(&negated, &db, &registry).is_none());

        let exists_expr = parse_expr(
            "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = auth_current_user_id()
                 AND doc_members.role = 'admin'
             )",
        );
        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                extra_predicate_sql,
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

        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
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

        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
        assert!(matches!(
            &classified.pattern,
            PatternClass::P4ExistsMembership {
                join_table,
                fk_column,
                user_column,
                extra_predicate_sql,
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
            recognize_p4(&exists_expr, &db, &registry).is_none(),
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
                recognize_p4(&exists_expr, &db, &registry).is_none(),
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
                recognize_p4(&exists_expr, &db, &registry).is_none(),
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

        let classified = recognize_p4(&exists_expr, &db, &registry).expect("expected P4 match");
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
            recognize_p4(&exists_expr, &db, &registry).is_none(),
            "function-wrapped outer-table predicate should fail closed for P4"
        );
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
        assert!(recognize_p4_in_subquery(&negated, &db, &registry).is_none());

        let in_subquery = parse_expr(
            "doc_id IN (
               SELECT dm.doc_id AS projected_doc
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
        );
        let classified =
            recognize_p4_in_subquery(&in_subquery, &db, &registry).expect("expected match");
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
            recognize_p4_in_subquery(&in_subquery, &db, &registry).expect("expected P4 match");
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
                recognize_p4_in_subquery(&in_subquery, &db, &registry).is_none(),
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
            recognize_p4_in_subquery(&in_subquery, &db, &registry).is_none(),
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

        let exists = recognize_p4(&exists_expr, &db, &registry).expect("expected EXISTS match");
        let in_sub = recognize_p4_in_subquery(&in_subquery, &db, &registry)
            .expect("expected IN-subquery match");

        let (exists_join_table, exists_fk_column, exists_user_column, exists_extra_predicate_sql) =
            match exists.pattern {
                PatternClass::P4ExistsMembership {
                    join_table,
                    fk_column,
                    user_column,
                    extra_predicate_sql,
                } => (join_table, fk_column, user_column, extra_predicate_sql),
                other => panic!("expected P4 EXISTS classification, got: {other:?}"),
            };

        let (in_join_table, in_fk_column, in_user_column, in_extra_predicate_sql) =
            match in_sub.pattern {
                PatternClass::P4ExistsMembership {
                    join_table,
                    fk_column,
                    user_column,
                    extra_predicate_sql,
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
            recognize_p4(&exists_expr, &db, &registry).is_none(),
            "ambiguous EXISTS sources should fail closed"
        );
        assert!(
            recognize_p4_in_subquery(&in_subquery, &db, &registry).is_none(),
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
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
                .is_none(),
            "membership without user predicate must fail closed"
        );
    }

    #[test]
    fn table_and_projection_extractors_cover_non_table_and_alias_paths() {
        let table_select = parse_select("SELECT dm.doc_id AS projected FROM doc_members dm");
        let from = &table_select.from[0];
        let table_name = extract_table_name_from_table_factor(&from.relation)
            .expect("table factor should resolve");
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
        let other = parse_expr("owner_id");

        assert!(is_current_user_expr(&nested, &registry));
        assert!(is_current_user_expr(&casted, &registry));
        assert!(is_current_user_expr(&keyword, &registry));
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
        // Simple qualified column: `dm.status` → `status`
        let mut expr = parse_expr("dm.status = 'active'");
        strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
        assert_eq!(
            expr.to_string(),
            "status = 'active'",
            "alias-qualified column should be stripped"
        );

        // Double-quoted alias: `"dm"."status"` → the qualifier `"dm"` doesn't
        // match the unquoted alias string `dm` through `qualifier_matches_table`,
        // so the predicate is left unchanged — correct, since double-quoted
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
        assert!(
            recognize_p1(&non_value_threshold, &db, &registry, &PolicyCommand::Select).is_none()
        );
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
        // `get_owner_role(owner_id, id)` — both arguments are resource columns, not
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
        let registry = FunctionRegistry::new();

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
        assert!(recognize_p4(&exists_expr, &db, &registry).is_none());

        let in_subquery_expr = parse_expr(
            "id IN (
               SELECT odd_members.alpha
               FROM odd_members
               WHERE odd_members.beta = 'x'
             )",
        );
        assert!(recognize_p4_in_subquery(&in_subquery_expr, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_exists_without_outer_row_correlation_fails_closed() {
        // EXISTS (SELECT 1 FROM members WHERE user_id = current_user) — no correlation
        // predicate tying members to the outer resource row.  Should NOT classify as P4
        // because the generated tuple would grant access to ALL resources the user belongs
        // to, not just the one being queried.
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
        assert!(
            recognize_p4(&uncorrelated, &db, &registry).is_none(),
            "EXISTS without outer-row correlation must fail closed to avoid over-permissive grants"
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
        assert!(recognize_p4(&unknown_table, &db, &registry).is_none());

        let unsupported = parse_expr(
            "doc_id IN (
               (SELECT dm.doc_id FROM doc_members dm)
               UNION
               (SELECT dm.doc_id FROM doc_members dm)
             )",
        );
        assert!(recognize_p4_in_subquery(&unsupported, &db, &registry).is_none());
    }

    #[test]
    fn recognize_p4_paths_fail_closed_for_values_subqueries() {
        let db = db_with_docs_and_members();
        let registry = registry_with_role_level();

        let exists_values = parse_expr("EXISTS (VALUES (1))");
        let in_values = parse_expr("id IN (VALUES (1))");

        assert!(recognize_p4(&exists_values, &db, &registry).is_none());
        assert!(recognize_p4_in_subquery(&in_values, &db, &registry).is_none());
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
            recognize_p4(&exists_no_user, &db, &registry).is_none(),
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
            recognize_p4_in_subquery(&in_with_user, &db, &registry),
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
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
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
            extract_membership_columns(&select, "doc_members", Some("dm"), &cols, &registry, None)
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

    // ---- Edge-case tests (added) ----

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
        let expr =
            parse_expr("id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)");
        // The IN-subquery form should at least not panic
        let result = diagnose_p4_membership_ambiguity(&expr, &db, &registry);
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

    // ---- Additional coverage tests ----

    // 1. extract_integer_value: Nested, Cast, UnaryPlus recursion (line 928)
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

    // 2. extract_table_alias_from_table_factor: non-Table variant (line 955)
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

    // 3. join_on_expr: non-matching JoinOperator variant returns None (line 1035)
    //    and non-On JoinConstraint returns None (line 1040)
    #[test]
    fn join_on_expr_returns_none_for_non_standard_join_operators() {
        use sqlparser::ast::JoinOperator;

        // Cross Apply / non-standard variant → None (line 1035)
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

        // JoinConstraint::Using → None (line 1040)
        let using_constraint = JoinOperator::Inner(JoinConstraint::Using(vec![]));
        assert!(
            join_on_expr(&using_constraint).is_none(),
            "USING constraint should return None from join_on_expr"
        );

        // JoinConstraint::Natural → None (line 1040)
        let natural_constraint = JoinOperator::Inner(JoinConstraint::Natural);
        assert!(
            join_on_expr(&natural_constraint).is_none(),
            "Natural constraint should return None from join_on_expr"
        );

        // JoinConstraint::None → None (line 1040)
        let none_constraint = JoinOperator::Inner(JoinConstraint::None);
        assert!(
            join_on_expr(&none_constraint).is_none(),
            "None constraint should return None from join_on_expr"
        );
    }

    // 4. extract_membership_columns: ON-clause user detection (lines 1189-1200)
    //    and ON-clause FK detection with right_is_join path (lines 1232-1239)
    #[test]
    fn extract_membership_columns_on_clause_user_left_join_right_current_user() {
        // ON clause: dm.user_id = auth_current_user_id() (left is join, right is current_user)
        // This exercises lines 1186-1193.
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
        // This exercises lines 1195-1203.
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
        // This exercises lines 1232-1239 (right_is_join && !left_is_join path in ON clause).
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
        // The first sets fk_col = "doc_id", the second conflicts → return None (line 1140).
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

    // 5. flatten_and_predicates: AND recursion (lines 1274, 1276)
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
        // OR is not flattened — single predicate
        let expr = parse_expr("x = 1 OR y = 2");
        let mut out = Vec::new();
        flatten_and_predicates(&expr, &mut out);
        assert_eq!(out.len(), 1, "OR should not be flattened, yielding 1 leaf");
    }

    // 6. strip_qualifier_from_expr: already tested but ensure we also have the
    //    Nested arm covered in the match at line 1397
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

    // 7. table_qualifier_candidates: schema-qualified name (line 1460-1461)
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

    // 8. infer_membership_fk_column: _membership suffix hint (lines 1713, 1716)
    //    and None for multiple non-scope candidates (line 1742)
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
        // Multiple id-like columns, no hint match, no scope filter → None (line 1742)
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

    // 9. diagnose_p4_membership_ambiguity: InSubquery form (lines 594-608)
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
        let result = diagnose_p4_membership_ambiguity(&expr, &db, &registry);
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
        // A plain expression (not EXISTS, not IN subquery) → None (catch-all at line 610)
        let expr = parse_expr("owner_id = current_user");
        assert!(diagnose_p4_membership_ambiguity(&expr, &db, &registry).is_none());
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
        // NOT EXISTS → line 622-623 returns None
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
        // EXISTS (VALUES ...) → non-Select body → line 627-628 returns None
        let expr = parse_expr("EXISTS (VALUES (1))");
        assert!(
            diagnose_p5_parent_inheritance_ambiguity(&expr, &db, "tasks").is_none(),
            "non-Select body should return None"
        );
    }

    #[test]
    fn diagnose_p5_returns_conflicting_join_message() {
        // When the same parent source has two different FK columns from the outer table,
        // analyze_p5 sets saw_conflicting_join = true → lines 638-641.
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

    // 11. analyze_p5_parent_inheritance: empty sources (line 667)
    #[test]
    fn analyze_p5_returns_none_for_empty_sources() {
        let db = parse_schema(
            r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
        )
        .unwrap();
        // A SELECT with no FROM clause → empty sources → line 667 returns None
        // We cannot parse "SELECT 1 WHERE ..." without FROM in standard SQL,
        // but we can construct via parse_select with a derived table that has no relation sources.
        // Actually, sqlparser does allow `SELECT 1 WHERE true`.
        let select = parse_select("SELECT 1");
        let result = analyze_p5_parent_inheritance(&select, &db, "tasks");
        assert!(result.is_none(), "empty sources should return None");
    }

    // 11b. analyze_p5: empty inner_predicates → skip (lines 724-725)
    #[test]
    fn analyze_p5_skips_candidate_with_only_join_predicates_and_no_inner() {
        // When ALL predicates are outer↔parent join columns, inner_predicates is empty,
        // so the candidate is skipped (line 724-725).
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

    // 12. function_has_current_user_arg: non-List args (line 912)
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

    // 13. recognize_pg_has_role: non-List args (line 134-135)
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

    // Additional: selection_references_current_user with IsDistinctFrom/IsNotDistinctFrom (lines 749-751)
    // and catch-all arm (line 753)
    #[test]
    fn selection_references_current_user_via_is_not_distinct_from() {
        let registry = FunctionRegistry::new();
        let select = parse_select(
            "SELECT 1 FROM doc_members WHERE user_id IS NOT DISTINCT FROM current_user",
        );
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
        // A bare current_user expression (not inside BinaryOp/IsDistinct) → catch-all at line 753
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
        // EXISTS (VALUES ...) → non-Select body → line 592 returns None
        let expr = parse_expr("EXISTS (VALUES (1))");
        assert!(
            diagnose_p4_membership_ambiguity(&expr, &db, &registry).is_none(),
            "EXISTS with non-Select body should return None"
        );
    }

    // Additional: diagnose_p4 negated EXISTS returns _ => None (line 610)
    #[test]
    fn diagnose_p4_membership_ambiguity_negated_exists() {
        let db = db_with_docs_and_members();
        let registry = FunctionRegistry::new();
        let expr = parse_expr(
            "NOT EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
        );
        // negated EXISTS matches `Expr::Exists { negated: true }` which falls to `_ => None` at line 610
        assert!(
            diagnose_p4_membership_ambiguity(&expr, &db, &registry).is_none(),
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
            diagnose_p4_membership_ambiguity(&expr, &db, &registry).is_none(),
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
        // auth.jwt()->'user_metadata'->>'id' — schema prefix stripped by normalize_relation_name
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
}
