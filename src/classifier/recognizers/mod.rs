#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArguments, Select, SelectItem, TableFactor, UnaryOperator, Value,
};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
pub use crate::parser::expr::extract_column_name;
use crate::parser::expr::function_arg_expr;
use crate::parser::expr::{extract_column_name_through_coalesce, is_coalesce_wrapped};
use crate::parser::names::{
    is_current_user_keyword_name, is_public_flag_column_name, is_user_related_column_name,
    lookup_table, normalize_relation_name, normalized_function_name, same_identifier,
    split_schema_and_relation, stored_ident_name,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike};

/// P7/P9 attribute-condition detection (non-user column comparisons, temporal guards).
mod attribute;
/// P4/P5 membership and parent-inheritance recognizers (correlated EXISTS / IN subqueries).
mod subquery;

pub use attribute::{attribute_literal_predicate, attribute_request_predicate, is_attribute_check};
pub(crate) use subquery::{
    diagnose_p4_membership_ambiguity, diagnose_p5_parent_inheritance_ambiguity,
};
pub use subquery::{recognize_p4, recognize_p4_in_subquery, recognize_p5};

/// Recognize P1: `role_fn(user, resource) >= N`, in either operand order.
pub fn recognize_p1<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
    command: PolicyCommand,
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
        // Guard against resource attribute comparisons.
        if !function_has_current_user_arg(func_expr, registry) {
            return None;
        }

        let threshold = extract_integer_value(threshold_expr)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold {
                function_name: func_name,
                operator,
                threshold,
                command,
            },
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Role name IN-list or `pg_has_role` built-in.
pub fn recognize_p2<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Expr::InList {
        expr: inner_expr,
        list,
        negated,
    } = expr
    {
        // Negated IN-lists cannot be expressed as static tuples.
        if *negated {
            return None;
        }

        if let Some(func_name) = extract_function_name(inner_expr) {
            if registry.is_role_threshold(&func_name) {
                if !function_has_current_user_arg(inner_expr, registry) {
                    return None;
                }

                let role_names = extract_role_names_from_in_list(list, true);

                if !role_names.is_empty() {
                    return Some(ClassifiedExpr {
                        pattern: PatternClass::P2RoleNameInList {
                            function_name: func_name,
                            role_names,
                            privilege: RolePrivilege::Member,
                        },
                        confidence: ConfidenceLevel::A,
                    });
                }
            }
        }
    }

    if let Some(c) = recognize_pg_has_role(expr, registry) {
        return Some(c);
    }

    recognize_role_accessor_comparison(expr, registry)
}

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

    // The implicit user of the two-argument form is `current_user`, not `session_user`:
    // probed under SET ROLE, where the two answer differently and the two-argument form
    // followed `current_user`.
    let (role_expr, privilege_expr) = match args.as_slice() {
        [user_expr, role_expr, privilege] if is_current_user_expr(user_expr, registry) => {
            (role_expr, privilege)
        }
        [role_expr, privilege] => (role_expr, privilege),
        _ => return None,
    };

    // The privilege decides which members the policy admits, so a privilege the crate cannot
    // read is refused rather than taken for plain membership.
    let privilege = match privilege_expr {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) => RolePrivilege::parse(s)?,
            _ => return None,
        },
        _ => return None,
    };

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
            privilege,
        },
        confidence: ConfidenceLevel::A,
    })
}

fn recognize_role_accessor_comparison(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let extract_role_func_name = |e: &Expr| -> Option<String> {
        let name = extract_function_name(e)?;
        if registry.is_role_accessor(&name) {
            Some(name)
        } else {
            None
        }
    };

    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    {
        let (func_name, literal_expr) = if let Some(name) = extract_role_func_name(left) {
            (name, right.as_ref())
        } else {
            let name = extract_role_func_name(right)?;
            (name, left.as_ref())
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
                // A role accessor names the caller's role rather than asking about a kind of
                // membership in another one, so the widest kind is the faithful reading.
                privilege: RolePrivilege::Member,
            },
            confidence: ConfidenceLevel::A,
        });
    }

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
                privilege: RolePrivilege::Member,
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

/// Direct ownership check.
pub fn recognize_p3<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
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
    let (
        col_name,
        accessor_name,
        accessor_indirection,
        accessor_is_bare_identifier,
        accessor_is_sql_keyword_expr,
        accessor_is_keyword_named_function_call,
    ) = if let (Some(col), Some(accessor)) =
        (extract_column_name(left), current_user_accessor_name(right))
    {
        let indirection = is_subquery_wrapped(right) || is_json_accessor_wrapped(right);
        let is_bare_identifier = is_bare_identifier_expr(right);
        let is_sql_keyword_expr = is_sql_current_user_keyword_expr(right);
        let is_keyword_named_function_call = is_keyword_named_function_call_expr(right);
        (
            col,
            accessor,
            indirection,
            is_bare_identifier,
            is_sql_keyword_expr,
            is_keyword_named_function_call,
        )
    } else if let (Some(accessor), Some(col)) =
        (current_user_accessor_name(left), extract_column_name(right))
    {
        let indirection = is_subquery_wrapped(left) || is_json_accessor_wrapped(left);
        let is_bare_identifier = is_bare_identifier_expr(left);
        let is_sql_keyword_expr = is_sql_current_user_keyword_expr(left);
        let is_keyword_named_function_call = is_keyword_named_function_call_expr(left);
        (
            col,
            accessor,
            indirection,
            is_bare_identifier,
            is_sql_keyword_expr,
            is_keyword_named_function_call,
        )
    } else if let (Some(col), Some(accessor)) = (
        extract_column_name_through_coalesce(left),
        current_user_accessor_name(right),
    ) {
        let indirection = is_subquery_wrapped(right)
            || is_json_accessor_wrapped(right)
            || is_coalesce_wrapped(left);
        let is_bare_identifier = is_bare_identifier_expr(right);
        let is_sql_keyword_expr = is_sql_current_user_keyword_expr(right);
        let is_keyword_named_function_call = is_keyword_named_function_call_expr(right);
        (
            col,
            accessor,
            indirection,
            is_bare_identifier,
            is_sql_keyword_expr,
            is_keyword_named_function_call,
        )
    } else if let (Some(accessor), Some(col)) = (
        current_user_accessor_name(left),
        extract_column_name_through_coalesce(right),
    ) {
        let indirection = is_subquery_wrapped(left)
            || is_json_accessor_wrapped(left)
            || is_coalesce_wrapped(right);
        let is_bare_identifier = is_bare_identifier_expr(left);
        let is_sql_keyword_expr = is_sql_current_user_keyword_expr(left);
        let is_keyword_named_function_call = is_keyword_named_function_call_expr(left);
        (
            col,
            accessor,
            indirection,
            is_bare_identifier,
            is_sql_keyword_expr,
            is_keyword_named_function_call,
        )
    } else {
        return None;
    };

    // Determine how we matched the accessor and assign confidence accordingly.
    let is_registry_confirmed = registry.is_current_user_accessor(&accessor_name);
    let is_sql_keyword = accessor_is_sql_keyword_expr;

    // Guard against false positives like `owner_id = author_id`:
    // bare identifiers that are not SQL current-user keywords are columns/aliases,
    // not accessor expressions.
    if accessor_is_bare_identifier && !is_sql_keyword && !is_registry_confirmed {
        return None;
    }

    // Prevent false positives from user-defined function calls that only *look*
    // like SQL current-user keywords (e.g. `"current_user"()`, `x.current_user()`).
    if accessor_is_keyword_named_function_call && !is_sql_keyword && !is_registry_confirmed {
        return None;
    }

    // Strict policy: only SQL current-user keywords and registry-confirmed
    // accessors are eligible for P3.
    if !is_registry_confirmed && !is_sql_keyword {
        return None;
    }

    // Subquery/JSON/COALESCE-wrapped accessors are accepted but capped at B
    // due to added indirection. This cap only applies after strict accessor
    // validation above.
    if accessor_indirection {
        return Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership { column: col_name },
            confidence: ConfidenceLevel::B,
        });
    }

    // Registry-confirmed or SQL keyword without indirection: confidence A.
    Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership { column: col_name },
        confidence: ConfidenceLevel::A,
    })
}

/// Recognise "the caller is an element of an array column" in each spelling
/// `PostgreSQL` accepts: `caller = ANY (col)`, `col @> ARRAY[caller]`,
/// `ARRAY[caller] <@ col` and `ARRAY[caller] && col`.
///
/// Verified on `PostgreSQL` 18: the four agree on every row except an array holding
/// only NULL, where `= ANY` yields NULL and the others false. Both filter the row
/// out, so all four admit the same rows and translate alike.
pub fn recognize_array_patterns(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let column = array_membership_column(expr, registry)?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P11ArrayMembership { column },
        confidence: ConfidenceLevel::A,
    })
}

/// The array column whose elements the caller is tested against, if `expr` is one
/// of the four membership spellings.
///
/// The array side must resolve to a column: `= ANY (SELECT ...)` is membership
/// through a table, handled by the P4 recognizers, and treating its subquery as a
/// column would emit SQL naming a column that does not exist.
fn array_membership_column(expr: &Expr, registry: &FunctionRegistry) -> Option<String> {
    /// How the caller is written on its side of the operator.
    enum CallerForm {
        /// `= ANY` compares the caller itself.
        Direct,
        /// The containment and overlap spellings wrap it in a one-element array.
        Singleton,
    }

    let (form, caller_side, array_side) = match expr {
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => (CallerForm::Direct, left.as_ref(), right.as_ref()),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::AtArrow,
            right,
        } => (CallerForm::Singleton, right.as_ref(), left.as_ref()),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::ArrowAt,
            right,
        } => (CallerForm::Singleton, left.as_ref(), right.as_ref()),
        // `&&` is symmetric, so either side may hold the singleton.
        Expr::BinaryOp {
            left,
            op: BinaryOperator::PGOverlap,
            right,
        } => {
            if is_singleton_caller_element(left, registry) {
                (CallerForm::Singleton, left.as_ref(), right.as_ref())
            } else {
                (CallerForm::Singleton, right.as_ref(), left.as_ref())
            }
        }
        _ => return None,
    };

    let names_the_caller = match form {
        CallerForm::Direct => is_current_user_expr(caller_side, registry),
        CallerForm::Singleton => is_singleton_caller_element(caller_side, registry),
    };
    if !names_the_caller {
        return None;
    }

    extract_column_name(unwrap_cast_or_nested(array_side))
}

/// Whether `expr` is a one-element array literal holding the caller.
fn is_singleton_caller_element(expr: &Expr, registry: &FunctionRegistry) -> bool {
    let Expr::Array(array) = unwrap_cast_or_nested(expr) else {
        return false;
    };
    let [only] = array.elem.as_slice() else {
        return false;
    };
    is_current_user_expr(only, registry)
}

/// Recognise `data ->> 'owner' = caller`, the caller's identity stored in a jsonb
/// field, in either operand order and through casts.
///
/// Only a `->>` last hop qualifies: `->` yields `jsonb`, so `data -> 'owner'` compares
/// a JSON string (quotes included) rather than the text the caller is spelled with.
pub fn recognize_jsonb_field_ownership(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    let (column, path) = if is_current_user_expr(right, registry) {
        jsonb_text_path(left)?
    } else if is_current_user_expr(left, registry) {
        jsonb_text_path(right)?
    } else {
        return None;
    };

    Some(ClassifiedExpr {
        pattern: PatternClass::P12JsonbFieldOwnership { column, path },
        confidence: ConfidenceLevel::A,
    })
}

/// The `(column, key chain)` of a jsonb text extraction, or `None` if `expr` is not one.
fn jsonb_text_path(expr: &Expr) -> Option<(String, Vec<String>)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::LongArrow,
        right,
    } = unwrap_cast_or_nested(expr)
    else {
        return None;
    };

    let mut path = vec![json_literal_key(right)?];
    let mut node = unwrap_cast_or_nested(left);
    // Walk the `->` hops leading up to the `->>`, innermost key last.
    while let Expr::BinaryOp {
        left: inner,
        op: BinaryOperator::Arrow,
        right: key,
    } = node
    {
        path.push(json_literal_key(key)?);
        node = unwrap_cast_or_nested(inner);
    }
    path.reverse();

    Some((extract_column_name(node)?, path))
}

/// A jsonb key written as a string literal. An integer index addresses an array
/// element, which names no field, and a non-literal key is not static.
fn json_literal_key(expr: &Expr) -> Option<String> {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(value) => match &value.value {
            Value::SingleQuotedString(key) => Some(key.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Constant boolean policy.
pub fn recognize_p10_constant_bool<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    constant_bool_value(expr).map(|value| ClassifiedExpr {
        pattern: PatternClass::P10ConstantBool { value },
        confidence: ConfidenceLevel::A,
    })
}

/// Boolean flag check.
pub fn recognize_p6<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    /// Pick confidence: A when the column is explicitly registered, B otherwise.
    ///
    /// Heuristic-only matches are capped at B because column names like `published`
    /// or `visible` commonly represent editorial state rather than access control;
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

/// Negated public-flag check: not expressible as static `OpenFGA` tuples.
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

/// Whether the clause filters every row out whatever the data holds.
///
/// A qual that is not true rejects the row, so a constant false admits nothing, an `AND`
/// admits nothing as soon as either side does, and an `OR` only when both do. Answered from
/// the expression rather than from its classification, since a pattern graded `no_access`
/// may equally be one the crate could not translate, which says nothing about the database.
pub(crate) fn is_constantly_false(expr: &Expr) -> bool {
    if constant_bool_value(expr) == Some(false) {
        return true;
    }
    match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => is_constantly_false(left) || is_constantly_false(right),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => is_constantly_false(left) && is_constantly_false(right),
        _ => false,
    }
}

/// Normalized name of the function `expr` calls, through casts and parentheses.
pub fn extract_function_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalized_function_name(func)),
        Expr::Cast { expr, .. } => extract_function_name(expr),
        Expr::Nested(inner) => extract_function_name(inner),
        _ => None,
    }
}

/// Normalized names of every function `expr` calls that does not identify the caller,
/// in source order, deduplicated.
///
/// Unlike [`extract_function_name`] this descends into operands and subqueries, so
/// it answers for diagnosis rather than recognition. Widening `extract_function_name`
/// instead would let P1 and P2 match a role function buried under an unrelated call.
/// The skip runs on the node so `is_current_user_expr` stays the only predicate that
/// decides what identifies the caller, keyword shape included.
pub(crate) fn called_function_names(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Expr::Function(func) = node {
            if !is_current_user_expr(node, registry) {
                let name = normalized_function_name(func);
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    names
}

/// Spellings of every operator in `expr` that no recognizer knows how to translate,
/// in source order, deduplicated.
///
/// A jsonb or array operator carries no function to blame, so without this the reason
/// names nothing at all. Comparison and boolean operators are omitted: a clause that
/// translates uses them too, so naming them would point at the wrong half.
pub(crate) fn unrecognized_operators(expr: &Expr) -> Vec<String> {
    let mut ops: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Expr::BinaryOp { op, .. } = node {
            if !operator_is_ordinary(op) {
                let spelling = op.to_string();
                if !ops.contains(&spelling) {
                    ops.push(spelling);
                }
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    ops
}

/// Whether `op` is a comparison or boolean connective, which says nothing about why a
/// clause failed to translate.
fn operator_is_ordinary(op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::And
            | BinaryOperator::Or
    )
}

/// to a current-user expression.
///
/// Used by the P1/P2 recognizers to guard against false positives where a
/// role-threshold function is called with non-user arguments, e.g.
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

/// Split a conjunction into its leaves, seeing through the parentheses `pg_dump`
/// writes around every conjunct it deparses.
fn flatten_and_predicates<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            flatten_and_predicates(left, out);
            flatten_and_predicates(right, out);
        }
        leaf => out.push(leaf),
    }
}

fn extract_qualified_column(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Identifier(id) => Some((None, stored_ident_name(id).into_owned())),
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [.., qualifier, last] => Some((
                Some(stored_ident_name(qualifier).into_owned()),
                stored_ident_name(last).into_owned(),
            )),
            _ => None,
        },
        _ => None,
    }
}

fn current_user_accessor_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Function(func) => Some(normalized_function_name(func)),
        Expr::Identifier(ident) => ident
            .quote_style
            .is_none()
            .then(|| normalize_relation_name(&ident.value)),
        Expr::Cast { expr, .. } => current_user_accessor_name(expr),
        Expr::Nested(inner) => current_user_accessor_name(inner),
        // Phase 6b: unwrap a scalar subquery, `(SELECT auth.uid())`.
        // The subquery must project exactly one non-wildcard expression.
        Expr::Subquery(query) => {
            if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
                if select.projection.len() == 1 {
                    if let Some(
                        SelectItem::UnnamedExpr(inner)
                        | SelectItem::ExprWithAlias { expr: inner, .. },
                    ) = select.projection.first()
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
fn is_subquery_wrapped(expr: &Expr) -> bool {
    matches!(unwrap_cast_or_nested(expr), Expr::Subquery(_))
}

/// Returns `true` when `expr` (or its Cast/Nested wrapper) contains a JSON
/// accessor operator (`->`, `->>`, `#>`, `#>>`).  Used in [`recognize_p3`] to
fn is_json_accessor_wrapped(expr: &Expr) -> bool {
    matches!(
        unwrap_cast_or_nested(expr),
        Expr::BinaryOp {
            op: BinaryOperator::Arrow
                | BinaryOperator::LongArrow
                | BinaryOperator::HashArrow
                | BinaryOperator::HashLongArrow,
            ..
        }
    )
}

fn is_bare_identifier_expr(expr: &Expr) -> bool {
    matches!(
        unwrap_cast_or_nested(expr),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Peel parentheses, which the parse has already resolved into tree shape and which
/// therefore say nothing about what an expression means. A cast is left in place: it
/// changes the value, and a leaf that reaches generated SQL has to keep it.
pub(crate) fn unparenthesize(mut expr: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expr {
        expr = inner.as_ref();
    }
    expr
}

fn unwrap_cast_or_nested(mut expr: &Expr) -> &Expr {
    loop {
        match expr {
            Expr::Cast { expr: inner, .. } | Expr::Nested(inner) => expr = inner.as_ref(),
            _ => return expr,
        }
    }
}

fn is_current_user_keyword(name: &str) -> bool {
    is_current_user_keyword_name(name)
}

fn is_sql_current_user_keyword_expr(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::Identifier(ident) => {
            ident.quote_style.is_none()
                && is_current_user_keyword(&normalize_relation_name(&ident.value))
        }
        Expr::Function(func) => {
            split_schema_and_relation(&func.name.to_string()).is_none()
                && matches!(func.args, FunctionArguments::None)
                && is_current_user_keyword(&normalized_function_name(func))
        }
        Expr::Subquery(query) => {
            if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
                if select.projection.len() == 1 {
                    if let Some(
                        SelectItem::UnnamedExpr(inner)
                        | SelectItem::ExprWithAlias { expr: inner, .. },
                    ) = select.projection.first()
                    {
                        return is_sql_current_user_keyword_expr(inner);
                    }
                }
            }
            false
        }
        Expr::BinaryOp {
            op:
                BinaryOperator::Arrow
                | BinaryOperator::LongArrow
                | BinaryOperator::HashArrow
                | BinaryOperator::HashLongArrow,
            left,
            ..
        } => is_sql_current_user_keyword_expr(left),
        _ => false,
    }
}

fn is_keyword_named_function_call_expr(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::Function(func) => is_current_user_keyword(&normalized_function_name(func)),
        Expr::Subquery(query) => {
            if let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() {
                if select.projection.len() == 1 {
                    if let Some(
                        SelectItem::UnnamedExpr(inner)
                        | SelectItem::ExprWithAlias { expr: inner, .. },
                    ) = select.projection.first()
                    {
                        return is_keyword_named_function_call_expr(inner);
                    }
                }
            }
            false
        }
        Expr::BinaryOp {
            op:
                BinaryOperator::Arrow
                | BinaryOperator::LongArrow
                | BinaryOperator::HashArrow
                | BinaryOperator::HashLongArrow,
            left,
            ..
        } => is_keyword_named_function_call_expr(left),
        _ => false,
    }
}

fn is_current_user_expr(expr: &Expr, registry: &FunctionRegistry) -> bool {
    let Some(name) = current_user_accessor_name(expr) else {
        return false;
    };
    let normalized = normalize_relation_name(&name);
    registry.is_current_user_accessor(&normalized)
        || (is_current_user_keyword(&normalized) && is_sql_current_user_keyword_expr(expr))
}

#[cfg(test)]
mod tests;
