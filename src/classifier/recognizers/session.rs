//! Values the request carries, declared by the deployment.
//!
//! PostgreSQL's request-scoped surface is open ended, so nothing in a policy says whether
//! `current_setting('app.subjects')` holds one person, one tenant or a set of grants. A
//! deployment declares that, and the kind it declares is what keeps a wrong allow
//! impossible: a set read where one value belongs finds no declaration of that kind and
//! stays unclassified, and so does the mirror case.
//!
//! The authority for these values is the token or the session, never a table, so they are
//! never copied into tuples. The row supplies its own value as tuple context, the request
//! supplies what only it knows, and a condition relates them.

use alloc::string::String;
use alloc::vec::Vec;

use sqlparser::ast::{BinaryOperator, Expr, FunctionArguments, Query, SelectItem};

use crate::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use crate::classifier::patterns::{
    CallerScalarEqualsConstant, ClassifiedExpr, ConfidenceLevel, ConstantInCallerSet, PatternClass,
    RowValueEqualsCallerScalar, RowValueInCallerSet,
};
use crate::parser::expr::{function_arg_expr, unwrap_cast_or_nested};
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::identifiers::ColumnName;
use crate::parser::names::normalized_function_name;

use super::{
    accessor_root_and_path, accessor_root_and_value_path, current_setting_literal_key,
    extract_column_name, projected_select, string_literal,
};

/// A value the request carries, compared against a row column or against a constant.
///
/// Four shapes, one recognizer, because they differ only in which side is the row's:
/// the caller's set holding a row value or a constant, and the caller's single value
/// equalling a row value or a constant.
pub fn recognize_session_attribute(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    set_membership(expr, registry)
        .or_else(|| set_membership_in_subquery(expr, registry))
        .or_else(|| scalar_equality(expr, registry))
}

/// `<row column or constant> = ANY (<the caller's set>)`.
fn set_membership(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::AnyOp {
        left,
        compare_op: BinaryOperator::Eq,
        right,
        ..
    } = expr
    else {
        return None;
    };
    let (source, separator) = caller_set(right, registry)?;
    tested_against_set(left, source, separator)
}

/// `<row column or constant> IN (SELECT <the caller's set>)`.
///
/// The same database as the `= ANY` spelling, so it routes through the same reader and
/// lands on the same pattern. The subquery has to be only its projection, which is what
/// keeps this away from a membership subquery: that one always reads a `FROM`.
fn set_membership_in_subquery(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::InSubquery {
        expr: left,
        subquery,
        negated: false,
    } = expr
    else {
        return None;
    };
    let (source, separator) = caller_row_set(sole_projection(subquery)?, registry)?;
    tested_against_set(left, source, separator)
}

/// What the caller's set is compared against decides which pattern it is, and both
/// spellings answer that the same way.
fn tested_against_set(
    tested: &Expr,
    source: &SessionAttribute,
    separator: Option<String>,
) -> Option<ClassifiedExpr> {
    let pattern = match tested_value(tested) {
        TestedValue::Column(column) => PatternClass::P14RowValueInCallerSet(RowValueInCallerSet {
            column,
            separator,
            source: source.clone(),
        }),
        TestedValue::Constant(value) => PatternClass::P16ConstantInCallerSet(ConstantInCallerSet {
            value,
            separator,
            source: source.clone(),
        }),
        TestedValue::Neither => return None,
    };
    Some(ClassifiedExpr {
        pattern,
        confidence: grade(source),
    })
}

/// `<row column or constant> = <declared single value>`, either way round.
fn scalar_equality(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    let (source, tested) = match declared_scalar(right, registry) {
        Some(source) => (source, left.as_ref()),
        None => (declared_scalar(left, registry)?, right.as_ref()),
    };

    let pattern = match tested_value(tested) {
        TestedValue::Column(column) => {
            PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
                column,
                source: source.clone(),
            })
        }
        TestedValue::Constant(value) => {
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
                value,
                source: source.clone(),
            })
        }
        TestedValue::Neither => return None,
    };
    Some(ClassifiedExpr {
        pattern,
        confidence: grade(source),
    })
}

/// What the declared value is being compared against.
enum TestedValue {
    /// A column of the guarded row, so the row supplies it as tuple context.
    Column(ColumnName),
    /// A literal from the policy, so the rule supplies it as tuple context.
    Constant(String),
    Neither,
}

fn tested_value(expr: &Expr) -> TestedValue {
    if let Some(column) = extract_column_name(expr) {
        return TestedValue::Column(column);
    }
    match string_literal(expr) {
        Some(value) => TestedValue::Constant(value),
        None => TestedValue::Neither,
    }
}

/// A field taken out of the caller's value is indirection, which caps at B exactly as a
/// scalar subquery wrapper and a `COALESCE` wrapper already do.
fn grade(source: &SessionAttribute) -> ConfidenceLevel {
    if source.path().is_empty() {
        ConfidenceLevel::A
    } else {
        ConfidenceLevel::B
    }
}

/// The declared source `expr` reads, when it was declared as one single value.
fn declared_scalar<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<&'r SessionAttribute> {
    declared_source(expr, registry)
        .filter(|source| source.kind() == SessionAttributeKind::ScalarAttribute)
}

/// A source the caller's set comes from, named rather than resolved, so one reader
/// answers both while classifying a policy and while the registry is still being built.
#[derive(Debug, Clone)]
pub(crate) struct SetSource {
    /// The `current_setting` key behind it.
    pub(crate) key: String,
    /// The field path taken out of that key's value.
    pub(crate) path: Vec<String>,
    /// The separator the policy splits on, absent where the source is already a list.
    pub(crate) separator: Option<String>,
}

/// An **array valued** expression yielding the caller's set, which is what `= ANY (...)`
/// takes.
///
/// Kept apart from the row valued reader because `PostgreSQL` keeps them apart: `= ANY`
/// refuses a set returning argument and `IN (SELECT ...)` refuses an array, so merging
/// the two would classify shapes the database rejects. A cast to an array type is a
/// different split, with a different contract for the caller, so it stays unclassified.
pub(super) fn array_valued_set(expr: &Expr, registry: &FunctionRegistry) -> Option<SetSource> {
    let Expr::Function(function) = unwrap_cast_or_nested(expr) else {
        return None;
    };
    // `ARRAY(SELECT ...)` collects rows into an array, so its projection is read as one.
    if let FunctionArguments::Subquery(query) = &function.args {
        return row_valued_set(sole_projection(query)?, registry);
    }
    if normalized_function_name(function) != "string_to_array" {
        return None;
    }
    let FunctionArguments::List(list) = &function.args else {
        return None;
    };
    // A third argument names a string that reads back as NULL, which changes which
    // elements exist.
    let [value, separator] = list.args.as_slice() else {
        return None;
    };
    let separator = string_literal(function_arg_expr(separator)?)?;
    let (key, path) = source_read_by(function_arg_expr(value)?, registry)?;
    Some(SetSource {
        key,
        path,
        separator: Some(separator),
    })
}

/// A **row valued** expression yielding the caller's set, which is what `IN (SELECT ...)`
/// takes and what the body of a set returning wrapper is.
pub(crate) fn row_valued_set(expr: &Expr, registry: &FunctionRegistry) -> Option<SetSource> {
    let Expr::Function(function) = unwrap_cast_or_nested(expr) else {
        return None;
    };
    let name = normalized_function_name(function);
    // A wrapper whose whole body reads a declared setting is a spelling of that setting,
    // which is the one route a function reaches a source by.
    if let Some(FunctionSemantic::SetReader {
        key,
        path,
        separator,
    }) = registry.get(&name)
    {
        return Some(SetSource {
            key: key.clone(),
            path: path.clone(),
            separator: separator.clone(),
        });
    }
    let FunctionArguments::List(list) = &function.args else {
        return None;
    };
    let [argument] = list.args.as_slice() else {
        return None;
    };
    let argument = function_arg_expr(argument)?;
    match name.as_str() {
        // A jsonb array yielded as text is the caller's list itself, so no separator
        // exists and the contract is simply to send the list.
        "jsonb_array_elements_text" => {
            let (key, path) = source_read_by(argument, registry)?;
            Some(SetSource {
                key,
                path,
                separator: None,
            })
        }
        // Expanding a split is the same database as the split, separator included.
        "unnest" => array_valued_set(argument, registry),
        _ => None,
    }
}

/// The single expression a subquery projects, when nothing in it can drop that row.
fn sole_projection(query: &Query) -> Option<&Expr> {
    let [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] =
        projected_select(query)?.projection.as_slice()
    else {
        return None;
    };
    Some(expr)
}

/// The key and field path an expression reads.
///
/// A jsonb array is reached through a chain ending in `->`, since `->>` renders the
/// array as text and `PostgreSQL` refuses to expand text, so this accepts either ending
/// while the scalar reader accepts only `->>`.
fn source_read_by(expr: &Expr, registry: &FunctionRegistry) -> Option<(String, Vec<String>)> {
    let (root, path) = accessor_root_and_value_path(expr)
        .filter(|(_, path)| !path.is_empty())
        .or_else(|| accessor_root_and_path(expr))?;
    Some((setting_key_read_by(root, registry)?, path))
}

/// The declared set an array valued expression yields.
pub(crate) fn caller_set<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r SessionAttribute, Option<String>)> {
    resolve_declared_set(array_valued_set(expr, registry)?, registry)
}

/// The declared set a row valued expression yields.
fn caller_row_set<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r SessionAttribute, Option<String>)> {
    resolve_declared_set(row_valued_set(expr, registry)?, registry)
}

/// The declaration a named source resolves to, when the deployment declared it a set.
///
/// The kind check is what makes the two wrong allows impossible rather than checked: a
/// single value read in set position finds no set declaration and stays unclassified.
fn resolve_declared_set(
    source: SetSource,
    registry: &FunctionRegistry,
) -> Option<(&SessionAttribute, Option<String>)> {
    let attribute = registry
        .session_attribute(&source.key, &source.path)
        .filter(|attribute| attribute.kind() == SessionAttributeKind::SetAttribute)?;
    Some((attribute, source.separator))
}

/// The declaration behind whatever `expr` reads, however the deployment spelled it.
fn declared_source<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<&'r SessionAttribute> {
    let (root, path) = accessor_root_and_path(expr)?;
    let key = setting_key_read_by(root, registry)?;
    registry.session_attribute(&key, &path)
}

/// The `current_setting` key a node names, written inline or wrapped in a function whose
/// whole body reads it. Both spellings reach one declaration, so they cannot disagree.
fn setting_key_read_by(root: &Expr, registry: &FunctionRegistry) -> Option<String> {
    if let Some(key) = current_setting_literal_key(root) {
        return Some(key);
    }
    let Expr::Function(function) = root else {
        return None;
    };
    match registry.get(&normalized_function_name(function))? {
        FunctionSemantic::SettingReader { key } => Some(key.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse_expr(sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(sql)
            .expect("tokenizes")
            .parse_expr()
            .expect("parses")
    }

    fn registry_with(attributes: Vec<SessionAttribute>) -> FunctionRegistry {
        let mut registry = FunctionRegistry::new();
        registry.declare_session_attributes(attributes);
        registry
    }

    /// A set read where one value belongs is the recorded tenant trap in the other
    /// direction, so the kind has to refuse it rather than fall through to ownership.
    #[test]
    fn a_declared_set_read_as_one_value_is_refused() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )]);
        let expr = parse_expr("owner = current_setting('app.subjects', true)");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a set is not one value"
        );
    }

    /// The mirror: one value read as a set grants by a split of something that holds one
    /// element, which is not what the deployment declared.
    #[test]
    fn a_declared_single_value_read_as_a_set_is_refused() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.tenant_id",
            SessionAttributeKind::ScalarAttribute,
        )]);
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.tenant_id'), ','))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "one value is not a set"
        );
    }

    /// A cast to an array splits on `PostgreSQL`'s array literal syntax rather than on a
    /// separator, so the caller contract differs and the shape falls closed.
    #[test]
    fn an_array_cast_is_not_the_declared_split() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )]);
        let expr = parse_expr("owner = ANY(current_setting('app.subjects', true)::text[])");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "an array cast is a different split"
        );
    }

    /// A separator other than a comma is still a split, and the disclosure has to name
    /// which one so the caller sends the matching elements.
    #[test]
    fn the_separator_is_carried_rather_than_assumed() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )]);
        let expr = parse_expr("owner = ANY(string_to_array(current_setting('app.subjects'), ';'))");
        assert!(
            matches!(
                recognize_session_attribute(&expr, &registry).map(|c| c.pattern),
                Some(PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { separator, .. }))
                    if separator.as_deref() == Some(";")
            ),
            "the separator decides which elements exist"
        );
    }

    /// A third argument to the split names a string that reads back as NULL, so the
    /// elements are not the ones the contract describes.
    #[test]
    fn a_null_string_argument_refuses_the_split() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )]);
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.subjects'), ',', 'x'))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a null string changes which elements exist"
        );
    }

    /// A field declared as the caller is inert, so configuration cannot open the identity
    /// door that was closed deliberately. Two halves hold it, and both are asserted: the
    /// kind never matches an attribute read, and the caller lookup asks for the whole
    /// value so a field path is unreachable from it.
    #[test]
    fn a_claim_declared_as_the_caller_is_inert() {
        let registry = registry_with(vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["sub"],
            SessionAttributeKind::CallerId,
        )]);
        let expr = parse_expr("owner = current_setting('request.jwt.claims')::json ->> 'sub'");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a field of the caller's value is never the caller"
        );
        assert!(
            !registry.names_caller_setting_key("request.jwt.claims"),
            "declaring a field of the token does not name the token as the caller"
        );
    }

    /// A different splitter is a different split, so the caller contract would name
    /// elements the database never produces. Only `string_to_array` reaches a set.
    #[test]
    fn another_splitting_function_is_not_the_declared_split() {
        let registry = registry_with(vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )]);
        let expr = parse_expr(
            "owner = ANY(regexp_split_to_array(current_setting('app.subjects', true), ','))",
        );
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a regexp split names different elements"
        );
    }

    /// Nothing named the key, so nothing may read it.
    #[test]
    fn an_undeclared_key_reads_as_nothing() {
        let registry = FunctionRegistry::new();
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.subjects', true), ','))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "an empty registry declares nothing"
        );
    }

    /// The path is part of the source, so a declaration of one field does not answer for
    /// another.
    #[test]
    fn a_declared_field_does_not_answer_for_its_sibling() {
        let registry = registry_with(vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["aal"],
            SessionAttributeKind::ScalarAttribute,
        )]);
        let expr = parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'role' = 'admin'");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "one field is not another"
        );
        let declared =
            parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2'");
        assert!(
            recognize_session_attribute(&declared, &registry).is_some(),
            "the declared field answers"
        );
    }

    /// A field is indirection, which caps at B, while a plain key read does not.
    #[test]
    fn a_field_read_grades_below_a_plain_key_read() {
        let registry = registry_with(vec![
            SessionAttribute::setting("app.tenant_id", SessionAttributeKind::ScalarAttribute),
            SessionAttribute::claim(
                "request.jwt.claims",
                ["aal"],
                SessionAttributeKind::ScalarAttribute,
            ),
        ]);
        let plain = parse_expr("tenant_id = current_setting('app.tenant_id')::uuid");
        let hopped = parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2'");
        assert_eq!(
            recognize_session_attribute(&plain, &registry).map(|c| c.confidence),
            Some(ConfidenceLevel::A)
        );
        assert_eq!(
            recognize_session_attribute(&hopped, &registry).map(|c| c.confidence),
            Some(ConfidenceLevel::B)
        );
    }
}
