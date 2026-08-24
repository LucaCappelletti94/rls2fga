//! Expanding a policy call to a declared single-expression `LANGUAGE sql`
//! function, so the documented workaround for policy self-recursion translates
//! from the dump alone.
//!
//! Every gate refuses by returning `Expansion::Refused`, which the classifier
//! turns into an [`crate::classifier::patterns::UnclassifiedExpr`] refusal, so a
//! body the expansion cannot prove falls closed rather than widening access.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::cell::{Cell, RefCell};
use core::ops::ControlFlow;

use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, FunctionSecurity, Ident, TableFactor,
    Value, Visit, VisitMut, Visitor, VisitorMut,
};

use crate::classifier::function_registry::FunctionRegistry;
use crate::parser::function_analyzer::{body_reads_effective_user, body_single_projection};
use crate::parser::names::{
    lookup_table, normalize_relation_name, normalized_function_name, same_identifier,
    split_schema_and_relation, stored_ident_name, stored_identifier, table_has_column,
};
use crate::parser::sql_parser::{DatabaseLike, FunctionLike, RoleLike, TableLike};

/// Expansions one classification may perform, bounding the work a schema can
/// demand: a body that doubles its calls per level is cut here rather than
/// growing geometrically under the depth limit alone.
const EXPANSION_BUDGET: u32 = 32;

/// What one classification has already expanded.
///
/// The stack cuts call cycles by name, and it must survive the recognizer
/// re-entries into classification, so it rides beside the depth counter rather
/// than resetting with it.
pub struct ExpansionState {
    in_flight: RefCell<Vec<String>>,
    budget: Cell<u32>,
    owner_reads: Cell<u32>,
}

impl ExpansionState {
    /// A fresh state, which is what one whole clause classification carries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: RefCell::new(Vec::new()),
            budget: Cell::new(EXPANSION_BUDGET),
            owner_reads: Cell::new(0),
        }
    }
}

impl Default for ExpansionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExpansionState {
    fn expanding(&self, name: &str) -> bool {
        self.in_flight.borrow().iter().any(|held| held == name)
    }

    /// Record that `name` is being expanded. Paired with [`ExpansionState::leave`].
    pub(crate) fn enter(&self, name: String) {
        self.in_flight.borrow_mut().push(name);
    }

    pub(crate) fn leave(&self) {
        self.in_flight.borrow_mut().pop();
    }

    /// True while a definer body whose reads provably bypass row level security
    /// is being classified, so a scan of the guarded table is the owner's read
    /// rather than the recursion `PostgreSQL` refuses to plan.
    pub(crate) fn reading_as_owner(&self) -> bool {
        self.owner_reads.get() > 0
    }

    pub(crate) fn enter_owner_read(&self) {
        self.owner_reads.set(self.owner_reads.get() + 1);
    }

    pub(crate) fn leave_owner_read(&self) {
        self.owner_reads.set(self.owner_reads.get() - 1);
    }

    fn take_budget(&self) -> bool {
        let left = self.budget.get();
        if left == 0 {
            return false;
        }
        self.budget.set(left - 1);
        true
    }
}

/// How a call to a declared function expands.
pub(crate) enum Expansion {
    /// The substituted body, ready to classify in the call's place.
    Body {
        /// The called function, as spelled in its declaration.
        function: String,
        /// The body's table reads run as an owner `PostgreSQL` lets past those
        /// tables' policies.
        reads_bypass_rls: bool,
        /// The body with the call-site arguments substituted.
        expr: Box<Expr>,
    },
    /// The call names a declared function the expansion cannot prove, so the
    /// clause falls closed with this reason.
    Refused {
        /// Why the call is not expanded.
        reason: String,
    },
}

/// Expand `expr` when it is a call to a declared, unregistered,
/// single-expression `LANGUAGE sql` function.
///
/// `None` means the expression is not such a call, and the caller's ordinary
/// blame path stands.
pub(crate) fn expand_function_call<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<Expansion> {
    let Expr::Function(func) = expr else {
        return None;
    };
    // A window, filter or parameterized call is not the plain boolean call this
    // expands, and an argument list with modifiers is not plain either.
    if func.over.is_some()
        || func.filter.is_some()
        || func.null_treatment.is_some()
        || !matches!(func.parameters, FunctionArguments::None)
        || !func.within_group.is_empty()
    {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };
    if arg_list.duplicate_treatment.is_some() || !arg_list.clauses.is_empty() {
        return None;
    }
    let mut call_args = Vec::with_capacity(arg_list.args.len());
    for arg in &arg_list.args {
        let FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) = arg else {
            return None;
        };
        call_args.push(value.clone());
    }

    let call_name = func.name.to_string();
    // A declaration wins: a registered semantic, or the standing owner-bound
    // refusal, is already how this call translates.
    if registry.get(&call_name).is_some() {
        return None;
    }
    let terminal = normalized_function_name(func);
    if registry
        .owner_bound_accessors()
        .any(|bound| normalize_relation_name(bound) == terminal)
    {
        return None;
    }

    let named: Vec<&DB::Function> = db
        .functions()
        .filter(|declared| call_matches_declared(&call_name, declared.name()))
        .collect();
    let first_named = named.first()?;
    let function_name = first_named.name().to_string();
    let candidates: Vec<&DB::Function> = named
        .iter()
        .copied()
        .filter(|declared| declared.argument_names(db).count() == call_args.len())
        .collect();
    let function = match candidates.as_slice() {
        [] => {
            return Some(refused(format!(
                "Function '{function_name}' is declared with a different argument count \
                 than this call passes, so the call is not the declared body"
            )))
        }
        [only] => *only,
        _ => {
            return Some(refused(format!(
                "More than one declaration of '{function_name}' matches this call, so \
                 which body the call runs cannot be known"
            )))
        }
    };

    if state.expanding(&terminal) {
        return Some(refused(format!(
            "Expanding '{function_name}' reaches a call of itself, and the call cycle \
             is not translated"
        )));
    }
    if !state.take_budget() {
        return Some(refused(format!(
            "Expanding '{function_name}' exceeds the expansion budget for one clause, \
             so the remainder is not translated"
        )));
    }

    match function.language() {
        Some(language) if language.eq_ignore_ascii_case("sql") => {}
        Some(language) => {
            return Some(refused(format!(
                "Function '{function_name}' is LANGUAGE {language}, and only a \
                 single-expression LANGUAGE sql body expands"
            )))
        }
        None => {
            return Some(refused(format!(
                "Function '{function_name}' declares no language, and only a \
                 single-expression LANGUAGE sql body expands"
            )))
        }
    }

    let body = match (function.body_expression(), function.body()) {
        (Some(parsed), _) => parsed.clone(),
        (None, Some(text)) => match body_single_projection(text) {
            Some(projected) => projected,
            None => {
                return Some(refused(format!(
                    "Function '{function_name}' has no single-expression SELECT body, \
                     so the call is not expanded"
                )))
            }
        },
        (None, None) => {
            return Some(refused(format!(
                "Function '{function_name}' has no readable body, so the call is not \
                 expanded"
            )))
        }
    };

    let security = function.security_mode();
    if matches!(security, FunctionSecurity::Definer)
        && body_reads_effective_user(
            &function
                .body()
                .map_or_else(|| body.to_string(), str::to_string),
        )
    {
        return Some(refused(format!(
            "Function '{function_name}' is SECURITY DEFINER and its body reads \
             current_user, whose value is the owner's for every caller"
        )));
    }

    let mut scan = BodyScan::default();
    let _ = body.visit(&mut scan);
    if let Some(shape) = scan.unmodeled_relation {
        return Some(refused(format!(
            "The body of '{function_name}' reads {shape}, a relation shape the \
             expansion does not model"
        )));
    }

    // Declared argument names, in position order, as PostgreSQL stores them.
    let named_args: Vec<(usize, String)> = function
        .argument_names(db)
        .enumerate()
        .filter_map(|(index, name)| {
            name.map(|name| {
                (
                    index,
                    stored_identifier(name.name(), name.name_is_quoted()).into_owned(),
                )
            })
        })
        .collect();

    // Q6: a bare body name matching both an argument and a column of a table in
    // scope resolves to the column, silently, so the clause would compare the
    // column to itself and admit every row.
    for (_, stored_arg) in &named_args {
        let occurs_bare = scan
            .bare_idents
            .iter()
            .any(|ident| stored_ident_name(ident).as_ref() == stored_arg);
        if !occurs_bare {
            continue;
        }
        if let Some(table) = scan
            .tables
            .iter()
            .find(|table| table_has_column(db, table, stored_arg))
        {
            return Some(refused(format!(
                "The body of '{function_name}' reads '{stored_arg}', which is both its \
                 argument and a column of '{table}', so PostgreSQL reads the column and \
                 the shadowed argument is silently unused"
            )));
        }
    }

    let mut reads_bypass_rls = false;
    if matches!(security, FunctionSecurity::Definer) && !scan.tables.is_empty() {
        let Ok(function_owner) = function.owner(db) else {
            return Some(refused(format!(
                "The owner of '{function_name}' cannot be read, so whether its reads \
                 bypass row level security cannot be known"
            )));
        };
        for spelling in &scan.tables {
            let Some(table) = lookup_table(db, spelling) else {
                return Some(refused(format!(
                    "The body of '{function_name}' reads '{spelling}', which the schema \
                     does not declare"
                )));
            };
            if table.has_forced_row_level_security(db) != Ok(false) {
                return Some(refused(format!(
                    "'{spelling}' has FORCE ROW LEVEL SECURITY, so the definer's own \
                     read of it is filtered and the self-referential shape recurses at \
                     runtime"
                )));
            }
            let Ok(table_owner) = table.owner(db) else {
                return Some(refused(format!(
                    "The owner of '{spelling}' cannot be read, so whether \
                     '{function_name}' reads it unfiltered cannot be known"
                )));
            };
            let owners_match = match (function_owner, table_owner) {
                (None, None) => true,
                (Some(of_function), Some(of_table)) => same_identifier(of_function, of_table),
                _ => false,
            };
            if owners_match || owner_bypasses_rls(db, function_owner) {
                continue;
            }
            let owner = function_owner.unwrap_or("the schema principal");
            return Some(refused(format!(
                "Function '{function_name}' runs as {owner}, which does not provably \
                 read '{spelling}' unfiltered, so the rows its body counts cannot be \
                 known from the schema"
            )));
        }
        reads_bypass_rls = true;
    }

    // A column argument substitutes as the policy table's own reference, since a
    // policy expression resolves a bare column against its table and the body's
    // subqueries would otherwise capture the name. A qualifier one of the body's
    // relations claims cannot be spelled from inside, so it refuses.
    let outer_parts = qualifier_idents(table);
    let capture_prone = call_args.iter().any(|arg| match arg {
        Expr::Identifier(_) => scan
            .scope_names
            .iter()
            .any(|name| *name == normalize_relation_name(table)),
        Expr::CompoundIdentifier(parts) => parts.first().is_some_and(|qualifier| {
            let qualifier = stored_ident_name(qualifier);
            scan.scope_names.iter().any(|name| *name == qualifier)
        }),
        _ => false,
    });
    if capture_prone {
        return Some(refused(format!(
            "The body of '{function_name}' reads a relation named like the argument's \
             table, so the substituted reference would be captured by the body's own \
             scope"
        )));
    }
    let replacements: Vec<Expr> = call_args
        .iter()
        .map(|arg| match arg {
            Expr::Identifier(column) => {
                let mut parts = outer_parts.clone();
                parts.push(column.clone());
                Expr::CompoundIdentifier(parts)
            }
            Expr::CompoundIdentifier(_) | Expr::Value(_) => arg.clone(),
            wrapped => Expr::Nested(Box::new(wrapped.clone())),
        })
        .collect();

    let mut substituted = body;
    let mut rewrite = Substitute {
        replacements: &replacements,
        named_args: &named_args,
        function_terminal: &terminal,
        scope_names: &scan.scope_names,
        failed: None,
    };
    let _ = VisitMut::visit(&mut substituted, &mut rewrite);
    if let Some(reason) = rewrite.failed {
        return Some(refused(format!(
            "The body of '{function_name}' {reason}, so the call is not expanded"
        )));
    }

    Some(Expansion::Body {
        function: function_name,
        reads_bypass_rls,
        expr: Box::new(substituted),
    })
}

fn refused(reason: String) -> Expansion {
    Expansion::Refused { reason }
}

/// The policy table's spelling as identifier parts, quoting preserved.
fn qualifier_idents(table: &str) -> Vec<Ident> {
    crate::parser::names::split_qualified_identifier_parts(table)
        .into_iter()
        .map(|part| {
            if part.starts_with('"') {
                Ident::with_quote('"', crate::parser::names::unquote_identifier(&part))
            } else {
                Ident::new(part)
            }
        })
        .collect()
}

/// Whether the call's spelling names the declared function, through quoting,
/// case folding and schema qualification, with an unqualified spelling matching
/// the way [`lookup_table`] lets the sole bearer of a name match.
fn call_matches_declared(call: &str, declared: &str) -> bool {
    if normalize_relation_name(call) != normalize_relation_name(declared) {
        return false;
    }
    match (
        split_schema_and_relation(call),
        split_schema_and_relation(declared),
    ) {
        (Some((call_schema, _)), Some((declared_schema, _))) => {
            same_identifier(&call_schema, &declared_schema)
        }
        _ => true,
    }
}

fn owner_bypasses_rls<DB: DatabaseLike>(db: &DB, owner: Option<&str>) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    db.roles()
        .find(|role| same_identifier(role.name(), owner))
        .is_some_and(RoleLike::can_bypass_rls)
}

/// Everything the substitution and the ownership gate need to know about the
/// body: the tables it reads, every name a bare or qualified reference may
/// resolve against, and every bare identifier.
#[derive(Default)]
struct BodyScan {
    /// Relation spellings the body reads, for the ownership gate.
    tables: Vec<String>,
    /// Normalized table and alias names in scope, which claim a qualifier.
    scope_names: Vec<String>,
    /// Every bare identifier, for the shadowed-argument guard.
    bare_idents: Vec<Ident>,
    /// A table factor the scan does not model, which refuses the expansion.
    unmodeled_relation: Option<&'static str>,
}

impl Visitor for BodyScan {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<()> {
        match table_factor {
            TableFactor::Table { name, alias, .. } => {
                let spelling = name.to_string();
                // An alias hides the table's own name for that scope, so only
                // the name a qualifier can actually resolve against is held.
                match alias {
                    Some(alias) => self
                        .scope_names
                        .push(stored_ident_name(&alias.name).into_owned()),
                    None => self.scope_names.push(normalize_relation_name(&spelling)),
                }
                self.tables.push(spelling);
            }
            TableFactor::Derived { alias, .. } => {
                if let Some(alias) = alias {
                    self.scope_names
                        .push(stored_ident_name(&alias.name).into_owned());
                }
            }
            _ => self.unmodeled_relation = Some("a joined or function-valued relation"),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::Identifier(ident) = expr {
            self.bare_idents.push(ident.clone());
        }
        ControlFlow::Continue(())
    }
}

/// Rewrites parameter references to the call-site arguments, bottom up so a
/// substituted argument is never rewritten again.
struct Substitute<'a> {
    /// Per-position call arguments, already spelled for the body's scope.
    replacements: &'a [Expr],
    /// Declared argument positions by stored name.
    named_args: &'a [(usize, String)],
    /// Normalized terminal name of the function, which qualifies its own
    /// arguments in the `f.arg` spelling.
    function_terminal: &'a str,
    /// Normalized names a qualifier resolves against before the function name.
    scope_names: &'a [String],
    failed: Option<&'static str>,
}

impl Substitute<'_> {
    fn argument_for(&self, stored: &str) -> Option<&Expr> {
        self.named_args
            .iter()
            .find(|(_, name)| name == stored)
            .and_then(|(index, _)| self.replacements.get(*index))
    }
}

impl VisitorMut for Substitute<'_> {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        let replacement = match &*expr {
            Expr::Value(value) => {
                if let Value::Placeholder(placeholder) = &value.value {
                    if let Some(argument) = placeholder
                        .strip_prefix('$')
                        .and_then(|index| index.parse::<usize>().ok())
                        .and_then(|index| index.checked_sub(1))
                        .and_then(|index| self.replacements.get(index))
                    {
                        Some(argument.clone())
                    } else {
                        self.failed = Some("names a positional parameter the declaration lacks");
                        None
                    }
                } else {
                    None
                }
            }
            Expr::Identifier(ident) => self
                .argument_for(stored_ident_name(ident).as_ref())
                .cloned(),
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [qualifier, name] => {
                    let qualifier = stored_ident_name(qualifier);
                    if self.scope_names.iter().any(|held| *held == qualifier) {
                        None
                    } else if qualifier == self.function_terminal {
                        self.argument_for(stored_ident_name(name).as_ref()).cloned()
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(replacement) = replacement {
            *expr = replacement;
        }
        ControlFlow::Continue(())
    }
}
