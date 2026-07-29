use super::*;

pub(super) fn render_dsl(types: &[TypePlan]) -> String {
    let mut dsl = String::new();
    let _ = writeln!(dsl, "model");
    let _ = writeln!(dsl, "  schema {OPENFGA_SCHEMA_VERSION}");

    for t in types {
        let _ = writeln!(dsl);
        let _ = writeln!(dsl, "type {}", t.type_name);

        if t.direct_relations.is_empty() && t.computed_relations.is_empty() {
            continue;
        }

        let _ = writeln!(dsl, "  relations");
        for (relation, subjects) in &t.direct_relations {
            let _ = writeln!(dsl, "    define {relation}: {}", format_subjects(subjects));
        }
        for (relation, expr) in &t.computed_relations {
            let _ = writeln!(dsl, "    define {relation}: {}", expr_to_dsl(expr, None));
        }
    }

    dsl
}

fn format_subjects(subjects: &[DirectSubject]) -> String {
    let parts = subjects
        .iter()
        .map(|s| match s {
            DirectSubject::Type(t) => t.clone(),
            DirectSubject::Wildcard(t) => format!("{t}:*"),
        })
        .collect::<Vec<_>>();
    format!("[{}]", parts.join(", "))
}

/// Render one userset. The DSL admits a single operator per nesting level, so a
/// child of another kind is parenthesized. `parent` is the operator this expression
/// sits under, or `None` at the top of a definition.
pub(super) fn expr_to_dsl(expr: &UsersetExpr, parent: Option<&str>) -> String {
    const ATOM: &str = "";
    let (operator, parts) = match expr {
        UsersetExpr::Computed(name) => return name.clone(),
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            return format!("{computed} from {tupleset}")
        }
        UsersetExpr::Union(children) => (
            "or",
            children
                .iter()
                .map(|child| expr_to_dsl(child, Some("or")))
                .collect::<Vec<_>>(),
        ),
        UsersetExpr::Intersection(children) => (
            "and",
            children
                .iter()
                .map(|child| expr_to_dsl(child, Some("and")))
                .collect::<Vec<_>>(),
        ),
        // `but not` takes exactly two operands and never chains, so both sides are
        // rendered as if they sat under no operator of their own.
        UsersetExpr::Exclusion { base, subtract } => (
            "but not",
            vec![
                expr_to_dsl(base, Some(ATOM)),
                expr_to_dsl(subtract, Some(ATOM)),
            ],
        ),
    };

    let rendered = parts.join(&format!(" {operator} "));
    if parent.is_some_and(|parent| parent != operator) {
        format!("({rendered})")
    } else {
        rendered
    }
}
