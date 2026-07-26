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
            let _ = writeln!(dsl, "    define {relation}: {}", expr_to_dsl(expr, 0));
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

pub(super) fn expr_to_dsl(expr: &UsersetExpr, parent_precedence: u8) -> String {
    // 0 = top, 1 = OR, 2 = AND, 3 = atom
    match expr {
        UsersetExpr::Computed(name) => name.clone(),
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            format!("{computed} from {tupleset}")
        }
        UsersetExpr::Union(children) => {
            let rendered = children
                .iter()
                .map(|c| expr_to_dsl(c, 1))
                .collect::<Vec<_>>()
                .join(" or ");
            if parent_precedence > 1 {
                format!("({rendered})")
            } else {
                rendered
            }
        }
        UsersetExpr::Intersection(children) => {
            let rendered = children
                .iter()
                .map(|c| expr_to_dsl(c, 2))
                .collect::<Vec<_>>()
                .join(" and ");
            if parent_precedence > 2 {
                format!("({rendered})")
            } else {
                rendered
            }
        }
    }
}
