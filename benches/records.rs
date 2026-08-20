//! Cost of deriving records from one row.
//!
//! The evaluator answers per change, so its cost is paid on every write a change
//! stream carries, not once per translation. Descriptions come from the public
//! pipeline rather than hand-built literals, so a bench cannot drift from the
//! shapes production actually emits.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::records::{
    records_from_row, RecordDerivation, RecordDescription, RowValues, ValueSource,
};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

/// A row held as plain values, which is the cheapest thing a caller can pass.
/// Anything slower than this is the caller's cost, not the evaluator's.
#[derive(Default)]
struct MapRow {
    text: BTreeMap<String, String>,
    lists: BTreeMap<String, Vec<String>>,
}

impl RowValues for MapRow {
    fn text(&self, column: &str) -> Option<Cow<'_, str>> {
        self.text.get(column).map(|v| Cow::Borrowed(v.as_str()))
    }

    fn list(&self, column: &str) -> Option<Vec<Option<Cow<'_, str>>>> {
        Some(
            self.lists
                .get(column)?
                .iter()
                .map(|v| Some(Cow::Borrowed(v.as_str())))
                .collect(),
        )
    }
}

/// Every pure description a schema's tuple queries carry.
fn descriptions(schema: &str) -> Vec<RecordDescription> {
    let db = parse_schema(schema).expect("benchmark schema parses");
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::C)
        .build();
    translator
        .translate(&db)
        .expect("benchmark schema should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
        .into_iter()
        .filter_map(|query| query.description)
        .collect()
}

/// The one description whose subject reads `source`, so a bench names the shape it
/// measures instead of trusting an index.
fn by_subject(schema: &str, want: &dyn Fn(&ValueSource) -> bool) -> RecordDescription {
    let found: Vec<_> = descriptions(schema)
        .into_iter()
        .filter(|d| match &d.derivation {
            RecordDerivation::FromRow { template, .. } => want(template.subject_key.part()),
            _ => false,
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one matching description, got {}",
        found.len()
    );
    found.into_iter().next().expect("checked above")
}

const OWNERSHIP: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);";

const ARRAY: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, editors TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (current_user = ANY (editors));";

const GUARDED: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (status = 'published');";

fn one_record(c: &mut Criterion) {
    let description = by_subject(OWNERSHIP, &|s| matches!(s, ValueSource::Column(_)));
    let mut row = MapRow::default();
    row.text.insert("id".to_string(), "d1".to_string());
    row.text.insert("owner_id".to_string(), "u1".to_string());

    c.bench_function("one_record", |b| {
        b.iter(|| {
            let records = records_from_row(black_box(&description), black_box(&row))
                .expect("a pure description answers");
            debug_assert_eq!(records.len(), 1);
            records
        });
    });
}

fn expanding_record(c: &mut Criterion) {
    let description = by_subject(ARRAY, &|s| matches!(s, ValueSource::ListElements(_)));
    let mut group = c.benchmark_group("expanding_record");

    for editors in [1_u64, 8, 64, 512] {
        let mut row = MapRow::default();
        row.text.insert("id".to_string(), "d1".to_string());
        row.lists.insert(
            "editors".to_string(),
            (0..editors).map(|i| format!("u{i}")).collect(),
        );

        group.throughput(Throughput::Elements(editors));
        group.bench_with_input(BenchmarkId::from_parameter(editors), &row, |b, row| {
            b.iter(|| {
                records_from_row(black_box(&description), black_box(row))
                    .expect("a pure description answers")
            });
        });
    }
    group.finish();
}

/// A guard the row fails costs only the guard, and it is the common case for a
/// change stream carrying every row of a table.
fn guard_rejects(c: &mut Criterion) {
    let description = by_subject(GUARDED, &|s| matches!(s, ValueSource::Literal(_)));
    let mut row = MapRow::default();
    row.text.insert("id".to_string(), "d1".to_string());
    row.text.insert("status".to_string(), "draft".to_string());

    c.bench_function("guard_rejects", |b| {
        b.iter(|| {
            let records = records_from_row(black_box(&description), black_box(&row))
                .expect("a pure description answers");
            debug_assert!(records.is_empty());
            records
        });
    });
}

criterion_group!(benches, one_record, expanding_record, guard_rejects);
criterion_main!(benches);
