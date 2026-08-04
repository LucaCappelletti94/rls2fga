#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use rls2fga::classifier::patterns::ConfidenceLevel;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

/// Drive the full translation pipeline on one SQL input.
///
/// The property under test is simple: no input, however malformed, may panic
/// or abort. Parse errors are an expected outcome for random bytes and are not
/// failures.
fn translate(sql: &str) {
    let Ok(db) = parse_schema(sql) else {
        return;
    };

    // Exercise every confidence threshold, since the level gates which policies
    // reach model, tuple, and report generation.
    for level in [
        ConfidenceLevel::A,
        ConfidenceLevel::B,
        ConfidenceLevel::C,
        ConfidenceLevel::D,
    ] {
        let translator = TranslatorBuilder::new().with_min_confidence(level).build();
        let translation = translator.translate(&db);
        black_box(translation.unhandled().count());
        let outputs = translation.outputs_accepting_gaps();

        black_box(outputs.model());
        black_box(outputs.json_model());
        black_box(format_tuples(&outputs.tuple_queries()));
        black_box(outputs.report());
    }
}

fuzz_target!(|data: &[u8]| {
    // sqlparser works on `&str`; non-UTF-8 inputs cannot form SQL, so skip them
    // rather than wasting the fuzzer on lossy conversions.
    if let Ok(sql) = std::str::from_utf8(data) {
        translate(sql);
    }
});
