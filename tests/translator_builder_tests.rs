use rls2fga::classifier::patterns::{ConfidenceLevel, PatternClass};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

#[test]
fn translator_builder_default_settings_reject_timezone_accessor_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')::uuid';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = wrong_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        !matches!(&using.pattern, PatternClass::P3DirectOwnership { .. }),
        "timezone-based current_setting must not infer direct ownership by default, got: {:?}",
        using.pattern
    );
}

#[test]
fn translator_builder_custom_current_setting_key_enables_schema_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')::uuid';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = wrong_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["timezone"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "custom allowlist should infer direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(
        using.confidence,
        ConfidenceLevel::A,
        "schema-inferred accessor should classify P3 at confidence A",
    );
}

#[test]
fn translator_builder_registry_json_and_settings_work_together() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = oauth_token());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["tenant.current_user_uuid"])
        .with_registry_json(
            r#"{
  "oauth_token": {"kind":"current_user_accessor","returns":"uuid"}
}"#,
        )
        .expect("registry json should parse")
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "registry-provided accessor should classify as direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(using.confidence, ConfidenceLevel::A);
}
