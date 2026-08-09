use rls2fga::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
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
fn translator_builder_default_settings_rejects_uuid_array_accessor_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION listed_ids_accessor() RETURNS UUID[]
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid[]';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = listed_ids_accessor());
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
        "UUID[] accessors must not infer direct ownership, got: {:?}",
        using.pattern
    );
}

#[test]
fn translator_builder_accepts_direct_accessor_with_keyword_substring_alias() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid AS from_id';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "direct accessor with alias substring should still infer P3 ownership, got: {:?}",
        using.pattern
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

/// A key names the caller wherever the call sits. Nothing forces a policy to route
/// the read through a declared function, and a wrapper's return type says nothing
/// about whether its value identifies the caller.
#[test]
fn translator_builder_names_the_caller_from_an_inline_setting_key() {
    let sql = r"
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner"),
        "a named key read inline should infer direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(
        using.confidence,
        ConfidenceLevel::A,
        "naming the key is the same statement a registered accessor makes",
    );
}

/// A helper naming the columns one translator classifies as owned, so a test asserting
/// what is refused also asserts what is admitted under the same configuration.
fn owned_columns(translator: &rls2fga::translator::Translator, sql: &str) -> Vec<String> {
    let db = parse_schema(sql).expect("schema should parse");
    let mut owned: Vec<String> = translator
        .classify(&db)
        .iter()
        .filter_map(
            |policy| match policy.using_classification.as_ref()?.pattern {
                PatternClass::P3DirectOwnership { ref column } => Some(column.clone()),
                _ => None,
            },
        )
        .collect();
    owned.sort();
    owned
}

/// The keys are an allowlist, so a key nobody named stays unknown. Trusting every key
/// would read a tenant identifier as a user and grant one tuple per tenant. The named
/// key beside it is the control: refusing everything would satisfy the refusal alone.
#[test]
fn translator_builder_does_not_name_the_caller_from_an_unnamed_setting_key() {
    let sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT, owner_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON rows_ FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY p_owner ON rows_ FOR UPDATE USING (owner_id = current_setting('app.user_id', true));
";
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    assert_eq!(
        owned_columns(&translator, sql),
        ["owner_id"],
        "the named key names the caller and the unnamed one names nobody"
    );
}

/// `request.jwt.claims` holds the whole token as one object, so its value is not an
/// identity. It is reached through a `->> 'sub'` hop, which names the caller on its own.
/// The key beside it is a built-in one, so the refusal is selective rather than total.
#[test]
fn translator_builder_does_not_name_the_caller_from_the_default_claims_object() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, claims_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_claims ON docs FOR SELECT USING (claims_id = current_setting('request.jwt.claims', true));
CREATE POLICY p_owner ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id', true));
";
    let translator = TranslatorBuilder::new().build();

    assert_eq!(
        owned_columns(&translator, sql),
        ["owner_id"],
        "a built-in key that holds an identity is the caller, the token object is not"
    );
}

/// Every recognizer asks one predicate who the caller is, so a named key reaches the
/// membership subquery too.
#[test]
fn translator_builder_names_the_caller_from_an_inline_key_inside_a_membership_subquery() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM doc_members m
  WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)
));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(
            &using.pattern,
            PatternClass::P4ExistsMembership { join_table, user_column, .. }
                if join_table == "doc_members" && user_column == "user_id"
        ),
        "a named key read inline should carry the membership too, got: {:?}",
        using.pattern
    );
}

/// A text identity is at least as common as a UUID one, and the declared return type
/// says nothing about whether the body's value identifies the caller.
#[test]
fn translator_builder_infers_a_text_returning_accessor_from_its_body() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION app_user_id() RETURNS TEXT
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = app_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "a TEXT accessor body should infer direct ownership, got: {:?}",
        using.pattern
    );
}

/// A cast changes the type, not who the value belongs to, so it must not decide whether
/// the key was named.
#[test]
fn translator_builder_names_the_caller_from_a_cast_inline_setting_key() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true)::uuid);
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "a cast key read inline should infer direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(
        using.confidence,
        ConfidenceLevel::A,
        "a cast is not indirection",
    );
}

/// A login token holds the identity in a field, and no expression says which field that
/// is, so naming the token's own key names nobody. The key holding just the subject is
/// the spelling that works, and `PostgREST` sets it alongside the token.
#[test]
fn translator_builder_reads_a_token_payload_only_through_the_subject_key() {
    let payload = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('request.jwt.claims', true)::json->>'sub');
";
    let subject = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('request.jwt.claim.sub', true));
";
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["request.jwt.claims", "request.jwt.claim.sub"])
        .build();

    assert!(
        owned_columns(&translator, payload).is_empty(),
        "a field of the token is not the token's value, so the key names nobody here"
    );
    assert_eq!(
        owned_columns(&translator, subject),
        ["owner_id"],
        "the key holding the subject names the caller"
    );
}

/// Which key names the caller is the caller's to say, so a key the crate ships no
/// default for works the moment it is named.
#[test]
fn translator_builder_names_the_caller_from_any_key_it_is_given() {
    let sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON rows_ FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.tenant_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "tenant_id"),
        "the named key decides, whatever it is called, got: {:?}",
        using.pattern
    );
}

/// The built-in keys are the ones a schema is most likely to spell, so they have to
/// reach an inline call with nothing configured.
#[test]
fn translator_builder_names_the_caller_from_a_built_in_key_with_no_configuration() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('app.current_user_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");

    let classified = TranslatorBuilder::new().build().classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "a built-in key read inline should infer direct ownership, got: {:?}",
        using.pattern
    );
}

/// `PostgreSQL` folds a setting name when it looks it up, so two spellings of one key
/// name one setting and have to name one caller.
#[test]
fn translator_builder_folds_the_case_of_a_setting_key() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('APP.User_Id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys([" app.USER_ID "])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification
        .as_ref()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership { column } if column == "owner_id"),
        "one setting under two spellings is one caller, got: {:?}",
        using.pattern
    );
}

/// A key named on the registry and a key named through the settings are two statements
/// by the same caller, so both hold.
#[test]
fn translator_builder_keeps_a_key_the_base_registry_already_named() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, editor_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT USING (owner_id = current_setting('one.key', true));
CREATE POLICY p_editor ON docs FOR UPDATE USING (editor_id = current_setting('other.key', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    registry.trust_current_user_setting_keys(["one.key"]);
    let translator = TranslatorBuilder::new()
        .with_registry(registry)
        .with_current_user_setting_keys(["other.key"])
        .build();

    let classified = translator.classify(&db);
    let mut owned: Vec<&str> = classified
        .iter()
        .filter_map(
            |policy| match policy.using_classification.as_ref()?.pattern {
                PatternClass::P3DirectOwnership { ref column } => Some(column.as_str()),
                _ => None,
            },
        )
        .collect();
    owned.sort_unstable();
    assert_eq!(
        owned,
        ["editor_id", "owner_id"],
        "both keys name the caller: {classified:#?}"
    );
}

// ── The session attribute vocabulary ──────────────────────────────────

/// Every in-scope spelling, so one declaration list answers the whole inventory.
fn declared(
    sql: &str,
    attributes: Vec<SessionAttribute>,
) -> Vec<(String, PatternClass, ConfidenceLevel)> {
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_session_attributes(attributes)
        .build();
    translator
        .classify(&db)
        .into_iter()
        .filter_map(|policy| {
            let using = policy
                .using_classification
                .or(policy.with_check_classification)?;
            Some((policy.name, using.pattern, using.confidence))
        })
        .collect()
}

/// Inventory row 1 and `shares_read`: the caller's held set against a row column.
#[test]
fn a_declared_set_holds_the_rows_value() {
    let sql = r"
CREATE TABLE notes(id INT PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (
    owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P14RowValueInCallerSet { column, source, .. }
                if column == "owner" && source.request_parameter() == "app_subjects"
        ),
        "a declared set holding the row's value is the whole grant, got {:?}",
        classified[0].1
    );
}

/// Inventory row 5: one request value against a row column.
#[test]
fn a_declared_scalar_equals_the_rows_value() {
    let sql = r"
CREATE TABLE tenants(id UUID PRIMARY KEY);
CREATE TABLE documents(id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id));
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents FOR SELECT USING (tenant_id = current_setting('app.tenant_id')::uuid);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.tenant_id",
            SessionAttributeKind::ScalarAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P15RowValueEqualsCallerScalar { column, source }
                if column == "tenant_id" && source.request_parameter() == "app_tenant_id"
        ),
        "a declared scalar equal to the row's value is the grant, got {:?}",
        classified[0].1
    );
}

/// Inventory row 10: a constant against the caller's held set, no row column at all.
#[test]
fn a_declared_set_holds_a_constant() {
    let sql = r"
CREATE TABLE audit_log(id UUID PRIMARY KEY, actor TEXT);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON audit_log FOR SELECT USING (
    'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.roles",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P16ConstantInCallerSet { value, source, .. }
                if value == "admin" && source.request_parameter() == "app_roles"
        ),
        "the request alone decides this grant, got {:?}",
        classified[0].1
    );
}

/// Inventory row 7: a declared field of the caller's token against a constant, reached
/// through the helper function whose body reads the setting the declaration names.
#[test]
fn a_declared_claim_field_equals_a_constant_through_its_wrapper() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE documents(id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id));
CREATE FUNCTION auth.jwt() RETURNS JSONB LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claims'')::jsonb';
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents AS RESTRICTIVE FOR SELECT
    USING ((SELECT auth.jwt() ->> 'aal') = 'aal2');
";
    let classified = declared(
        sql,
        vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["aal"],
            SessionAttributeKind::ScalarAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P17CallerScalarEqualsConstant { value, source }
                if value == "aal2" && source.request_parameter() == "request_jwt_claims_aal"
        ),
        "a declared token field is a request value, got {:?}",
        classified[0].1
    );
}

/// The same field written against the setting itself, so the two spellings are one
/// declaration and cannot disagree.
#[test]
fn a_declared_claim_field_is_reached_through_either_spelling() {
    let sql = r"
CREATE TABLE documents(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents FOR SELECT
    USING (current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2');
";
    let classified = declared(
        sql,
        vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["aal"],
            SessionAttributeKind::ScalarAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P17CallerScalarEqualsConstant { value, .. } if value == "aal2"
        ),
        "the inline spelling and the wrapper spelling are one declaration, got {:?}",
        classified[0].1
    );
}

/// An undeclared key stays unreadable, so the door opens only where a deployment said so.
#[test]
fn an_undeclared_key_still_yields_unknown() {
    let sql = r"
CREATE TABLE notes(id INT PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (
    owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);
";
    let classified = declared(sql, Vec::new());
    assert!(
        matches!(&classified[0].1, PatternClass::Unknown { .. }),
        "nothing named this key, so nothing may read it, got {:?}",
        classified[0].1
    );
}

/// Inventory row 3: the caller's held set tested inside a membership subquery. The
/// sharing row is the table's authority and the held set is the request's, so the grant
/// is a request-completed gate on the parent, keyed by the sharing row's parent column.
#[test]
fn a_declared_set_inside_a_membership_subquery_grants_through_the_parent() {
    let sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P18MembershipInCallerSet {
                join_table,
                fk_column,
                member_column,
                source,
                ..
            } if join_table == "paper_shares"
                && fk_column == "paper_id"
                && member_column == "viewer"
                && source.request_parameter() == "app_subjects"
        ),
        "a share row naming a key the caller holds is the grant, got {:?}",
        classified[0].1
    );
}

/// The same subquery with nothing declared stays unreadable, so the door opens only
/// where a deployment said so.
#[test]
fn an_undeclared_set_inside_a_membership_subquery_yields_unknown() {
    let sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let classified = declared(sql, Vec::new());
    assert!(
        matches!(&classified[0].1, PatternClass::Unknown { .. }),
        "nothing named this key, so nothing may read it, got {:?}",
        classified[0].1
    );
}

/// The uncorrelated shape, where the subquery names no column of the guarded table, is
/// the widest grant the crate emits: whoever appears in the member table gets the whole
/// table. A column holding a grant the caller carries names no person, so reading it
/// that way would declare grant keys to be users and hand them every row.
#[test]
fn an_uncorrelated_subquery_testing_a_declared_set_is_refused() {
    let sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE grants_table (grant_key TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM grants_table g
        WHERE g.grant_key = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(&classified[0].1, PatternClass::Unknown { .. }),
        "a grant key is not a person, so it cannot hold the whole table open, got {:?}",
        classified[0].1
    );
}

/// Inventory row 9, from the Supabase documentation: "the caller is known, and the
/// caller owns this row". A fact exists only for a row that has an owner and a caller
/// with no identifier matches none, so the first half is already enforced by how facts
/// are produced and contributes nothing. Refusing the pair is pure over-denial.
#[test]
fn a_redundant_caller_is_known_check_leaves_the_ownership_half() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id));
CREATE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (auth.uid() IS NOT NULL AND auth.uid() = user_id);
";
    let classified = declared(sql, Vec::new());
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P3DirectOwnership { column } if column == "user_id"
        ),
        "the ownership half is the whole rule, got {:?}",
        classified[0].1
    );
    assert_eq!(
        classified[0].2,
        ConfidenceLevel::A,
        "dropping a conjunct that says nothing costs no confidence"
    );
}

/// The same test on a row column is a real filter and must survive: dropping it would
/// grant rows the policy refuses.
#[test]
fn a_not_null_check_on_a_row_column_is_never_dropped() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id), approved_at TIMESTAMPTZ);
CREATE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (approved_at IS NOT NULL AND auth.uid() = user_id);
";
    let classified = declared(sql, Vec::new());
    assert!(
        !matches!(&classified[0].1, PatternClass::P3DirectOwnership { .. }),
        "the row's own guard decides which rows are granted, got {:?}",
        classified[0].1
    );
}
