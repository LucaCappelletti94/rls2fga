use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{records_from_row, ConfidenceLevel, Record, TableId};

mod support;

const TABLES: &str = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE shares(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
                    PRIMARY KEY(doc, user_id));
CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
                    PRIMARY KEY(doc, user_id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";
const OWNER: &str = "owner = current_setting('app.user_id', true)";
const SHARED: &str = "EXISTS (SELECT 1 FROM shares s WHERE s.doc = docs.id
                           AND s.user_id = current_setting('app.user_id', true))";
const BLOCKED: &str = "EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id
                            AND b.user_id = current_setting('app.user_id', true))";

fn translator() -> rls2fga::translator::Translator {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
        ])
        .build()
}

fn schema(clause: &str) -> String {
    format!("{TABLES} CREATE POLICY docs_read ON docs FOR SELECT USING ({clause});")
}

fn translate(sql: &str) -> Translation {
    let db = parse_schema(sql).expect("schema parses");
    translator().translate(&db).expect("translation plans")
}

fn records(translation: &Translation, table: &str, doc: &str, user: &str) -> Vec<Record> {
    let table = TableId::from_stored(None, table.to_string());
    let row = support::row(&[("doc", doc), ("user_id", user)]);
    translation
        .relations()
        .iter()
        .flat_map(|relation| &relation.shapes)
        .filter(|shape| shape.tables.contains(&table))
        .flat_map(|shape| records_from_row(shape, &row).expect("membership row is decodable"))
        .collect()
}

#[test]
fn an_owner_minus_a_blocklist_keeps_the_memberships_grade() {
    let positive = parse_schema(&schema(BLOCKED)).expect("schema parses");
    let negative =
        parse_schema(&schema(&format!("{OWNER} AND NOT {BLOCKED}"))).expect("schema parses");
    let translator = translator();
    let positive = translator.classify(&positive);
    let negative = translator.classify(&negative);
    assert_eq!(
        negative[0].using_classification().unwrap().confidence,
        positive[0].using_classification().unwrap().confidence
    );
    let translated = translator
        .translate(&parse_schema(&schema(&format!("{OWNER} AND NOT {BLOCKED}"))).unwrap())
        .unwrap();
    assert!(
        translated
            .notes()
            .iter()
            .all(|note| !note.severity().diverges_from_database()),
        "{:?}",
        translated.notes()
    );
}

#[test]
fn positive_shares_and_negative_blocks_write_separate_relations() {
    let translated = translate(&schema(&format!("({OWNER} OR {SHARED}) AND NOT {BLOCKED}")));
    let blocked = records(&translated, "blocks", "d1", "alice");
    let shared = records(&translated, "shares", "d1", "alice");
    assert!(
        blocked.iter().any(|record| {
            record.object == "docs:d1"
                && record.relation == "blocked"
                && record.subject == "user:alice"
        }),
        "{blocked:?}"
    );
    assert!(
        shared.iter().all(|record| record.relation != "blocked"),
        "{shared:?}"
    );
    assert!(
        shared.iter().any(|record| record.subject == "user:alice"),
        "{shared:?}"
    );
    let moved = records(&translated, "blocks", "d2", "bob");
    assert!(
        moved.iter().any(|record| {
            record.object == "docs:d2"
                && record.relation == "blocked"
                && record.subject == "user:bob"
        }),
        "{moved:?}"
    );
    assert!(moved.iter().all(|record| !blocked.contains(record)));
}

#[test]
fn unsafe_exclusion_shapes_stay_below_the_threshold() {
    let nullable = "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT);";
    let without_blocks = TABLES.replace(
        "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,\n                    PRIMARY KEY(doc, user_id));",
        nullable,
    );
    let clauses = [
        format!("NOT {BLOCKED}"),
        "current_setting('app.user_id', true) NOT IN (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id)".to_string(),
        format!("{OWNER} AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id AND b.user_id = ANY(string_to_array(current_setting('app.subjects', true), ',')))"),
        format!("{OWNER} AND NOT EXISTS (SELECT 1 FROM blocks b JOIN shares s ON s.doc = b.doc WHERE b.doc = docs.id AND b.user_id = current_setting('app.user_id', true))"),
        format!("{OWNER} AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id AND b.user_id = current_setting('app.user_id', true) LIMIT 1 OFFSET 1)"),
        format!("{OWNER} AND current_setting('app.user_id', true) NOT IN (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id LIMIT 1)"),
    ];
    for clause in clauses {
        let translated = translate(&schema(&clause));
        assert!(
            translated
                .notes()
                .iter()
                .any(|note| note.severity().diverges_from_database()),
            "{clause}"
        );
        assert!(
            support::footgun::relation_denies(
                &translated.outputs_accepting_gaps().model(),
                "docs",
                "can_select"
            ),
            "{clause}"
        );
    }
    for (tables, suffix) in [
        (without_blocks.as_str(), ""),
        (without_blocks.as_str(), "CREATE UNIQUE INDEX blocks_member ON blocks(doc, user_id);"),
        (TABLES, "ALTER TABLE blocks ENABLE ROW LEVEL SECURITY; CREATE POLICY blocks_read ON blocks FOR SELECT USING (true);"),
        (TABLES, "ALTER TABLE blocks ENABLE ROW LEVEL SECURITY;"),
    ] {
        let clause = format!("{OWNER} AND current_setting('app.user_id', true) NOT IN (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id)");
        let sql = format!("{tables} {suffix} CREATE POLICY docs_read ON docs FOR SELECT USING ({clause});");
        let translated = translate(&sql);
        assert!(translated.notes().iter().any(|note| note.severity().diverges_from_database()), "{sql}");
        assert!(support::footgun::relation_denies(
            &translated.outputs_accepting_gaps().model(), "docs", "can_select"
        ), "{sql}");
    }
}

#[test]
fn a_failed_blocklist_witness_denies_its_positive_grant() {
    let sql = format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
         CREATE TABLE blocks(
           doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
           starts_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)
             AND b.starts_at <= now() AND b.expires_at > now()));"
    );
    let translated = translate(&sql);
    assert!(translated.notes().iter().any(|note| matches!(
        note,
        rls2fga::types::TranslationNote::ExpressionRefused { .. }
    )));
    assert!(support::footgun::relation_denies(
        &translated.outputs_accepting_gaps().model(),
        "docs",
        "can_select"
    ));
}

#[test]
fn unkeyed_equality_clock_blocklist_requires_a_monotone_witness() {
    let sql = format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
         CREATE TABLE blocks(
           doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
           stamp TIMESTAMPTZ NOT NULL);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)
             AND b.stamp = now()));"
    );
    let translated = translate(&sql);
    assert!(translated.notes().iter().any(|note| matches!(
        note,
        rls2fga::types::TranslationNote::ExpressionRefused { .. }
    )));
    assert!(support::footgun::relation_denies(
        &translated.outputs_accepting_gaps().model(),
        "docs",
        "can_select"
    ));
}

#[test]
fn cast_caller_blocklist_without_declared_identity_is_refused() {
    let tables = TABLES.replace(
        "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,\n                    PRIMARY KEY(doc, user_id));",
        "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id INTEGER NOT NULL,\n                    PRIMARY KEY(doc, user_id));",
    );
    let sql = format!(
        "{tables} CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)::integer));"
    );
    let translated = translate(&sql);
    assert!(
        translated
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "{:?}",
        translated.notes()
    );
    assert!(support::footgun::relation_denies(
        &translated.outputs_accepting_gaps().model(),
        "docs",
        "can_select"
    ));
}

#[test]
fn cast_caller_blocklist_with_declared_identity_is_accepted() {
    let tables = TABLES.replace(
        "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,\n                    PRIMARY KEY(doc, user_id));",
        "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id INTEGER NOT NULL,\n                    PRIMARY KEY(doc, user_id));",
    );
    let sql = format!(
        "{tables} CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)::integer));"
    );
    let db = parse_schema(&sql).expect("schema parses");
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("integer")])
        .build();
    let translated = translator.translate(&db).expect("translation plans");
    assert!(
        translated
            .notes()
            .iter()
            .all(|note| !note.severity().diverges_from_database()),
        "{:?}",
        translated.notes()
    );
}

#[test]
fn stacked_caller_cast_blocklist_is_refused_despite_a_matching_outer_cast() {
    let sql = format!(
        "{TABLES} CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)::integer::text));"
    );
    let db = parse_schema(&sql).expect("schema parses");
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("text")])
        .build();
    let translated = translator.translate(&db).expect("translation plans");
    assert!(
        translated
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "{:?}",
        translated.notes()
    );
    assert!(support::footgun::relation_denies(
        &translated.outputs_accepting_gaps().model(),
        "docs",
        "can_select"
    ));
}

#[test]
fn unkeyed_monotone_clock_blocklist_still_compresses() {
    let sql = format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
         CREATE TABLE blocks(
           doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
           expires_at TIMESTAMPTZ NOT NULL);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT USING (
           {OWNER} AND NOT EXISTS (
             SELECT 1 FROM blocks b WHERE b.doc = docs.id
             AND b.user_id = current_setting('app.user_id', true)
             AND b.expires_at > now()));"
    );
    let translated = translate(&sql);
    assert!(
        translated
            .notes()
            .iter()
            .all(|note| !note.severity().diverges_from_database()),
        "{:?}",
        translated.notes()
    );
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use super::*;
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    const ATTRIBUTES: &str = r#"[{"key":"app.user_id","kind":"caller_id"}]"#;
    const UUID_ATTRIBUTES: &str =
        r#"[{"key":"app.user_id","kind":"caller_id","identity_cast":"uuid"}]"#;
    const SEED: &[&str] = &[
        "INSERT INTO docs VALUES ('d1', 'alice'), ('d2', 'bob'), ('d3', 'alice');",
        "INSERT INTO shares VALUES ('d1', 'carol'), ('d2', 'carol'), ('d3', 'carol');",
        "INSERT INTO blocks VALUES ('d1', 'carol'), ('d2', 'bob');",
        "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN; CREATE ROLE carol LOGIN;
         GRANT SELECT ON docs, shares, blocks TO alice, bob, carol;",
    ];

    fn case(name: &str, sql: &str, changes: &[&str]) -> ParityCase {
        let mut seed = SEED.to_vec();
        seed.extend_from_slice(changes);
        ParityCase::reading(
            name,
            sql,
            &seed,
            ["alice", "bob", "carol"]
                .into_iter()
                .map(|user| Principal::with_setting(user, user, "app.user_id", user))
                .collect(),
        )
        .with_attributes(ATTRIBUTES)
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn every_blocklist_spelling_agrees_with_postgres() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let not_in = "current_setting('app.user_id', true) NOT IN
                          (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id)";
            let all = "current_setting('app.user_id', true) <> ALL
                       (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id)";
            let shared_grant = format!("({OWNER} OR {SHARED})");
            let variants = [
                ("exists-owner", schema(&format!("{OWNER} AND NOT {BLOCKED}")), false),
                ("exists-union", schema(&format!("{shared_grant} AND NOT {BLOCKED}")), true),
                ("in-owner", schema(&format!("{OWNER} AND {not_in}")), false),
                ("in-union", schema(&format!("{shared_grant} AND {not_in}")), true),
                ("all-union", schema(&format!("{shared_grant} AND {all}")), true),
                ("not-first", schema(&format!("NOT {BLOCKED} AND {shared_grant}")), true),
                ("unary-not", schema(&format!("{shared_grant} AND NOT ({BLOCKED})")), true),
                ("union-of-differences", schema(&format!(
                    "({OWNER} AND NOT {BLOCKED}) OR ({SHARED} AND NOT {BLOCKED})"
                )), true),
                ("restrictive-exists", format!(
                    "{} CREATE POLICY docs_blocks ON docs AS RESTRICTIVE FOR SELECT USING (NOT {BLOCKED});",
                    schema(&shared_grant)
                ), true),
                ("restrictive-in", format!(
                    "{} CREATE POLICY docs_blocks ON docs AS RESTRICTIVE FOR SELECT USING ({not_in});",
                    schema(&shared_grant)
                ), true),
            ];
            for (name, sql, shared) in variants {
                for from_rows in [false, true] {
                    let name = format!("{name}-rows-{from_rows}");
                    let mut case = case(&name, &sql, &[]);
                    case.loading_from_rows = from_rows;
                    let run = support::parity::run(&cluster, &case).await;
                    for (subject, object, visible) in [
                        ("alice", "docs:d1", true),
                        ("bob", "docs:d2", false),
                        ("carol", "docs:d1", false),
                        ("carol", "docs:d3", shared),
                    ] {
                        assert_postgres(&case, &run, subject, object, ActionStatement::Select, visible);
                    }
                    assert_agrees(&case, &run);
                }
            }
            let sql = schema(&format!("{shared_grant} AND NOT {BLOCKED}"));
            let changes = [
                ("unblocked", vec!["DELETE FROM blocks WHERE doc = 'd2' AND user_id = 'bob';"], "bob", "docs:d2", true),
                ("new-block", vec!["INSERT INTO blocks VALUES ('d3', 'carol');"], "carol", "docs:d3", false),
                ("moved-block", vec!["UPDATE blocks SET doc = 'd3' WHERE doc = 'd1';"], "carol", "docs:d1", true),
            ];
            for (name, seed, subject, object, visible) in changes {
                let case = case(name, &sql, &seed).loading_from_rows();
                let run = support::parity::run(&cluster, &case).await;
                assert_postgres(&case, &run, subject, object, ActionStatement::Select, visible);
                assert_agrees(&case, &run);
            }
            let mute_schema = "CREATE TABLE mutes(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
                         PRIMARY KEY(doc, user_id));";
            let muted = "EXISTS (SELECT 1 FROM mutes m WHERE m.doc = docs.id
                         AND m.user_id = current_setting('app.user_id', true))";
            let multiple = format!(
                "{TABLES} {mute_schema} CREATE POLICY docs_read ON docs FOR SELECT
                 USING (NOT {BLOCKED} AND ({shared_grant} AND NOT {muted}));"
            );
            let distinct_arms = format!(
                "{TABLES} {mute_schema} CREATE POLICY docs_read ON docs FOR SELECT USING ({OWNER} AND NOT {BLOCKED});
                 CREATE POLICY docs_share ON docs FOR SELECT USING ({SHARED} AND NOT {muted});"
            );
            for (name, sql, alice_visible, carol_visible) in [
                ("multiple-exclusions", multiple, false, false),
                ("independent-arms", distinct_arms, true, false),
            ] {
                let case = case(name, &sql, &[
                    "INSERT INTO blocks VALUES ('d3', 'alice');",
                    "INSERT INTO mutes VALUES ('d3', 'carol');",
                    "INSERT INTO shares VALUES ('d3', 'alice');",
                    "GRANT SELECT ON mutes TO alice, bob, carol;",
                ]).loading_from_rows();
                let run = support::parity::run(&cluster, &case).await;
                for (subject, visible) in [("alice", alice_visible), ("carol", carol_visible)] {
                    assert_postgres(&case, &run, subject, "docs:d3", ActionStatement::Select, visible);
                }
                assert_agrees(&case, &run);
            }
            let nullable = TABLES.replace(
                "user_id TEXT NOT NULL,\n                    PRIMARY KEY(doc, user_id));\nALTER",
                "user_id TEXT);\nALTER",
            );
            let sql = format!(
                "{nullable} CREATE POLICY docs_read ON docs FOR SELECT USING ({shared_grant} AND NOT {BLOCKED});"
            );
            let case = case("nullable-exists", &sql, &[
                "INSERT INTO blocks VALUES ('d3', NULL);",
            ]).loading_from_rows();
            let run = support::parity::run(&cluster, &case).await;
            assert_postgres(&case, &run, "alice", "docs:d3", ActionStatement::Select, true);
            assert_agrees(&case, &run);
            let filtered_tables = TABLES.replace(
                "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,",
                "CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT true,",
            );
            let sql = format!(
                "{filtered_tables} CREATE POLICY docs_read ON docs FOR SELECT USING (
                 {shared_grant} AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id
                 AND b.user_id = current_setting('app.user_id', true) AND b.active));"
            );
            let mut filtered_seed = vec![
                "INSERT INTO docs VALUES ('d1', 'alice'), ('d2', 'bob'), ('d3', 'alice');",
                "INSERT INTO shares VALUES ('d1', 'carol'), ('d2', 'carol'), ('d3', 'carol');",
                "INSERT INTO blocks(doc, user_id, active) VALUES ('d1', 'carol', true), ('d2', 'bob', false);",
            ];
            filtered_seed.push(SEED[3]);
            let filtered = ParityCase::reading(
                "static-block-filter",
                &sql,
                &filtered_seed,
                ["alice", "bob", "carol"].into_iter()
                    .map(|user| Principal::with_setting(user, user, "app.user_id", user))
                    .collect(),
            ).with_attributes(ATTRIBUTES).loading_from_rows();
            let run = support::parity::run(&cluster, &filtered).await;
            assert_postgres(&filtered, &run, "bob", "docs:d2", ActionStatement::Select, true);
            assert_postgres(&filtered, &run, "carol", "docs:d1", ActionStatement::Select, false);
            assert_agrees(&filtered, &run);
            let sql = format!(
                "{filtered_tables} CREATE POLICY docs_owner ON docs FOR SELECT USING (
                 {OWNER} AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id
                 AND b.user_id = current_setting('app.user_id', true) AND b.active));
                 CREATE POLICY docs_share ON docs FOR SELECT USING (
                 {SHARED} AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id
                 AND b.user_id = current_setting('app.user_id', true) AND NOT b.active));"
            );
            let independent = ParityCase::reading(
                "independent-block-filters",
                &sql,
                &filtered_seed,
                ["alice", "bob", "carol"].into_iter()
                    .map(|user| Principal::with_setting(user, user, "app.user_id", user))
                    .collect(),
            ).with_attributes(ATTRIBUTES).loading_from_rows();
            let run = support::parity::run(&cluster, &independent).await;
            assert_postgres(&independent, &run, "bob", "docs:d2", ActionStatement::Select, true);
            assert_postgres(&independent, &run, "carol", "docs:d1", ActionStatement::Select, true);
            assert_agrees(&independent, &run);
        })
        .await
        .expect("blocklist-spellings-1 must finish within 300 seconds");
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn clock_filtered_blocks_require_one_witnessing_row() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let sql = format!(
                "{TABLES}
                 CREATE TABLE timed_blocks(
                   id TEXT PRIMARY KEY, doc TEXT NOT NULL REFERENCES docs(id),
                   user_id TEXT NOT NULL, starts_at TIMESTAMPTZ NOT NULL,
                   expires_at TIMESTAMPTZ NOT NULL);
                 CREATE POLICY docs_read ON docs FOR SELECT USING (
                   ({OWNER} OR {SHARED}) AND NOT EXISTS (
                     SELECT 1 FROM timed_blocks b WHERE b.doc = docs.id
                     AND b.user_id = current_setting('app.user_id', true)
                     AND b.starts_at <= now() AND b.expires_at > now()));"
            );
            for from_rows in [false, true] {
                let mut case = case(&format!("clock-blocklist-{from_rows}"), &sql, &[
                    "INSERT INTO timed_blocks VALUES
                     ('expired', 'd1', 'carol', now() - interval '2 years', now() - interval '1 year'),
                     ('future', 'd1', 'carol', now() + interval '1 day', now() + interval '2 years'),
                     ('active', 'd2', 'bob', now() - interval '1 day', now() + interval '2 years');",
                    "GRANT SELECT ON timed_blocks TO alice, bob, carol;",
                ]).also_at(
                    "1 year",
                    "SELECT c.subject, 'docs:' || d.id AS object
                     FROM docs d CROSS JOIN (VALUES ('alice'), ('bob'), ('carol')) c(subject)
                     WHERE (d.owner = c.subject OR EXISTS (
                       SELECT 1 FROM shares s WHERE s.doc = d.id AND s.user_id = c.subject))
                     AND NOT EXISTS (
                       SELECT 1 FROM timed_blocks b WHERE b.doc = d.id AND b.user_id = c.subject
                       AND b.starts_at <= $1::timestamptz AND b.expires_at > $1::timestamptz)",
                );
                for principal in &mut case.principals {
                    principal.carries_request_time = true;
                }
                if from_rows {
                    case = case.loading_from_rows();
                }
                let run = support::parity::run(&cluster, &case).await;
                assert_postgres(&case, &run, "carol", "docs:d1", ActionStatement::Select, true);
                assert_postgres(&case, &run, "bob", "docs:d2", ActionStatement::Select, false);
                assert_agrees(&case, &run);
            }
        })
        .await
        .expect("clock-blocklist-1 must finish within 300 seconds");
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn restrictive_blocklists_respect_grants_and_role_scope() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let shared_grant = format!("({OWNER} OR {SHARED})");
            let sql = format!(
                "{} CREATE POLICY docs_blocks ON docs AS RESTRICTIVE FOR SELECT
                 TO targeted USING (NOT {BLOCKED});",
                schema(&shared_grant)
            );
            let mut scoped = case("role-scoped-blocklist", &sql, &["GRANT targeted TO bob;"])
                .after(&["CREATE ROLE targeted;"])
                .loading_from_rows();
            scoped.principals[1].pg_roles.push("targeted".to_string());
            let run = support::parity::run(&cluster, &scoped).await;
            for (subject, object, visible) in [
                ("alice", "docs:d1", true),
                ("bob", "docs:d2", false),
                ("carol", "docs:d1", true),
            ] {
                assert_postgres(&scoped, &run, subject, object, ActionStatement::Select, visible);
            }
            assert_agrees(&scoped, &run);
            let sql = format!(
                "{TABLES} CREATE POLICY docs_blocks ON docs AS RESTRICTIVE FOR SELECT USING (NOT {BLOCKED});"
            );
            let no_grant = case("blocklist-without-grant", &sql, &[]);
            let run = support::parity::run(&cluster, &no_grant).await;
            assert_postgres(&no_grant, &run, "alice", "docs:d1", ActionStatement::Select, false);
            assert_agrees(&no_grant, &run);
        })
        .await
        .expect("restrictive-blocklists-1 must finish within 300 seconds");
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn uuid_blocklists_preserve_casted_caller_identity() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let tables = TABLES.replace("TEXT", "UUID");
            let alice = "00000000-0000-0000-0000-000000000001";
            let bob = "00000000-0000-0000-0000-000000000002";
            let carol = "00000000-0000-0000-0000-000000000003";
            let d1 = "10000000-0000-0000-0000-000000000001";
            let d2 = "10000000-0000-0000-0000-000000000002";
            let caller = "current_setting('app.user_id', true)::uuid";
            let grant = format!("(owner = {caller} OR EXISTS (SELECT 1 FROM shares s
                                 WHERE s.doc = docs.id AND s.user_id = {caller}))");
            let exclusions = [
                format!("NOT EXISTS (SELECT 1 FROM blocks b WHERE b.doc = docs.id AND b.user_id = {caller})"),
                format!("{caller} NOT IN (SELECT b.user_id FROM blocks b WHERE b.doc = docs.id)"),
            ];
            for (index, exclusion) in exclusions.into_iter().enumerate() {
                let sql = format!("{tables} CREATE POLICY docs_read ON docs FOR SELECT USING ({grant} AND {exclusion});");
                let seed = [
                    format!("INSERT INTO docs VALUES ('{d1}', '{alice}'), ('{d2}', '{bob}');"),
                    format!("INSERT INTO shares VALUES ('{d1}', '{carol}'), ('{d2}', '{carol}');"),
                    format!("INSERT INTO blocks VALUES ('{d1}', '{carol}'), ('{d2}', '{bob}');"),
                    SEED[3].to_string(),
                ];
                let seed: Vec<&str> = seed.iter().map(String::as_str).collect();
                let case = ParityCase::reading(
                    &format!("uuid-blocklist-{index}"),
                    &sql,
                    &seed,
                    vec![
                        Principal::with_setting(alice, "alice", "app.user_id", alice),
                        Principal::with_setting(bob, "bob", "app.user_id", bob),
                        Principal::with_setting(carol, "carol", "app.user_id", carol),
                    ],
                ).with_attributes(UUID_ATTRIBUTES).loading_from_rows();
                let run = support::parity::run(&cluster, &case).await;
                for (subject, object, visible) in [
                    (alice, format!("docs:{d1}"), true),
                    (bob, format!("docs:{d2}"), false),
                    (carol, format!("docs:{d1}"), false),
                    (carol, format!("docs:{d2}"), true),
                ] {
                    assert_postgres(&case, &run, subject, &object, ActionStatement::Select, visible);
                }
                assert_agrees(&case, &run);
            }
        })
        .await
        .expect("uuid-blocklists-1 must finish within 300 seconds");
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn non_key_correlations_reach_the_named_blocked_object() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let sql = format!(
                "{TABLES} ALTER TABLE docs ADD COLUMN linked TEXT REFERENCES docs(id);
                 CREATE POLICY docs_read ON docs FOR SELECT USING (
                   ({OWNER} OR {SHARED}) AND NOT EXISTS (
                     SELECT 1 FROM blocks b WHERE b.doc = docs.linked
                     AND b.user_id = current_setting('app.user_id', true)));"
            );
            for from_rows in [false, true] {
                let mut case = case(
                    &format!("non-key-blocklist-{from_rows}"),
                    &sql,
                    &["UPDATE docs SET linked = CASE id
                       WHEN 'd1' THEN 'd2' WHEN 'd2' THEN 'd3' WHEN 'd3' THEN 'd1' END;"],
                );
                if from_rows {
                    case = case.loading_from_rows();
                }
                let run = support::parity::run(&cluster, &case).await;
                assert_postgres(&case, &run, "bob", "docs:d2", ActionStatement::Select, true);
                assert_postgres(
                    &case,
                    &run,
                    "carol",
                    "docs:d3",
                    ActionStatement::Select,
                    false,
                );
                assert_agrees(&case, &run);
            }
        })
        .await
        .expect("non-key-blocklist-1 must finish within 300 seconds");
    }
}
