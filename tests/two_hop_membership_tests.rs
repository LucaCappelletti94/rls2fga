extern crate alloc;

use alloc::collections::BTreeSet;

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{
    records_from_row, ConfidenceLevel, Record, RecordDerivation, TranslationNote,
};

mod support;

const SCHEMA: &str = "
CREATE TABLE principals (id TEXT PRIMARY KEY);
CREATE TABLE owners (id TEXT PRIMARY KEY);
CREATE TABLE ownables (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE memberships (
    owner_id TEXT NOT NULL REFERENCES owners(id),
    member_id TEXT NOT NULL REFERENCES principals(id),
    role TEXT NOT NULL,
    PRIMARY KEY (owner_id, member_id));
CREATE TABLE ownable_ancestors (
    ownable TEXT NOT NULL REFERENCES ownables(id),
    owner TEXT NOT NULL REFERENCES owners(id),
    PRIMARY KEY (ownable, owner));
CREATE TABLE orders (id TEXT PRIMARY KEY REFERENCES ownables(id), title TEXT);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
";

const CALLER: &str = "current_setting('app.user_id', true)";

fn nested(guard: &str) -> String {
    format!("EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner AND m.member_id = {CALLER}{guard}))")
}

fn joined(guard: &str) -> String {
    format!("EXISTS (SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner WHERE a.ownable = orders.id AND m.member_id = {CALLER}{guard})")
}

fn indirect_in(guard: &str) -> String {
    format!("orders.id IN (SELECT a.ownable FROM ownable_ancestors a WHERE a.owner IN (SELECT m.owner_id FROM memberships m WHERE m.member_id = {CALLER}{guard}))")
}

fn translate(policy: &str, extra: &str) -> Translation {
    let sql = format!(
        "{SCHEMA}{extra}\nCREATE POLICY orders_read ON orders FOR SELECT USING ({policy});"
    );
    let db = parse_schema(&sql).expect("the schema parses");
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::A)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .expect("translation plans")
}

fn row_records(translation: &Translation, table: &str, cells: &[(&str, &str)]) -> BTreeSet<Record> {
    let row = support::row(cells);
    translation
        .relations()
        .iter()
        .flat_map(|relation| &relation.shapes)
        .filter(|shape| matches!(&shape.derivation, RecordDerivation::FromRow { table: source, .. } if source.name() == table))
        .flat_map(|shape| records_from_row(shape, &row).expect("the row decides its records"))
        .collect()
}

#[test]
fn two_hop_spellings_have_independent_row_sources() {
    for policy in [
        nested(" AND m.role = 'read'"),
        joined(" AND m.role = 'read'"),
        indirect_in(" AND m.role = 'read'"),
    ] {
        let translation = translate(&policy, "");
        assert!(
            !translation
                .notes()
                .iter()
                .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
            "{:?}",
            translation.notes()
        );
        let closure = row_records(
            &translation,
            "ownable_ancestors",
            &[("ownable", "o1"), ("owner", "org1")],
        );
        assert_eq!(closure.len(), 1);
        let bridge = closure.first().unwrap();
        assert_eq!(bridge.object, "orders:o1");
        assert_eq!(bridge.subject, "owners:org1");
        let members = row_records(
            &translation,
            "memberships",
            &[
                ("owner_id", "org1"),
                ("member_id", "alice"),
                ("role", "read"),
            ],
        );
        assert_eq!(members.len(), 1);
        let member = members.first().unwrap();
        assert_eq!(member.object, "owners:org1");
        assert_eq!(member.subject, "user:alice");
        assert!(row_records(
            &translation,
            "memberships",
            &[
                ("owner_id", "org1"),
                ("member_id", "bob"),
                ("role", "write")
            ]
        )
        .is_empty());
        let dsl = translation
            .outputs()
            .expect("the translation has no gaps")
            .model();
        assert_eq!(
            support::footgun::relation_definition(&dsl, "orders", "can_select"),
            Some(format!("{} from {}", member.relation, bridge.relation))
        );
    }
}

#[test]
fn membership_without_a_role_guard_grants_every_listed_member() {
    let translation = translate(&nested(""), "");
    assert!(
        !translation
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
        "{:?}",
        translation.notes()
    );
    let records = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "write"),
        ],
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records.first().unwrap().subject, "user:alice");
}

#[test]
fn far_table_role_lists_emit_separate_member_relations() {
    let translation = translate(&nested(" AND m.role IN ('read', 'write', 'admin')"), "");
    assert!(
        !translation
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
        "{:?}",
        translation.notes()
    );
    let mut relations = BTreeSet::new();
    for role in ["read", "write", "admin"] {
        let records = row_records(
            &translation,
            "memberships",
            &[("owner_id", "org1"), ("member_id", "alice"), ("role", role)],
        );
        assert_eq!(records.len(), 1, "{role}");
        relations.insert(records.first().unwrap().relation.clone());
    }
    assert_eq!(relations.len(), 3);
    assert!(row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "other")
        ]
    )
    .is_empty());
    let model = translation
        .outputs()
        .expect("the translation has no gaps")
        .model();
    let select = support::footgun::relation_definition(&model, "orders", "can_select").unwrap();
    for relation in relations {
        assert!(select.contains(&format!("{relation} from ")), "{model}");
    }
}

#[test]
fn guarded_tables_are_disclosed_at_each_hop() {
    for table in ["ownable_ancestors", "memberships"] {
        let extra = format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; CREATE POLICY guarded ON {table} FOR SELECT USING (TRUE);");
        let translation = translate(&nested(" AND m.role = 'read'"), &extra);
        assert!(translation.notes().iter().any(|note| matches!(note, TranslationNote::MembershipTableGuarded { policy, join_table } if policy == "orders_read" && join_table.name() == table)), "{:?}", translation.notes());
    }
}

#[test]
fn separate_action_role_guards_do_not_share_member_relations() {
    let delete = format!(
        "CREATE POLICY orders_delete ON orders FOR DELETE USING ({});",
        joined(" AND m.role = 'write'")
    );
    let translation = translate(&nested(" AND m.role = 'read'"), &delete);
    assert!(
        !translation
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
        "{:?}",
        translation.notes()
    );
    let read = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "read"),
        ],
    );
    let write = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "write"),
        ],
    );
    assert_eq!(read.len(), 1);
    assert_eq!(write.len(), 1);
    assert_ne!(
        read.first().unwrap().relation,
        write.first().unwrap().relation
    );
    let model = translation
        .outputs()
        .expect("the translation has no gaps")
        .model();
    let select = support::footgun::relation_definition(&model, "orders", "can_select").unwrap();
    assert!(
        select.contains(read.first().unwrap().relation.as_str()),
        "{model}"
    );
    assert!(
        !select.contains(write.first().unwrap().relation.as_str()),
        "{model}"
    );
}

#[test]
fn incomplete_or_cross_table_correlations_remain_refused() {
    for policy in [
        format!("EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.owner = orders.id AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.ownable AND m.member_id = {CALLER}))"),
        format!("EXISTS (SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner WHERE a.ownable = orders.id AND m.member_id = {CALLER} AND m.role = orders.title)"),
        format!("EXISTS (SELECT 1 FROM ownable_ancestors a LEFT JOIN memberships m ON m.owner_id = a.owner WHERE a.ownable = orders.id AND m.member_id = {CALLER})"),
        format!("EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id AND EXISTS (SELECT 1 FROM memberships a WHERE a.owner_id = a.owner_id AND a.member_id = {CALLER}))"),
    ] {
        let translation = translate(&policy, "");
        assert!(translation.notes().iter().any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })), "{policy}");
    }
}

#[cfg(all(feature = "client", not(target_os = "windows")))]
#[tokio::test]
#[ignore = "requires Docker with PostgreSQL and OpenFGA"]
async fn two_hop_membership_postgres_openfga_parity() {
    use core::fmt::Write as _;
    use core::time::Duration;
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    tokio::time::timeout(Duration::from_secs(240), async {
        let cluster = Cluster::start().await;
        for (name, policy, from_rows, clock, witness) in [
            ("nested_read_sql", nested(" AND m.role = 'read'"), false, false, false),
            ("joined_role_list_rows", joined(" AND m.role IN ('read', 'write', 'admin')"), true, false, false),
            ("indirect_in_read_sql", indirect_in(" AND m.role = 'read'"), false, false, false),
            ("shared_clock_policies_sql", nested(" AND m.role = 'read' AND m.expires_at > now()"), false, true, false),
            ("witness_clock_policies_sql", nested(" AND m.role = 'read' AND m.expires_at > now()"), false, true, true),
            ("witness_clock_policies_rows", nested(" AND m.role = 'read' AND m.expires_at > now()"), true, true, true),
        ] {
            let mut base = SCHEMA.to_string();
            if clock {
                base = base.replace("role TEXT NOT NULL,", "expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '1 day'), role TEXT NOT NULL,");
            }
            if witness {
                base = base.replace("owner_id TEXT NOT NULL REFERENCES owners(id),", "id TEXT NOT NULL DEFAULT gen_random_uuid()::text, owner_id TEXT NOT NULL REFERENCES owners(id),")
                    .replace("PRIMARY KEY (owner_id, member_id)", "PRIMARY KEY (id)");
            }
            let mut schema = format!("{base} CREATE POLICY orders_read ON orders FOR SELECT USING ({policy});");
            if clock {
                write!(schema, "CREATE POLICY orders_delete ON orders FOR DELETE USING ({policy});").expect("write policy");
            }
            let case = ParityCase::reading(
                name,
                &schema,
                &[
                    "INSERT INTO principals VALUES ('alice'), ('bob'), ('carol'), ('dave'), ('outsider')",
                    "INSERT INTO owners VALUES ('org1'), ('org2'), ('team1')",
                    "INSERT INTO ownables VALUES ('o1', 'org1'), ('o2', 'org2'), ('o3', 'org1')",
                    "INSERT INTO orders VALUES ('o1', 'first'), ('o2', 'second'), ('o3', 'unlinked')",
                    "INSERT INTO ownable_ancestors VALUES ('o1', 'org1'), ('o1', 'team1'), ('o2', 'org2')",
                    "INSERT INTO memberships (owner_id, member_id, role) VALUES ('org1', 'alice', 'read'), ('org1', 'bob', 'write'), ('org2', 'carol', 'admin'), ('team1', 'dave', 'read')",
                    "CREATE ROLE app_reader LOGIN; GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader; GRANT DELETE ON orders TO app_reader",
                ],
                ["alice", "bob", "carol", "dave", "outsider"]
                    .into_iter()
                    .map(|subject| Principal::with_setting(subject, "app_reader", "app.user_id", subject).with_clock())
                    .collect(),
            )
            .with_attributes(r#"[{"key":"app.user_id","kind":"caller_id"}]"#);
            let case = if from_rows { case.loading_from_rows() } else { case };
            let run = support::parity::run(&cluster, &case).await;
            let role_list = name == "joined_role_list_rows";
            assert_postgres(&case, &run, "alice", "orders:o1", ActionStatement::Select, true);
            assert_postgres(&case, &run, "dave", "orders:o1", ActionStatement::Select, true);
            assert_postgres(&case, &run, "bob", "orders:o1", ActionStatement::Select, role_list);
            assert_postgres(&case, &run, "carol", "orders:o2", ActionStatement::Select, role_list);
            assert_postgres(&case, &run, "outsider", "orders:o1", ActionStatement::Select, false);
            assert_postgres(&case, &run, "alice", "orders:o3", ActionStatement::Select, false);
            if clock {
                assert_postgres(&case, &run, "alice", "orders:o1", ActionStatement::Delete, true);
                assert_postgres(&case, &run, "dave", "orders:o1", ActionStatement::Delete, true);
                assert_postgres(&case, &run, "bob", "orders:o1", ActionStatement::Delete, false);
                assert_postgres(&case, &run, "outsider", "orders:o1", ActionStatement::Delete, false);
            }
            assert_agrees(&case, &run);
            println!("{name} compared {} PostgreSQL/OpenFGA decisions", run.compared());
        }
    })
    .await
    .expect("two-hop parity completes within four minutes");
}

#[test]
fn both_hops_preserve_composite_key_order() {
    let sql = format!(
        "
CREATE TABLE owners (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
CREATE TABLE orders (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
CREATE TABLE ancestors (
    tenant TEXT, ownable TEXT, owner TEXT, PRIMARY KEY (tenant, ownable, owner),
    FOREIGN KEY (tenant, ownable) REFERENCES orders (tenant, id),
    FOREIGN KEY (tenant, owner) REFERENCES owners (tenant, id));
CREATE TABLE memberships (
    tenant TEXT, owner_id TEXT, member_id TEXT, role TEXT,
    PRIMARY KEY (tenant, owner_id, member_id),
    FOREIGN KEY (tenant, owner_id) REFERENCES owners (tenant, id));
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_read ON orders FOR SELECT USING (
    EXISTS (SELECT 1 FROM ancestors a
            WHERE a.ownable = orders.id AND a.tenant = orders.tenant
              AND EXISTS (SELECT 1 FROM memberships m
                          WHERE m.owner_id = a.owner AND m.tenant = a.tenant
                            AND m.member_id = {CALLER} AND m.role = 'read')));
"
    );
    let db = parse_schema(&sql).expect("the composite schema parses");
    let translation = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::A)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .expect("the composite schema plans");
    assert!(
        !translation
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
        "{:?}",
        translation.notes()
    );
    let closure = row_records(
        &translation,
        "ancestors",
        &[("tenant", "t1"), ("ownable", "o1"), ("owner", "org1")],
    );
    assert_eq!(closure.len(), 1);
    assert_eq!(closure.first().unwrap().object, "orders:t1|o1");
    assert_eq!(closure.first().unwrap().subject, "owners:t1|org1");
    let members = row_records(
        &translation,
        "memberships",
        &[
            ("tenant", "t1"),
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "read"),
        ],
    );
    assert_eq!(members.len(), 1);
    assert_eq!(members.first().unwrap().object, "owners:t1|org1");
    assert_eq!(members.first().unwrap().subject, "user:alice");
}

#[test]
fn different_membership_sources_do_not_share_an_unfiltered_relation() {
    let other = nested("").replace("memberships", "other_memberships");
    let extra = format!(
        "CREATE TABLE other_memberships (
        owner_id TEXT REFERENCES owners(id), member_id TEXT, role TEXT,
        PRIMARY KEY (owner_id, member_id));
        CREATE POLICY orders_delete ON orders FOR DELETE USING ({other});"
    );
    let translation = translate(&nested(""), &extra);
    let first = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "read"),
        ],
    );
    let other = row_records(
        &translation,
        "other_memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "bob"),
            ("role", "write"),
        ],
    );
    assert_eq!(first.len(), 1);
    assert_eq!(other.len(), 1);
    assert_ne!(
        first.first().unwrap().relation,
        other.first().unwrap().relation
    );
    let bridge = row_records(
        &translation,
        "ownable_ancestors",
        &[("ownable", "o1"), ("owner", "org1")],
    );
    let model = translation
        .outputs()
        .expect("both sources translate")
        .model();
    let select = support::footgun::relation_definition(&model, "orders", "can_select").unwrap();
    assert_eq!(
        select,
        format!(
            "{} from {}",
            first.first().unwrap().relation,
            bridge.first().unwrap().relation
        ),
    );
}

#[test]
fn different_closure_sources_do_not_share_a_tupleset() {
    let other = nested(" AND m.role = 'write'").replace("ownable_ancestors", "other_ancestors");
    let extra = format!(
        "CREATE TABLE other_ancestors (
        ownable TEXT REFERENCES ownables(id), owner TEXT REFERENCES owners(id),
        PRIMARY KEY (ownable, owner));
        CREATE POLICY orders_delete ON orders FOR DELETE USING ({other});"
    );
    let translation = translate(&nested(" AND m.role = 'read'"), &extra);
    let first = row_records(
        &translation,
        "ownable_ancestors",
        &[("ownable", "o1"), ("owner", "org1")],
    );
    let other = row_records(
        &translation,
        "other_ancestors",
        &[("ownable", "o1"), ("owner", "org2")],
    );
    assert_eq!(first.len(), 1);
    assert_eq!(other.len(), 1);
    assert_ne!(
        first.first().unwrap().relation,
        other.first().unwrap().relation
    );
    let members = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("role", "read"),
        ],
    );
    let model = translation
        .outputs()
        .expect("both closure sources translate")
        .model();
    let select = support::footgun::relation_definition(&model, "orders", "can_select").unwrap();
    assert_eq!(
        select,
        format!(
            "{} from {}",
            members.first().unwrap().relation,
            first.first().unwrap().relation
        ),
    );
}

#[test]
fn different_far_key_or_member_columns_do_not_pool_members() {
    for (original, replacement) in [
        ("m.owner_id", "m.other_owner"),
        ("m.member_id", "m.other_member"),
    ] {
        let read = nested(" AND m.role = 'read'");
        let other = read.replace(original, replacement);
        let schema = SCHEMA.replace(
            "role TEXT NOT NULL,",
            "other_owner TEXT REFERENCES owners(id), other_member TEXT REFERENCES principals(id), role TEXT NOT NULL,",
        );
        let sql = format!(
            "{schema} CREATE POLICY orders_read ON orders FOR SELECT USING ({read});
             CREATE POLICY orders_delete ON orders FOR DELETE USING ({other});"
        );
        let db = parse_schema(&sql).expect("the two-source schema parses");
        let translation = TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_session_attributes([SessionAttribute::setting(
                "app.user_id",
                SessionAttributeKind::CallerId,
            )])
            .build()
            .translate(&db)
            .expect("both source mappings translate");
        let records = row_records(
            &translation,
            "memberships",
            &[
                ("owner_id", "org1"),
                ("other_owner", "org2"),
                ("member_id", "alice"),
                ("other_member", "bob"),
                ("role", "read"),
            ],
        );
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .map(|record| &record.relation)
                .collect::<BTreeSet<_>>()
                .len(),
            2,
        );
        let read_member = records
            .iter()
            .find(|record| record.object == "owners:org1" && record.subject == "user:alice")
            .expect("the read membership keeps its key and member column");
        let bridge = row_records(
            &translation,
            "ownable_ancestors",
            &[("ownable", "o1"), ("owner", "org1")],
        );
        let model = translation
            .outputs()
            .expect("both sources have no gaps")
            .model();
        assert_eq!(
            support::footgun::relation_definition(&model, "orders", "can_select"),
            Some(format!(
                "{} from {}",
                read_member.relation,
                bridge.first().unwrap().relation
            )),
        );
    }
}

#[test]
fn shared_clock_guards_keep_each_policy_condition_on_its_own_tuple_source() {
    for witness in [false, true] {
        let policy = nested(" AND m.role = 'read' AND m.expires_at > now()");
        let mut schema = SCHEMA.replace(
            "role TEXT NOT NULL,",
            "expires_at TIMESTAMPTZ, role TEXT NOT NULL,",
        );
        if witness {
            schema = schema
                .replace(
                    "owner_id TEXT NOT NULL REFERENCES owners(id),",
                    "id TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES owners(id),",
                )
                .replace("PRIMARY KEY (owner_id, member_id)", "PRIMARY KEY (id)");
        }
        let sql = format!(
            "{schema} CREATE POLICY orders_read ON orders FOR SELECT USING ({policy});
             CREATE POLICY orders_delete ON orders FOR DELETE USING ({policy});"
        );
        let db = parse_schema(&sql).expect("the clock-guarded schema parses");
        let translation = TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_session_attributes([SessionAttribute::setting(
                "app.user_id",
                SessionAttributeKind::CallerId,
            )])
            .build()
            .translate(&db)
            .expect("both clock-guarded policies translate");
        let records = row_records(
            &translation,
            "memberships",
            &[
                ("id", "membership42"),
                ("owner_id", "org1"),
                ("member_id", "alice"),
                ("role", "read"),
                ("expires_at", "2100-01-01T00:00:00Z"),
            ],
        );
        let conditional = records.iter().filter(|record| record.context.is_some());
        assert_eq!(conditional.clone().count(), 2);
        assert_eq!(
            conditional
                .clone()
                .map(|record| &record.relation)
                .collect::<BTreeSet<_>>()
                .len(),
            2,
        );
        assert_eq!(
            conditional
                .clone()
                .map(|record| &record.context.as_ref().unwrap().condition)
                .collect::<BTreeSet<_>>()
                .len(),
            2,
        );
        let mut links = records.iter().filter(|record| record.context.is_none());
        let member_object = if witness {
            let link = links.next().expect("the owner links to one witness");
            assert_eq!(link.object, "owners:org1");
            link.subject.as_str()
        } else {
            "owners:org1"
        };
        assert!(links.next().is_none());
        for record in conditional {
            assert_eq!(record.object, member_object);
            assert_eq!(record.subject, "user:alice");
        }
        translation.outputs().expect("both policies have no gaps");
    }
}

#[test]
fn renamed_source_columns_remain_refused() {
    for policy in [
        nested(" AND m.role = 'read'").replace("a WHERE", "a(owner, ownable) WHERE"),
        nested(" AND m.role = 'read'").replace(
            "memberships m WHERE",
            "memberships m(owner_id, role, member_id) WHERE",
        ),
        joined(" AND m.role = 'read'").replace(
            "memberships m ON",
            "memberships m(owner_id, role, member_id) ON",
        ),
    ] {
        let translation = translate(&policy, "");
        assert!(
            translation
                .notes()
                .iter()
                .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })),
            "{policy}",
        );
    }
}

#[test]
fn quoted_far_role_lists_preserve_identifier_case() {
    let schema = SCHEMA.replace("role TEXT NOT NULL,", "\"Role\" TEXT NOT NULL,");
    let policy = joined(" AND m.\"Role\" IN ('read', 'write')");
    let sql = format!("{schema} CREATE POLICY orders_read ON orders FOR SELECT USING ({policy});");
    let db = parse_schema(&sql).expect("the quoted role schema parses");
    let translation = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .expect("the quoted role list translates");
    let read = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("Role", "read"),
        ],
    );
    let write = row_records(
        &translation,
        "memberships",
        &[
            ("owner_id", "org1"),
            ("member_id", "alice"),
            ("Role", "write"),
        ],
    );
    assert_eq!(read.len(), 1);
    assert_eq!(write.len(), 1);
    assert_ne!(
        read.first().unwrap().relation,
        write.first().unwrap().relation
    );
    translation
        .outputs()
        .expect("the quoted role list has no gaps");
}
