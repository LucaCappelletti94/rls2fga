//! The class of inputs the translation has to answer exactly, and cases drawn from it.
//!
//! The grammar is written from `PostgreSQL`'s own rules rather than from the recognizers. A
//! shape belongs to the class because the database decides each row from that row's values
//! and the request, so one tuple per row can carry the whole answer. Reading the class off
//! the classifier instead would make the oracle agree with the code under test by
//! construction, which is the thing this exists to avoid.
//!
//! Membership is the grammar's decision alone. A case the grammar admits has to agree with
//! `PostgreSQL` outright, and a translation reporting that it diverges on one of them is
//! reporting a defect in itself.

use core::fmt::Write as _;

use rls2fga::types::identity::MAX_OBJECT_NAME_CHARS;

/// Preconditions every admitted case satisfies, each a rule of the database.
///
/// 1. One permissive `SELECT` policy and no restrictive one, so no clause is composed with
///    another and no barrier can remove a grant.
/// 2. The clause is an equality between one column of the guarded row and one scalar the
///    request supplies, so the row's own values settle the answer.
/// 3. The key is a single column of a type an object name can carry.
/// 4. Row-level security is on and the reader does not own the table, since an owner is
///    exempt from every policy unless the table forces it.
/// 5. Nothing the clause reads is another table, so no second table's policies apply.
/// 8. Where the answer comes from a membership row, that membership table carries no row
///    security of its own. `PostgreSQL` shows every caller the same membership rows then,
///    which is what makes a tuple loaded as the owner true for everyone. A guarded
///    membership table is outside the class, and the translation says so.
/// 7. The guarded table is not spelled as a well-known type. The translation refuses that
///    outright with `ReservedTypeName` rather than renaming anything, so it belongs outside
///    the class, and `a_table_named_as_a_reserved_type_is_refused` pins the refusal.
/// 6. The deployment declares what the request value means. `current_setting('k')` is a
///    session key like any other, and only the deployment knows that this one carries the
///    caller's identity rather than a tenant or a flag, so an undeclared key is outside
///    the class by construction rather than by omission.
pub(crate) const PRECONDITIONS: usize = 8;

/// The request-scoped values every admitted case declares, satisfying precondition 6.
pub(crate) const DECLARED_KEY: &str = r#"[{ "key": "app.who", "kind": "caller_id" }]"#;

/// The type a key column carries, which decides how an object name is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
    /// Keys that can carry the identity encoder's own separator and escape marker.
    Text,
    Integer,
    Uuid,
}

impl KeyType {
    /// Every key type in the grammar.
    pub(crate) const ALL: [Self; 3] = [Self::Text, Self::Integer, Self::Uuid];

    fn column(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Integer => "INT",
            Self::Uuid => "UUID",
        }
    }

    /// Key values worth seeding, as SQL literals.
    ///
    /// The text keys carry `|` and `~`, which the identity encoder gives meaning to, so a
    /// case in this class also exercises the escaping.
    fn keys(self, length: KeyLength, base_type: &str, disambiguated: bool) -> Vec<String> {
        // One more key than a case has values, so the membership shape always leaves a
        // guarded row no membership row mentions.
        let short = match self {
            Self::Text => vec![
                "'plain'",
                "'pipe|key'",
                "'tilde~key'",
                "'both|and~key'",
                "'unnamed'",
            ],
            Self::Integer => vec!["1", "2", "3", "4", "5"],
            Self::Uuid => vec![
                "'00000000-0000-0000-0000-00000000000a'::uuid",
                "'00000000-0000-0000-0000-00000000000b'::uuid",
                "'00000000-0000-0000-0000-00000000000c'::uuid",
                "'00000000-0000-0000-0000-00000000000d'::uuid",
                "'00000000-0000-0000-0000-00000000000e'::uuid",
            ],
        };
        if length == KeyLength::Short || self != Self::Text {
            // Only a text key can be made long. A number and a UUID have the length their
            // type gives them, so those cases repeat the short keys deliberately rather
            // than pretending the axis reaches them.
            return short.into_iter().map(ToString::to_string).collect();
        }
        // At the boundary, not near it: one more character and the row has no name.
        let width = length.characters(base_type, disambiguated);
        (0..5)
            .map(|at| format!("'{}{at}'", "l".repeat(width - 1)))
            .collect()
    }

    fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "int",
            Self::Uuid => "uuid",
        }
    }
}

/// How the policy reads the value the request supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accessor {
    /// `current_setting('k')`, which raises where the caller set nothing.
    BareSetting,
    /// `current_setting('k', true)`, which yields NULL instead of raising.
    MissingOkSetting,
    /// A declared function around the bare form, so it raises as well.
    DeclaredFunction,
}

impl Accessor {
    /// Every accessor spelling in the grammar.
    pub(crate) const ALL: [Self; 3] = [
        Self::BareSetting,
        Self::MissingOkSetting,
        Self::DeclaredFunction,
    ];

    fn expression(self) -> &'static str {
        match self {
            Self::BareSetting => "current_setting('app.who')",
            Self::MissingOkSetting => "current_setting('app.who', true)",
            Self::DeclaredFunction => "auth_who()",
        }
    }

    /// Whether a caller that set nothing makes the read raise.
    ///
    /// `PostgreSQL`'s rule, not the translation's: `current_setting` without `missing_ok`
    /// raises `42704`, and wrapping it in a function does not change that.
    pub(crate) fn raises_when_unset(self) -> bool {
        matches!(self, Self::BareSetting | Self::DeclaredFunction)
    }

    fn declaration(self) -> &'static str {
        match self {
            Self::DeclaredFunction => {
                "CREATE FUNCTION auth_who() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.who'')';
"
            }
            Self::BareSetting | Self::MissingOkSetting => "",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::BareSetting => "bare",
            Self::MissingOkSetting => "missing-ok",
            Self::DeclaredFunction => "declared",
        }
    }
}

/// How far the guarded rows sit below the table that carries the policies.
///
/// `PostgreSQL` applies the policies of the table a read names, so a read through the root
/// is filtered while a read naming a partition is filtered by nothing. The model answers
/// for the row, which is the read through the root, and the partitions are declared as
/// tables the case does not read directly. Depth is an axis because a boundary tested at
/// one level is not tested: walking one ancestor and walking to the top are the same thing
/// there, which is how the subpartition disclosure was missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Depth {
    /// The guarded table holds its own rows.
    One,
    /// One partition below the root.
    Two,
    /// A partition of a partition.
    Three,
}

impl Depth {
    pub(crate) const ALL: [Self; 3] = [Self::One, Self::Two, Self::Three];

    /// The partitions a case declares, root first, each a child of the one before.
    fn partitions(self) -> &'static [&'static str] {
        match self {
            Self::One => &[],
            Self::Two => &["guarded_eu"],
            Self::Three => &["guarded_eu", "guarded_eu_gold"],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::One => "depth-one",
            Self::Two => "depth-two",
            Self::Three => "depth-three",
        }
    }
}

/// Where the answer comes from.
///
/// Either the guarded row settles it alone, or one row of a membership table does. Both are
/// decided by a single row plus the request, which is what puts them in the class, and the
/// join is where most of the review's findings lived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A column of the guarded row against the request.
    SelfIdentity,
    /// A membership row naming the guarded row and the caller.
    MembershipJoin,
}

impl Shape {
    pub(crate) const ALL: [Self; 2] = [Self::SelfIdentity, Self::MembershipJoin];

    fn label(self) -> &'static str {
        match self {
            Self::SelfIdentity => "self",
            Self::MembershipJoin => "membership",
        }
    }
}

/// Whether a second table folds to the same type name as the guarded one.
///
/// `PostgreSQL` tells `"guarded"` and `"Guarded"` apart, and a type name folds case, so two
/// distinct tables arrive at one type and the translation has to keep them apart. Findings
/// 1 and 2 were both name collisions, which is why the grammar admits this rather than
/// avoiding it. A table named as a well-known type is a different matter: the translation
/// refuses that outright, so precondition 7 keeps it outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableName {
    /// One table, its own name.
    Plain,
    /// A second table whose name folds to the first's.
    FoldedCollision,
}

impl TableName {
    pub(crate) const ALL: [Self; 2] = [Self::Plain, Self::FoldedCollision];

    /// The names a case declares, guarded alike. The second folds onto the first.
    fn tables(self) -> Vec<&'static str> {
        match self {
            Self::Plain => vec!["\"guarded\""],
            Self::FoldedCollision => vec!["\"guarded\"", "\"Guarded\""],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Plain => "one-table",
            Self::FoldedCollision => "folded-collision",
        }
    }
}

/// How long the key is, in characters before encoding.
///
/// An object name is capped, and the report already says a row past the cap is left out
/// while the database grants it. A key that fits is inside the class; the cap itself is a
/// boundary the runner cannot compare at all, since naming such a row raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLength {
    Short,
    /// Long, and still inside the cap once the type name and separator are counted.
    NearTheCap,
}

impl KeyLength {
    pub(crate) const ALL: [Self; 2] = [Self::Short, Self::NearTheCap];

    /// The longest key that still leaves every row a name.
    ///
    /// An object name is the type, a separator and the encoded key, capped whole. Derived
    /// from the cap rather than picked: a key comfortably inside it would let a budget
    /// regression reject the last thirty characters and still pass every case. One more
    /// character than this and naming the row raises, which the runner now refuses.
    ///
    /// `disambiguated` allows for the suffix a colliding type name carries, since the case
    /// cannot know the hash the translator will choose.
    fn characters(self, base_type: &str, disambiguated: bool) -> usize {
        match self {
            Self::Short => 8,
            Self::NearTheCap => {
                // `_` and eight hex digits, the shape `stable_hex_suffix` renders.
                let suffix = usize::from(disambiguated) * 9;
                MAX_OBJECT_NAME_CHARS - (base_type.chars().count() + suffix + 1)
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Short => "short-key",
            Self::NearTheCap => "long-key",
        }
    }
}

/// One caller state the generated case compares.
pub(crate) struct Caller {
    /// Subject key, and the login role's name.
    pub(crate) subject: &'static str,
    /// What it sets, absent where it sets nothing at all.
    pub(crate) value: Option<&'static str>,
}

/// The caller states every generated case compares.
///
/// One holding the value a row carries, one holding another, and one holding none, which is
/// the state the accessor's own spelling decides the meaning of.
pub(crate) const CALLERS: [Caller; 3] = [
    Caller {
        subject: "alice",
        value: Some("alice"),
    },
    Caller {
        subject: "mallory",
        value: Some("nobody"),
    },
    Caller {
        subject: "silent",
        value: None,
    },
];

/// One case the grammar admits, as the SQL a runner needs.
pub(crate) struct ExactCase {
    /// Names the axes it came from, so a failure says which point of the grammar broke.
    pub(crate) name: String,
    pub(crate) schema: String,
    /// Rows, and the grant the reading role needs.
    pub(crate) seed: [String; 2],
    pub(crate) accessor: Accessor,
    /// Tables whose rows are reached through their root rather than by name.
    pub(crate) not_read_directly: Vec<String>,
}

/// Every case the grammar admits, one per point of its axes.
///
/// Deliberately an enumeration rather than a sampler: the axes are small enough to cover
/// whole, and a failure names a point rather than a seed.
pub(crate) fn every_case() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    // Key type against accessor spelling against nullability against shape, whole. The
    // shape decides which row settles the answer, and every spelling has to reach both.
    for shape in Shape::ALL {
        for key in KeyType::ALL {
            for accessor in Accessor::ALL {
                for nullable in [false, true] {
                    cases.push(case(
                        key,
                        accessor,
                        nullable,
                        TableName::Plain,
                        KeyLength::Short,
                        shape,
                        Depth::One,
                    ));
                }
            }
        }
    }
    // The two axes that only interact with naming, against the spellings and key types that
    // reach it. Crossing all five whole would be 108 cases against two containers for no
    // more coverage than this: a name collision is decided by the table's name and its key
    // type, and neither knows how the caller was spelled.
    for key in KeyType::ALL {
        for length in KeyLength::ALL {
            cases.push(case(
                key,
                Accessor::MissingOkSetting,
                false,
                TableName::FoldedCollision,
                length,
                Shape::SelfIdentity,
                Depth::One,
            ));
        }
    }
    for key in KeyType::ALL {
        cases.push(case(
            key,
            Accessor::BareSetting,
            true,
            TableName::Plain,
            KeyLength::NearTheCap,
            Shape::SelfIdentity,
            Depth::One,
        ));
    }
    // Depth, against every key type, since a composite key is how a partitioned table
    // names its rows and the encoder joins the parts.
    for depth in [Depth::Two, Depth::Three] {
        for key in KeyType::ALL {
            cases.push(case(
                key,
                Accessor::MissingOkSetting,
                false,
                TableName::Plain,
                KeyLength::Short,
                Shape::SelfIdentity,
                depth,
            ));
        }
    }
    cases
}

fn case(
    key: KeyType,
    accessor: Accessor,
    nullable: bool,
    name: TableName,
    length: KeyLength,
    shape: Shape,
    depth: Depth,
) -> ExactCase {
    let tables = name.tables();
    let keys = key.keys(length, "guarded", name == TableName::FoldedCollision);
    // The values a row can carry: the caller's own, another, the empty string, and NULL
    // where the column admits it. NULL and the empty string are where an equality stops
    // behaving like one, so they are the boundaries worth seeding.
    let mut values = vec!["'alice'", "'someone_else'", "''"];
    if nullable {
        values.push("NULL");
    }
    assert!(
        values.len() <= keys.len(),
        "one key per row, or the seed collides on the primary key"
    );

    ExactCase {
        name: format!(
            "exact-{}-{}-{}-{}-{}-{}-{}",
            shape.label(),
            key.label(),
            accessor.label(),
            if nullable { "nullable" } else { "not-null" },
            name.label(),
            length.label(),
            depth.label()
        ),
        schema: match (shape, depth) {
            (Shape::SelfIdentity, Depth::One) => schema_of(&tables, key, accessor, nullable),
            (Shape::SelfIdentity, _) => partitioned_schema_of(key, accessor, nullable, depth),
            (Shape::MembershipJoin, _) => membership_schema_of(&tables, key, accessor, nullable),
        },
        seed: match (shape, depth) {
            (Shape::SelfIdentity, Depth::One) => seed_of(&tables, &keys, &values),
            (Shape::SelfIdentity, _) => partitioned_seed_of(&keys, &values),
            (Shape::MembershipJoin, _) => membership_seed_of(&tables, &keys, &values),
        },
        accessor,
        not_read_directly: depth
            .partitions()
            .iter()
            .map(|partition| (*partition).to_string())
            .collect(),
    }
}

/// The guarded table partitioned, with the policy on the root alone.
///
/// A partitioned table's key has to contain its partition key, so the rows are named by two
/// columns here, which the object encoder joins. Only the root carries a policy, since that
/// is the layout the model answers for: the partitions hold the rows and filter nothing.
fn partitioned_schema_of(key: KeyType, accessor: Accessor, nullable: bool, depth: Depth) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = format!(
        "CREATE TABLE \"guarded\" (id {} NOT NULL, region TEXT NOT NULL, who TEXT{null},\n\
        \x20   PRIMARY KEY (id, region)) PARTITION BY LIST (region);\n",
        key.column()
    );
    for (at, partition) in depth.partitions().iter().enumerate() {
        let parent = if at == 0 {
            "\"guarded\""
        } else {
            depth.partitions()[at - 1]
        };
        // The last one holds the rows; the ones above it partition further.
        let further = if at + 1 == depth.partitions().len() {
            String::new()
        } else {
            " PARTITION BY LIST (region)".to_string()
        };
        let _ = writeln!(
            schema,
            "CREATE TABLE {partition} PARTITION OF {parent} FOR VALUES IN ('eu'){further};"
        );
    }
    schema.push_str(accessor.declaration());
    let _ = write!(
        schema,
        "ALTER TABLE \"guarded\" ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_0 ON \"guarded\" FOR SELECT USING (who = {});\n",
        accessor.expression()
    );
    schema
}

/// Rows inserted through the root, which routes them to the partition that holds them.
fn partitioned_seed_of(keys: &[String], values: &[&str]) -> [String; 2] {
    let mut rows = String::new();
    for (at, value) in values.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(rows, "{joiner}({}, 'eu', {value})", keys[at]);
    }
    [
        format!("INSERT INTO \"guarded\" (id, region, who) VALUES {rows}"),
        "CREATE ROLE alice LOGIN; CREATE ROLE mallory LOGIN; CREATE ROLE silent LOGIN;
         GRANT SELECT ON \"guarded\" TO alice, mallory, silent"
            .to_string(),
    ]
}

/// The guarded table, a membership table with no security of its own, and the join.
///
/// Precondition 8 is the `ALTER TABLE` that is absent: with row security off, every caller
/// sees the same membership rows, which is what makes a tuple loaded as the owner true for
/// everyone. Turning it on puts the case outside the class, and the translation says so.
fn membership_schema_of(
    tables: &[&str],
    key: KeyType,
    accessor: Accessor,
    nullable: bool,
) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = String::new();
    for table in tables {
        let _ = writeln!(
            schema,
            "CREATE TABLE {table} (id {} PRIMARY KEY);",
            key.column()
        );
    }
    for (at, table) in tables.iter().enumerate() {
        let _ = writeln!(
            schema,
            "CREATE TABLE members_{at} (doc_id {} REFERENCES {table}(id), who TEXT{null});",
            key.column()
        );
    }
    schema.push_str(accessor.declaration());
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            schema,
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY own_{at} ON {table} FOR SELECT USING (EXISTS (\n\
             \x20   SELECT 1 FROM members_{at} m\n\
             \x20   WHERE m.doc_id = {table}.id AND m.who = {}));\n",
            accessor.expression()
        );
    }
    schema
}

/// Guarded rows, and one membership row for all but the last of them.
///
/// The unnamed row is the boundary that matters most here: a guarded row no membership row
/// mentions is denied to everybody, and a model keyed on the table rather than the row
/// would grant it.
fn membership_seed_of(tables: &[&str], keys: &[String], values: &[&str]) -> [String; 2] {
    let mut seed = String::new();
    let mut grants = String::new();
    for (at, table) in tables.iter().enumerate() {
        let rows: Vec<String> = keys.iter().map(|key| format!("({key})")).collect();
        let _ = write!(
            seed,
            "INSERT INTO {table} (id) VALUES {}; ",
            rows.join(", ")
        );
        // One membership row per value, and the final key left unmentioned.
        let members: Vec<String> = values
            .iter()
            .enumerate()
            .map(|(row, value)| {
                let value = if at == 0 {
                    value
                } else {
                    &values[values.len() - 1 - row]
                };
                format!("({}, {value})", keys[row])
            })
            .collect();
        let _ = write!(
            seed,
            "INSERT INTO members_{at} (doc_id, who) VALUES {}; ",
            members.join(", ")
        );
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(grants, "{joiner}{table}, members_{at}");
    }
    [
        seed,
        format!(
            "CREATE ROLE alice LOGIN; CREATE ROLE mallory LOGIN; CREATE ROLE silent LOGIN;
             GRANT SELECT ON {grants} TO alice, mallory, silent"
        ),
    ]
}

/// The tables, the accessor they read and the policy each carries.
fn schema_of(tables: &[&str], key: KeyType, accessor: Accessor, nullable: bool) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = String::new();
    for table in tables {
        let _ = writeln!(
            schema,
            "CREATE TABLE {table} (id {} PRIMARY KEY, who TEXT{null});",
            key.column()
        );
    }
    schema.push_str(accessor.declaration());
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            schema,
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY own_{at} ON {table} FOR SELECT USING (who = {});\n",
            accessor.expression()
        );
    }
    schema
}

/// The rows, and the grant the reading roles need.
///
/// A second table carries the same keys with its values rotated, so one type standing for
/// both tables would hand a caller the other table's row under a name it owns.
fn seed_of(tables: &[&str], keys: &[String], values: &[&str]) -> [String; 2] {
    let row_list = |rotated: bool| {
        let mut rows = String::new();
        for (at, value) in values.iter().enumerate() {
            let joiner = if at == 0 { "" } else { ", " };
            let value = if rotated {
                values[values.len() - 1 - at]
            } else {
                value
            };
            let _ = write!(rows, "{joiner}({}, {value})", keys[at]);
        }
        rows
    };
    let mut seed = String::new();
    let mut grants = String::new();
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            seed,
            "INSERT INTO {table} (id, who) VALUES {}; ",
            row_list(at > 0)
        );
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(grants, "{joiner}{table}");
    }
    [
        seed,
        format!(
            "CREATE ROLE alice LOGIN; CREATE ROLE mallory LOGIN; CREATE ROLE silent LOGIN;
             GRANT SELECT ON {grants} TO alice, mallory, silent"
        ),
    ]
}
