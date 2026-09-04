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
/// 7. The guarded table is not spelled as a well-known type. The translation refuses that
///    outright with `ReservedTypeName` rather than renaming anything, so it belongs outside
///    the class, and `a_table_named_as_a_reserved_type_is_refused` pins the refusal.
/// 6. The deployment declares what the request value means. `current_setting('k')` is a
///    session key like any other, and only the deployment knows that this one carries the
///    caller's identity rather than a tenant or a flag, so an undeclared key is outside
///    the class by construction rather than by omission.
pub(crate) const PRECONDITIONS: usize = 7;

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
    fn keys(self, length: KeyLength) -> Vec<String> {
        let short = match self {
            Self::Text => vec!["'plain'", "'pipe|key'", "'tilde~key'", "'both|and~key'"],
            Self::Integer => vec!["1", "2", "3", "4"],
            Self::Uuid => vec![
                "'00000000-0000-0000-0000-00000000000a'::uuid",
                "'00000000-0000-0000-0000-00000000000b'::uuid",
                "'00000000-0000-0000-0000-00000000000c'::uuid",
                "'00000000-0000-0000-0000-00000000000d'::uuid",
            ],
        };
        if length == KeyLength::Short || self != Self::Text {
            // Only a text key can be made long. A number and a UUID have the length their
            // type gives them, so those cases repeat the short keys deliberately rather
            // than pretending the axis reaches them.
            return short.into_iter().map(ToString::to_string).collect();
        }
        // Long enough to exercise the encoder and the name budget, short enough that every
        // row still has a name: the cap counts the type name and the separator too.
        (0..4)
            .map(|at| format!("'{}{at}'", "l".repeat(200)))
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
}

/// Every case the grammar admits, one per point of its axes.
///
/// Deliberately an enumeration rather than a sampler: the axes are small enough to cover
/// whole, and a failure names a point rather than a seed.
pub(crate) fn every_case() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    // Key type against accessor spelling against nullability, whole.
    for key in KeyType::ALL {
        for accessor in Accessor::ALL {
            for nullable in [false, true] {
                cases.push(case(
                    key,
                    accessor,
                    nullable,
                    TableName::Plain,
                    KeyLength::Short,
                ));
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
        ));
    }
    cases
}

fn case(
    key: KeyType,
    accessor: Accessor,
    nullable: bool,
    name: TableName,
    length: KeyLength,
) -> ExactCase {
    let null = if nullable { "" } else { " NOT NULL" };
    let tables = name.tables();
    let mut schema = String::new();
    for table in &tables {
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

    // The values a row can carry: the caller's own, another, the empty string, and NULL
    // where the column admits it. NULL and the empty string are where an equality stops
    // behaving like one, so they are the boundaries worth seeding.
    let mut values = vec!["'alice'", "'someone_else'", "''"];
    if nullable {
        values.push("NULL");
    }
    let keys = key.keys(length);
    assert!(
        values.len() <= keys.len(),
        "one key per row, or the seed collides on the primary key"
    );
    let mut rows = String::new();
    for (at, value) in values.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(rows, "{joiner}({}, {value})", keys[at]);
    }
    // The second table carries the same keys with the values rotated, so one type standing
    // for both tables would hand a caller the other table's row under a name it owns.
    let mut mirrored = String::new();
    for (at, value) in values.iter().rev().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(mirrored, "{joiner}({}, {value})", keys[at]);
    }
    let mut seed = String::new();
    let mut grants = String::new();
    for (at, table) in tables.iter().enumerate() {
        let values = if at == 0 { &rows } else { &mirrored };
        let _ = write!(seed, "INSERT INTO {table} (id, who) VALUES {values}; ");
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(grants, "{joiner}{table}");
    }

    ExactCase {
        name: format!(
            "exact-{}-{}-{}-{}-{}",
            key.label(),
            accessor.label(),
            if nullable { "nullable" } else { "not-null" },
            name.label(),
            length.label()
        ),
        schema,
        seed: [
            seed,
            format!(
                "CREATE ROLE alice LOGIN; CREATE ROLE mallory LOGIN; CREATE ROLE silent LOGIN;
                 GRANT SELECT ON {grants} TO alice, mallory, silent"
            ),
        ],
        accessor,
    }
}
