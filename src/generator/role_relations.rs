use std::collections::{BTreeSet, HashMap};

use crate::parser::names::{canonical_fga_type_name, stable_hex_suffix};

/// Normalized relation naming metadata for a role level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoleRelationName {
    pub(crate) original_name: String,
    pub(crate) level: i32,
    pub(crate) token: String,
}

impl RoleRelationName {
    pub(crate) fn grant_relation(&self) -> String {
        format!("grant_{}", self.token)
    }

    pub(crate) fn role_relation(&self) -> String {
        format!("role_{}", self.token)
    }
}

/// Build role relation names sorted by `(level, name)` and disambiguated for collisions.
pub(crate) fn sorted_role_relation_names(
    role_levels: &HashMap<String, i32>,
) -> Vec<RoleRelationName> {
    let mut pairs: Vec<(String, i32)> = role_levels
        .iter()
        .map(|(name, level)| (name.clone(), *level))
        .collect();
    pairs.sort_by(|(a_name, a_level), (b_name, b_level)| {
        a_level.cmp(b_level).then_with(|| a_name.cmp(b_name))
    });

    let mut base_counts: HashMap<String, usize> = HashMap::new();
    for (name, _) in &pairs {
        let base = canonical_fga_type_name(name);
        *base_counts.entry(base).or_insert(0) += 1;
    }

    let mut used_tokens = BTreeSet::new();
    let mut out = Vec::with_capacity(pairs.len());

    for (name, level) in pairs {
        let base = canonical_fga_type_name(&name);
        let mut token = if base_counts.get(&base).copied().unwrap_or(0) > 1 {
            format!("{base}_{}", stable_hex_suffix(&name))
        } else {
            base
        };

        if used_tokens.contains(&token) {
            let mut idx = 2usize;
            while used_tokens.contains(&format!("{token}_{idx}")) {
                idx += 1;
            }
            token = format!("{token}_{idx}");
        }

        used_tokens.insert(token.clone());
        out.push(RoleRelationName {
            original_name: name,
            level,
            token,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_role_relation_names_canonicalizes_and_disambiguates_tokens() {
        let role_levels = HashMap::from([
            ("read-write".to_string(), 1),
            ("read write".to_string(), 2),
            ("Team Admin".to_string(), 3),
        ]);

        let roles = sorted_role_relation_names(&role_levels);
        let tokens: Vec<String> = roles.iter().map(|role| role.token.clone()).collect();

        assert!(
            tokens.iter().all(|token| {
                token
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
            }),
            "tokens should contain only OpenFGA-safe characters: {tokens:?}"
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.starts_with("read_write"))
                .count(),
            2,
            "colliding canonical names should be disambiguated with stable suffixes"
        );
        assert_eq!(
            tokens.iter().collect::<BTreeSet<_>>().len(),
            tokens.len(),
            "disambiguated tokens should remain unique"
        );
    }
}
