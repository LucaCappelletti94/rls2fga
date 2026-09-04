use super::*;

use crate::generator::db_lookup::{TEAM_PRINCIPAL_TABLES, USER_PRINCIPAL_TABLES};
use crate::types::TypeName;
pub(super) struct RoleThresholdTables<'a> {
    pub(super) source: &'a TableId,
    pub(super) grant: &'a TableId,
    pub(super) team_membership: Option<&'a TableId>,
}

/// Populate `TupleSource` entries on `table_plan`, on the owner the ladder judges, and on
/// `all_types` for team membership. The renderer deduplicates via
/// [`TupleSource::dedup_key`], which is what collapses one owner's facts across every table
/// reading them.
pub(super) fn populate_role_threshold_sources<DB: DatabaseLike>(
    function_name: &str,
    tables: &RoleThresholdTables<'_>,
    db: &DB,
    registry: &FunctionRegistry,
    scope: &OwnerScope<'_>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) {
    let source_table = tables.source;
    let grant_table = tables.grant;
    let team_membership_table = tables.team_membership;
    let Some(FunctionSemantic::RoleThreshold {
        grant_table: _,
        grant_grantee_col,
        grant_resource_col,
        grant_role_col,
        team_membership,
        user_table,
        user_pk_col,
        team_table,
        team_pk_col,
        role_levels,
        ..
    }) = registry.get(function_name)
    else {
        return; // error already emitted in the pattern arm
    };

    let has_team = team_membership_table.is_some();

    let user_principal = resolve_principal_info(
        db,
        user_table.as_deref(),
        user_pk_col.as_ref(),
        USER_PRINCIPAL_TABLES,
    );
    let team_principal = if has_team {
        resolve_principal_info(
            db,
            team_table.as_deref(),
            team_pk_col.as_ref(),
            TEAM_PRINCIPAL_TABLES,
        )
    } else {
        None
    };

    // --- Owner identities ---
    // The function grants the top role when the caller *is* the owner, so that comparison
    // becomes a fact about the owner identity rather than one per row carrying it.
    let mut identities: Vec<TupleSource> = Vec::new();
    if let Some(upi) = user_principal.clone() {
        identities.push(TupleSource::OwnerIdentity {
            owner_type: scope.type_name.clone(),
            principal_table: upi.table,
            principal_identity_col: upi.identity_col,
            subject_type: table_plan.well_known.user.clone(),
            relation: owner_user_relation(),
        });
    } else {
        table_plan.add_source(TupleSource::Skipped {
            reason: SkippedTuples::NoUserPrincipalTable {
                table: source_table.clone(),
            },
        });
    }
    if has_team {
        if let Some(tpi) = team_principal.clone() {
            identities.push(TupleSource::OwnerIdentity {
                owner_type: scope.type_name.clone(),
                principal_table: tpi.table,
                principal_identity_col: tpi.identity_col,
                subject_type: table_plan.well_known.team.clone(),
                relation: owner_team_relation(),
            });
        } else {
            table_plan.add_source(TupleSource::Skipped {
                reason: SkippedTuples::NoTeamPrincipalTable {
                    table: source_table.clone(),
                },
            });
        }
    }

    // --- Team membership ---
    if let (Some(tm_table), Some(membership)) = (team_membership_table, team_membership.as_ref()) {
        let membership_source = TupleSource::TeamMembership {
            membership_table: tm_table.clone(),
            team_col: membership.team_col.clone(),
            user_col: membership.user_col.clone(),
        };
        table_plan.add_source(membership_source.clone());
        all_types
            .entry(table_plan.well_known.team.clone())
            .or_insert_with(|| {
                TypePlan::new_with_well_known(
                    table_plan.well_known.team.clone(),
                    &table_plan.well_known,
                )
            })
            .add_source(membership_source);
    }

    // --- The row's pointer at the owner it carries ---
    if bridge_is_buildable(
        table_plan,
        source_table,
        core::slice::from_ref(scope.column),
        scope.type_name,
        db,
    ) {
        table_plan.add_source(TupleSource::ParentBridge {
            table: source_table.clone(),
            fk_cols: vec![scope.column.clone()],
            parent_type: scope.type_name.clone(),
            relation: scope.pointer.clone(),
        });
    }

    // --- Explicit grants ---
    let sorted_roles = sorted_role_relation_names(role_levels);
    if sorted_roles.is_empty() {
        return;
    }

    // Deduplicate by integer level: two role names at the same level produce
    // duplicate WHEN arms in the generated CASE expression (second is unreachable).
    // Keep only the first occurrence of each level (sorted by (level, name)).
    let mut seen_levels = BTreeSet::new();
    let role_cases: Vec<(i32, RelationName, String)> = sorted_roles
        .iter()
        .filter(|role| seen_levels.insert(role.level))
        .map(|role| {
            (
                role.level,
                role.grant_relation(),
                role.original_name.clone(),
            )
        })
        .collect();

    let grants = TupleSource::ExplicitGrants {
        owner_type: scope.type_name.clone(),
        grant_table: grant_table.clone(),
        grant_role_col: grant_role_col.clone(),
        grant_grantee_col: grant_grantee_col.clone(),
        grant_resource_col: grant_resource_col.clone(),
        role_cases,
        user_principal,
        team_principal,
    };

    // Every fact the ladder reads belongs to the owner, so they hang on its plan and two
    // guarded tables reading one function write them once.
    if let Some(owner_plan) = all_types.get_mut(scope.type_name) {
        for identity in identities {
            owner_plan.add_source(identity);
        }
        owner_plan.add_source(grants);
    }
}
