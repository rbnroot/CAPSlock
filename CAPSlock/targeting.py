from __future__ import annotations
from typing import Any, Dict, List, Optional, Set
from CAPSlock.models import UserContext, WorkloadContext, TargetingResult, NameResolver
from CAPSlock.resolvers import friendly_ids


def evaluate_user_targeting(detail: Dict[str, Any], user_ctx: UserContext, resolver: Optional[NameResolver] = None) -> TargetingResult:
    cond_users = (detail.get("Conditions", {}) or {}).get("Users", {}) or {}
    include_blocks = cond_users.get("Include") or []
    exclude_blocks = cond_users.get("Exclude") or []

    inc_users: Set[str] = set()
    inc_groups: Set[str] = set()
    inc_roles: Set[str] = set()

    exc_users: Set[str] = set()
    exc_groups: Set[str] = set()
    exc_roles: Set[str] = set()

    include_all_users = False

    for blk in include_blocks:
        users = blk.get("Users") or []
        groups = blk.get("Groups") or []
        roles = (
            blk.get("DirectoryRoles")
            or blk.get("Roles")
            or blk.get("RoleTemplateIds")
            or []
        )

        if "All" in users or "All" in groups or "All" in roles:
            include_all_users = True

        inc_users.update(u for u in users if u != "All")
        inc_groups.update(g for g in groups if g != "All")
        inc_roles.update(r for r in roles if r != "All")

    if not include_blocks:
        include_all_users = True

    for blk in exclude_blocks:
        users = blk.get("Users") or []
        groups = blk.get("Groups") or []
        roles = (
            blk.get("DirectoryRoles")
            or blk.get("Roles")
            or blk.get("RoleTemplateIds")
            or []
        )

        exc_users.update(users)
        exc_groups.update(groups)
        exc_roles.update(roles)

    matched_exc_users = [user_ctx.object_id] if user_ctx.object_id in exc_users else []
    all_groups = user_ctx.groups | user_ctx.assumed_groups
    all_roles = user_ctx.role_object_ids | user_ctx.role_template_ids | user_ctx.assumed_roles
    matched_exc_groups = list(all_groups & exc_groups)
    matched_exc_roles = list(all_roles & exc_roles)

    if matched_exc_users or matched_exc_groups or matched_exc_roles:
        if matched_exc_users:
            reason = "Excluded: user explicitly excluded"
        elif matched_exc_groups:
            friendly = friendly_ids(resolver, matched_exc_groups, "group")
            reason = f"Excluded: user in excluded group(s): {friendly[:3]}{'...' if len(friendly) > 3 else ''}"
        else:
            friendly = friendly_ids(resolver, matched_exc_roles, "role")
            reason = f"Excluded: user has excluded role(s): {friendly[:3]}{'...' if len(friendly) > 3 else ''}"

        return TargetingResult(
            status="excluded",
            applies_reason=reason,
            matched_exclude_users=matched_exc_users,
            matched_exclude_groups=matched_exc_groups,
            matched_exclude_roles=matched_exc_roles,
            matched_include_users=[],
            matched_include_groups=[],
            matched_include_roles=[],
        )

    matched_inc_users = [user_ctx.object_id] if user_ctx.object_id in inc_users else []
    matched_inc_groups = list(all_groups & inc_groups)
    matched_inc_roles = list(all_roles & inc_roles)

    if include_all_users:
        if not include_blocks:
            return TargetingResult(
                status="included",
                applies_reason="Included: no include blocks found (treat as All users)",
                include_via="All users",
                matched_include_users=[],
                matched_include_groups=[],
                matched_include_roles=[],
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )
        return TargetingResult(
            status="included",
            applies_reason="Included: All users",
            include_via="All users",
            matched_include_users=[],
            matched_include_groups=[],
            matched_include_roles=[],
            matched_exclude_users=[],
            matched_exclude_groups=[],
            matched_exclude_roles=[],
        )

    if inc_users or inc_groups or inc_roles:
        if matched_inc_users:
            return TargetingResult(
                status="included",
                applies_reason="Included: user explicitly targeted",
                include_via="User",
                matched_include_users=matched_inc_users,
                matched_include_groups=[],
                matched_include_roles=[],
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )
        if matched_inc_groups:
            friendly = friendly_ids(resolver, matched_inc_groups, "group")
            return TargetingResult(
                status="included",
                applies_reason=f"Included: user in targeted group(s): {friendly[:3]}{'...' if len(friendly) > 3 else ''}",
                include_via="Group",
                matched_include_users=[],
                matched_include_groups=matched_inc_groups,
                matched_include_roles=[],
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )
        if matched_inc_roles:
            friendly = friendly_ids(resolver, matched_inc_roles, "role")
            return TargetingResult(
                status="included",
                applies_reason=f"Included: user has targeted role(s): {friendly[:3]}{'...' if len(friendly) > 3 else ''}",
                include_via="Role",
                matched_include_users=[],
                matched_include_groups=[],
                matched_include_roles=matched_inc_roles,
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )

        return TargetingResult(
            status="not_targeted",
            applies_reason="Not included: user/group/role did not match any include rules",
            matched_include_users=[],
            matched_include_groups=[],
            matched_include_roles=[],
            matched_exclude_users=[],
            matched_exclude_groups=[],
            matched_exclude_roles=[],
        )

    return TargetingResult(
        status="not_targeted",
        applies_reason="Not included: no include rules understood",
        matched_include_users=[],
        matched_include_groups=[],
        matched_include_roles=[],
        matched_exclude_users=[],
        matched_exclude_groups=[],
        matched_exclude_roles=[],
    )


# Accept both "All" and "ServicePrincipalsInMyTenant" for "all service principals". MS Graph uses
# ServicePrincipalsInMyTenant; the form roadrecon stores for this setting has not been seen in real data.
SP_ALL_VALUES = {"all", "serviceprincipalsinmytenant"}


def _sp_ids(blocks: List[Dict[str, Any]]) -> Set[str]:
    return {s.strip().lower() for blk in blocks for s in (blk.get("ServicePrincipals") or [])}


def _sp_filter_rules(blocks: List[Dict[str, Any]]) -> List[str]:
    rules: List[str] = []
    for blk in blocks:
        rule = blk.get("ServicePrincipalFilterRule")
        if isinstance(rule, list):
            rules.extend(r for r in rule if r)
        elif rule:
            rules.append(rule)
    return rules


def _sp_result(status: str, reason: str, include_via: str = "", matched_include=None, matched_exclude=None) -> TargetingResult:
    return TargetingResult(
        status=status,
        applies_reason=reason,
        include_via=include_via,
        matched_include_users=matched_include or [],
        matched_include_groups=[],
        matched_include_roles=[],
        matched_exclude_users=matched_exclude or [],
        matched_exclude_groups=[],
        matched_exclude_roles=[],
    )


def evaluate_sp_targeting(detail: Dict[str, Any], wl_ctx: WorkloadContext) -> TargetingResult:
    cond_sps = (detail.get("Conditions", {}) or {}).get("ServicePrincipals", {}) or {}
    if not cond_sps:
        return _sp_result("not_targeted", "Not a workload identity policy")

    include_blocks = cond_sps.get("Include") or []
    exclude_blocks = cond_sps.get("Exclude") or []
    inc_sps = _sp_ids(include_blocks)
    exc_sps = _sp_ids(exclude_blocks)
    inc_rules = _sp_filter_rules(include_blocks)
    exc_rules = _sp_filter_rules(exclude_blocks)

    oid = (wl_ctx.object_id or "").lower()
    name = getattr(wl_ctx.sp, "displayName", None) or wl_ctx.object_id

    if oid in exc_sps:
        return _sp_result("excluded", f"Excluded: service principal explicitly excluded ({name})",
                          matched_exclude=[wl_ctx.object_id])

    notes: List[str] = []
    if oid in inc_sps:
        reason = f"Included: service principal explicitly targeted ({name})"
        via = "ServicePrincipal"
    elif inc_sps & SP_ALL_VALUES or inc_rules:
        if wl_ctx.in_scope is False:
            return _sp_result("not_targeted", f"Not applicable: {wl_ctx.scope_reason}")
        if inc_sps & SP_ALL_VALUES:
            reason = "Included: All service principals"
            via = "All service principals"
        else:
            reason = "Included: service principal filter rule"
            via = "ServicePrincipalFilterRule"
            notes.append(f"include filter rule cannot be evaluated offline ({'; '.join(inc_rules)})")
        if wl_ctx.in_scope is None:
            notes.append(wl_ctx.scope_reason)
    else:
        return _sp_result("not_targeted", "Not included: service principal not in include list")

    if exc_rules:
        notes.append(f"excluded if it matches filter rule ({'; '.join(exc_rules)})")
    if notes:
        reason += " | Signal-dependent: " + "; ".join(notes)

    return _sp_result("included", reason, include_via=via,
                      matched_include=[wl_ctx.object_id] if via == "ServicePrincipal" else [])
