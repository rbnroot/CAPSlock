from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple
from CAPSlock.models import UserContext, TargetingResult, NameResolver
from CAPSlock.resolvers import friendly_ids
from CAPSlock.external_users import (
    MATCH,
    UNCERTAIN,
    classify_external_user,
    display_type,
    home_tenant_id,
    is_legacy_value,
    match_external_block,
)


def _match_external(specs: list, legacy: bool, ext_type: Optional[str], home_tenant: Optional[str]) -> Tuple[Optional[str], List[str]]:
    """Combine GuestsOrExternalUsers blocks: MATCH wins over UNCERTAIN. Returns (result, reasons)."""
    if ext_type is None:
        return None, []
    if legacy:
        return MATCH, []
    results = [match_external_block(spec, ext_type, home_tenant) for spec in specs]
    if any(r == MATCH for r, _ in results):
        return MATCH, []
    why = [w for r, w in results if r == UNCERTAIN]
    return (UNCERTAIN, why) if why else (None, [])


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

    # Guest/external user targeting: GuestsOrExternalUsers blocks, or the legacy value in Users.
    inc_ext_specs: list = []
    exc_ext_specs: list = []
    inc_ext_legacy = False
    exc_ext_legacy = False

    for blk in include_blocks:
        if blk.get("GuestsOrExternalUsers"):
            inc_ext_specs.append(blk["GuestsOrExternalUsers"])
        users = [u for u in (blk.get("Users") or []) if not is_legacy_value(u)]
        if len(users) != len(blk.get("Users") or []):
            inc_ext_legacy = True
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
        if blk.get("GuestsOrExternalUsers"):
            exc_ext_specs.append(blk["GuestsOrExternalUsers"])
        users = [u for u in (blk.get("Users") or []) if not is_legacy_value(u)]
        if len(users) != len(blk.get("Users") or []):
            exc_ext_legacy = True
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

    user_obj = getattr(user_ctx, "user", None)
    ext_type = classify_external_user(user_obj)
    home_tenant = home_tenant_id(user_obj)
    runtime_notes: list = []

    exc_ext, exc_why = _match_external(exc_ext_specs, exc_ext_legacy, ext_type, home_tenant)
    if exc_ext == UNCERTAIN:
        runtime_notes.extend(f"Users: policy excludes {w}" for w in exc_why)

    if matched_exc_users or matched_exc_groups or matched_exc_roles or exc_ext == MATCH:
        if matched_exc_users:
            reason = "Excluded: user explicitly excluded"
        elif exc_ext == MATCH:
            reason = f"Excluded: guest or external user ({display_type(ext_type)})"
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

    inc_ext, inc_why = _match_external(inc_ext_specs, inc_ext_legacy, ext_type, home_tenant)

    if include_all_users:
        if not include_blocks:
            return TargetingResult(
                status="included",
                applies_reason="Included: no include blocks found (treat as All users)",
                include_via="All users",
                runtime_notes=runtime_notes,
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
            runtime_notes=runtime_notes,
            matched_include_users=[],
            matched_include_groups=[],
            matched_include_roles=[],
            matched_exclude_users=[],
            matched_exclude_groups=[],
            matched_exclude_roles=[],
        )

    if inc_users or inc_groups or inc_roles or inc_ext_specs or inc_ext_legacy:
        if matched_inc_users:
            return TargetingResult(
                status="included",
                applies_reason="Included: user explicitly targeted",
                include_via="User",
                runtime_notes=runtime_notes,
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
                runtime_notes=runtime_notes,
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
                runtime_notes=runtime_notes,
                matched_include_users=[],
                matched_include_groups=[],
                matched_include_roles=matched_inc_roles,
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )
        if inc_ext is not None:
            notes = list(runtime_notes)
            if inc_ext == UNCERTAIN:
                notes.extend(f"Users: policy includes {w}" for w in inc_why)
            return TargetingResult(
                status="included",
                applies_reason=f"Included: guest or external user ({display_type(ext_type)})",
                include_via="GuestsOrExternalUsers",
                runtime_notes=notes,
                matched_include_users=[],
                matched_include_groups=[],
                matched_include_roles=[],
                matched_exclude_users=[],
                matched_exclude_groups=[],
                matched_exclude_roles=[],
            )

        return TargetingResult(
            status="not_targeted",
            applies_reason="Not included: user/group/role/guest type did not match any include rules",
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