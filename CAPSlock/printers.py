from __future__ import annotations
from typing import List, Optional, Set, Tuple, Any, Dict
from CAPSlock.models import PolicyResult, NameResolver
from CAPSlock.resolvers import friendly_ids


def _has_signal_dependent_note(reason: str | None) -> bool:
    if not reason:
        return False
    return "Signal-dependent:" in reason


def _cond_blocks(cond: dict, key: str) -> tuple[list, list]:
    blk = (cond.get(key) or {})
    return (blk.get("Include") or [], blk.get("Exclude") or [])


def _flatten_list(blocks: list, field: str) -> list:
    vals = []
    for b in blocks:
        v = b.get(field) or []
        if isinstance(v, list):
            vals.extend(v)
        elif isinstance(v, str):
            vals.append(v)

    out, seen = [], set()
    for x in vals:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def _format_inc_exc(title: str, inc: list, exc: list, max_items: int = 6) -> list[str]:
    lines = []
    if not inc and not exc:
        return lines

    def fmt(vals):
        if not vals:
            return "(none)"
        s = ", ".join(vals[:max_items])
        if len(vals) > max_items:
            s += ", ..."
        return s

    lines.append(f"  {title}:")
    lines.append(f"    Include: {fmt(inc)}")
    if exc:
        lines.append(f"    Exclude: {fmt(exc)}")
    return lines


def render_conditions_summary(detail: dict, resolver: Optional[NameResolver] = None) -> str:
    cond = detail.get("Conditions") or {}
    out = []

    def resolve(ids, kind):
        if not resolver or not ids:
            return ids
        return friendly_ids(resolver, ids, kind)

    # Apps
    a_inc_b, a_exc_b = _cond_blocks(cond, "Applications")
    a_inc = resolve(_flatten_list(a_inc_b, "Applications"), "app")
    a_exc = resolve(_flatten_list(a_exc_b, "Applications"), "app")
    out += _format_inc_exc("Apps", a_inc, a_exc)

    # Users, Groups, Roles
    u = cond.get("Users") or {}
    u_inc = u.get("Include") or []
    u_exc = u.get("Exclude") or []

    inc_users = resolve(_flatten_list(u_inc, "Users"), "user")
    inc_groups = resolve(_flatten_list(u_inc, "Groups"), "group")
    inc_roles = resolve(
        _flatten_list(u_inc, "DirectoryRoles")
        or _flatten_list(u_inc, "Roles")
        or _flatten_list(u_inc, "RoleTemplateIds"),
        "role",
    )

    exc_users = resolve(_flatten_list(u_exc, "Users"), "user")
    exc_groups = resolve(_flatten_list(u_exc, "Groups"), "group")
    exc_roles = resolve(
        _flatten_list(u_exc, "DirectoryRoles")
        or _flatten_list(u_exc, "Roles")
        or _flatten_list(u_exc, "RoleTemplateIds"),
        "role",
    )

    if any([inc_users, inc_groups, inc_roles, exc_users, exc_groups, exc_roles]):
        out.append("  Users:")
        if inc_users:
            out.append(f"    Include Users: {', '.join(inc_users[:6])}{', ...' if len(inc_users) > 6 else ''}")
        if inc_groups:
            out.append(f"    Include Groups: {', '.join(inc_groups[:6])}{', ...' if len(inc_groups) > 6 else ''}")
        if inc_roles:
            out.append(f"    Include Roles: {', '.join(inc_roles[:6])}{', ...' if len(inc_roles) > 6 else ''}")
        if exc_users:
            out.append(f"    Exclude Users: {', '.join(exc_users[:6])}{', ...' if len(exc_users) > 6 else ''}")
        if exc_groups:
            out.append(f"    Exclude Groups: {', '.join(exc_groups[:6])}{', ...' if len(exc_groups) > 6 else ''}")
        if exc_roles:
            out.append(f"    Exclude Roles: {', '.join(exc_roles[:6])}{', ...' if len(exc_roles) > 6 else ''}")

    # Locations
    l_inc_b, l_exc_b = _cond_blocks(cond, "Locations")
    l_inc = resolve(_flatten_list(l_inc_b, "Locations"), "location")
    l_exc = resolve(_flatten_list(l_exc_b, "Locations"), "location")
    out += _format_inc_exc("Locations", l_inc, l_exc)

    # Device platform
    p_inc_b, p_exc_b = _cond_blocks(cond, "DevicePlatforms")
    p_inc = _flatten_list(p_inc_b, "DevicePlatforms")
    p_exc = _flatten_list(p_exc_b, "DevicePlatforms")
    out += _format_inc_exc("Device platform", p_inc, p_exc)

    # Client app
    c_inc_b, c_exc_b = _cond_blocks(cond, "ClientTypes")
    c_inc = _flatten_list(c_inc_b, "ClientTypes")
    c_exc = _flatten_list(c_exc_b, "ClientTypes")
    out += _format_inc_exc("Client app", c_inc, c_exc)

    # Sign-in risk
    s_inc_b, s_exc_b = _cond_blocks(cond, "SignInRisks")
    s_inc = _flatten_list(s_inc_b, "SignInRisks")
    s_exc = _flatten_list(s_exc_b, "SignInRisks")
    out += _format_inc_exc("Sign-in risk", s_inc, s_exc)

    # User risk
    ur_inc_b, ur_exc_b = _cond_blocks(cond, "UserRisks")
    ur_inc = _flatten_list(ur_inc_b, "UserRisks")
    ur_exc = _flatten_list(ur_exc_b, "UserRisks")
    out += _format_inc_exc("User risk", ur_inc, ur_exc)

    # Auth flow
    af_inc_b, af_exc_b = _cond_blocks(cond, "AuthFlows")
    af_inc = _flatten_list(af_inc_b, "AuthFlows")
    af_exc = _flatten_list(af_exc_b, "AuthFlows")
    out += _format_inc_exc("Auth flow", af_inc, af_exc)

    # Device rules
    dev = cond.get("Devices") or {}
    rules = []
    for b in (dev.get("Include") or []):
        r = (b.get("DeviceRule") or "").strip()
        if r:
            rules.append(r)

    if rules:
        out.append("  Device rule:")
        for r in rules[:2]:
            out.append(f"    - {r}")
        if len(rules) > 2:
            out.append("    - ...")

    if not out:
        return "  Conditions: (none)"

    return "\n".join(["  Conditions summary:"] + out)

def _extract_location_sets(detail: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    locs = ((detail.get("Conditions", {}) or {}).get("Locations", {}) or {})
    inc_blocks = locs.get("Include") or []
    exc_blocks = locs.get("Exclude") or []

    inc: Set[str] = set()
    exc: Set[str] = set()

    for blk in inc_blocks:
        inc.update(blk.get("Locations", []) or [])

    for blk in exc_blocks:
        exc.update(blk.get("Locations", []) or [])

    return inc, exc


def _fmt_set(vals: Set[str]) -> str:
    if not vals:
        return "None"
    items = sorted(vals)
    return ", ".join(items)

def print_full(r: PolicyResult, show_raw: bool = False, resolver: Optional[NameResolver] = None):
    print(f"- {r.policy.displayName} ({r.policy.objectId})")
    if r.state:
        print(f"  State:   {r.state}")
    if r.effect:
        print(f"  Effect:  {r.effect}")
    if r.controls is not None:
        print(f"  Controls:{r.controls}")
    print(f"  Reason:  {r.applies_reason}")

    print(render_conditions_summary(r.detail, resolver=resolver))

    if show_raw:
        cond = r.detail.get("Conditions", {}) or {}
        apps = cond.get("Applications", {}) or {}
        users_cond = cond.get("Users", {}) or {}
        locs = cond.get("Locations", {}) or {}

        print(f"  Apps Include:   {apps.get('Include', [])}")
        print(f"  Users Include:  {users_cond.get('Include', [])}")
        print(f"  Users Exclude:  {users_cond.get('Exclude', [])}")
        print(f"  Locations:      {locs}")

    print()


def print_minimal(r: PolicyResult):
    print(f"- {r.policy.displayName} ({r.policy.objectId})")
    print(f"  Reason:  {r.applies_reason}")
    print()


def print_sections_get_policies(results: List[PolicyResult], results_mode: str, resolver: Optional[NameResolver] = None):
    applied: List[PolicyResult] = []
    excluded: List[PolicyResult] = []
    not_included: List[PolicyResult] = []

    for r in results:
        if r.applies:
            applied.append(r)
        else:
            if (r.applies_reason or "").lower().startswith("excluded:"):
                excluded.append(r)
            else:
                not_included.append(r)

    if results_mode in ("applied", "all"):
        print("\n=== Applied ===\n")
        for r in applied:
            print_full(r, resolver=resolver)

    if results_mode in ("exclusions", "all"):
        print("\n=== Excluded ===\n")
        for r in excluded:
            print_full(r, resolver=resolver)

    if results_mode == "all":
        print("\n=== Not included / not targeted ===\n")
        for r in not_included:
            print_minimal(r)


def print_sections_what_if(results: List[PolicyResult], strict: bool, resolver: Optional[NameResolver] = None):
    applied_all = [r for r in results if r.applies]
    applied_def = [r for r in applied_all if not _has_signal_dependent_note(r.applies_reason)]
    applied_rt = [r for r in applied_all if _has_signal_dependent_note(r.applies_reason)]

    print("\n=== Applied (definitive) ===\n")
    if applied_def:
        for r in applied_def:
            print_full(r, resolver=resolver)
    else:
        print("(none)\n")

    if strict:
        return

    print("\n=== Applied (signal-dependent) ===\n")
    if applied_rt:
        for r in applied_rt:
            print_full(r, resolver=resolver)
    else:
        print("(none)\n")