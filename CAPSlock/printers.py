from __future__ import annotations
from typing import List, Set, Tuple, Any, Dict
from CAPSlock.models import PolicyResult


def _has_runtime_dependent_note(reason: str | None) -> bool:
    if not reason:
        return False
    return "Runtime-dependent:" in reason


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


def render_conditions_summary(detail: dict) -> str:
    cond = detail.get("Conditions") or {}
    out = []

    a_inc_b, a_exc_b = _cond_blocks(cond, "Applications")
    a_inc = _flatten_list(a_inc_b, "Applications")
    a_exc = _flatten_list(a_exc_b, "Applications")
    out += _format_inc_exc("Apps", a_inc, a_exc)

    u = cond.get("Users") or {}
    u_inc = u.get("Include") or []
    u_exc = u.get("Exclude") or []

    inc_users = _flatten_list(u_inc, "Users")
    inc_groups = _flatten_list(u_inc, "Groups")
    inc_roles = (
        _flatten_list(u_inc, "DirectoryRoles")
        or _flatten_list(u_inc, "Roles")
        or _flatten_list(u_inc, "RoleTemplateIds")
    )

    exc_users = _flatten_list(u_exc, "Users")
    exc_groups = _flatten_list(u_exc, "Groups")
    exc_roles = (
        _flatten_list(u_exc, "DirectoryRoles")
        or _flatten_list(u_exc, "Roles")
        or _flatten_list(u_exc, "RoleTemplateIds")
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

    p_inc_b, p_exc_b = _cond_blocks(cond, "DevicePlatforms")
    p_inc = _flatten_list(p_inc_b, "DevicePlatforms")
    p_exc = _flatten_list(p_exc_b, "DevicePlatforms")
    out += _format_inc_exc("Device platform", p_inc, p_exc)

    c_inc_b, c_exc_b = _cond_blocks(cond, "ClientTypes")
    c_inc = _flatten_list(c_inc_b, "ClientTypes")
    c_exc = _flatten_list(c_exc_b, "ClientTypes")
    out += _format_inc_exc("Client app", c_inc, c_exc)

    s_inc_b, s_exc_b = _cond_blocks(cond, "SignInRisks")
    s_inc = _flatten_list(s_inc_b, "SignInRisks")
    s_exc = _flatten_list(s_exc_b, "SignInRisks")
    out += _format_inc_exc("Sign-in risk", s_inc, s_exc)

    ur_inc_b, ur_exc_b = _cond_blocks(cond, "UserRisks")
    ur_inc = _flatten_list(ur_inc_b, "UserRisks")
    ur_exc = _flatten_list(ur_exc_b, "UserRisks")
    out += _format_inc_exc("User risk", ur_inc, ur_exc)

    af_inc_b, af_exc_b = _cond_blocks(cond, "AuthFlows")
    af_inc = _flatten_list(af_inc_b, "AuthFlows")
    af_exc = _flatten_list(af_exc_b, "AuthFlows")
    out += _format_inc_exc("Auth flow", af_inc, af_exc)

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


def print_full(r: PolicyResult, show_raw: bool = False):
    print(f"- {r.policy.displayName} ({r.policy.objectId})")
    if r.state:
        print(f"  State:   {r.state}")
    if r.effect:
        print(f"  Effect:  {r.effect}")
    if r.controls is not None:
        print(f"  Controls:{r.controls}")
    print(f"  Reason:  {r.applies_reason}")

    print(render_conditions_summary(r.detail))

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


def print_sections_get_policies(results: List[PolicyResult], results_mode: str):
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
            print_full(r)

    if results_mode in ("exclusions", "all"):
        print("\n=== Excluded ===\n")
        for r in excluded:
            print_full(r)

    if results_mode == "all":
        print("\n=== Not included / not targeted ===\n")
        for r in not_included:
            print_minimal(r)


def print_sections_what_if(results: List[PolicyResult], strict: bool):
    applied_all = [r for r in results if r.applies]
    applied_def = [r for r in applied_all if not _has_runtime_dependent_note(r.applies_reason)]
    applied_rt = [r for r in applied_all if _has_runtime_dependent_note(r.applies_reason)]

    print("\n=== Applied (definitive) ===\n")
    if applied_def:
        for r in applied_def:
            print_full(r)
    else:
        print("(none)\n")

    if strict:
        return

    print("\n=== Applied (runtime-dependent) ===\n")
    if applied_rt:
        for r in applied_rt:
            print_full(r)
    else:
        print("(none)\n")