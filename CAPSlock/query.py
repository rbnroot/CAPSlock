from __future__ import annotations
import base64
import json
import zlib
from typing import List, Optional
from sqlalchemy import func
from roadtools.roadlib.metadef.database import User, Group, DirectoryRole, Application, ServicePrincipal, Policy
from CAPSlock.db import load_capolicies, parse_policy_details, load_named_locations
from CAPSlock.models import SignInContext, PolicyResult, UserContext
from CAPSlock.resolvers import build_name_resolver
from CAPSlock.evaluator import evaluate_policy_detail


def _get_user_by_upn(session, upn: str) -> Optional[User]:
    return (
        session.query(User).filter(func.lower(User.userPrincipalName) == upn.strip().lower()).one_or_none()
    )

def _resolve_groups(session, group_identifiers: List[str]) -> tuple[set[str], List[str]]:
    if not group_identifiers:
        return set(), []

    resolved_ids = set()
    not_found = []

    for identifier in group_identifiers:
        group = session.query(Group).filter(
            (Group.objectId == identifier) |
            (func.lower(Group.displayName) == identifier.strip().lower())
        ).first()

        if group:
            resolved_ids.add(group.objectId)
        else:
            not_found.append(identifier)

    return resolved_ids, not_found

def _resolve_roles(session, role_identifiers: List[str]) -> tuple[set[str], List[str]]:
    if not role_identifiers:
        return set(), []

    resolved_ids = set()
    not_found = []

    for identifier in role_identifiers:
        role = session.query(DirectoryRole).filter(
            (DirectoryRole.objectId == identifier) |
            (DirectoryRole.roleTemplateId == identifier) |
            (func.lower(DirectoryRole.displayName) == identifier.strip().lower())
        ).first()

        if role:
            resolved_ids.add(role.roleTemplateId if role.roleTemplateId else role.objectId)
        else:
            not_found.append(identifier)

    return resolved_ids, not_found

def _build_user_context(session, user: User, assumed_groups: set[str] = None, assumed_roles: set[str] = None) -> UserContext:
    groups = (
        session.query(Group)
        .join(Group.memberUsers)
        .filter(User.objectId == user.objectId)
        .all()
    )
    group_ids = {g.objectId for g in groups}

    roles = (
        session.query(DirectoryRole)
        .join(DirectoryRole.memberUsers)
        .filter(User.objectId == user.objectId)
        .all()
    )

    role_object_ids = {r.objectId for r in roles}

    role_template_ids = {getattr(r, "roleTemplateId", None) for r in roles}
    role_template_ids.discard(None)

    return UserContext(
        user=user,
        object_id=user.objectId,
        groups=group_ids,
        role_object_ids=role_object_ids,
        role_template_ids=role_template_ids,
        assumed_groups=assumed_groups if assumed_groups else set(),
        assumed_roles=assumed_roles if assumed_roles else set(),
    )


def get_policy_results_for_user(
    session,
    user_upn: str,
    signin_ctx: Optional[SignInContext] = None,
    mode: str = "get-policies",
    assume_groups: List[str] = None,
    assume_roles: List[str] = None,
) -> List[PolicyResult]:
    if signin_ctx is None:
        signin_ctx = SignInContext()

    user: Optional[User] = _get_user_by_upn(session, user_upn)
    if not user:
        print(f"[!] User {user_upn} not found in DB")
        return []

    assumed_group_ids = set()
    assumed_role_ids = set()

    if assume_groups:
        resolved_groups, not_found_groups = _resolve_groups(session, assume_groups)
        if not_found_groups:
            raise ValueError(f"Groups not found in DB: {', '.join(not_found_groups)}")
        assumed_group_ids = resolved_groups

    if assume_roles:
        resolved_roles, not_found_roles = _resolve_roles(session, assume_roles)
        if not_found_roles:
            raise ValueError(f"Roles not found in DB: {', '.join(not_found_roles)}")
        assumed_role_ids = resolved_roles

    resolver = build_name_resolver(session)

    uctx = _build_user_context(session, user, assumed_group_ids, assumed_role_ids)
    policies = load_capolicies(session)

    location_trust_map = load_named_locations(session)
    location_kinds = _location_kinds(_named_location_records(session)) if signin_ctx.location_id else {}

    results: List[PolicyResult] = []
    for p in policies:
        for d in parse_policy_details(p):
            results.append(
                evaluate_policy_detail(
                    policy=p,
                    detail=d,
                    user_ctx=uctx,
                    signin_ctx=signin_ctx,
                    mode=mode,
                    resolver=resolver,
                    location_trust_map=location_trust_map,
                    location_kinds=location_kinds,
                )
            )

    return results

def _decompress_cidrs(compressed: str) -> List[str]:
    try:
        raw = zlib.decompress(base64.b64decode(compressed), -zlib.MAX_WBITS)
        return [c for c in raw.decode().split(",") if c]
    except Exception:
        return []


def _named_location_records(session) -> List[dict]:
    """Parse every named location (policyType 6) once, in database order.

    This is the one place that reads named locations for listing and lookup. The web
    /api/locations endpoints, the CLI list-locations command and --location all build on it.
    Each record has the ID that CA policies reference (policyIdentifier, objectId as a
    fallback), the other IDs the row is known by, and its IP ranges, countries and bundled
    KnownNetworkPolicies entries. Trust comes from load_named_locations(), the same map
    the evaluator uses.
    """
    trust = load_named_locations(session)
    records: List[dict] = []
    for loc in session.query(Policy).filter(Policy.policyType == 6).all():
        loc_id = loc.policyIdentifier or loc.objectId
        ip_ranges: List[str] = []
        countries: List[str] = []
        knp_entries: List[dict] = []
        for detail_raw in (loc.policyDetail or []):
            try:
                detail = json.loads(detail_raw)
                if detail.get("CompressedCidrIpRanges"):
                    ip_ranges = _decompress_cidrs(detail["CompressedCidrIpRanges"])
                if detail.get("CountryIsoCodes"):
                    countries = detail["CountryIsoCodes"]
                knp = detail.get("KnownNetworkPolicies")
                if knp and knp.get("NetworkId") and knp.get("NetworkName"):
                    knp_ip_ranges = []
                    for cidr_obj in (knp.get("CidrIpRanges") or []):
                        if isinstance(cidr_obj, dict):
                            if cidr_obj.get("CidrIpAddress"):
                                knp_ip_ranges.append(cidr_obj["CidrIpAddress"])
                        elif isinstance(cidr_obj, str):
                            knp_ip_ranges.append(cidr_obj)
                    knp_entries.append({
                        "name": knp["NetworkName"].strip(),
                        "id": knp["NetworkId"],
                        "is_trusted": trust.get(knp["NetworkId"], False),
                        "ip_ranges": knp_ip_ranges,
                    })
            except Exception:
                pass

        records.append({
            "name": loc.displayName or loc_id,
            "id": loc_id,
            "alias_ids": [i for i in (loc.policyIdentifier, loc.objectId) if i],
            "is_trusted": trust.get(loc_id, False),
            "ip_ranges": ip_ranges,
            "countries": countries,
            "knp_entries": knp_entries,
        })
    return records


def _location_type(rec: dict) -> str:
    if rec["ip_ranges"]:
        n = len(rec["ip_ranges"])
        return f"IP-based ({n} range{'s' if n != 1 else ''})"
    if rec["countries"]:
        n = len(rec["countries"])
        return f"Country-based ({n} countr{'ies' if n != 1 else 'y'})"
    if rec["knp_entries"]:
        n = len(rec["knp_entries"])
        return f"Bundled ({n} network{'s' if n != 1 else ''})"
    return "Unknown"


def _location_kinds(records: List[dict]) -> dict:
    """Map location IDs to "ip" or "country". Locations with neither are left out."""
    kinds = {}
    for rec in records:
        kind = "ip" if rec["ip_ranges"] else "country" if rec["countries"] else None
        if kind:
            for i in rec["alias_ids"]:
                kinds[i] = kind
        for knp in rec["knp_entries"]:
            if knp["ip_ranges"]:
                kinds[knp["id"]] = "ip"
    return kinds


def describe_named_locations(session) -> List[dict]:
    """Named locations with their details, as the web /api/locations endpoints return them."""
    result = []
    for rec in _named_location_records(session):
        result.append({
            "name": rec["name"],
            "id": rec["id"],
            "is_trusted": rec["is_trusted"],
            "type": _location_type(rec),
            "ip_ranges": rec["ip_ranges"],
            "countries": rec["countries"],
            "knp_entries": rec["knp_entries"],
        })
    return sorted(result, key=lambda x: (x["name"] or "").lower())


def _selectable_locations(records: List[dict]) -> List[tuple]:
    """(id, name, is_trusted, alias_ids, type) for each location a sign-in can be placed at.

    Same set and order as the web GUI location dropdown: each named location, then the
    bundled KnownNetworkPolicies entries inside it.
    """
    out = []
    for rec in records:
        out.append((rec["id"], rec["name"], bool(rec["is_trusted"]), rec["alias_ids"], _location_type(rec)))
        for knp in rec["knp_entries"]:
            knp_rec = {"ip_ranges": knp["ip_ranges"], "countries": [], "knp_entries": []}
            out.append((knp["id"], knp["name"], bool(knp["is_trusted"]), [knp["id"]], _location_type(knp_rec)))
    return out


def list_named_locations(session) -> List[dict]:
    """Named locations as the web GUI location dropdown lists them: one entry per name.

    IDs are the ones CA policies reference: policyIdentifier, the objectId as a fallback,
    and the NetworkId of bundled KnownNetworkPolicies entries.
    """
    from CAPSlock.conditions import LEGACY_MFA_TRUSTED_IPS_ID

    selectable = _selectable_locations(_named_location_records(session))
    out: List[dict] = []
    seen_names = set()
    for lid, name, is_trusted, _, loc_type in selectable:
        if name in seen_names:
            continue
        seen_names.add(name)
        out.append({"id": lid, "name": name, "is_trusted": is_trusted, "type": loc_type})
    if not any(LEGACY_MFA_TRUSTED_IPS_ID in aliases for _, _, _, aliases, _ in selectable):
        out.append({"id": LEGACY_MFA_TRUSTED_IPS_ID, "name": "MFA trusted IPs (legacy, not in roadrecon data)",
                    "is_trusted": True, "type": "Legacy MFA trusted IPs"})
    return sorted(out, key=lambda x: x["name"].lower())


def canonical_location_id(session, location_id: Optional[str]) -> Optional[str]:
    """Return the ID policies reference for a named location given by any of its IDs.

    A named location's objectId maps to its policyIdentifier. Bundled network IDs,
    AllTrusted and the legacy MFA trusted IPs ID are accepted as they are. Raises
    ValueError for an empty or unknown ID.
    """
    from CAPSlock.conditions import LEGACY_MFA_TRUSTED_IPS_ID

    if location_id is None:
        return None
    ident = location_id.strip().lower()
    if not ident:
        raise ValueError("location_id is empty")
    for special in ("AllTrusted", LEGACY_MFA_TRUSTED_IPS_ID):
        if ident == special.lower():
            return special
    for lid, _, _, aliases, _ in _selectable_locations(_named_location_records(session)):
        if any(alias.lower() == ident for alias in aliases):
            return lid
    for known in load_named_locations(session):
        if known.lower() == ident:
            return known
    raise ValueError(f"Named location not found: {location_id} (see /api/locations)")


def resolve_named_location(session, identifier: str) -> dict:
    """Find a named location by ID or display name (case-insensitive). Raises ValueError if not found."""
    from CAPSlock.conditions import LEGACY_MFA_TRUSTED_IPS_ID

    ident = identifier.strip()
    if not ident:
        raise ValueError("Named location is empty (see 'capslock list-locations')")
    records = _named_location_records(session)
    locations = list_named_locations(session)

    for lid, name, is_trusted, aliases, _ in _selectable_locations(records):
        for alias in aliases:
            if alias.lower() == ident.lower():
                return {"id": lid, "name": name, "is_trusted": is_trusted}
    for loc in locations:
        if loc["id"].lower() == ident.lower() or loc["name"].strip().lower() == ident.lower():
            return loc

    partial = [
        loc for loc in locations
        if loc["id"] != LEGACY_MFA_TRUSTED_IPS_ID and ident.lower() in loc["name"].lower()
    ]
    if len(partial) == 1:
        return partial[0]
    if partial:
        raise ValueError(
            f"Location '{identifier}' matches several named locations: "
            + ", ".join(f"{l['name']} ({l['id']})" for l in partial[:10])
        )
    raise ValueError(f"Named location not found: {identifier} (see 'capslock list-locations')")


def convert_from_id(session, object_id: str) -> List[str]:
    out: List[str] = []
    oid = object_id.strip()

    u = session.query(User).filter(User.objectId == oid).one_or_none()
    if u:
        label = u.userPrincipalName or u.displayName or "(no upn)"
        out.append(f"[User]: {label} - {u.objectId}")

    g = session.query(Group).filter(Group.objectId == oid).one_or_none()
    if g:
        label = g.displayName or "(no name)"
        out.append(f"[Group]: {label} - {g.objectId}")

    r = session.query(DirectoryRole).filter(DirectoryRole.roleTemplateId == oid).one_or_none()
    if r:
        label = r.displayName or "(no name)"
        out.append(f"[Role]: {label} - {r.roleTemplateId}")

    a = session.query(Application).filter(Application.objectId == oid).one_or_none()
    if a:
        label = a.displayName or "(no name)"
        out.append(f"[Application]: {label} - {a.objectId}")

    sp = session.query(ServicePrincipal).filter(ServicePrincipal.appId == oid).one_or_none()
    if sp:
        label = sp.displayName or "(no name)"
        out.append(f"[ServicePrincipal]: {label} - {sp.objectId}")

    if not out:
        out.append(f"[Unknown]: {oid}")

    return out

def convert_from_name(session, name: str, limit: int = 10) -> List[str]:
    out: List[str] = []
    q = name.strip()
    if not q:
        return ["[Unknown]: (empty)"]

    pattern = f"%{q}%"

    users = session.query(User).filter(
        (User.userPrincipalName.ilike(pattern)) | (User.displayName.ilike(pattern))
    ).limit(limit).all()
    for u in users:
        label = u.userPrincipalName or u.displayName or "(no upn)"
        out.append(f"[User]: {label} - {u.objectId}")

    groups = session.query(Group).filter(Group.displayName.ilike(pattern)).limit(limit).all()
    for g in groups:
        label = g.displayName or "(no name)"
        out.append(f"[Group]: {label} - {g.objectId}")

    roles = session.query(DirectoryRole).filter(DirectoryRole.displayName.ilike(pattern)).limit(limit).all()
    for r in roles:
        label = r.displayName or "(no name)"
        out.append(f"[Role]: {label} - {r.roleTemplateId}")

    apps = session.query(Application).filter(Application.displayName.ilike(pattern)).limit(limit).all()
    for a in apps:
        label = a.displayName or "(no name)"
        out.append(f"[Application]: {label} - {a.objectId}")

    sps = session.query(ServicePrincipal).filter(ServicePrincipal.displayName.ilike(pattern)).limit(limit).all()
    for sp in sps:
        label = sp.displayName or "(no name)"
        out.append(f"[ServicePrincipal]: {label} - {sp.objectId}")

    if not out:
        out.append(f"[Unknown]: {q}")

    return out