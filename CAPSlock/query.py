from __future__ import annotations
from typing import List, Optional
from sqlalchemy import func
from roadtools.roadlib.metadef.database import User, Group, DirectoryRole, Application, ServicePrincipal
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
                )
            )

    return results

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
        out.append(f"[Role]: {label} - {r.objectId}")

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

    users = session.query(User).filter(
        (User.userPrincipalName == q) | (User.displayName == q)
    ).limit(limit).all()
    for u in users:
        label = u.userPrincipalName or u.displayName or "(no upn)"
        out.append(f"[User]: {label} - {u.objectId}")

    groups = session.query(Group).filter(Group.displayName == q).limit(limit).all()
    for g in groups:
        label = g.displayName or "(no name)"
        out.append(f"[Group]: {label} - {g.objectId}")

    roles = session.query(DirectoryRole).filter(DirectoryRole.displayName == q).limit(limit).all()
    for r in roles:
        label = r.displayName or "(no name)"
        out.append(f"[Role]: {label} - {r.objectId}")

    apps = session.query(Application).filter(Application.displayName == q).limit(limit).all()
    for a in apps:
        label = a.displayName or "(no name)"
        out.append(f"[Application]: {label} - {a.objectId}")

    sps = session.query(ServicePrincipal).filter(ServicePrincipal.displayName == q).limit(limit).all()
    for sp in sps:
        label = sp.displayName or "(no name)"
        out.append(f"[ServicePrincipal]: {label} - {sp.objectId}")

    if not out:
        out.append(f"[Unknown]: {q}")

    return out