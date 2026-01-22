from __future__ import annotations
from typing import List, Optional
from roadtools.roadlib.metadef.database import User, Group, DirectoryRole
from CAPSlock.db import load_capolicies, parse_policy_details
from CAPSlock.models import SignInContext, PolicyResult, UserContext
from CAPSlock.resolvers import build_name_resolver
from CAPSlock.evaluator import evaluate_policy_detail


def _get_user_by_upn(session, upn: str) -> Optional[User]:
    return session.query(User).filter(User.userPrincipalName == upn).one_or_none()

def _build_user_context(session, user: User) -> UserContext:
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
    )


def get_policy_results_for_user(
    session,
    user_upn: str,
    signin_ctx: Optional[SignInContext] = None,
    mode: str = "get-policies",
) -> List[PolicyResult]:
    if signin_ctx is None:
        signin_ctx = SignInContext()

    user: Optional[User] = _get_user_by_upn(session, user_upn)
    if not user:
        print(f"[!] User {user_upn} not found in DB")
        return []

    resolver = build_name_resolver(session)

    uctx = _build_user_context(session, user)
    policies = load_capolicies(session)

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
                )
            )

    return results