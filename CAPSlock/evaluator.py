from __future__ import annotations
from typing import Any, Dict, List, Set, Optional
from roadtools.roadlib.metadef.database import Policy
from CAPSlock.models import PolicyResult, UserContext, SignInContext
from CAPSlock.targeting import evaluate_user_targeting
from CAPSlock.conditions import evaluate_conditions

def evaluate_policy_detail(
    policy: Policy,
    detail: Dict[str, Any],
    user_ctx: UserContext,
    signin_ctx: SignInContext,
    mode: str = "get-policies",
    resolver: Optional[object] = None,
) -> PolicyResult:
    state = detail.get("State")

    if state not in ("Enabled", "Reporting"):
        return PolicyResult(
            applies=False,
            effect="Unknown",
            controls=[],
            state=state,
            policy=policy,
            detail=detail,
            applies_reason=f"Not applicable: policy state is {state}",
        )

    tgt = evaluate_user_targeting(detail, user_ctx)
    if tgt.status != "included":
        return PolicyResult(
            applies=False,
            effect="Unknown",
            controls=[],
            state=state,
            policy=policy,
            detail=detail,
            applies_reason=tgt.applies_reason,
        )

    if mode == "get-policies":
        controls = _policy_controls(detail)
        effect = "Unknown"
        normalized_controls = [c.lower() for c in controls]
        if "block" in normalized_controls:
            effect = "Block"
        elif controls:
            effect = "Grant"

        return PolicyResult(
            applies=True,
            effect=effect,
            controls=controls,
            state=state,
            policy=policy,
            detail=detail,
            applies_reason=tgt.applies_reason,
        )

    matched_all, blockers, runtime_notes = evaluate_conditions(detail, signin_ctx)
    if not matched_all:
        reason = "Not applicable: " + "; ".join(blockers[:3]) + ("..." if len(blockers) > 3 else "")
        return PolicyResult(
            applies=False,
            effect="Unknown",
            controls=[],
            state=state,
            policy=policy,
            detail=detail,
            applies_reason=reason,
        )

    controls = _policy_controls(detail)
    effect = "Unknown"
    normalized_controls = [c.lower() for c in controls]
    if "block" in normalized_controls:
        effect = "Block"
    elif controls:
        effect = "Grant"

    if runtime_notes:
        note = " | Signal-dependent: " + ", ".join(runtime_notes[:2]) + ("..." if len(runtime_notes) > 2 else "")
        reason = tgt.applies_reason + note
    else:
        reason = tgt.applies_reason

    return PolicyResult(
        applies=True,
        effect=effect,
        controls=controls,
        state=state,
        policy=policy,
        detail=detail,
        applies_reason=reason,
    )

def _policy_controls(detail: Dict[str, Any]) -> List[str]:
    controls_blocks = detail.get("Controls") or []
    names: List[str] = []

    for blk in controls_blocks:
        ctrl = blk.get("Control") or []
        if isinstance(ctrl, list):
            names.extend(ctrl)
        elif isinstance(ctrl, str):
            names.append(ctrl)

        auth_strength_ids = blk.get("AuthStrengthIds") or []
        if isinstance(auth_strength_ids, list) and len(auth_strength_ids) > 0:
            names.append("AuthStrength")

        grant = blk.get("GrantControls") or []
        if isinstance(grant, list):
            names.extend(grant)
        elif isinstance(grant, str):
            names.append(grant)

        sess = blk.get("SessionControls") or []
        if isinstance(sess, list):
            names.extend(sess)
        elif isinstance(sess, str):
            names.append(sess)

    seen: Set[str] = set()
    out: List[str] = []
    for n in names:
        if not n:
            continue
        if n not in seen:
            out.append(n)
            seen.add(n)

    return out
