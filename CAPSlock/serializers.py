from __future__ import annotations
from typing import Any, Dict, List
from CAPSlock.models import PolicyResult


def serialize_policy_result(result: PolicyResult) -> Dict[str, Any]:
    """Convert a PolicyResult to a JSON-serializable dictionary."""
    return {
        "policy_id": result.policy.objectId,
        "policy_name": result.policy.displayName,
        "applies": result.applies,
        "effect": result.effect,
        "controls": result.controls or [],
        "state": result.state,
        "applies_reason": result.applies_reason,
        "detail": result.detail,
    }


def serialize_policy_results(results: List[PolicyResult]) -> List[Dict[str, Any]]:
    """Convert a list of PolicyResults to JSON-serializable dictionaries."""
    return [serialize_policy_result(r) for r in results]


def categorize_get_policies_results(results: List[PolicyResult]) -> Dict[str, Any]:
    """Categorize get-policies results into applied, excluded, and not_included."""
    applied = []
    excluded = []
    not_included = []

    for r in results:
        serialized = serialize_policy_result(r)
        if r.applies:
            applied.append(serialized)
        else:
            reason = (r.applies_reason or "").lower()
            if reason.startswith("excluded:"):
                excluded.append(serialized)
            else:
                not_included.append(serialized)

    return {
        "applied": applied,
        "excluded": excluded,
        "not_included": not_included,
        "total_policies": len(results),
        "applied_count": len(applied),
        "excluded_count": len(excluded),
        "not_included_count": len(not_included),
    }


def categorize_what_if_results(results: List[PolicyResult]) -> Dict[str, Any]:
    """Categorize what-if results into definitive and signal-dependent."""
    applied_all = [r for r in results if r.applies]

    applied_definitive = []
    applied_signal_dependent = []

    for r in applied_all:
        serialized = serialize_policy_result(r)
        reason = r.applies_reason or ""
        if "Signal-dependent:" in reason:
            applied_signal_dependent.append(serialized)
        else:
            applied_definitive.append(serialized)

    return {
        "applied_definitive": applied_definitive,
        "applied_signal_dependent": applied_signal_dependent,
        "total_policies": len(results),
        "applied_count": len(applied_all),
        "definitive_count": len(applied_definitive),
        "signal_dependent_count": len(applied_signal_dependent),
    }
