from __future__ import annotations

import itertools
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from CAPSlock.models import PolicyResult, SignInContext
from CAPSlock.query import get_policy_results_for_user


def _has_signal_dependent_note(reason: Optional[str]) -> bool:
    if not reason:
        return False
    return "Signal-dependent:" in reason


def _controls_lower(r: PolicyResult) -> List[str]:
    if not r.controls:
        return []
    return [str(x).lower() for x in r.controls if x is not None]


def _is_mfa(r: PolicyResult) -> bool:
    return "mfa" in _controls_lower(r)


def _is_block(r: PolicyResult) -> bool:
    if (r.effect or "").lower() == "block":
        return True
    return "block" in _controls_lower(r)


def _definitive_enabled(results: List[PolicyResult]) -> List[PolicyResult]:
    out: List[PolicyResult] = []
    for r in results:
        if not r.applies:
            continue
        if (r.state or "") != "Enabled":
            continue
        if _has_signal_dependent_note(r.applies_reason):
            continue
        out.append(r)
    return out


def _definitive_reporting(results: List[PolicyResult]) -> List[PolicyResult]:
    out: List[PolicyResult] = []
    for r in results:
        if not r.applies:
            continue
        if (r.state or "") != "Reporting":
            continue
        if _has_signal_dependent_note(r.applies_reason):
            continue
        out.append(r)
    return out


def _summarize_policy(r: PolicyResult) -> Dict[str, Any]:
    return {
        "policy_id": r.policy.objectId,
        "display_name": r.policy.displayName,
        "state": r.state,
        "effect": r.effect,
        "controls": r.controls or [],
        "reason": r.applies_reason,
        "detail": r.detail,
    }


def _scenario_dict(ctx: SignInContext) -> Dict[str, Any]:
    d = asdict(ctx)
    return {
        "resource": d.get("app_id"),
        "acr": d.get("acr"),
        "trusted_location": d.get("trusted_location"),
        "platform": d.get("platform"),
        "client_app": d.get("client_app"),
        "signin_risk": d.get("signin_risk"),
        "user_risk": d.get("user_risk"),
        "auth_flow": d.get("auth_flow"),
        "device_filter": d.get("device_filter"),
    }


def _gap_record(
    gap_type: str,
    scenario: Dict[str, Any],
    summary: str,
    definitive: List[PolicyResult],
    signal_dependent: List[PolicyResult],
) -> Dict[str, Any]:
    return {
        "gap_type": gap_type,
        "scenario": scenario,
        "summary": summary,
        "policies": {
            "definitive": [_summarize_policy(r) for r in definitive],
            "signal_dependent": [_summarize_policy(r) for r in signal_dependent],
        },
    }


def _classify_gaps(results: List[PolicyResult], ctx: SignInContext) -> List[Dict[str, Any]]:
    sig = [r for r in results if r.applies and _has_signal_dependent_note(r.applies_reason)]
    def_en = _definitive_enabled(results)
    def_rep = _definitive_reporting(results)

    scenario = _scenario_dict(ctx)
    gaps: List[Dict[str, Any]] = []

    if ctx.trusted_location is True:
        if not def_en and not def_rep:
            gaps.append(
                _gap_record(
                    "TRUSTED_LOCATION_BYPASS",
                    scenario,
                    "No definitive policies apply when signing in from a trusted location.",
                    definitive=[],
                    signal_dependent=sig,
                )
            )
            return gaps

        if not def_en and def_rep:
            gaps.append(
                _gap_record(
                    "TRUSTED_LOCATION_BYPASS",
                    scenario,
                    "Only report-only (Reporting) policies apply from trusted location; no enforcement.",
                    definitive=def_rep,
                    signal_dependent=sig,
                )
            )
            return gaps

        if def_en:
            has_block = any(_is_block(r) for r in def_en)
            has_mfa = any(_is_mfa(r) for r in def_en)
            if not has_block and not has_mfa:
                gaps.append(
                    _gap_record(
                        "TRUSTED_LOCATION_BYPASS",
                        scenario,
                        "Trusted location has definitive policies, but none enforce MFA or Block.",
                        definitive=def_en,
                        signal_dependent=sig,
                    )
                )

    if not def_en and not def_rep:
        gaps.append(
            _gap_record(
                "NO_POLICIES_APPLY",
                scenario,
                "No definitive policies apply in this scenario.",
                definitive=[],
                signal_dependent=sig,
            )
        )
        return gaps

    if not def_en and def_rep:
        gaps.append(
            _gap_record(
                "REPORT_ONLY_BYPASS",
                scenario,
                "Only report-only (Reporting) definitive policies apply; no enforcement.",
                definitive=def_rep,
                signal_dependent=sig,
            )
        )
        return gaps

    return gaps


def _values_or_default(v: Optional[Any], default_values: List[Any]) -> List[Any]:
    if v is None:
        return default_values
    return [v]


def iter_scenarios(
    base: SignInContext,
    platforms: Optional[str] = None,
    client_app: Optional[str] = None,
    trusted_location: Optional[bool] = None,
    signin_risk: Optional[str] = None,
    user_risk: Optional[str] = None,
    auth_flow: Optional[str] = None,
    device_filter: Optional[bool] = None,
) -> Iterable[SignInContext]:
    platform_vals = _values_or_default(platforms, ["windows", "macos", "linux", "ios", "android"])
    client_vals = _values_or_default(client_app, [None, "browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"])
    trusted_vals = _values_or_default(trusted_location, [None, True, False])
    signin_vals = _values_or_default(signin_risk, [None, "none", "low", "medium", "high"])
    user_vals = _values_or_default(user_risk, [None, "low", "medium", "high"])
    auth_vals = _values_or_default(auth_flow, [None, "devicecodeflow", "authtransfer"])
    device_filter_vals = _values_or_default(device_filter, [None, True, False])

    for p, c, t, sr, ur, af, df in itertools.product(
        platform_vals, client_vals, trusted_vals, signin_vals, user_vals, auth_vals, device_filter_vals
    ):
        yield SignInContext(
            app_id=base.app_id,
            acr=base.acr,
            trusted_location=t,
            platform=p,
            client_app=c,
            signin_risk=sr,
            user_risk=ur,
            auth_flow=af,
            device_filter=df,
            device_hybrid_joined=base.device_hybrid_joined,
            device_compliant=base.device_compliant,
        )


def analyze(
    session,
    user_upn: str,
    base: SignInContext,
    fixed: Dict[str, Any],
    max_scenarios: int = 1000,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    gaps_out: List[Dict[str, Any]] = []
    gap_counts = {
        "NO_POLICIES_APPLY": 0,
        "REPORT_ONLY_BYPASS": 0,
        "TRUSTED_LOCATION_BYPASS": 0,
    }

    scenarios_evaluated = 0

    for ctx in iter_scenarios(
        base=base,
        platforms=fixed.get("platform"),
        client_app=fixed.get("client_app"),
        trusted_location=fixed.get("trusted_location"),
        signin_risk=fixed.get("signin_risk"),
        user_risk=fixed.get("user_risk"),
        auth_flow=fixed.get("auth_flow"),
        device_filter=fixed.get("device_filter"),
    ):
        scenarios_evaluated += 1
        results = get_policy_results_for_user(session, user_upn=user_upn, signin_ctx=ctx, mode="what-if")
        gaps = _classify_gaps(results, ctx)
        for g in gaps:
            gt = g["gap_type"]
            if gt in gap_counts:
                gap_counts[gt] += 1
            gaps_out.append(g)

        if scenarios_evaluated >= max_scenarios:
            break

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": user_upn,
        "resource": base.app_id,
        "acr": base.acr,
        "scenarios_evaluated": scenarios_evaluated,
        "max_scenarios": max_scenarios,
        "gap_counts": gap_counts,
    }

    return summary, gaps_out


def write_outputs(summary: Dict[str, Any], gaps: List[Dict[str, Any]], prefix: str) -> Tuple[str, str]:
    summary_path = f"{prefix}.summary.json"
    gaps_path = f"{prefix}.gaps.jsonl"

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=False)

    with open(gaps_path, "w", encoding="utf-8") as f:
        for g in gaps:
            f.write(json.dumps(g, ensure_ascii=False) + "\n")

    return summary_path, gaps_path