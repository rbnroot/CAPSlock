from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple
from CAPSlock.models import SignInContext, ConditionEval

def _get_apps_from_condition(detail: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    apps_cond = (detail.get("Conditions", {}) or {}).get("Applications", {}) or {}
    include_blocks = apps_cond.get("Include") or []
    exclude_blocks = apps_cond.get("Exclude") or []

    inc_apps: Set[str] = set()
    exc_apps: Set[str] = set()

    for blk in include_blocks:
        inc_apps.update(blk.get("Applications", []) or [])

    for blk in exclude_blocks:
        exc_apps.update(blk.get("Applications", []) or [])

    return inc_apps, exc_apps


def _get_acrs_from_condition(detail: Dict[str, Any]) -> Set[str]:
    cond = (detail.get("Conditions", {}) or {})
    apps = cond.get("Applications", {}) or {}
    include_blocks = apps.get("Include") or []

    policy_acrs: Set[str] = set()
    for blk in include_blocks:
        acrs = blk.get("Acrs") or []
        for a in acrs:
            if a:
                policy_acrs.add(a)
    return policy_acrs


def _policy_target_mode(detail: Dict[str, Any]) -> str:
    acrs = _get_acrs_from_condition(detail)
    if acrs:
        return "user_action"
    return "cloud_app"


def _eval_app_condition(detail: Dict[str, Any], signin_ctx: SignInContext, mode: str) -> ConditionEval:
    # If policy targets user actions, cloud-app resource scoping is not applicable.
    # If scenario incorrectly provided a resource for a user_action policy, treat as non-match.
    if mode == "user_action":
        if signin_ctx.app_id is not None:
            return ConditionEval(
                matched=False,
                reason="Resource: scenario resource provided but policy targets User actions"
            )
        return ConditionEval(matched=True, reason="Resource: policy targets User actions (resource not applicable)")

    inc_apps, exc_apps = _get_apps_from_condition(detail)

    # Policy targets "None" resources => does NOT apply 
    if "None" in inc_apps:
        return ConditionEval(matched=False, reason="Resource: policy target resources set to None (does not apply)")

    # No resource scoping present. Treat as match, but if scenario resource is missing, it can be runtime-dependent.
    if not inc_apps and not exc_apps:
        if signin_ctx.app_id is None:
            return ConditionEval(matched=True, reason="Resource: no resource condition present (scenario resource not provided)", runtime_dependent=True)
        return ConditionEval(matched=True, reason="Resource: no resource condition present")

    # If scenario resource is not provided, the outcome depends on what resource is being accessed
    if signin_ctx.app_id is None:
        return ConditionEval(matched=True, reason="Resource: scenario resource not provided", runtime_dependent=True)

    resource = signin_ctx.app_id

    if resource in exc_apps:
        return ConditionEval(matched=False, reason=f"Resource: excluded resource matched ({resource})")
    if "All" in exc_apps:
        return ConditionEval(matched=False, reason="Resource: excluded All")

    if inc_apps:
        if "All" in inc_apps:
            return ConditionEval(matched=True, reason="Resource: included All")
        if resource in inc_apps:
            return ConditionEval(matched=True, reason=f"Resource: included resource matched ({resource})")
        return ConditionEval(matched=False, reason=f"Resource: resource did not match include list ({resource})")

    return ConditionEval(matched=True, reason="Resource: no include list (treat as match)")

def _eval_acr_condition(detail: Dict[str, Any], signin_ctx: SignInContext, mode: str) -> ConditionEval:
    policy_acrs = _get_acrs_from_condition(detail)

    # Cloud app policy: if scenario is an ACR test, this policy should not apply
    if mode != "user_action":
        if signin_ctx.acr is not None:
            return ConditionEval(matched=False, reason="ACR: scenario acr provided but policy targets Cloud apps")
        return ConditionEval(matched=True, reason="ACR: policy targets Cloud apps (ACR not applicable)")

    # User action policy: scenario must NOT include a resource
    if signin_ctx.app_id is not None:
        return ConditionEval(matched=False, reason="ACR: scenario resource provided but policy targets User actions")

    if not policy_acrs:
        return ConditionEval(matched=True, reason="ACR: no ACR condition present")

    if signin_ctx.acr is None:
        return ConditionEval(matched=True, reason="ACR: scenario acr not provided", runtime_dependent=True)

    if signin_ctx.acr in policy_acrs:
        return ConditionEval(matched=True, reason=f"ACR: matched ({signin_ctx.acr})")

    return ConditionEval(matched=False, reason=f"ACR: scenario acr did not match policy ({signin_ctx.acr})")

def _eval_trusted_location_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    locs = ((detail.get("Conditions", {}) or {}).get("Locations", {}) or {})
    if not locs:
        return ConditionEval(matched=True, reason="Locations: no location condition present")

    if signin_ctx.trusted_location is None:
        return ConditionEval(matched=True, reason="Locations: scenario trusted_location not provided", runtime_dependent=True)

    include_blocks = locs.get("Include") or []
    exclude_blocks = locs.get("Exclude") or []

    inc_locs: Set[str] = set()
    exc_locs: Set[str] = set()

    for blk in include_blocks:
        inc_locs.update(blk.get("Locations", []) or [])
    for blk in exclude_blocks:
        exc_locs.update(blk.get("Locations", []) or [])

    if "All" in inc_locs and not exc_locs:
        return ConditionEval(matched=True, reason="Locations: includes All with no excludes")

    return ConditionEval(
        matched=True,
        reason="Locations: policy uses named locations (not fully modeled in yet)",
        runtime_dependent=True
    )

def _eval_user_risk_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})
    ur = cond.get("UserRisks") or {}
    include_blocks = ur.get("Include") or []

    wanted: Set[str] = set()
    for blk in include_blocks:
        wanted.update([str(x).lower() for x in (blk.get("UserRisks") or [])])

    if not wanted:
        return ConditionEval(matched=True, reason="UserRisk: no user risk condition present")

    if signin_ctx.user_risk is None:
        return ConditionEval(matched=True, reason="UserRisk: scenario user_risk not provided", runtime_dependent=True)

    got = str(signin_ctx.user_risk).lower()
    if got in wanted:
        return ConditionEval(matched=True, reason=f"UserRisk: matched ({got})")

    return ConditionEval(matched=False, reason=f"UserRisk: did not match ({got})")

def _eval_auth_flow_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})
    af = cond.get("AuthFlows") or {}
    include_blocks = af.get("Include") or []

    wanted: Set[str] = set()
    for blk in include_blocks:
        wanted.update([str(x).lower() for x in (blk.get("AuthFlows") or [])])

    if not wanted:
        return ConditionEval(matched=True, reason="AuthFlow: no auth flow condition present")

    if signin_ctx.auth_flow is None:
        return ConditionEval(matched=True, reason="AuthFlow: scenario auth_flow not provided", runtime_dependent=True)

    got = str(signin_ctx.auth_flow).lower()
    if got in wanted:
        return ConditionEval(matched=True, reason=f"AuthFlow: matched ({got})")

    return ConditionEval(matched=False, reason=f"AuthFlow: did not match ({got})")

def _policy_has_device_filter(detail: Dict[str, Any]) -> bool:
    cond = (detail.get("Conditions", {}) or {})
    dev = cond.get("Devices") or {}

    flt = dev.get("Filter") or {}
    if (flt.get("Rule") or "").strip():
        return True

    for blk in (dev.get("Include") or []):
        if (blk.get("DeviceRule") or "").strip():
            return True

    return False


def _eval_device_filter_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    if not _policy_has_device_filter(detail):
        return ConditionEval(matched=True, reason="DeviceFilter: no device filter condition present")

    if signin_ctx.device_filter is None:
        return ConditionEval(matched=True, reason="DeviceFilter: scenario device_filter not provided", runtime_dependent=True)

    if signin_ctx.device_filter is True:
        return ConditionEval(matched=True, reason="DeviceFilter: matched (true)")
    return ConditionEval(matched=False, reason="DeviceFilter: did not match (false)")

def _eval_device_compliance_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})
    devices = cond.get("Devices") or {}
    device_states = cond.get("DeviceStates") or {}

    wants_compliant = False

    for blk in (device_states.get("Include") or []):
        vals = blk.get("DeviceStates") or []
        if "Compliant" in vals or "compliant" in [str(x).lower() for x in vals]:
            wants_compliant = True

    flt = devices.get("Filter") or {}
    rule = (flt.get("Rule") or "")
    if "iscompliant" in rule.replace(" ", "").lower():
        wants_compliant = True

    if not wants_compliant:
        return ConditionEval(matched=True, reason="Device: no compliant-device requirement detected")

    if signin_ctx.device_compliant is None:
        return ConditionEval(matched=True, reason="Device: scenario device_compliant not provided", runtime_dependent=True)

    if signin_ctx.device_compliant is True:
        return ConditionEval(matched=True, reason="Device: scenario compliant device = true")
    return ConditionEval(matched=False, reason="Device: requires compliant device (scenario false)")


def _extract_platforms(detail: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    cond = (detail.get("Conditions", {}) or {})

    # Graph-style
    plats = cond.get("Platforms") or {}
    inc_blocks = plats.get("Include") or []
    exc_blocks = plats.get("Exclude") or []

    # ROADrecon-style
    dp = cond.get("DevicePlatforms") or {}
    if dp:
        inc_blocks = dp.get("Include") or inc_blocks
        exc_blocks = dp.get("Exclude") or exc_blocks

    inc: Set[str] = set()
    exc: Set[str] = set()

    for blk in inc_blocks:
        vals = blk.get("Platforms") or blk.get("DevicePlatforms") or []
        inc.update([str(x).strip().lower() for x in vals if x])

    for blk in exc_blocks:
        vals = blk.get("Platforms") or blk.get("DevicePlatforms") or []
        exc.update([str(x).strip().lower() for x in vals if x])

    return inc, exc


def _eval_platform_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    inc, exc = _extract_platforms(detail)

    # No platform condition at all
    if not inc and not exc:
        return ConditionEval(matched=True, reason="Platform: no platform condition present")

    # Condition exists but scenario didn’t provide platform
    if signin_ctx.platform is None:
        return ConditionEval(matched=True, reason="Platform: scenario platform not provided", runtime_dependent=True)

    p = str(signin_ctx.platform).strip().lower()

    # Exclusions win
    if p in exc:
        return ConditionEval(matched=False, reason=f"Platform: excluded platform matched ({p})")

    # Include=All means “everything except excluded”
    if "all" in inc:
        return ConditionEval(matched=True, reason="Platform: included All (and not excluded)")

    # If include list exists, must match
    if inc:
        if p in inc:
            return ConditionEval(matched=True, reason=f"Platform: included platform matched ({p})")
        return ConditionEval(matched=False, reason=f"Platform: platform did not match include list ({p})")

    # If only excludes exist, treat includes as All
    return ConditionEval(matched=True, reason="Platform: not excluded (implicit All)")

def _eval_client_app_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})

    # Graph-style
    cats = cond.get("ClientAppTypes") or []

    # ROADrecon-style
    ct = cond.get("ClientTypes") or {}
    if ct:
        cats = []
        for blk in (ct.get("Include") or []):
            cats.extend(blk.get("ClientTypes") or [])

    if not cats:
        return ConditionEval(matched=True, reason="ClientApp: no client app type condition present")

    if signin_ctx.client_app is None:
        return ConditionEval(matched=True, reason="ClientApp: scenario client_app not provided", runtime_dependent=True)

    wanted = set([str(x).strip().lower() for x in cats if x])
    got = str(signin_ctx.client_app).strip().lower()

    if "all" in wanted:
        return ConditionEval(matched=True, reason="ClientApp: includes All")

    if got in wanted:
        return ConditionEval(matched=True, reason=f"ClientApp: matched ({got})")

    return ConditionEval(matched=False, reason=f"ClientApp: did not match ({got})")

def _eval_signin_risk_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})
    sir = cond.get("SignInRisks") or {}
    include_blocks = sir.get("Include") or []

    wanted: Set[str] = set()
    for blk in include_blocks:
        wanted.update([str(x).lower() for x in (blk.get("SignInRisks") or [])])

    if not wanted:
        return ConditionEval(matched=True, reason="SignInRisk: no sign-in risk condition present")

    if signin_ctx.signin_risk is None:
        return ConditionEval(matched=True, reason="SignInRisk: scenario signin_risk not provided", runtime_dependent=True)

    got = str(signin_ctx.signin_risk).lower()
    if got in wanted:
        return ConditionEval(matched=True, reason=f"SignInRisk: matched ({got})")

    return ConditionEval(matched=False, reason=f"SignInRisk: did not match ({got})")

def evaluate_conditions(detail: Dict[str, Any], signin_ctx: SignInContext) -> Tuple[bool, List[str], List[str]]:
    policy_mode = _policy_target_mode(detail)

    evals: List[ConditionEval] = []
    evals.append(_eval_app_condition(detail, signin_ctx, policy_mode))
    evals.append(_eval_acr_condition(detail, signin_ctx, policy_mode))
    evals.append(_eval_trusted_location_condition(detail, signin_ctx))
    #evals.append(_eval_device_compliance_condition(detail, signin_ctx)) #come back to later.
    evals.append(_eval_platform_condition(detail, signin_ctx))
    evals.append(_eval_client_app_condition(detail, signin_ctx))
    evals.append(_eval_signin_risk_condition(detail, signin_ctx))
    evals.append(_eval_user_risk_condition(detail, signin_ctx))
    evals.append(_eval_auth_flow_condition(detail, signin_ctx))
    evals.append(_eval_device_filter_condition(detail, signin_ctx))

    blockers: List[str] = []
    runtime_notes: List[str] = []

    for e in evals:
        if not e.matched:
            blockers.append(e.reason)
        elif e.runtime_dependent:
            runtime_notes.append(e.reason)

    return (len(blockers) == 0), blockers, runtime_notes
