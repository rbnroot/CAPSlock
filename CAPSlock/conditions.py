from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple
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

# Legacy "MFA trusted IPs" pseudo-location. Policies reference it by this ID; it is part of
# AllTrusted, but roadrecon does not export it as a named location.
LEGACY_MFA_TRUSTED_IPS_ID = "00000000-0000-0000-0000-000000000000"


def _location_trust(location_id: str, location_trust_map: Dict[str, bool]) -> Optional[bool]:
    """Trust status of a named location: True, False, or None when unknown."""
    if location_id == "AllTrusted" or location_id == LEGACY_MFA_TRUSTED_IPS_ID:
        return True
    return location_trust_map.get(location_id)


def _may_overlap(location_id: str, other_id: str, location_kinds: Dict[str, str]) -> bool:
    """True when a sign-in at location_id could also be inside other_id.

    A sign-in has one IP and one country, so it can be in an IP-based and a country-based
    location at the same time. Locations of the same kind are treated as separate.
    AllTrusted and the legacy MFA trusted IPs are IP-based.
    """
    def kind(l: str) -> Optional[str]:
        if l == "AllTrusted" or l == LEGACY_MFA_TRUSTED_IPS_ID:
            return "ip"
        return location_kinds.get(l)
    a, b = kind(location_id), kind(other_id)
    return location_id != other_id and a is not None and b is not None and a != b


def _fmt_locs(ids: List[str]) -> str:
    ids = sorted(ids)
    return ", ".join(ids[:3]) + (", ..." if len(ids) > 3 else "")


def _eval_trusted_location_condition(detail: Dict[str, Any], signin_ctx: SignInContext, location_trust_map: Dict[str, bool] = None, location_kinds: Dict[str, str] = None) -> ConditionEval:
    """Evaluate the Locations condition.

    The scenario gives either a named location (location_id) or only a trusted/untrusted flag.
    A named location is matched by ID. The flag alone says "some location with this trust status",
    so it matches AllTrusted, but it cannot tell whether the sign-in is at a specific named
    location. When a policy includes or excludes specific locations whose trust status matches the
    flag (or is unknown), the result is signal-dependent instead of a definitive match. The same
    holds for a named location when the policy lists a location of the other kind (IP vs country)
    that the sign-in could also be in.
    """
    locs = ((detail.get("Conditions", {}) or {}).get("Locations", {}) or {})
    if not locs:
        return ConditionEval(matched=True, reason="Locations: no location condition present")

    has_location = signin_ctx.location_id is not None
    has_trusted = signin_ctx.trusted_location is not None

    if not has_location and not has_trusted:
        return ConditionEval(matched=True, reason="Locations: scenario location not provided", runtime_dependent=True)

    include_blocks = locs.get("Include") or []
    exclude_blocks = locs.get("Exclude") or []

    inc_locs: Set[str] = set()
    exc_locs: Set[str] = set()

    for blk in include_blocks:
        inc_locs.update(blk.get("Locations", []) or [])
    for blk in exclude_blocks:
        exc_locs.update(blk.get("Locations", []) or [])

    if location_trust_map is None:
        location_trust_map = {}
    if location_kinds is None:
        location_kinds = {}

    def _overlapping(ids: Set[str]) -> List[str]:
        # Listed locations the named location may overlap with. AllTrusted is decided by an explicit flag.
        return [
            l for l in ids - {"All"}
            if not (l == "AllTrusted" and has_trusted)
            and _may_overlap(signin_ctx.location_id, l, location_kinds)
        ]

    # Derive trusted status from the selected location when not explicitly set
    is_from_trusted = signin_ctx.trusted_location
    if is_from_trusted is None and has_location:
        is_from_trusted = bool(_location_trust(signin_ctx.location_id, location_trust_map))

    # --- Exclusions ---
    exc_note = None
    if exc_locs:
        if "All" in exc_locs:
            return ConditionEval(matched=False, reason="Locations: policy excludes All locations")

        if "AllTrusted" in exc_locs and is_from_trusted:
            return ConditionEval(matched=False, reason="Locations: user in trusted location, policy excludes AllTrusted")

        if has_location and signin_ctx.location_id in exc_locs:
            return ConditionEval(matched=False, reason=f"Locations: user at excluded location ({signin_ctx.location_id})")

        if has_location:
            possible = _overlapping(exc_locs)
            if possible:
                exc_note = (
                    f"Locations: policy excludes location(s) of another type ({_fmt_locs(possible)}); "
                    f"the sign-in could be in one of them as well"
                )
        else:
            # Only a trusted flag: the sign-in could be at any excluded location with the same trust status.
            possible = [
                l for l in exc_locs - {"All", "AllTrusted"}
                if _location_trust(l, location_trust_map) in (None, is_from_trusted)
            ]
            if possible:
                exc_note = (
                    f"Locations: policy excludes specific {'trusted' if is_from_trusted else 'untrusted'} "
                    f"location(s) ({_fmt_locs(possible)}); trusted flag cannot tell if the sign-in is at one of them"
                )

    def _matched(reason: str) -> ConditionEval:
        if exc_note:
            return ConditionEval(matched=True, reason=exc_note, runtime_dependent=True)
        return ConditionEval(matched=True, reason=reason)

    # --- Inclusions ---
    if not inc_locs:
        return _matched("Locations: no location inclusion specified")

    if "All" in inc_locs:
        return _matched("Locations: policy includes All locations")

    if has_location:
        if signin_ctx.location_id in inc_locs:
            return _matched(f"Locations: user at included location ({signin_ctx.location_id})")
        if "AllTrusted" in inc_locs and is_from_trusted:
            return _matched("Locations: user in trusted location, policy includes AllTrusted")
        possible_inc = _overlapping(inc_locs)
        if possible_inc:
            return ConditionEval(
                matched=True,
                reason=(
                    f"Locations: policy includes location(s) of another type ({_fmt_locs(possible_inc)}); "
                    f"the sign-in could be in one of them as well"
                ),
                runtime_dependent=True,
            )
        return ConditionEval(matched=False, reason="Locations: user location not in include list")

    # No specific location, only trusted flag
    if "AllTrusted" in inc_locs and is_from_trusted:
        return _matched("Locations: user in trusted location, policy includes AllTrusted")

    possible_inc = [
        l for l in inc_locs - {"All", "AllTrusted"}
        if _location_trust(l, location_trust_map) in (None, is_from_trusted)
    ]
    if possible_inc:
        return ConditionEval(
            matched=True,
            reason=(
                f"Locations: policy includes specific {'trusted' if is_from_trusted else 'untrusted'} "
                f"location(s) ({_fmt_locs(possible_inc)}); trusted flag cannot tell if the sign-in is at one of them"
            ),
            runtime_dependent=True,
        )

    if "AllTrusted" in inc_locs:
        return ConditionEval(matched=False, reason="Locations: policy requires a trusted location, user not in trusted location")
    return ConditionEval(
        matched=False,
        reason=f"Locations: policy only includes {'untrusted' if is_from_trusted else 'trusted'} locations, "
               f"user in {'trusted' if is_from_trusted else 'untrusted'} location",
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

def _eval_device_state_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    """
    Evaluate device state conditions (compliance, hybrid joined, domain joined).
    Handles both Include and Exclude blocks.
    """
    cond = (detail.get("Conditions", {}) or {})
    device_states = cond.get("DeviceStates") or {}

    if not device_states:
        return ConditionEval(matched=True, reason="DeviceState: no device state condition present")

    include_blocks = device_states.get("Include") or []
    exclude_blocks = device_states.get("Exclude") or []

    inc_states: Set[str] = set()
    exc_states: Set[str] = set()

    for blk in include_blocks:
        vals = blk.get("DeviceStates") or []
        inc_states.update(str(v).lower() for v in vals)

    for blk in exclude_blocks:
        vals = blk.get("DeviceStates") or []
        exc_states.update(str(v).lower() for v in vals)

    if not inc_states and not exc_states:
        return ConditionEval(matched=True, reason="DeviceState: no device state requirements")

    # Check if we have the required signals
    has_compliant_signal = signin_ctx.device_compliant is not None
    has_joined_signal = signin_ctx.device_hybrid_joined is not None

    # Determine what states are being checked
    checks_compliant = "compliant" in inc_states or "compliant" in exc_states
    checks_joined = any(x in inc_states or x in exc_states for x in ["domainjoined", "hybridazureaadjoined"])

    # If policy checks states we don't have signals for, return runtime-dependent
    if checks_compliant and not has_compliant_signal:
        return ConditionEval(matched=True, reason="DeviceState: policy checks compliance but signal not provided", runtime_dependent=True)
    if checks_joined and not has_joined_signal:
        return ConditionEval(matched=True, reason="DeviceState: policy checks join state but signal not provided", runtime_dependent=True)

    # FIRST: Check exclusions - if device matches an exclusion, policy does NOT apply
    if exc_states:
        if signin_ctx.device_compliant is True and "compliant" in exc_states:
            return ConditionEval(matched=False, reason="DeviceState: device is compliant, policy excludes compliant devices")
        if signin_ctx.device_compliant is False and any(x in exc_states for x in ["noncompliant", "non-compliant"]):
            return ConditionEval(matched=False, reason="DeviceState: device is non-compliant, policy excludes non-compliant devices")
        if signin_ctx.device_hybrid_joined is True and any(x in exc_states for x in ["domainjoined", "hybridazureaadjoined"]):
            return ConditionEval(matched=False, reason="DeviceState: device is hybrid joined, policy excludes joined devices")
        if signin_ctx.device_hybrid_joined is False and not any(x in exc_states for x in ["domainjoined", "hybridazureaadjoined"]):
            # Device is not joined, and exclusion is not for joined devices
            pass

    # SECOND: Check inclusions - if device matches an inclusion, policy applies
    if not inc_states:
        # No inclusions means no requirement
        return ConditionEval(matched=True, reason="DeviceState: no device state inclusions specified")

    # Check if device state matches any inclusion
    matched = False
    reason_parts = []

    if "compliant" in inc_states:
        if signin_ctx.device_compliant is True:
            matched = True
            reason_parts.append("device is compliant")
        elif signin_ctx.device_compliant is False:
            reason_parts.append("policy requires compliant device, but device is non-compliant")
            return ConditionEval(matched=False, reason=f"DeviceState: {', '.join(reason_parts)}")

    if any(x in inc_states for x in ["domainjoined", "hybridazureaadjoined"]):
        if signin_ctx.device_hybrid_joined is True:
            matched = True
            reason_parts.append("device is hybrid joined")
        elif signin_ctx.device_hybrid_joined is False:
            reason_parts.append("policy requires joined device, but device is not joined")
            if not matched:  # Only return false if we didn't already match on another condition
                return ConditionEval(matched=False, reason=f"DeviceState: {', '.join(reason_parts)}")

    if matched:
        return ConditionEval(matched=True, reason=f"DeviceState: {', '.join(reason_parts)}")

    # No match found
    return ConditionEval(matched=False, reason="DeviceState: device state does not match policy requirements")


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

_CLIENT_APP_CATEGORIES = {
    "browser": {"browser"},
    "mobileappsanddesktopclients": {"native"},
    "exchangeactivesync": {"eassupported", "easunsupported"},
    "other": {
        "otherlegacy", "legacysmtp", "legacypop", "legacyimap",
        "legacymapi", "legacyoffice",
    },
}
_CLIENT_APP_TYPES = set().union(*_CLIENT_APP_CATEGORIES.values())


def _client_app_members(value: str) -> Set[str]:
    value = str(value).strip().lower()
    return _CLIENT_APP_CATEGORIES.get(value, {value})


def _client_app_values(values) -> list:
    # Accept a single stored value without splitting it into characters.
    return [values] if isinstance(values, str) else (values or [])


def _client_app_set(values: list) -> Tuple[Set[str], bool, List[str]]:
    members: Set[str] = set()
    includes_all = False
    unknown: List[str] = []
    for value in values:
        if value is None or not str(value).strip():
            continue
        normalized = str(value).strip().lower()
        if normalized == "all":
            includes_all = True
        elif normalized in _CLIENT_APP_TYPES or normalized in _CLIENT_APP_CATEGORIES:
            members.update(_client_app_members(normalized))
        else:
            unknown.append(str(value).strip())
    return members, includes_all, unknown


def _eval_client_app_condition(detail: Dict[str, Any], signin_ctx: SignInContext) -> ConditionEval:
    cond = (detail.get("Conditions", {}) or {})
    inc_values = _client_app_values(cond.get("ClientAppTypes"))
    exc_values = []
    ct = cond.get("ClientTypes") or {}
    if ct:
        # Keep the existing preference for ROADrecon blocks when present.
        inc_values = []
        for blk in ct.get("Include") or []:
            inc_values.extend(_client_app_values(blk.get("ClientTypes")))
        for blk in ct.get("Exclude") or []:
            exc_values.extend(_client_app_values(blk.get("ClientTypes")))

    inc, inc_all, inc_unknown = _client_app_set(inc_values)
    exc, exc_all, exc_unknown = _client_app_set(exc_values)
    if exc_all:
        return ConditionEval(matched=False, reason="ClientApp: excluded All")
    if not (inc or inc_all or inc_unknown or exc or exc_unknown):
        return ConditionEval(matched=True, reason="ClientApp: no client app type condition present")
    if signin_ctx.client_app is None:
        return ConditionEval(matched=True, reason="ClientApp: scenario client_app not provided", runtime_dependent=True)

    got = str(signin_ctx.client_app).strip().lower()
    if got not in _CLIENT_APP_TYPES and got not in _CLIENT_APP_CATEGORIES:
        return ConditionEval(matched=True, reason=f"ClientApp: unrecognized scenario client_app ({got})", runtime_dependent=True)

    scenario_members = _client_app_members(got)
    implicit_all = not (inc or inc_all or inc_unknown)
    included = scenario_members if inc_all or implicit_all else scenario_members & inc
    # Unknown includes may cover otherwise unmatched subtypes; unknown excludes
    # may remove known matches. Explicit exclusions always win.
    possible = (scenario_members if inc_unknown else included) - exc
    definite = (included - exc) if not exc_unknown else set()
    if not possible:
        return ConditionEval(matched=False, reason=f"ClientApp: no included, non-excluded subtype matched ({got})")
    if scenario_members <= definite:
        return ConditionEval(matched=True, reason=f"ClientApp: matched ({got})")

    notes = []
    if inc_unknown:
        notes.append("unrecognized include value(s): " + ", ".join(inc_unknown))
    if exc_unknown:
        notes.append("unrecognized exclude value(s): " + ", ".join(exc_unknown))
    if not notes:
        notes.append("policy covers only part of category; actual protocol or subtype not provided")
    return ConditionEval(matched=True, reason=f"ClientApp: signal-dependent ({got}); " + "; ".join(notes), runtime_dependent=True)

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

def evaluate_conditions(detail: Dict[str, Any], signin_ctx: SignInContext, location_trust_map: Dict[str, bool] = None, location_kinds: Dict[str, str] = None) -> Tuple[bool, List[str], List[str]]:
    policy_mode = _policy_target_mode(detail)

    evals: List[ConditionEval] = []
    evals.append(_eval_app_condition(detail, signin_ctx, policy_mode))
    evals.append(_eval_acr_condition(detail, signin_ctx, policy_mode))
    evals.append(_eval_trusted_location_condition(detail, signin_ctx, location_trust_map, location_kinds))
    evals.append(_eval_device_state_condition(detail, signin_ctx))
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
