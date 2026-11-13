from __future__ import annotations
from typing import Any, Iterable, Optional, Set, Tuple

# Guest and external user targeting (Conditions.Users "GuestsOrExternalUsers").
#
# roadrecon stores the condition in policyDetail as an include or exclude block:
#   {"GuestsOrExternalUsers": {"GuestOrExternalUserTypes": "InternalGuest, B2bCollaborationGuest, ...",
#                              "ExternalTenants": ...}}
# ExternalTenants is missing when the policy covers all external tenants. When present it is read
# like Graph's conditionalAccessExternalTenants ({"membershipKind": "all"} or
# {"membershipKind": "enumerated", "members": [<tenant id>, ...]}) or as a plain list of tenant ids.
# Any other shape is reported as signal-dependent.
# Older policies use a plain "GuestsOrExternalUsers" or "Guests" value in the Users list instead.
#
# Entra assigns one external user type per sign-in. Offline we only have the user object in
# roadrecon.db, so this module classifies a user from userType and whether the account is external.
# An account counts as external when the UPN has "#EXT#", creationType is "Invitation", or
# originTenantInfo names a home tenant. An invited user whose UPN was renamed
# and whose creationType is not set is treated as a local account.
#
#   userType Guest  + external account -> b2bCollaborationGuest  (guest)
#   userType Guest  + local account    -> internalGuest
#   other userType  + external account -> b2bCollaborationMember (member)
#   other userType  + local account    -> not external
#
# What cannot be determined offline:
#   - b2bDirectConnectUser: these users have no user object in the resource tenant, but Entra also
#     applies policies that target them to B2B collaboration users who access Teams or SharePoint
#     Online. For a B2B collaboration user this is reported as signal-dependent (depends on the app).
#   - serviceProvider: GDAP/partner admins have no user object in the resource tenant, so this
#     module does not assign the type.
#   - otherExternalUser: Entra's catch-all for external users that fit no other category. It cannot
#     be told apart from the types above with the data roadrecon collects, so this module never
#     assigns it. A policy that only targets otherExternalUser does not match.
#   - The home tenant is only known when originTenantInfo is filled. It is filled for invited users
#     who redeemed with a Microsoft Entra account and for cross-tenant sync users. It is empty for
#     unredeemed invites and for Microsoft account, social or one-time-code guests. For other users,
#     a type match in a block limited to specific ExternalTenants is reported as signal-dependent
#     instead of a definitive match.

INTERNAL_GUEST = "internalguest"
B2B_COLLABORATION_GUEST = "b2bcollaborationguest"
B2B_COLLABORATION_MEMBER = "b2bcollaborationmember"
B2B_DIRECT_CONNECT_USER = "b2bdirectconnectuser"
OTHER_EXTERNAL_USER = "otherexternaluser"
SERVICE_PROVIDER = "serviceprovider"

# Legacy values in a Users include/exclude list that mean "all guest and external users".
LEGACY_USER_VALUES = {"guests", "guestsorexternalusers"}

DISPLAY_NAMES = {
    INTERNAL_GUEST: "internalGuest",
    B2B_COLLABORATION_GUEST: "b2bCollaborationGuest",
    B2B_COLLABORATION_MEMBER: "b2bCollaborationMember",
    B2B_DIRECT_CONNECT_USER: "b2bDirectConnectUser",
    OTHER_EXTERNAL_USER: "otherExternalUser",
    SERVICE_PROVIDER: "serviceProvider",
}

MATCH = "match"
UNCERTAIN = "uncertain"


def home_tenant_id(user: Any) -> Optional[str]:
    """Home tenant id from roadrecon originTenantInfo, if filled.

    Filled for invited users who redeemed with a Microsoft Entra account and for cross-tenant sync
    users. Empty for unredeemed invites and for Microsoft account, social or one-time-code guests.
    """
    info = getattr(user, "originTenantInfo", None)
    if isinstance(info, dict):
        tid = info.get("originTenantId") or info.get("OriginTenantId")
        if tid:
            return str(tid).strip().lower()
    return None


def classify_external_user(user: Any) -> Optional[str]:
    """Return the external user type for a roadrecon User, or None for an internal member."""
    user_type = str(getattr(user, "userType", "") or "").strip().lower()
    upn = str(getattr(user, "userPrincipalName", "") or "").lower()
    creation_type = str(getattr(user, "creationType", "") or "").strip().lower()
    external_account = "#ext#" in upn or creation_type == "invitation" or home_tenant_id(user) is not None

    if user_type == "guest":
        return B2B_COLLABORATION_GUEST if external_account else INTERNAL_GUEST
    if external_account:
        return B2B_COLLABORATION_MEMBER
    return None


def is_legacy_value(value: Any) -> bool:
    return str(value).strip().lower() in LEGACY_USER_VALUES


def _parse_types(raw: Any) -> Set[str]:
    if raw is None:
        return set()
    if isinstance(raw, str):
        items: Iterable[Any] = raw.split(",")
    elif isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        items = [raw]
    return {str(x).strip().lower() for x in items if str(x).strip()}


def _tenant_scope(raw: Any) -> Tuple[str, Optional[Set[str]]]:
    """Read ExternalTenants. Returns ("all", None), ("enumerated", {tenant ids}) or ("unknown", None)."""
    if raw is None or raw == "" or raw == []:
        return "all", None
    if isinstance(raw, str):
        return ("all", None) if raw.strip().lower() == "all" else ("unknown", None)
    if isinstance(raw, (list, tuple)):
        if all(isinstance(x, str) for x in raw):
            vals = {x.strip().lower() for x in raw if x.strip()}
            if "all" in vals:
                return "all", None
            if vals:
                return "enumerated", vals
        return "unknown", None
    if isinstance(raw, dict):
        d = {str(k).lower(): v for k, v in raw.items()}
        kind = str(d.get("membershipkind") or "").strip().lower()
        members = d.get("members")
        if kind == "all":
            return "all", None
        if kind == "enumerated" and isinstance(members, list) and members and all(isinstance(x, str) for x in members):
            return "enumerated", {x.strip().lower() for x in members}
    return "unknown", None


def match_external_block(spec: Any, ext_type: Optional[str], home_tenant: Optional[str] = None) -> Tuple[Optional[str], str]:
    """Match a GuestsOrExternalUsers block against a user's external type.

    Returns (MATCH, ""), (UNCERTAIN, why), or (None, "") for no match.
    """
    if ext_type is None or not isinstance(spec, dict):
        return None, ""

    types = _parse_types(spec.get("GuestOrExternalUserTypes", spec.get("guestOrExternalUserTypes")))
    if ext_type in types:
        matched = display_type(ext_type)
        app_note = ""
    elif B2B_DIRECT_CONNECT_USER in types and ext_type in (B2B_COLLABORATION_GUEST, B2B_COLLABORATION_MEMBER):
        # Entra applies b2bDirectConnectUser policies to B2B collaboration users in Teams/SharePoint Online.
        matched = display_type(B2B_DIRECT_CONNECT_USER)
        app_note = " (also applies to B2B collaboration users in Teams and SharePoint Online, depends on target app)"
    else:
        return None, ""

    kind, members = _tenant_scope(spec.get("ExternalTenants", spec.get("externalTenants")))
    if kind == "enumerated" and home_tenant is not None:
        if home_tenant not in members:
            return None, ""
        kind = "all"
    if kind == "enumerated":
        return UNCERTAIN, f"{matched} users from specific external tenants (user's home tenant unknown){app_note}"
    if kind == "unknown":
        return UNCERTAIN, f"{matched} users with an unrecognized ExternalTenants value{app_note}"
    if app_note:
        return UNCERTAIN, f"{matched} users{app_note}"
    return MATCH, ""


def display_type(ext_type: Optional[str]) -> str:
    return DISPLAY_NAMES.get(ext_type or "", ext_type or "")


def describe_block(spec: Any) -> str:
    """Short human-readable form of a GuestsOrExternalUsers block."""
    if not isinstance(spec, dict):
        return str(spec)
    types = _parse_types(spec.get("GuestOrExternalUserTypes", spec.get("guestOrExternalUserTypes")))
    names = [DISPLAY_NAMES.get(t, t) for t in sorted(types)] or ["(no types)"]
    text = ", ".join(names)
    kind, members = _tenant_scope(spec.get("ExternalTenants", spec.get("externalTenants")))
    if kind == "enumerated":
        count = len(members)
        text += f" (from {count} specific external tenant{'s' if count != 1 else ''})"
    elif kind == "unknown":
        text += " (unrecognized ExternalTenants value)"
    return text
