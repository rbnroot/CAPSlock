from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

@dataclass
class UserContext:
    user: User
    object_id: str
    groups: Set[str]
    role_object_ids: Set[str]
    role_template_ids: Set[str]
    assumed_groups: Set[str] = None
    assumed_roles: Set[str] = None

    def __post_init__(self):
        if self.assumed_groups is None:
            self.assumed_groups = set()
        if self.assumed_roles is None:
            self.assumed_roles = set()


@dataclass
class SignInContext:
    # App / resource
    app_id: Optional[str] = None   
    acr: Optional[str] = None

    # Location
    trusted_location: Optional[bool] = None

    # Device
    device_compliant: Optional[bool] = None          # Update later 
    device_hybrid_joined: Optional[bool] = None      # Update later
    platform: Optional[str] = None

    # Client app
    client_app: Optional[str] = None

    # Risk
    signin_risk: Optional[str] = None
    user_risk: Optional[str] = None

    # Auth flow
    auth_flow: Optional[str] = None

    # Device filter (bool)
    device_filter: Optional[bool] = None


@dataclass
class PolicyResult:
    applies: bool
    effect: str
    controls: List[str]
    state: str
    policy: Policy
    detail: Dict[str, Any]
    applies_reason: str


@dataclass
class NameResolver:
    group_names_by_id: Dict[str, str]
    role_names_by_template_id: Dict[str, str]
    role_names_by_object_id: Dict[str, str]

    def group_name(self, gid: str) -> str:
        name = self.group_names_by_id.get(gid)
        return f"{name} ({gid})" if name else gid

    def role_name(self, rid: str) -> str:
        name = (
            self.role_names_by_template_id.get(rid)
            or self.role_names_by_object_id.get(rid)
        )
        return f"{name} ({rid})" if name else rid


@dataclass
class TargetingResult:
    status: str
    applies_reason: str
    include_via: str = ""
    exclude_via: str = ""
    matched_include_users: List[str] = None
    matched_include_groups: List[str] = None
    matched_include_roles: List[str] = None
    matched_exclude_users: List[str] = None
    matched_exclude_groups: List[str] = None
    matched_exclude_roles: List[str] = None


@dataclass
class ConditionEval:
    matched: bool
    reason: str
    runtime_dependent: bool = False