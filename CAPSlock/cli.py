from __future__ import annotations
import argparse
from CAPSlock.db import DB_PATH, get_session
from CAPSlock.models import SignInContext
from CAPSlock.normalize import normalize_bool_str, normalize_unknown_str
from CAPSlock.query import get_policy_results_for_user, convert_from_id, convert_from_name
from CAPSlock.printers import print_sections_get_policies, print_sections_what_if


def _add_common_user_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-u", "--user", required=True, help="User UPN")
    p.add_argument("--db", default=DB_PATH, help="Path to roadrecon.db (default: roadrecon.db)")


def cmd_get_policies(args) -> int:
    session = get_session(args.db)
    try:
        signin_ctx = SignInContext(app_id=args.app)

        results = get_policy_results_for_user(
            session=session,
            user_upn=args.user.strip().lower(),
            signin_ctx=signin_ctx,
            mode="get-policies",
        )

        print(f"\nPolicies for user: {args.user}")
        print("=" * 64)

        print_sections_get_policies(results, args.results.lower())
        return 0
    finally:
        session.close()


def cmd_what_if(args) -> int:
    session = get_session(args.db)
    try:
        # Policy can either be for resource or user action but not both
        if args.resource and args.acr:
            raise SystemExit("[!] Invalid scenario: --resource and --acr are mutually exclusive (choose one).")

        signin_ctx = SignInContext(
            app_id=normalize_unknown_str(args.resource),
            acr=normalize_unknown_str(args.acr),
            trusted_location=normalize_bool_str(args.trusted_location),
            platform=(normalize_unknown_str(args.platform).lower() if normalize_unknown_str(args.platform) else None),
            client_app=normalize_unknown_str(args.client_app),
            signin_risk=(normalize_unknown_str(args.signin_risk).lower() if normalize_unknown_str(args.signin_risk) else None),
            user_risk=(normalize_unknown_str(getattr(args, "user_risk", None)).lower() if normalize_unknown_str(getattr(args, "user_risk", None)) else None),
            auth_flow=(normalize_unknown_str(getattr(args, "auth_flow", None)).lower() if normalize_unknown_str(getattr(args, "auth_flow", None)) else None),
            device_filter=normalize_bool_str(getattr(args, "device_filter", None)),
            # accepted but not evaluated yet
            device_hybrid_joined=normalize_bool_str(getattr(args, "entra_joined", None)),
            device_compliant=normalize_bool_str(getattr(args, "device_compliant", None)),
        )

        results = get_policy_results_for_user(
            session=session,
            user_upn=args.user.strip().lower(),
            signin_ctx=signin_ctx,
            mode="what-if",
        )

        print(f"\nWhat-If policies for user: {args.user}")
        print("=" * 64)
        print("Scenario:")
        print(f"  resource:         {signin_ctx.app_id}")
        print(f"  acr:              {signin_ctx.acr}")
        print(f"  trusted_location: {signin_ctx.trusted_location}")
        print(f"  platform:         {signin_ctx.platform}")
        print(f"  client_app:       {signin_ctx.client_app}")
        print(f"  signin_risk:      {signin_ctx.signin_risk}")
        print(f"  user_risk:        {signin_ctx.user_risk}")
        print(f"  auth_flow:        {signin_ctx.auth_flow}")
        print(f"  device_filter:    {signin_ctx.device_filter}")
        print()

        print_sections_what_if(results, strict=bool(getattr(args, "strict", False)))
        return 0
    finally:
        session.close()

from CAPSlock.query import convert_from_id, convert_from_name

def cmd_convert(args) -> int:
    session = get_session(args.db)
    try:
        if getattr(args, "object_id", None):
            lines = convert_from_id(session, args.object_id)
        else:
            lines = convert_from_name(session, args.friendly_name)

        for line in lines:
            print(line)

        return 0
    finally:
        session.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CAPSlock",
        description="CAPSlock Conditional Access analysis helper",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # get-policies parser
    p1 = sub.add_parser("get-policies", help="List CA policies by user targeting")
    _add_common_user_args(p1)
    p1.add_argument("--app", default=None, help="Optional app id / logical name (filters app condition only if provided)")
    p1.add_argument("--results", choices=["applied", "exclusions", "all"], default="applied")
    p1.set_defaults(func=cmd_get_policies)

    # what-if parser
    p2 = sub.add_parser("what-if", help="Evaluate CA policies for a hypothetical sign-in context")
    _add_common_user_args(p2)

    p2.add_argument("--resource", default="All", help="[Optional] Resource / cloud app / resource set (Default = All)")
    p2.add_argument("--acr", default=None, help="User action / ACR (e.g. urn:user:registerdevice) (optional)")

    p2.add_argument("--trusted-location", default=None, choices=["true", "false"], help="[optional] Trusted location flag")
    p2.add_argument("--platform", default="windows", choices=["windows", "macos", "linux", "ios", "android"], help="Device platform (Default = windows)")
    p2.add_argument("--client-app", default=None, choices=["browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"], help="Client app type (optional)")
    p2.add_argument("--signin-risk", default=None, choices=["none", "low", "medium", "high"], help="Sign-in risk level (optional)")
    p2.add_argument("--user-risk", default=None, choices=["low", "medium", "high"], help="User risk level (optional)")
    p2.add_argument("--auth-flow", default=None, choices=["devicecodeflow", "authtransfer"], help="Authentication flow (optional)")
    p2.add_argument("--device-filter", default=None, choices=["true", "false"], help="Device filter match flag (optional)")

    # Come back later to implement
    p2.add_argument("--entra-joined", default=None, choices=["true", "false"], help="Entra joined flag (accepted, not evaluated in MVP2)")
    p2.add_argument("--device-compliant", default=None, choices=["true", "false"], help="Device compliance flag (accepted, not evaluated in MVP2)")

    p2.add_argument("--strict", action="store_true", help="Only show policies that definitively apply (hide runtime-dependent policies)")
    p2.set_defaults(func=cmd_what_if)

    #Convert parser
    p3 = sub.add_parser("convert", help="Convert ID <-> friendly name using roadrecon.db")
    p3.add_argument("--db", default=DB_PATH, help="Path to roadrecon.db (default: roadrecon.db)")

    g = p3.add_mutually_exclusive_group(required=True)
    g.add_argument("-id", "--id", dest="object_id", help="Object ID (GUID)")
    g.add_argument("-name", "--name", dest="friendly_name", help="Friendly name / UPN / displayName")
    p3.set_defaults(func=cmd_convert)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())