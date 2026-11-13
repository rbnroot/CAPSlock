from __future__ import annotations
import argparse
import os
import sys
from CAPSlock.db import DB_PATH, get_session
from CAPSlock.models import SignInContext
from CAPSlock.conditions import LEGACY_MFA_TRUSTED_IPS_ID
from CAPSlock.normalize import normalize_bool_str, normalize_unknown_str
from CAPSlock.query import (
    get_policy_results_for_user,
    convert_from_id,
    convert_from_name,
    list_named_locations,
    resolve_named_location,
)
from CAPSlock.printers import print_sections_get_policies, print_sections_what_if
from CAPSlock.resolvers import build_name_resolver
from CAPSlock.analyze import analyze, write_outputs

def _add_common_user_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-u", "--user", required=True, help="User UPN")
    p.add_argument("--db", default=DB_PATH, help="Path to roadrecon.db (default: roadrecon.db)")


TRUSTED_LOCATION_HELP = (
    "Sign in from some trusted (true) or untrusted (false) location without naming it. "
    "Matches AllTrusted, but cannot match a specific named location: policies that include or "
    "exclude specific locations with that trust status are shown as signal-dependent. "
    "Use --location for a definitive answer. With --location, this overrides the location's trust status."
)

LOCATION_HELP = (
    "Sign in from this named location (display name or ID, see 'list-locations'). "
    "Matched against the location IDs that policies include or exclude. The sign-in is placed in this "
    "one location; policies that list a location of the other kind (IP vs country) are shown as signal-dependent."
)


def _resolve_location_arg(session, value):
    """Return (location_id, label) for --location, or (None, None) when not given."""
    if not value:
        return None, None
    loc = resolve_named_location(session, value)
    label = f"{loc['name']} ({loc['id']}) [{'trusted' if loc['is_trusted'] else 'not trusted'}]"
    return loc["id"], label


def cmd_get_policies(args) -> int:
    session = get_session(args.db)
    try:
        resolver = build_name_resolver(session)
        signin_ctx = SignInContext(app_id=args.app)

        assume_groups = getattr(args, "assume_group", None) or []
        assume_roles = getattr(args, "assume_role", None) or []

        try:
            results = get_policy_results_for_user(
                session=session,
                user_upn=args.user.strip().lower(),
                signin_ctx=signin_ctx,
                mode="get-policies",
                assume_groups=assume_groups,
                assume_roles=assume_roles,
                resolver=resolver,
            )
        except ValueError as e:
            print(f"[!] {e}")
            return 1

        print(f"\nPolicies for user: {args.user}")
        print("=" * 64)

        if assume_groups or assume_roles:
            print("Assumed memberships:")
            if assume_groups:
                print(f"  Groups: {', '.join(assume_groups)}")
            if assume_roles:
                print(f"  Roles:  {', '.join(assume_roles)}")
            print()

        print_sections_get_policies(results, args.results.lower(), resolver=resolver)
        return 0
    finally:
        session.close()


def cmd_what_if(args) -> int:
    session = get_session(args.db)
    try:
        resolver = build_name_resolver(session)
        # Policy can either be for resource or user action but not both
        if args.resource and args.acr:
            raise SystemExit("[!] Invalid scenario: --resource and --acr are mutually exclusive (choose one).")

        try:
            location_id, location_label = _resolve_location_arg(session, getattr(args, "location", None))
        except ValueError as e:
            print(f"[!] {e}")
            return 1

        signin_ctx = SignInContext(
            app_id=normalize_unknown_str(args.resource),
            acr=normalize_unknown_str(args.acr),
            trusted_location=normalize_bool_str(args.trusted_location),
            location_id=location_id,
            platform=(normalize_unknown_str(args.platform).lower() if normalize_unknown_str(args.platform) else None),
            client_app=normalize_unknown_str(args.client_app),
            signin_risk=(normalize_unknown_str(args.signin_risk).lower() if normalize_unknown_str(args.signin_risk) else None),
            user_risk=(normalize_unknown_str(getattr(args, "user_risk", None)).lower() if normalize_unknown_str(getattr(args, "user_risk", None)) else None),
            auth_flow=(normalize_unknown_str(getattr(args, "auth_flow", None)).lower() if normalize_unknown_str(getattr(args, "auth_flow", None)) else None),
            device_filter=normalize_bool_str(getattr(args, "device_filter", None)),
            device_hybrid_joined=normalize_bool_str(getattr(args, "entra_joined", None)),
            device_compliant=normalize_bool_str(getattr(args, "device_compliant", None)),
        )

        assume_groups = getattr(args, "assume_group", None) or []
        assume_roles = getattr(args, "assume_role", None) or []

        try:
            results = get_policy_results_for_user(
                session=session,
                user_upn=args.user.strip().lower(),
                signin_ctx=signin_ctx,
                mode="what-if",
                assume_groups=assume_groups,
                assume_roles=assume_roles,
                resolver=resolver,
            )
        except ValueError as e:
            print(f"[!] {e}")
            return 1

        print(f"\nWhat-If policies for user: {args.user}")
        print("=" * 64)

        if assume_groups or assume_roles:
            print("Assumed memberships:")
            if assume_groups:
                print(f"  Groups: {', '.join(assume_groups)}")
            if assume_roles:
                print(f"  Roles:  {', '.join(assume_roles)}")
            print()

        print("Scenario:")
        print(f"  resource:            {signin_ctx.app_id}")
        print(f"  acr:                 {signin_ctx.acr}")
        print(f"  location:            {location_label}")
        print(f"  trusted_location:    {signin_ctx.trusted_location}")
        print(f"  platform:            {signin_ctx.platform}")
        print(f"  client_app:          {signin_ctx.client_app}")
        print(f"  signin_risk:         {signin_ctx.signin_risk}")
        print(f"  user_risk:           {signin_ctx.user_risk}")
        print(f"  auth_flow:           {signin_ctx.auth_flow}")
        print(f"  device_filter:       {signin_ctx.device_filter}")
        print(f"  device_compliant:    {signin_ctx.device_compliant}")
        print(f"  device_hybrid_joined: {signin_ctx.device_hybrid_joined}")
        print()

        print_sections_what_if(results, strict=bool(getattr(args, "strict", False)), resolver=resolver)
        return 0
    finally:
        session.close()

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


def cmd_list_locations(args) -> int:
    session = get_session(args.db)
    try:
        locations = list_named_locations(session)

        if all(loc["id"] == LEGACY_MFA_TRUSTED_IPS_ID for loc in locations):
            print("No named locations found in database.")
            return 0

        print(f"\nNamed Locations ({len(locations)} total)")
        print("=" * 80)

        for loc in locations:
            trust_label = "[TRUSTED]" if loc["is_trusted"] else "[NOT TRUSTED]"
            print(f"\n{loc['name']}")
            print(f"  ID:     {loc['id']}")
            print(f"  Status: {trust_label}")
            print(f"  Type:   {loc['type']}")

        print()
        print("Use the name or ID with: capslock what-if --location <name|id>")
        print()
        return 0
    finally:
        session.close()

def cmd_analyze(args) -> int:
    session = get_session(args.db)
    try:
        if args.resource and args.acr:
            raise SystemExit("[!] Invalid scenario: --resource and --acr are mutually exclusive (choose one).")
        if not args.resource and not args.acr:
            raise SystemExit("[!] Invalid scenario: you must provide --resource or --acr.")

        try:
            location_id, _ = _resolve_location_arg(session, getattr(args, "location", None))
        except ValueError as e:
            print(f"[!] {e}")
            return 1

        base = SignInContext(
            app_id=normalize_unknown_str(args.resource),
            acr=normalize_unknown_str(args.acr),
            trusted_location=None,
            platform=None,
            client_app=None,
            signin_risk=None,
            user_risk=None,
            auth_flow=None,
            device_filter=None,
            device_hybrid_joined=normalize_bool_str(getattr(args, "entra_joined", None)),
            device_compliant=normalize_bool_str(getattr(args, "device_compliant", None)),
        )

        fixed = {
            "trusted_location": normalize_bool_str(getattr(args, "trusted_location", None)),
            "location_id": location_id,
            "platform": (normalize_unknown_str(getattr(args, "platform", None)).lower() if normalize_unknown_str(getattr(args, "platform", None)) else None),
            "client_app": normalize_unknown_str(getattr(args, "client_app", None)),
            "signin_risk": (normalize_unknown_str(getattr(args, "signin_risk", None)).lower() if normalize_unknown_str(getattr(args, "signin_risk", None)) else None),
            "user_risk": (normalize_unknown_str(getattr(args, "user_risk", None)).lower() if normalize_unknown_str(getattr(args, "user_risk", None)) else None),
            "auth_flow": (normalize_unknown_str(getattr(args, "auth_flow", None)).lower() if normalize_unknown_str(getattr(args, "auth_flow", None)) else None),
            "device_filter": normalize_bool_str(getattr(args, "device_filter", None)),
        }

        assume_groups = getattr(args, "assume_group", None) or []
        assume_roles = getattr(args, "assume_role", None) or []

        summary, gaps = analyze(
            session=session,
            user_upn=args.user,
            base=base,
            fixed=fixed,
            max_scenarios=int(args.max_scenarios),
            assume_groups=assume_groups,
            assume_roles=assume_roles,
        )

        summary_path, gaps_path = write_outputs(summary, gaps, prefix=args.out)

        print()
        print("Analyze complete")
        print("=" * 64)
        print(f"Scenarios evaluated: {summary['scenarios_evaluated']}")
        print("Gap counts:")
        for k, v in summary["gap_counts"].items():
            print(f"  {k}: {v}")
        print()
        print(f"Summary: {summary_path}")
        print(f"Gaps:    {gaps_path}")
        print()

        return 0
    finally:
        session.close()


def cmd_web_gui(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("[!] uvicorn not installed. Install web dependencies:")
        print("    pip install -r web-gui/requirements.txt")
        return 1

    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    web_gui_dir = os.path.join(current_dir, "web-gui")

    if not os.path.exists(os.path.join(web_gui_dir, "api.py")):
        print(f"[!] Web GUI not found at {web_gui_dir}")
        return 1

    sys.path.insert(0, web_gui_dir)

    if args.db:
        db_path = os.path.abspath(args.db)
        if not os.path.isfile(db_path):
            print(f"[!] Database not found: {db_path}")
            return 1
        # Environment variable so the uvicorn worker (and --reload children) see it
        os.environ["CAPSLOCK_DB"] = db_path

    print("=" * 64)
    print("Starting CAPSlock Web GUI")
    print("=" * 64)
    if args.db:
        print(f"DB:   {os.environ['CAPSLOCK_DB']}")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"URL:  http://{args.host}:{args.port}")
    print("=" * 64)
    print()

    uvicorn.run(
        "api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )

    return 0


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
    p1.add_argument("--assume-group", dest="assume_group", nargs="*", help="Assume user is in these groups (group IDs or names)")
    p1.add_argument("--assume-role", dest="assume_role", nargs="*", help="Assume user has these roles (role IDs, template IDs, or names)")
    p1.set_defaults(func=cmd_get_policies)

    # what-if parser
    p2 = sub.add_parser("what-if", help="Evaluate CA policies for a hypothetical sign-in context")
    _add_common_user_args(p2)

    p2.add_argument("--resource", default="All", help="[Optional] Resource / cloud app / resource set (Default = All)")
    p2.add_argument("--acr", default=None, help="User action / ACR (e.g. urn:user:registerdevice) (optional)")

    p2.add_argument("--location", default=None, metavar="NAME_OR_ID", help=LOCATION_HELP)
    p2.add_argument("--trusted-location", default=None, choices=["true", "false"], help=TRUSTED_LOCATION_HELP)
    p2.add_argument("--platform", default="windows", choices=["windows", "macos", "linux", "ios", "android"], help="Device platform (Default = windows)")
    p2.add_argument("--client-app", default=None, choices=["browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"], help="Client app type (optional)")
    p2.add_argument("--signin-risk", default=None, choices=["none", "low", "medium", "high"], help="Sign-in risk level (optional)")
    p2.add_argument("--user-risk", default=None, choices=["low", "medium", "high"], help="User risk level (optional)")
    p2.add_argument("--auth-flow", default=None, choices=["devicecodeflow", "authtransfer"], help="Authentication flow (optional)")
    p2.add_argument("--device-filter", default=None, choices=["true", "false"], help="Device filter match flag (optional)")

    p2.add_argument("--entra-joined", default=None, choices=["true", "false"], help="Device Entra/Hybrid Azure AD joined flag (optional)")
    p2.add_argument("--device-compliant", default=None, choices=["true", "false"], help="Device compliance flag (optional)")

    p2.add_argument("--assume-group", dest="assume_group", nargs="*", help="Assume user is in these groups (group IDs or names)")
    p2.add_argument("--assume-role", dest="assume_role", nargs="*", help="Assume user has these roles (role IDs, template IDs, or names)")

    p2.add_argument("--strict", action="store_true", help="Only show policies that definitively apply (hide runtime-dependent policies)")
    p2.set_defaults(func=cmd_what_if)

    #Convert parser
    p3 = sub.add_parser("convert", help="Convert ID <-> friendly name using roadrecon.db")
    p3.add_argument("--db", default=DB_PATH, help="Path to roadrecon.db (default: roadrecon.db)")

    g = p3.add_mutually_exclusive_group(required=True)
    g.add_argument("-id", "--id", dest="object_id", help="Object ID (GUID)")
    g.add_argument("-name", "--name", dest="friendly_name", help="Friendly name / UPN / displayName")
    p3.set_defaults(func=cmd_convert)

    # List-locations parser
    p3b = sub.add_parser("list-locations", help="List all named locations with trust status")
    p3b.add_argument("--db", default=DB_PATH, help="Path to roadrecon.db (default: roadrecon.db)")
    p3b.set_defaults(func=cmd_list_locations)

    #Analyze parser
    p4 = sub.add_parser("analyze", help="Permute sign-in scenarios and report Conditional Access gaps")
    _add_common_user_args(p4)

    p4.add_argument("--resource", default=None, help="Resource / cloud app / resource set")
    p4.add_argument("--acr", default=None, help="User action / ACR (e.g. urn:user:registerdevice)")

    p4.add_argument("--location", default=None, metavar="NAME_OR_ID", help=LOCATION_HELP + " (fixed if provided)")
    p4.add_argument("--trusted-location", default=None, choices=["true", "false"], help=TRUSTED_LOCATION_HELP + " (fixed if provided)")
    p4.add_argument("--platform", default=None, choices=["windows", "macos", "linux", "ios", "android"], help="Device platform (fixed if provided)")
    p4.add_argument("--client-app", default=None, choices=["browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"], help="Client app type (fixed if provided)")
    p4.add_argument("--signin-risk", default=None, choices=["none", "low", "medium", "high"], help="Sign-in risk level (fixed if provided)")
    p4.add_argument("--user-risk", default=None, choices=["low", "medium", "high"], help="User risk level (fixed if provided)")
    p4.add_argument("--auth-flow", default=None, choices=["devicecodeflow", "authtransfer"], help="Authentication flow (fixed if provided)")
    p4.add_argument("--device-filter", default=None, choices=["true", "false"], help="Device filter match flag (fixed if provided)")

    p4.add_argument("--entra-joined", default=None, choices=["true", "false"], help="Device Entra/Hybrid Azure AD joined flag (fixed if provided)")
    p4.add_argument("--device-compliant", default=None, choices=["true", "false"], help="Device compliance flag (fixed if provided)")

    p4.add_argument("--assume-group", dest="assume_group", nargs="*", help="Assume user is in these groups (group IDs or names)")
    p4.add_argument("--assume-role", dest="assume_role", nargs="*", help="Assume user has these roles (role IDs, template IDs, or names)")

    p4.add_argument("--max-scenarios", default="1000", help="Maximum scenarios to evaluate (default 1000)")
    p4.add_argument("--out", default="capslock_analyze", help="Output file prefix (default capslock_analyze)")

    p4.set_defaults(func=cmd_analyze)

    # web-gui parser
    p5 = sub.add_parser("web-gui", help="Start the web interface")
    p5.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    p5.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    p5.add_argument("--reload", action="store_true", help="Enable auto-reload (for development)")
    p5.add_argument("--db", default=None, help="Path to roadrecon.db used as the web GUI default (default: roadrecon.db)")
    p5.set_defaults(func=cmd_web_gui)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())