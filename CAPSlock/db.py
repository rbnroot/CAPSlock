from __future__ import annotations
import json
import os
from typing import Any, Dict, List
from sqlalchemy.orm import sessionmaker
from roadtools.roadlib.metadef import database
from roadtools.roadlib.metadef.database import Policy


DB_PATH = "roadrecon.db"


def get_engine(db_path: str = DB_PATH):
    if not os.path.isabs(db_path):
        dburl = f"sqlite:///{os.path.join(os.getcwd(), db_path)}"
    else:
        dburl = f"sqlite:///{db_path}"

    return database.init(False, dburl=dburl)


def get_session(db_path: str = DB_PATH):
    engine = get_engine(db_path)
    Session = sessionmaker(bind=engine)
    return Session()

def load_capolicies(session) -> List[Policy]:
    # policyType == 18 => Conditional Access
    return session.query(Policy).filter(Policy.policyType == 18).all()


def parse_policy_details(policy: Policy) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    if not getattr(policy, "policyDetail", None):
        return details

    for raw in policy.policyDetail:
        try:
            details.append(json.loads(raw))
        except Exception as e:
            print(f"[!] Failed to parse policyDetail for {policy.displayName}: {e}")
    return details


def load_named_locations(session) -> Dict[str, bool]:
    """
    Load named locations from the database and return a map of location_id -> is_trusted.

    policyType == 6 => Named Locations
    A location is trusted if "trusted" is in the Categories array of its detail.

    Returns:
        Dict mapping location objectId to boolean indicating if it's trusted
    """
    location_trust_map: Dict[str, bool] = {}

    try:
        locations = session.query(Policy).filter(Policy.policyType == 6).all()

        for loc in locations:
            is_trusted = False
            if loc.policyDetail:
                for detail_raw in loc.policyDetail:
                    try:
                        detail = json.loads(detail_raw)
                        categories = detail.get("Categories", []) or []
                        if "trusted" in [str(c).lower() for c in categories]:
                            is_trusted = True
                            break
                    except:
                        pass

            location_trust_map[loc.objectId] = is_trusted

    except Exception as e:
        print(f"[!] Failed to load named locations: {e}")

    return location_trust_map