from __future__ import annotations
from typing import Optional


def normalize_bool_str(v: Optional[str]) -> Optional[bool]:
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "t", "1", "yes", "y"):
        return True
    if s in ("false", "f", "0", "no", "n"):
        return False
    if s in ("unknown", "unset", "none", ""):
        return None
    return None


def normalize_unknown_str(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if s.lower() in ("unknown", "unset", "none"):
        return None
    return s