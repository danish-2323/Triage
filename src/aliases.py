"""
Normalisation helpers for matching product names typed by a user
against product names present in the vulnerability dataset.

Kept deliberately simple: lowercase, strip punctuation/whitespace,
and a small alias table for common shorthand. This is NOT a universal
CPE parser by design (out of scope per the challenge brief).
"""

import re

# Small, documented alias table. Extend as needed.
ALIASES = {
    "core banking": "core banking framework",
    "banking framework": "core banking framework",
    "idp": "identity provider saas",
    "identity provider": "identity provider saas",
    "sso": "identity provider saas",
    "cloud db": "cloud database engine",
    "database engine": "cloud database engine",
    "db engine": "cloud database engine",
    "waf": "web application firewall",
    "app firewall": "web application firewall",
    "iot gateway": "embedded iot gateway",
    "iot": "embedded iot gateway",
    "router os": "enterprise router os",
    "router": "enterprise router os",
}


def normalize(name: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation, apply alias table."""
    if not isinstance(name, str) or not name.strip():
        return ""
    cleaned = name.strip().lower()
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return ALIASES.get(cleaned, cleaned)


def names_match(a: str, b: str) -> bool:
    """True if two product name strings refer to the same normalised product."""
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    # loose containment match for things like "Cloud Database Engine v2"
    return na in nb or nb in na
