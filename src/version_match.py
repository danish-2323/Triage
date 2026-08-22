"""
Version-range comparison for the production schema described in the
challenge brief's Appendix A (vendor, product, version_start, version_end,
version_note). This is deliberately NOT a full CPE parser -- it handles the
common case (clean dotted numeric versions, e.g. "2.4.51") and is honest
about everything else by returning NEEDS_VERIFICATION rather than guessing.

Outcomes (matches Figure 3 in the brief):
    AFFECTED          -> installed version falls inside [version_start, version_end]
    NOT_AFFECTED       -> installed version falls outside the range (safe to exclude)
    NEEDS_VERIFICATION -> range/installed version missing or not cleanly comparable
"""

from __future__ import annotations
import re
from enum import Enum
from typing import Optional


class VersionOutcome(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    NEEDS_VERIFICATION = "needs_verification"


_NUMERIC_VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}$")


def _parse(v: Optional[str]) -> Optional[tuple]:
    """Parse a clean numeric dotted version into a comparable tuple, else None."""
    if v is None:
        return None
    v = str(v).strip()
    if not v or not _NUMERIC_VERSION_RE.match(v):
        return None
    parts = [int(p) for p in v.split(".")]
    parts += [0] * (4 - len(parts))
    return tuple(parts)


def compare_version(
    installed_version: Optional[str],
    version_start: Optional[str],
    version_end: Optional[str],
    version_note: Optional[str],
) -> VersionOutcome:
    """
    Decide whether `installed_version` falls in the affected [start, end]
    range (both inclusive, either bound optionally unbounded/empty).
    """
    # An explicit note from the source data means the range is flagged as
    # not cleanly comparable -- never silently guess past it.
    if version_note and str(version_note).strip():
        return VersionOutcome.NEEDS_VERIFICATION

    if not installed_version or not str(installed_version).strip():
        # No installed version on record for this org's technology entry.
        return VersionOutcome.NEEDS_VERIFICATION

    installed = _parse(installed_version)
    if installed is None:
        return VersionOutcome.NEEDS_VERIFICATION

    start = _parse(version_start) if version_start else None
    end = _parse(version_end) if version_end else None

    # Unbounded on both sides but numeric installed version -> treat as affected
    # (a bare CVE-product match with no range info at all still needs the
    # product-level match to have happened upstream).
    if start is None and (version_start not in (None, "", "nan")):
        return VersionOutcome.NEEDS_VERIFICATION
    if end is None and (version_end not in (None, "", "nan")):
        return VersionOutcome.NEEDS_VERIFICATION

    if start is not None and installed < start:
        return VersionOutcome.NOT_AFFECTED
    if end is not None and installed > end:
        return VersionOutcome.NOT_AFFECTED
    return VersionOutcome.AFFECTED
