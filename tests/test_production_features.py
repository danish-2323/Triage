import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.version_match import compare_version, VersionOutcome
from src.matcher import match_profile, split_candidates
from src.loader import normalize_profile
from src.evaluate import evaluate


# ---------------------------------------------------------------- version_match

def test_version_inside_range_is_affected():
    outcome = compare_version("2.4.51", "2.4.0", "2.4.60", "")
    assert outcome == VersionOutcome.AFFECTED


def test_version_outside_range_is_not_affected():
    outcome = compare_version("2.4.61", "2.4.0", "2.4.60", "")
    assert outcome == VersionOutcome.NOT_AFFECTED


def test_version_below_range_is_not_affected():
    outcome = compare_version("2.2.0", "2.4.0", "2.4.60", "")
    assert outcome == VersionOutcome.NOT_AFFECTED


def test_missing_installed_version_needs_verification():
    outcome = compare_version(None, "2.4.0", "2.4.60", "")
    assert outcome == VersionOutcome.NEEDS_VERIFICATION


def test_explicit_version_note_forces_needs_verification():
    outcome = compare_version("2.4.51", "2.4.0", "2.4.60", "range covers multiple branches")
    assert outcome == VersionOutcome.NEEDS_VERIFICATION


def test_non_numeric_version_needs_verification():
    outcome = compare_version("2.4.x-beta", "2.4.0", "2.4.60", "")
    assert outcome == VersionOutcome.NEEDS_VERIFICATION


def test_unbounded_range_open_ended_start_only():
    # No upper bound -> anything >= start is affected
    assert compare_version("9.9.9", "2.4.0", None, "") == VersionOutcome.AFFECTED
    assert compare_version("1.0.0", "2.4.0", None, "") == VersionOutcome.NOT_AFFECTED


# ---------------------------------------------------------------- matcher with versions

def test_matcher_excludes_patched_version_as_not_affected():
    vulns = pd.DataFrame([
        {
            "cve_id": "CVE-2099-0001", "product_name": "Apache HTTP Server",
            "cvss_base_score": 9.8, "cisa_kev": False, "first_epss": 0.5,
            "data_quality": "ok",
            "vendor": "apache", "version_start": "2.4.0", "version_end": "2.4.50",
            "version_note": "", "published_date": "", "reference_url": "",
            "source_snapshot_date": "", "description": "",
        }
    ])
    profile = normalize_profile({
        "name": "Test Org",
        "technologies": [{"vendor": "apache", "product": "Apache HTTP Server", "version": "2.4.60"}],
    })
    matched = match_profile(vulns, profile)
    assert matched.iloc[0]["match_status"] == "not_affected"
    candidates, excluded = split_candidates(matched)
    assert candidates.empty
    assert len(excluded) == 1
    assert "outside the affected range" in excluded.iloc[0]["exclude_reason"]


def test_matcher_includes_vulnerable_version():
    vulns = pd.DataFrame([
        {
            "cve_id": "CVE-2099-0002", "product_name": "Apache HTTP Server",
            "cvss_base_score": 9.8, "cisa_kev": True, "first_epss": 0.9,
            "data_quality": "ok",
            "vendor": "apache", "version_start": "2.4.0", "version_end": "2.4.50",
            "version_note": "", "published_date": "", "reference_url": "",
            "source_snapshot_date": "", "description": "",
        }
    ])
    profile = normalize_profile({
        "name": "Test Org",
        "technologies": [{"vendor": "apache", "product": "Apache HTTP Server", "version": "2.4.10"}],
    })
    matched = match_profile(vulns, profile)
    assert matched.iloc[0]["match_status"] == "include"


# ---------------------------------------------------------------- evaluator

def test_evaluate_produces_positive_correlation_for_both_demo_profiles():
    report = evaluate()
    assert "Global Retail Bank" in report
    assert "Agile Cloud Tech Startup" in report
    for name, r in report.items():
        assert r["spearman_rank_correlation"] is not None
        # Weights should broadly track practitioner judgement, not be random.
        assert r["spearman_rank_correlation"] > 0.5, f"{name} correlation too low: {r}"
