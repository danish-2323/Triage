import sys
from pathlib import Path
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.loader import load_vulnerabilities, load_demo_profiles
from src.matcher import match_profile, split_candidates
from src.ranker import rank, negative_test, score_row
from src.aliases import names_match

DATA_DIR = Path(__file__).parent.parent / "data"


def test_aws_autofill_products_match_cloud_product_family():
    for product in [
        "amazon web services", "amazon ec2", "amazon s3",
        "amazon rds", "amazon rds", "amazon s3", "amazon vpc",
    ]:
        assert names_match(product, "Cloud Database Engine")


def test_banking_autofill_products_match_core_banking_family():
    products = ["core banking system", "Finacle", "Oracle FLEXCUBE", "SBI CBS"]
    assert all(names_match(product, "Core Banking Framework") for product in products)


def test_real_dataset_loads_and_two_profiles_differ():
    vulns = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")
    assert len(vulns) > 0
    assert len(profiles) >= 2

    top5_a = rank(*split_candidates(match_profile(vulns, profiles[0]))[:1], profiles[0])
    matched_a = match_profile(vulns, profiles[0])
    cands_a, _ = split_candidates(matched_a)
    top5_a = rank(cands_a, profiles[0])

    matched_b = match_profile(vulns, profiles[1])
    cands_b, _ = split_candidates(matched_b)
    top5_b = rank(cands_b, profiles[1])

    set_a = set(top5_a["cve_id"]) if not top5_a.empty else set()
    set_b = set(top5_b["cve_id"]) if not top5_b.empty else set()
    assert set_a != set_b


def test_known_product_is_included():
    vulns = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")
    bank = next(p for p in profiles if "Bank" in p["name"])
    matched = match_profile(vulns, bank)
    included = matched[matched["match_status"] == "include"]
    assert not included.empty
    assert included["matched_product"].isin(bank["critical_products"]).all()


def test_unused_product_is_excluded_with_reason():
    vulns = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")
    bank = next(p for p in profiles if "Bank" in p["name"])
    matched = match_profile(vulns, bank)
    excluded = matched[matched["match_status"] == "exclude"]
    assert not excluded.empty
    assert excluded["exclude_reason"].notna().all()


def test_negative_test_returns_high_cvss_row():
    vulns = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")
    bank = next(p for p in profiles if "Bank" in p["name"])
    matched = match_profile(vulns, bank)
    neg = negative_test(matched, bank)
    assert neg is not None
    assert neg["cvss_base_score"] >= 9.0


def test_ranker_orders_by_score_desc_and_dedupes():
    vulns = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    profiles = load_demo_profiles(DATA_DIR / "profiles.json")
    bank = next(p for p in profiles if "Bank" in p["name"])
    matched = match_profile(vulns, bank)
    cands, _ = split_candidates(matched)
    top5 = rank(cands, bank, top_n=5)
    scores = top5["score"].tolist()
    assert scores == sorted(scores, reverse=True)
    assert len(top5) <= 5
    assert top5["cve_id"].is_unique


def test_score_row_higher_kev_weight_favours_kev_items():
    row_kev = pd.Series({"cvss_base_score": 5.0, "first_epss": 0.1, "cisa_kev": True, "match_status": "include"})
    row_no_kev = pd.Series({"cvss_base_score": 5.0, "first_epss": 0.1, "cisa_kev": False, "match_status": "include"})
    profile = {"weight_modifiers": {"cvss_weight": 0.2, "cisa_kev_weight": 0.6, "first_epss_weight": 0.2}}
    score_kev, _ = score_row(row_kev, profile)
    score_no_kev, _ = score_row(row_no_kev, profile)
    assert score_kev > score_no_kev
