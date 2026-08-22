import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_demo_profiles_returns_three_orgs():
    resp = client.get("/demo-profiles")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_triage_requires_products():
    resp = client.post("/triage", json={"profile": {"name": "Empty Org"}})
    assert resp.status_code == 400


def test_triage_returns_ranked_top5_with_evidence():
    resp = client.post("/triage", json={
        "profile": {
            "name": "Test Bank",
            "sector": "Financial Services",
            "critical_products": ["Core Banking Framework"],
            "weight_modifiers": {"cvss_weight": 0.3, "cisa_kev_weight": 0.45, "first_epss_weight": 0.25},
        }
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["top_actions"]) <= 5
    for action in data["top_actions"]:
        assert "priority" in action
        assert "factors" in action
        assert "next_step" in action
        assert action["cve_id"]


def test_triage_unmatched_product_returns_honest_message():
    resp = client.post("/triage", json={
        "profile": {"name": "Test Org", "critical_products": ["Nonexistent Product XYZ"]},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["top_actions"] == []
    assert "Nothing matched" in data["message"]


def test_models_endpoint_never_errors():
    resp = client.get("/models")
    assert resp.status_code == 200
    body = resp.json()
    assert "ai_available" in body
    assert "models" in body and len(body["models"]) > 0


def test_triage_use_ai_falls_back_without_key(monkeypatch):
    monkeypatch.delenv("FEATHERLESS_API_KEY", raising=False)
    resp = client.post("/triage", json={
        "profile": {"name": "Test Bank", "critical_products": ["Core Banking Framework"]},
        "top_n": 1,
        "use_ai": True,
    })
    assert resp.status_code == 200
    body = resp.json()
    action = body["top_actions"][0]
    assert action["ai_summary"]["used_ai"] is False
    assert action["ai_summary"]["text"]
