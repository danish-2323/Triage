"""
Production API for the triage engine.

Streamlit is fine for a human demo but nothing else can call it
programmatically. This gives the same engine a stable HTTP contract so it
can be wired into a ticketing system, a scheduled job, a Slack bot, etc.

Run:
    uvicorn api:app --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health
    POST /triage            body: {"profile": {...}} -> top-5 + negative test
    POST /profiles/validate body: {"profile": {...}} -> normalized profile
    GET  /demo-profiles     -> the 3 bundled organisations
"""

from __future__ import annotations
import io
import logging
import math
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")  # populates os.environ from .env if present

import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from src.loader import load_vulnerabilities, load_demo_profiles, normalize_profile, REQUIRED_VULN_COLUMNS
from src.matcher import match_profile, split_candidates
from src.ranker import rank, rank_with_watchlist, negative_test
from src.explainer import build_explanation, no_match_message
from src import llm_phraser
from src import company_lookup
from src import report as report_mod

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("vuln_triage.api")

DATA_DIR = Path(__file__).parent / "data"
FRONTEND_DIR = Path(__file__).parent / "frontend"

app = FastAPI(
    title="Personalised Vulnerability Triage API",
    version="1.0.0",
    description="Turns public vulnerability data into a ranked, explained top-5 for one organisation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your real origin(s) before shipping to production
    allow_methods=["*"],
    allow_headers=["*"],
)

_vulns_cache = None
_demo_profiles_cache = None
_dataset_info = {"source": "bundled", "filename": "vulnerabilities.csv"}


def get_vulnerabilities():
    global _vulns_cache
    if _vulns_cache is None:
        _vulns_cache = load_vulnerabilities(DATA_DIR / "vulnerabilities.csv")
    return _vulns_cache


def _clean(v):
    """Make a value JSON-safe (NaN/NaT -> None)."""
    if v is None:
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    try:
        if pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    return v


def _row_to_dict(row: pd.Series) -> dict:
    d = {k: _clean(v) for k, v in row.to_dict().items()}
    return d


def get_demo_profiles():
    global _demo_profiles_cache
    if _demo_profiles_cache is None:
        _demo_profiles_cache = load_demo_profiles(DATA_DIR / "profiles.json")
    return _demo_profiles_cache


class TechnologyIn(BaseModel):
    vendor: str = ""
    product: str
    version: str = ""


class WeightModifiers(BaseModel):
    cvss_weight: float = 0.34
    cisa_kev_weight: float = 0.33
    first_epss_weight: float = 0.33


class ProfileIn(BaseModel):
    org_id: Optional[str] = None
    name: str
    sector: str = "Not specified"
    risk_appetite: str = "Medium"
    weight_modifiers: WeightModifiers = Field(default_factory=WeightModifiers)
    critical_products: list[str] = Field(default_factory=list)
    technologies: list[TechnologyIn] = Field(default_factory=list)
    service: str = ""
    exposure: str = ""
    importance: str = ""


class TriageRequest(BaseModel):
    profile: ProfileIn
    top_n: int = 5
    use_ai: bool = False
    ai_model: Optional[str] = None


class CompanyAutofillRequest(BaseModel):
    name: str
    sector_hint: str = ""


@app.post("/company/autofill")
def company_autofill(req: CompanyAutofillRequest):
    """
    Best-effort AI guess of a starting organisation profile from just a
    company name. Never treated as fact by the pipeline -- it only returns
    suggested form-field values for the caller to show as editable and
    clearly marked as an unverified guess. Fails soft: 200 with
    used_ai=false + a reason, never a 500, so the frontend can fall back to
    the plain manual form.
    """
    if not company_lookup.is_available():
        return {"used_ai": False,
                "error": "No AI provider configured (set FEATHERLESS_API_KEY and/or GROQ_API_KEY)", "profile": None}
    result = company_lookup.suggest_profile(req.name, req.sector_hint)
    return {"used_ai": result.used_ai, "error": result.error, "profile": result.profile}


@app.get("/company/autofill/status")
def company_autofill_status():
    return {"available": company_lookup.is_available()}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def serve_frontend():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    raise HTTPException(status_code=404, detail="Frontend not built.")


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/demo-profiles")
def demo_profiles():
    return get_demo_profiles()


@app.get("/models")
def models():
    """AI phrasing status + a model picker list for the frontend. Never
    errors -- if Featherless is unreachable this still returns the
    curated fallback list with is_available=False."""
    return {
        "ai_available": llm_phraser.is_available(),
        "default_model": llm_phraser.DEFAULT_MODEL,
        "models": llm_phraser.list_models(),
    }


@app.post("/profiles/validate")
def validate_profile(payload: ProfileIn):
    return normalize_profile(payload.model_dump())


@app.get("/vulnerabilities/meta")
def vulnerabilities_meta():
    """Dataset provenance + summary counts, for the console header."""
    df = get_vulnerabilities()
    return {
        "source": _dataset_info["source"],
        "filename": _dataset_info["filename"],
        "total": int(len(df)),
        "kev_count": int(df["cisa_kev"].sum()),
        "missing_cvss": int((df["data_quality"] == "missing_cvss").sum()),
        "missing_epss": int((df["data_quality"] == "missing_epss").sum()),
        "product_count": int(df["product_name"].nunique()),
        "avg_cvss": _clean(round(float(df["cvss_base_score"].mean()), 2)) if len(df) else None,
        "high_epss_count": int((df["first_epss"].fillna(0) > 0.3).sum()),
    }


@app.get("/vulnerabilities")
def list_vulnerabilities(
    q: Optional[str] = Query(None, description="Free-text search across CVE id / product / vendor / description"),
    kev_only: bool = False,
    min_cvss: Optional[float] = None,
    product: Optional[str] = None,
    sort_by: str = Query("cvss_base_score", pattern="^(cvss_base_score|first_epss|cve_id|product_name|published_date)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
):
    """Browse/filter/paginate the full loaded vulnerability dataset, for the
    UI's Vulnerability Database view."""
    df = get_vulnerabilities().copy()

    if q:
        needle = q.strip().lower()
        haystack = (
            df["cve_id"].str.lower() + " " + df["product_name"].str.lower() + " "
            + df.get("vendor", "").astype(str).str.lower() + " "
            + df.get("description", "").astype(str).str.lower()
        )
        df = df[haystack.str.contains(needle, na=False)]
    if kev_only:
        df = df[df["cisa_kev"] == True]  # noqa: E712
    if min_cvss is not None:
        df = df[df["cvss_base_score"].fillna(-1) >= min_cvss]
    if product:
        df = df[df["product_name"].str.lower() == product.strip().lower()]

    df = df.sort_values(by=sort_by, ascending=(sort_dir == "asc"), na_position="last")

    total = len(df)
    start = (page - 1) * page_size
    page_df = df.iloc[start:start + page_size]

    return {
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)),
        "items": [_row_to_dict(r) for _, r in page_df.iterrows()],
    }


@app.get("/vulnerabilities/products")
def list_products():
    """Distinct product names in the current dataset, for autocomplete."""
    df = get_vulnerabilities()
    return sorted(df["product_name"].dropna().unique().tolist())


@app.post("/vulnerabilities/upload")
async def upload_vulnerabilities(file: UploadFile = File(...)):
    """Replace the working dataset with a user-uploaded CSV. Validated with
    the exact same loader used for the bundled file, so an upload can never
    put the engine into a state the rest of the pipeline doesn't understand."""
    global _vulns_cache, _dataset_info

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file.")

    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (25MB limit).")

    try:
        preview = pd.read_csv(io.BytesIO(raw))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {e}")

    missing = [c for c in REQUIRED_VULN_COLUMNS if c not in preview.columns]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing required column(s): {', '.join(missing)}. "
                   f"Required: {', '.join(REQUIRED_VULN_COLUMNS)}.",
        )

    try:
        df = load_vulnerabilities(io.BytesIO(raw))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not load dataset: {e}")

    _vulns_cache = df
    _dataset_info = {"source": "uploaded", "filename": file.filename}
    logger.info("vulnerabilities dataset replaced by upload filename=%s rows=%d", file.filename, len(df))

    return {
        "status": "ok",
        "filename": file.filename,
        "rows": int(len(df)),
        "kev_count": int(df["cisa_kev"].sum()),
        "columns": list(df.columns),
    }


@app.post("/vulnerabilities/reset")
def reset_vulnerabilities():
    """Revert to the bundled demo dataset."""
    global _vulns_cache, _dataset_info
    _vulns_cache = None
    _dataset_info = {"source": "bundled", "filename": "vulnerabilities.csv"}
    df = get_vulnerabilities()
    return {"status": "ok", "rows": int(len(df))}


def _run_triage(req: TriageRequest) -> dict:
    """Shared logic behind /triage and /report/generate so the report can
    never drift from what the plain triage endpoint actually returns."""
    if not req.profile.critical_products and not req.profile.technologies:
        raise HTTPException(status_code=400, detail="Profile must list at least one product/technology.")

    profile = normalize_profile(req.profile.model_dump())
    vulns = get_vulnerabilities()

    matched = match_profile(vulns, profile)
    candidates, excluded = split_candidates(matched)

    if candidates.empty:
        return {
            "profile": profile["name"],
            "message": no_match_message(profile),
            "top_actions": [],
            "negative_test": None,
            "watchlist_item": None,
            "excluded_count": len(excluded),
            "candidate_count": 0,
        }

    top, watchlist_row = rank_with_watchlist(candidates, profile, top_n=req.top_n)
    actions = []
    for _, row in top.iterrows():
        explanation = build_explanation(row, profile)
        explanation.pop("raw_row", None)  # not JSON-serializable as-is

        ai_summary = None
        if req.use_ai:
            status = llm_phraser.phrase(explanation, model=req.ai_model or llm_phraser.DEFAULT_MODEL)
            ai_summary = status.to_dict()

        explanation["ai_summary"] = ai_summary
        actions.append(explanation)

    watchlist_item = None
    if watchlist_row is not None:
        watchlist_item = build_explanation(watchlist_row, profile)
        watchlist_item.pop("raw_row", None)
        cutoff_score = actions[-1]["score"] if actions else None
        gap = round(cutoff_score - watchlist_item["score"], 1) if cutoff_score is not None else None
        watchlist_item["why_watch"] = (
            f"Scored {watchlist_item['score']}/100 -- only {gap} point(s) below the lowest item that made "
            f"today's top {req.top_n}. Worth checking again if its exploitation data changes."
            if gap is not None else
            f"Scored {watchlist_item['score']}/100 -- just outside today's top {req.top_n}."
        )
        watchlist_ai_summary = None
        if req.use_ai:
            status = llm_phraser.phrase(watchlist_item, model=req.ai_model or llm_phraser.DEFAULT_MODEL)
            watchlist_ai_summary = status.to_dict()
        watchlist_item["ai_summary"] = watchlist_ai_summary

    neg = negative_test(matched, profile)
    neg_out = None
    if neg is not None:
        neg_out = {
            "cve_id": neg["cve_id"],
            "product_name": neg["product_name"],
            "cvss_base_score": neg["cvss_base_score"],
            "kind": neg["negative_kind"],
            "reason": neg["negative_reason"],
        }

    logger.info("triage served profile=%s candidates=%d excluded=%d", profile["name"], len(candidates), len(excluded))

    return {
        "profile": profile["name"],
        "top_actions": actions,
        "negative_test": neg_out,
        "watchlist_item": watchlist_item,
        "excluded_count": len(excluded),
        "candidate_count": len(candidates),
    }


@app.post("/triage")
def triage(req: TriageRequest):
    return _run_triage(req)


@app.post("/report/generate")
def generate_report(req: TriageRequest):
    """
    Runs the same triage pipeline as /triage, then adds a deterministic
    stats block (for charts, always present) and an optional AI-written
    executive summary paragraph over those same stats (never over the raw
    dataset, never inventing a fact not already in the stats). Falls back
    to a template paragraph if no key is configured or the call fails --
    the report is never blocked on AI being available.
    """
    result = _run_triage(req)

    if not result["top_actions"]:
        return {**result, "stats": None, "executive_summary": {
            "text": result.get("message", "No matched items to report."), "used_ai": False, "error": None,
        }}

    stats = report_mod.build_report_stats(
        result["top_actions"], result["negative_test"],
        result["excluded_count"], result["candidate_count"],
        watchlist_item=result.get("watchlist_item"),
    )
    summary = report_mod.write_executive_summary(stats, result["profile"])

    return {**result, "stats": stats, "executive_summary": summary}
