# Personalised Vulnerability Triage

Turns public vulnerability data into a ranked top-5 list, explained in plain
language, for one specific organisation — instead of a generic table sorted
by severity. Started as a 24-hour hackathon prototype; this version adds the
pieces needed to run it for real: version-aware matching, live public-data
ingestion, a programmatic API, an objective evaluation harness, and
deployment tooling.

## Run it (under 5 minutes)

```bash
pip install -r requirements.txt
streamlit run app.py          # human-facing demo UI, http://localhost:8501
# or
uvicorn api:app --reload      # programmatic API, http://localhost:8000/docs
# or
docker compose up             # both, containerized
```

No API key or internet connection is required for the core app — it runs
entirely from the bundled CSV/JSON. Live data (below) and AI phrasing
(`FEATHERLESS_API_KEY` and/or `GROQ_API_KEY`) are both optional upgrades.

## What's new in this production pass

| Area | Before | Now |
|---|---|---|
| Matching | Product name only | Product name **+ optional vendor/version-range matching** (`src/version_match.py`) — can tell a patched version isn't affected, and says so honestly, not just "product not used" |
| Data | Frozen CSV only | Same frozen CSV by default, **plus optional live NVD + CISA KEV + FIRST EPSS ingestion** with disk caching and rate-limit pacing (`src/live_sources.py`), toggled from the sidebar |
| Scoring | 3 fixed signals | Same 3 signals, **plus optional exposure/service-importance bonuses** when a profile states them (`src/ranker.py`) |
| Integration | Streamlit only | **FastAPI service** (`api.py`) — `POST /triage` returns the same ranked, explained, sourced output as JSON, for wiring into a ticketing system, Slack bot, or scheduled job |
| Quality | Gold set unused | `python -m src.evaluate` scores the engine's weights against `gold_set.csv` and reports Spearman rank correlation vs. practitioner judgement (currently **0.9** for both demo profiles) |
| Ops | `pip install && run` | `Dockerfile` + `docker-compose.yml` (UI + API, non-root user, healthcheck), GitHub Actions CI running tests + evaluation on every push |
| Tests | 6 tests | 21 tests: original matcher/ranker suite + version-range matching + evaluator + API contract tests |

## Two ways to use it (UI)

## Two ways to use it

1. **Demo organisations** — 3 built-in profiles (`data/profiles.json`) from
   the organiser starter pack, run against `data/vulnerabilities.csv`
   (540 rows). Good for a fast judge demo and for the required
   "two profiles produce different top-5 lists" check.
2. **Your own company** — sidebar form to enter a company name, sector,
   risk appetite, and a list of critical products/technologies, with an
   optional CSV upload to replace the vulnerability dataset entirely. This
   proves the matching/ranking engine is not hard-coded to the demo data.

## Data sources

- `data/vulnerabilities.csv` — bundled snapshot. Required columns:
  `cve_id, product_name, cvss_base_score, cisa_kev, first_epss`. Optional
  production columns (used automatically when present, ignored otherwise):
  `vendor, version_start, version_end, version_note, published_date,
  reference_url, source_snapshot_date, description`.
- `data/profiles.json` — demo organisations. Supports either
  `critical_products: [str]` (simple) or `technologies: [{vendor, product,
  version}]` (version-aware), plus optional `exposure` / `importance` /
  `service` context fields.
- `data/gold_set.csv` — small practitioner-ranked sample used by
  `src/evaluate.py` to sanity-check the scoring weights (its CVE IDs are
  deliberately standalone, not rows from `vulnerabilities.csv` — see
  the module docstring for why).
- **Live**: `src/live_sources.py` pulls the same NVD/CISA KEV/FIRST EPSS
  public sources at runtime, cached on disk for 6h and paced to respect
  NVD's unauthenticated rate limit. Exposed as a sidebar toggle in the UI;
  never required for the core app to run.

## Matching logic (`src/matcher.py`, `src/aliases.py`)

For each vulnerability row, the product name is normalised (lowercase,
punctuation stripped) and compared against the organisation's
`critical_products` list, with a small documented alias table for common
shorthand (e.g. "WAF" → "Web Application Firewall"). Three honest outcomes:

- **include** — product matched and all scoring data present
- **needs_verification** — product matched but CVSS or EPSS was missing
  from the source row (never silently dropped, never guessed)
- **exclude** — product not used by this organisation (reason recorded)

## Ranking logic (`src/ranker.py`)

```
score = 100 * ( cvss_weight     * (cvss_base_score / 10)
              + cisa_kev_weight * (1 if in_kev else 0)
              + epss_weight     * first_epss )
        - 15  (if match_status == needs_verification)
```

Weights come from each organisation's own `weight_modifiers`, so risk
appetite genuinely changes the outcome (e.g. a startup with high EPSS
weighting vs. a bank with high KEV weighting). Every contributing factor
is shown in the UI ("Why this score" expander) — no opaque single number.

Priority labels: URGENT (≥70), HIGH (≥45), MEDIUM (≥20), LOW (below).

## Explainability (`src/explainer.py`)

Every card shows: priority, plain-language title, matched context, why it
matters, potential impact, next step, confidence (+ reason), and the raw
source row (provenance). All text is built from fixed templates referencing
only dataset fields — no invented versions, dates, or remediation steps.
An optional phrasing layer (`src/llm_phraser.py`) may restyle wording only;
it always falls back to the template text if disabled or if the call fails.
It supports two providers, Featherless and Groq (`groq:`-prefixed model
ids) — set `FEATHERLESS_API_KEY` and/or `GROQ_API_KEY` in `.env` (copy from
`.env.example`); either is enough, and having both gives the fallback chain
a second provider to try if one is slow or rate-limited. Then in the web UI
toggle **AI phrasing** and pick a model from the dropdown (populated live
from `GET /models`, which reports `ai_available` and merges each configured
provider's own model catalog with a curated shortlist). Every card marks
whether the shown paragraph was AI-phrased or is the deterministic
fallback, and why, so nothing is silently swapped in without disclosure.

## Negative test

The app always displays one CVSS ≥ 9.0 item that was either excluded
(product not used) or matched but ranked low (low weighting for that
signal), with the reason — proving the tool does more than sort by
severity.

## Known assumptions

- The organiser dataset has no `vendor` or `version` columns, so matching
  is done on normalised `product_name` strings only (not full CPE/version
  range matching, which is explicitly out of scope per the brief).
- The dataset has no `exposure` or `service importance` fields; instead,
  each organisation profile carries its own `weight_modifiers`, which play
  the equivalent role of "how much does each signal matter to this org."
- The dataset has no `reference_url`, so traceability is provided via the
  raw source row shown in the "Show source row" expander instead of a link.

## Version-aware matching (`src/version_match.py`)

When a vulnerability row carries `version_start`/`version_end` and an org's
`technologies[]` entry states an installed `version`, the engine compares
them (clean dotted-numeric versions only, by design) and can now say
**"not affected — your version is outside the range"**, not just "not
used". Anything not cleanly comparable (a `version_note` flag, a non-numeric
version, a missing installed version) becomes `needs_verification` — never
guessed, never silently dropped. Falls back to the original product-name-only
behaviour when version data isn't present, so the bundled demo dataset works
exactly as before.

## Programmatic API (`api.py`)

```bash
uvicorn api:app --reload
curl -X POST localhost:8000/triage -H 'content-type: application/json' -d '{
  "profile": {
    "name": "Test Bank", "sector": "Financial Services",
    "critical_products": ["Core Banking Framework"],
    "exposure": "internet-facing", "importance": "critical",
    "weight_modifiers": {"cvss_weight": 0.3, "cisa_kev_weight": 0.45, "first_epss_weight": 0.25}
  }
}'
```

Returns the same ranked, explained, sourced top-5 as the UI, as JSON —
so it can be called from a cron job, a ticketing system, or a chatbot,
not just viewed by a human. Interactive docs at `/docs`.

## Evaluation (`src/evaluate.py`)

```bash
python -m src.evaluate
```

Scores each demo profile's weights against `gold_set.csv` and reports
Spearman rank correlation vs. a practitioner's stated priority order (0.9
for both bundled profiles) plus top-3 agreement — an objective check that
weight changes are actually improving alignment with expert judgement,
not just producing a plausible-looking list.

## Deployment

```bash
docker compose up            # UI on :8501, API on :8000
```

Runs as a non-root user, has a container healthcheck, and persists the
live-data cache in a bind-mounted volume. `.github/workflows/ci.yml` runs
the full test suite and the evaluation harness on every push.

## Known limitations

- Product matching is name-based with a small alias table, not full CPE
  parsing; version comparison handles clean dotted-numeric versions only
  (not full semver, epoch/distro suffixes, or vendor-specific formats) —
  anything else is honestly flagged `needs_verification` rather than guessed.
- With only ~6 distinct products in the demo dataset, some profiles may see
  fewer than 5 relevant candidates.
- Live ingestion depends on NVD/CISA/FIRST availability and rate limits;
  the app always falls back to cached or bundled data rather than failing.
- AI phrasing is a cosmetic wording layer only; it is optional, not scored,
  and never adds facts.
