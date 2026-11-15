# Personalised Vulnerability Triage

**Author:** Danish M

A vulnerability prioritisation application that ranks security findings according to an organisation's technology profile and risk context. It combines vulnerability severity, exploitation signals and product matching to produce an explainable shortlist rather than relying on severity scores alone.

## Overview

The application provides a Streamlit interface and a FastAPI endpoint. It can run against bundled vulnerability data and optionally retrieve current information from public vulnerability sources.

## Key capabilities

- Match vulnerability records against an organisation's critical products.
- Support vendor and version-range matching when the relevant fields are available.
- Distinguish matched findings, findings requiring verification and findings that do not apply to the supplied profile.
- Rank findings using configurable CVSS, CISA KEV and EPSS weights.
- Explain prioritisation decisions with contributing signals and source data.
- Optionally retrieve data from NVD, CISA KEV and FIRST EPSS.
- Expose triage results through a JSON API.
- Run automated tests and a small evaluation harness.

## Technology stack

| Area | Technology |
|---|---|
| Application interface | Streamlit |
| API | FastAPI, Uvicorn |
| Data processing | Python, pandas |
| Validation and ranking | Custom matching and scoring modules |
| Containerisation | Docker, Docker Compose |
| Quality checks | pytest, evaluation script, GitHub Actions |

## Project structure

```text
.
├── app.py
├── api.py
├── data/
│   ├── vulnerabilities.csv
│   ├── profiles.json
│   └── gold_set.csv
├── src/
│   ├── matcher.py
│   ├── aliases.py
│   ├── version_match.py
│   ├── ranker.py
│   ├── explainer.py
│   ├── live_sources.py
│   └── evaluate.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Getting started

### Prerequisites

- Python 3.10 or later
- pip
- Docker and Docker Compose (optional)

### Install dependencies

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Run the interface

```bash
streamlit run app.py
```

### Run the API

```bash
uvicorn api:app --reload
```

The interactive API documentation is available at `http://localhost:8000/docs`.

### Run with Docker

```bash
docker compose up --build
```

## Configuration

The core application can use the bundled dataset. Optional AI phrasing providers require credentials supplied through environment variables:

- `FEATHERLESS_API_KEY`
- `GROQ_API_KEY`

Store credentials in a local environment file and do not commit secrets. Live public-data ingestion does not require a private API key for the configured sources, but availability and rate limits are controlled by those providers.

## Evaluation and tests

Run the test suite:

```bash
pytest
```

Run the bundled ranking evaluation:

```bash
python -m src.evaluate
```

The evaluation score describes agreement with the small bundled reference set; it should not be interpreted as a production accuracy guarantee.

## Limitations

- Product matching depends on the quality and completeness of the supplied product and vulnerability data.
- Version comparison is intentionally limited to supported version formats.
- The bundled evaluation dataset is small and is not a substitute for validation against an organisation's real environment.
- Live ingestion depends on the availability and rate limits of external public data sources.
- This project is a prioritisation aid and does not replace a security assessment or remediation decision.

## Author

Danish M
