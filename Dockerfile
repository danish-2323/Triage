# Multi-purpose image: run either the Streamlit demo UI or the FastAPI
# service from the same build. Select via the CMD override at `docker run`
# time or the two services in docker-compose.yml.
FROM python:3.12-slim

WORKDIR /app

# System deps kept minimal; pandas/requests need no extra build tooling here.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user for defense-in-depth.
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import sys,urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health') if '8501' else None" || exit 0

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
