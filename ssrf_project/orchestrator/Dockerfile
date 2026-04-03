FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests pyyaml

COPY ./orchestrator /app/orchestrator
COPY ./plugins /app/plugins
COPY ./tools /app/tools
COPY ./scanners /app/scanners
COPY ./payloads /app/payloads
COPY ./input /app/input

ENV PYTHONPATH=/app

CMD ["python3", "-m", "orchestrator.orchestrator"]
