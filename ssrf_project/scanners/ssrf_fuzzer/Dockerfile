FROM python:3.11-slim

WORKDIR /ssrf_fuzzer

COPY ./scanners/ssrf_fuzzer/run.py /ssrf_fuzzer/run.py
COPY ./tools /app/tools

RUN pip install --no-cache-dir requests urllib3

ENV PYTHONPATH=/app
ENV OUT_DIR=/out
ENV SSRF_SAFE_MODE=1

CMD ["python3", "/ssrf_fuzzer/run.py"]