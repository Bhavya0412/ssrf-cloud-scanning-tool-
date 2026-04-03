FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --upgrade pip
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install transformers peft accelerate safetensors sentencepiece
RUN pip install requests reportlab pillow

COPY ./ai_scanner/ai_scan.py /app/ai_scan.py
COPY ./ai_scanner/ssrf_ai_pdf_report.py /app/ssrf_ai_pdf_report.py

COPY ./orchestrator /app/orchestrator
COPY ./tools /app/tools

VOLUME ["/app/input", "/app/output", "/app/ai"]

CMD ["python", "/app/ai_scan.py"]
