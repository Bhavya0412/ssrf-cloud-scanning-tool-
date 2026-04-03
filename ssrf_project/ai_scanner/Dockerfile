FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --upgrade pip

# Install torch CPU-only (avoids 2GB GPU build)
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu

# LLM + LoRA stack
RUN pip install transformers peft accelerate safetensors sentencepiece

# Classical ML + HTTP + PDF
RUN pip install requests reportlab pillow scikit-learn pandas joblib

# Copy scanner files
COPY ./ai_scanner/ai_scan.py /app/ai_scan.py
COPY ./ai_scanner/ssrf_ai_pdf_report.py /app/ssrf_ai_pdf_report.py

# Copy shared modules
COPY ./orchestrator /app/orchestrator
COPY ./tools /app/tools

VOLUME ["/app/input", "/app/output", "/app/ai"]

ENV PYTHONPATH=/app

CMD ["python", "/app/ai_scan.py"]