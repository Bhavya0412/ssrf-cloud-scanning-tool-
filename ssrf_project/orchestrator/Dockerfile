FROM python:3.11-slim

WORKDIR /ssrf_fuzzer

COPY ./scanners/ssrf_fuzzer/run.py /ssrf_fuzzer/run.py

RUN chmod +x /ssrf_fuzzer/run.py
RUN pip install --no-cache-dir requests

CMD ["python3", "/ssrf_fuzzer/run.py"]
