FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/swisskyrepo/SSRFmap.git /ssrfmap
RUN pip install --no-cache-dir -r /ssrfmap/requirements.txt flask

WORKDIR /app
COPY ./plugins/ssrfmap/service.py /app/service.py

EXPOSE 8081

CMD ["python3", "/app/service.py"]
