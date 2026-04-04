FROM projectdiscovery/nuclei:latest

USER root

RUN apk add --no-cache python3 py3-pip && pip3 install flask --break-system-packages

WORKDIR /app

COPY ./plugins/nuclei/service.py /app/service.py

VOLUME ["/templates"]

ENV TEMPLATES_DIR=/templates

EXPOSE 8080

ENTRYPOINT []
CMD ["python3", "/app/service.py"]
