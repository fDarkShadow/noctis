# Shared base for the Python mocks (noctis/py-mock-base:latest).
#
# Holds everything the mocks used to repeat in each Dockerfile: python 3.11, openssl,
# a self-signed cert in /certs, and mocklib.py (HTTP:80 + HTTPS:443 bootstrap).
# Built first by playbooks/00-build-mocks.yml; a mock's Dockerfile.{vuln,patched}
# is then just FROM + COPY server.py + ENV <PRODUCT>_MODE.
FROM python:3.11-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /certs \
    && openssl req -x509 -newkey rsa:2048 -keyout /certs/server.key \
       -out /certs/server.crt -days 3650 -nodes \
       -subj "/CN=noctis-mock"
COPY mocklib.py /app/mocklib.py
ENV PYTHONPATH=/app
EXPOSE 80 443
CMD ["python3", "/app/server.py"]
