FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-security2 python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY modsecurity /rules/modsecurity
COPY tests/modsecurity /test
COPY tests/test_modsecurity.py /test/test_modsecurity.py
COPY tests/test_modsecurity_experimental.py /test/test_modsecurity_experimental.py
USER www-data
CMD ["python3", "/test/engine_test.py"]
