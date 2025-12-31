# docker/attack/Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 LANG=C.UTF-8

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

# preinstall common libs used by PoCs (helps reliability)
RUN pip install --no-cache-dir pycryptodome gmpy2 requests tlslite-ng cryptography pyjwt || true

# default sleep to keep container alive if no command
CMD ["bash", "-lc", "sleep infinity"]
