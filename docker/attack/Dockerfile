FROM python:3.10-slim

RUN apt-get update \
    && apt-get update && apt-get install -y netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install \
    requests \
    gmpy2 \
    pycryptodome \
    tlslite-ng\
    pyjwt\
    cryptography

WORKDIR /app

CMD ["sleep", "infinity"]