# Dockerfile.patched
FROM python:3.11-slim

WORKDIR /app

# Minimal deps
RUN pip install --no-cache-dir pycryptodome

# Copy patched server
COPY server.py /app/server.py

ENV HOST=0.0.0.0
ENV PORT=1338
ENV PUB_DIR=/app/poc/Bleichenbacher
ENV PRIVATE_DIR=/app/keys

EXPOSE 1337

CMD ["python", "/app/server.py"]
