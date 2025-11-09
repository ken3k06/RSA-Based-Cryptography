FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 LANG=C.UTF-8
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libgmp-dev netcat-openbsd \
  && rm -rf /var/lib/apt/lists/*

# copy server into image build context (ensure server.py present in context)
COPY server.py /app/server.py

# create private key dir inside image (not mounted)
RUN mkdir -p /app/keys && chmod 700 /app/keys

# pub dir will be a mount at runtime (/app/poc/Bleichenbacher), so no need to create it here
RUN pip install --no-cache-dir pycryptodome

EXPOSE 1337
CMD ["python", "/app/server.py"]
