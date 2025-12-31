# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir pycryptodome

COPY server.py /app/server.py

EXPOSE 8000

CMD ["python", "/app/server.py"]
