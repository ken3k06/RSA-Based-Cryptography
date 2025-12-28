# Dockerfile
FROM python:3.12-slim

# Tối ưu log + không tạo .pyc
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Cài dependency tối thiểu
RUN pip install --no-cache-dir pycryptodome

# Copy server vào image
COPY server.py /app/server.py

EXPOSE 8000

CMD ["python", "/app/server.py"]
