FROM python:3.11-slim

WORKDIR /app

# Cài gói cần thiết
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy code
COPY gen_keys.py /app/gen_keys.py
COPY server.py /app/server.py
COPY server.sh /app/server.sh

# Tạo thư mục lưu key
RUN mkdir -p /app/keys

# Cho phép thực thi server.sh
RUN chmod +x /app/server.sh

EXPOSE 8000

# ENTRYPOINT chạy shell script -> sinh key + start server
CMD ["/bin/bash", "/app/server.sh"]
