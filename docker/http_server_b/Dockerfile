FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server /app/server

# RUN gcc -O2 -o server server.c -lcrypto

EXPOSE 5000
CMD ["./server"]
