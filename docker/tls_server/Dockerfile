# docker/tls_server/Dockerfile (OpenSSL 1.0.2 build)
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential wget perl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
# tải và build openssl 1.0.2u (ví dụ)
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz \
  && tar xzf openssl-1.0.2u.tar.gz \
  && cd openssl-1.0.2u \
  && ./config --prefix=/usr/local/openssl-1.0.2 shared \
  && make -j"$(nproc)" \
  && make install

ENV PATH="/usr/local/openssl-1.0.2/bin:${PATH}"

WORKDIR /app
COPY server.sh /app/server.sh
COPY gen_cert.sh /app/gen_cert.sh
COPY openssl.cnf /tmp/openssl.cnf
RUN chmod +x /app/server.sh /app/gen_cert.sh

EXPOSE 4433
CMD ["/app/server.sh"]
