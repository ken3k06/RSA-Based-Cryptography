# Quay lại Ubuntu 18.04 làm OS nền, nó ổn định và có tool build.
FROM ubuntu:18.04

# Cài đặt các gói cần thiết để build OpenSSL từ source
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Tải và build OpenSSL 1.0.1f (phiên bản có lỗ hổng)
WORKDIR /opt
RUN wget https://www.openssl.org/source/openssl-1.0.1f.tar.gz && \
    tar -xvzf openssl-1.0.1f.tar.gz

WORKDIR /opt/openssl-1.0.1f


RUN ./config no-manpages && make && make install_sw


# Tạo thư mục làm việc cho server
WORKDIR /srv
COPY server.sh .
RUN chmod +x server.sh

# Mở cổng 4433
EXPOSE 4433

# Chạy server
CMD ["/bin/bash", "server.sh"]