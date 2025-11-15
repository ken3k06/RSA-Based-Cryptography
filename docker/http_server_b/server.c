// server.c (AMPLIFY 50x version for stable timing in Docker)
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <time.h>

#define PORT 5000
#define READ_BUF 8192
#define AMP 80      // AMPLIFICATION FACTOR

static inline long long diff_ns(struct timespec *a, struct timespec *b){
    return (b->tv_sec - a->tv_sec) * 1000000000LL + (b->tv_nsec - a->tv_nsec);
}

void handle_client(int fd, BIGNUM *n, BIGNUM *e, BIGNUM *d){
    char line[READ_BUF];
    int pos = 0;

    // read one line (m)
    while (1){
        int r = read(fd, line + pos, sizeof(line)-pos-1);
        if (r <= 0) return;
        pos += r;
        line[pos] = 0;
        char *nl = strchr(line, '\n');
        if (nl){ *nl = 0; break; }
        if (pos > sizeof(line)-100) return; /* too long */
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BN_dec2bn(&m, line);

    BIGNUM *c = BN_new();
    BN_mod_exp(c, m, e, n, ctx);

    int d_bits = BN_num_bits(d);

    long long *sq = calloc(d_bits, sizeof(long long));
    long long *mul = calloc(d_bits, sizeof(long long));
    int *bits = calloc(d_bits, sizeof(int));

    BIGNUM *res = BN_new();
    BIGNUM *tmp = BN_new();
    BN_one(res);

    for (int i = d_bits - 1, idx = 0; i >= 0; i--, idx++){
        bits[idx] = BN_is_bit_set(d, i);

        // square
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
        BN_mod_mul(tmp, res, res, n, ctx);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
        sq[idx] = diff_ns(&t0, &t1);

        BN_copy(res, tmp);

        // amplified multiply
        mul[idx] = 0;
        if (bits[idx]){
            struct timespec t2, t3;
            clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

            for (int k = 0; k < AMP; k++)
                BN_mod_mul(tmp, res, c, n, ctx);

            clock_gettime(CLOCK_MONOTONIC_RAW, &t3);
            mul[idx] = diff_ns(&t2, &t3);

            BN_copy(res, tmp);
        }
    }

    char *d_dec = BN_bn2dec(d);
    char *res_dec = BN_bn2dec(res);

    dprintf(fd, "{\"d\":\"%s\",\"res\":\"%s\",\"bit_time\":[", d_dec, res_dec);

    free(d_dec);
    free(res_dec);

    for (int i = 0; i < d_bits; i++){
        if (i) dprintf(fd, ",");
        dprintf(fd, "[%d,%lld,%lld]", bits[i], sq[i], mul[i]);
    }

    dprintf(fd, "]}");
    dprintf(fd, "\n");

    free(sq);
    free(mul);
    free(bits);
    BN_free(m);
    BN_free(c);
    BN_free(res);
    BN_free(tmp);
    BN_CTX_free(ctx);
}

int main(){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new();
    BIGNUM *e = BN_new(), *phi = BN_new(), *d = BN_new();
    BIGNUM *p1 = BN_new(), *q1 = BN_new();

    BN_generate_prime_ex(p, 512, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 512, 0, NULL, NULL, NULL);

    BN_mul(n, p, q, ctx);

    BN_set_word(e, 65537);

    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(phi, p1, q1, ctx);

    BN_mod_inverse(d, e, phi, ctx);

    fprintf(stderr, "Server C (AMP=%d) running on port %d\n", AMP, PORT);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(PORT);

    bind(sock, (struct sockaddr*)&serv, sizeof(serv));
    listen(sock, 5);

    while (1){
        int c = accept(sock, NULL, NULL);
        if (c >= 0){
            handle_client(c, n, e, d);
            close(c);
        }
    }

    return 0;
}
