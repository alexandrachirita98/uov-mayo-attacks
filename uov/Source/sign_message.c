#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "parameters.h"
#include "F16Field.h"
#include "F32Field.h"
#include "F48Field.h"
#include "F64Field.h"
#include "F80Field.h"
#include "UOVHash.h"
#include "UOVClassic.h"
#include "LUOV.h"
#include "LinearAlgebra.h"
#include "twister.h"
#include "buffer.h"
#include "api.h"

static void usage(const char *a0) {
    fprintf(stderr,
        "usage: %s --message <str> --out-dir <path>"
        " [--pk-file <name>] [--sig-file <name>] [--msg-file <name>]\n", a0);
}

static int mkdir_p(const char *p) {
    return (mkdir(p, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

static int write_file(const char *dir, const char *name,
                      const unsigned char *buf, size_t len) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror(path); return -1; }
    if (fwrite(buf, 1, len, fp) != len) { perror(path); fclose(fp); return -1; }
    fclose(fp);
    printf("%s (%zu bytes)\n", path, len);
    return 0;
}

int main(int argc, char **argv) {
    const char *message = NULL, *out_dir = NULL;
    const char *pk_file = "uov_pk.bin";
    const char *sig_file = "uov_sig.bin";
    const char *msg_file = "uov_msg.txt";

    for (int i = 1; i < argc; i++) {
        if (i + 1 < argc && !strcmp(argv[i], "--message"))   message  = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--out-dir"))  out_dir  = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--pk-file"))  pk_file  = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--sig-file")) sig_file = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--msg-file")) msg_file = argv[++i];
        else { usage(argv[0]); return 1; }
    }
    if (!message || !out_dir) { usage(argv[0]); return 1; }
    if (mkdir_p(out_dir) != 0) { perror(out_dir); return 1; }

    size_t mlen = strlen(message);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char *m  = malloc(mlen);
    unsigned char *sm = malloc(mlen + CRYPTO_BYTES);
    if (!sk || !m || !sm) { fprintf(stderr, "alloc failed\n"); return 1; }
    memcpy(m, message, mlen);

    /* Keypair. Keep PK/SK live so we can expand the public matrices below. */
    PublicKey PK; SecretKey SK;
    generateKeyPair(&PK, &SK);
    {
        writer Wsk = newWriter(sk);
        serialize_SecretKey(&Wsk, &SK);
    }

    /* Expand pk to the m × N*(N+1)/2 upper-triangular layout expected by the
     * notebook parser: for each equation k, walk rows i in [0,N) and write
     * columns j in [i,N) using Q for the v×v and v×o blocks, PK.B2 for o×o. */
    size_t tri = (size_t)N * (N + 1) / 2;
    size_t pk_bytes_len = (size_t)M * tri;
    unsigned char *pk_bytes = malloc(pk_bytes_len);
    if (!pk_bytes) { fprintf(stderr, "alloc failed\n"); return 1; }
    /* Reproduce exactly what UOVClassic_verify consumes for the v×v and v×o
     * blocks: a fresh twister seeded with PK.seed, generating D × M field
     * elements in the same (i,j) row-major order verify walks. Do NOT use
     * calculatePrivateQ — that returns the *private* Q with v×o modified by T. */
    twister MT;
    seedMT(&MT, PK.seed);
    Matrix Q = randomMatrixMT(V * (V + 1) / 2 + V * O, M, &MT);
    for (int k = 0; k < M; k++) {
        size_t out = (size_t)k * tri;
        int q_col = -1;          /* cursor into Q's rows for the v×v/v×o blocks */
        int b2_col = -1;         /* cursor into PK.B2's rows for the o×o block */
        for (int i = 0; i < N; i++) {
            for (int j = i; j < N; j++) {
                FELT val;
                if (i < V) {
                    if (j < V)      val = Q.array[++q_col][k];   /* v×v upper-tri */
                    else            val = Q.array[++q_col][k];   /* v×o */
                } else {
                    /* recompute lex index in B2 only when entering oil row i */
                    if (j == i) {
                        /* lex index of (i-V, i-V) in O*(O+1)/2 layout */
                        int row = i - V;
                        b2_col = row * O - (row * (row - 1)) / 2 - 1;
                    }
                    val = PK.B2.array[++b2_col][k];
                }
                pk_bytes[out++] = (unsigned char)val;
            }
        }
    }
    destroy(Q);

    /* Sign: sm = msg || sig (signature at offset mlen, length CRYPTO_BYTES). */
    {
        reader R = newReader(sk);
        writer W = newWriter(sm);
        W.next = mlen;
        SecretKey skey;
        deserialize_SecretKey(&R, &skey);
        for (size_t i = 0; i < mlen; i++) sm[i] = m[i];
        Signature signature = signDocument(skey, m, mlen);
        serialize_signature(&W, &signature);
        serialize_uint64_t(&W, 0, (8 - W.bitsUsed) % 8);
        destroy_signature(&signature);
        destroy_SecretKey(&skey);
    }

    int rc = 0;
    rc |= write_file(out_dir, pk_file,  pk_bytes, pk_bytes_len);
    rc |= write_file(out_dir, sig_file, sm + mlen, CRYPTO_BYTES);
    rc |= write_file(out_dir, msg_file, m, mlen);

    {
        unsigned long long q;
#ifdef PRIME_FIELD
        q = (unsigned long long)FIELDPRIME;
#else
        q = 1ULL << BITS_PER_FELT;
#endif
        char path[4096];
        snprintf(path, sizeof(path), "%s/uov_params.json", out_dir);
        FILE *fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "{\"n\":%d,\"m\":%d,\"q\":%llu}\n", (int)N, (int)M, q);
            fclose(fp);
            printf("%s\n", path);
        }
    }

    destroy_SecretKey(&SK);
    destroy_PublicKey(&PK);
    free(pk_bytes); free(sk); free(m); free(sm);
    return rc ? 1 : 0;
}
