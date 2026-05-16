// SPDX-License-Identifier: Apache-2.0
//
// Signs a user-provided message and writes pk / sig / msg files in the layout
// the ks_vs_intersection_attacks notebook parser expects:
//   pk = for each k in [0,m): nbytes(tri_v) || nbytes(rect) || nbytes(tri_o)
// where each block holds the upper-triangular (or full v×o) nibble entries
// of equation k packed low-nibble-first.
//
// MAYO-C's internal layout is the opposite: per coefficient position, m
// nibbles packed together (m-vec layout, m_bytes per position). We therefore
// re-run the AES-CTR expansion of P1+P2 from seed_pk, append P3 from cpk, and
// transpose the result.

#include <api.h>
#include <mayo.h>
#include <mem.h>
#include <aes_ctr.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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

/* Pull nibble k (0..m-1) from a block laid out as `count` consecutive m-vecs,
 * each m-vec being m_bytes bytes (m nibbles, low-first per byte). */
static unsigned char read_nibble(const unsigned char *block, int pos,
                                 int k, int m_bytes) {
    unsigned char b = block[pos * m_bytes + k / 2];
    return (k & 1) ? (b >> 4) : (b & 0xF);
}

/* Pack `count` nibbles from src (one nibble per byte, low half) into dst,
 * low-nibble first. Returns number of bytes written. */
static size_t pack_nibbles(unsigned char *dst, const unsigned char *src, int count) {
    size_t nb = (count + 1) / 2;
    memset(dst, 0, nb);
    for (int i = 0; i < count; i++) {
        if ((i & 1) == 0) dst[i / 2] = src[i] & 0xF;
        else              dst[i / 2] |= (src[i] & 0xF) << 4;
    }
    return nb;
}

int main(int argc, char **argv) {
    const char *message = NULL, *out_dir = NULL;
    const char *pk_file = "mayo_pk.bin";
    const char *sig_file = "mayo_sig.bin";
    const char *msg_file = "mayo_msg.txt";

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

    /* Per-variant constants. SM_VARIANT is set by CMake (MAYO_1 / MAYO_2 / ...).
     * We can't use PARAM_NAME directly because defining MAYO_VARIANT would
     * mangle the crypto_sign_* symbols and break linkage. */
#define _SM_JOIN(a, b) a##_##b
#define _SM_EXPAND(a, b) _SM_JOIN(a, b)
#define SM(end) _SM_EXPAND(SM_VARIANT, end)
    const int n        = SM(n);
    const int o        = SM(o);
    const int v        = n - o;
    const int m        = SM(m);
    const int m_bytes  = SM(m_bytes);
    const int pk_seed_bytes = SM(pk_seed_bytes);
    const size_t P1_bytes = SM(P1_bytes);
    const size_t P2_bytes = SM(P2_bytes);
    (void)SM(P3_bytes);
    const int tri_v = v * (v + 1) / 2;
    const int rect  = v * o;
    const int tri_o = o * (o + 1) / 2;
    const size_t per_eq = (tri_v + 1) / 2 + (rect + 1) / 2 + (tri_o + 1) / 2;

    size_t msglen = strlen(message);
    size_t smlen  = CRYPTO_BYTES + msglen;

    unsigned char *cpk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    unsigned char *csk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    unsigned char *sm  = calloc(smlen, 1);
    unsigned char *p12 = malloc(P1_bytes + P2_bytes);
    unsigned char *out = calloc((size_t)m * per_eq, 1);
    unsigned char *nibs = malloc(tri_v > rect ? (tri_v > tri_o ? tri_v : tri_o)
                                              : (rect > tri_o ? rect : tri_o));
    if (!cpk || !csk || !sm || !p12 || !out || !nibs) {
        fprintf(stderr, "alloc failed\n"); return 1;
    }

    if (crypto_sign_keypair(cpk, csk) != 0) { fprintf(stderr, "keypair failed\n"); return 1; }
    if (crypto_sign(sm, &smlen, (const unsigned char *)message, msglen, csk) != 0) {
        fprintf(stderr, "sign failed\n"); return 1;
    }

    /* cpk layout: seed_pk(pk_seed_bytes) || P3_packed(P3_bytes). */
    AES_128_CTR(p12, P1_bytes + P2_bytes, cpk, pk_seed_bytes);
    const unsigned char *p3 = cpk + pk_seed_bytes;

    for (int k = 0; k < m; k++) {
        unsigned char *dst = out + (size_t)k * per_eq;

        for (int i = 0; i < tri_v; i++) nibs[i] = read_nibble(p12, i, k, m_bytes);
        dst += pack_nibbles(dst, nibs, tri_v);

        for (int i = 0; i < rect; i++)  nibs[i] = read_nibble(p12 + P1_bytes, i, k, m_bytes);
        dst += pack_nibbles(dst, nibs, rect);

        for (int i = 0; i < tri_o; i++) nibs[i] = read_nibble(p3, i, k, m_bytes);
        dst += pack_nibbles(dst, nibs, tri_o);
    }

    int rc = 0;
    rc |= write_file(out_dir, pk_file,  out, (size_t)m * per_eq);
    rc |= write_file(out_dir, sig_file, sm, CRYPTO_BYTES);
    rc |= write_file(out_dir, msg_file, (const unsigned char *)message, msglen);

    free(cpk);
    mayo_secure_free(csk, CRYPTO_SECRETKEYBYTES);
    free(sm); free(p12); free(out); free(nibs);
    return rc ? 1 : 0;
}
