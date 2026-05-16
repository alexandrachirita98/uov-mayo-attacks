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
    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char *m  = malloc(mlen);
    unsigned char *sm = malloc(mlen + CRYPTO_BYTES);
    if (!pk || !sk || !m || !sm) { fprintf(stderr, "alloc failed\n"); return 1; }
    memcpy(m, message, mlen);

    /* keypair: replicates the wrappers from common/main.c without modifying it */
    {
        writer W = newWriter(sk);
        PublicKey PK; SecretKey SK;
        generateKeyPair(&PK, &SK);
        serialize_SecretKey(&W, &SK);
        W = newWriter(pk);
        serialize_PublicKey(&W, &PK);
        destroy_SecretKey(&SK);
        destroy_PublicKey(&PK);
    }

    /* sign: layout is sm = msg || sig (sig at offset mlen, length CRYPTO_BYTES) */
    unsigned long long smlen;
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
        smlen = W.next;
        destroy_signature(&signature);
        destroy_SecretKey(&skey);
    }

    int rc = 0;
    rc |= write_file(out_dir, pk_file,  pk, CRYPTO_PUBLICKEYBYTES);
    rc |= write_file(out_dir, sig_file, sm + mlen, CRYPTO_BYTES);
    rc |= write_file(out_dir, msg_file, m, mlen);

    /* Emit uov_params.json from compile-time macros (avoids fragile header parsing). */
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

    free(pk); free(sk); free(m); free(sm);
    (void)smlen;
    return rc ? 1 : 0;
}
