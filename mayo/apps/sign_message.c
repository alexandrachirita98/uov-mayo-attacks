// SPDX-License-Identifier: Apache-2.0

#include <api.h>
#include <mem.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s --message <str> --out-dir <path>"
        " [--pk-file <name>] [--sig-file <name>] [--msg-file <name>]\n",
        argv0);
}

static int mkdir_p(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    return -1;
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

    size_t msglen = strlen(message);
    size_t smlen  = CRYPTO_BYTES + msglen;

    unsigned char *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    unsigned char *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    unsigned char *sm = calloc(smlen, 1);
    if (!pk || !sk || !sm) { fprintf(stderr, "alloc failed\n"); return 1; }

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "crypto_sign_keypair failed\n"); return 1;
    }
    if (crypto_sign(sm, &smlen, (const unsigned char *)message, msglen, sk) != 0) {
        fprintf(stderr, "crypto_sign failed\n"); return 1;
    }

    int rc = 0;
    rc |= write_file(out_dir, pk_file,  pk, CRYPTO_PUBLICKEYBYTES);
    rc |= write_file(out_dir, sig_file, sm, CRYPTO_BYTES);
    rc |= write_file(out_dir, msg_file, (const unsigned char *)message, msglen);

    free(pk);
    mayo_secure_free(sk, CRYPTO_SECRETKEYBYTES);
    free(sm);
    return rc ? 1 : 0;
}
