#define _GNU_SOURCE
/* Fuzzer for the WPK256 package verifier (shared/os_crypto/signature).
 *
 * Threat model:
 * - w_wpk_unsign() validates WPK256 update packages, whose bytes are fully
 *   attacker-controlled when they arrive from a compromised/malicious
 *   source: it parses the "WPK256" container (magic, embedded X.509
 *   certificate, 256-byte RSA signature, content), verifies the embedded
 *   certificate against the configured CA store, hashes the content and
 *   checks the PKCS1-SHA256 signature before ever writing the payload out.
 * - A real finding is a memory-safety violation (OOB read/write around the
 *   magic/certificate/signature framing, OpenSSL-object misuse that the
 *   caller can observe, per-iteration leak) or a crash for malformed
 *   packages.
 *
 * Harness contract (legitimate input): the package is written to a file and
 * handed to w_wpk_unsign() by path, together with a writable target path
 * and a NULL-terminated CA-store array. The store holds one throwaway
 * self-signed test certificate taken from $OUT/wz_test_ca.pem (never a real
 * trust anchor); when it is unavailable the store is left empty, which the
 * verifier reports through its normal no-CA path. Both temporary files are
 * removed every iteration, so leaks are never harness-owned.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os_crypto/signature/signature.h"

#define FZ_MAX_INPUT (4u * 1024u * 1024u)
#define FZ_SRC_PATH "/tmp/wz-fuzz-src.wpk"
#define FZ_TARGET_PATH "/tmp/wz-fuzz-target.out"
#define FZ_CA_PATH "/tmp/wz-fuzz-ca.pem"

static const char *ca_store[2] = { NULL, NULL };

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;

    const char *out = getenv("OUT");
    if (out != NULL) {
        char src[512];
        snprintf(src, sizeof(src), "%s/wz_test_ca.pem", out);
        FILE *in = fopen(src, "rb");
        if (in != NULL) {
            FILE *dst = fopen(FZ_CA_PATH, "wb");
            if (dst != NULL) {
                char buf[1024];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
                    fwrite(buf, 1, n, dst);
                }
                fclose(dst);
                ca_store[0] = FZ_CA_PATH;
            }
            fclose(in);
        }
    }
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8 || size > FZ_MAX_INPUT) {
        return 0;
    }

    FILE *file = fopen(FZ_SRC_PATH, "wb");
    if (file == NULL) {
        return 0;
    }
    (void) fwrite(data, size, 1, file);
    fclose(file);

    unlink(FZ_TARGET_PATH);
    (void) w_wpk_unsign(FZ_SRC_PATH, FZ_TARGET_PATH, ca_store);
    unlink(FZ_TARGET_PATH);
    unlink(FZ_SRC_PATH);
    return 0;
}
