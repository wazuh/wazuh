/*
 * AES-CMAC request signing — SPIKE #37738 PoC
 * Implements the #37732 canonical-request authentication scheme:
 *
 *   canonical = "WAZUH-REQUEST\n" ver "\n" METHOD "\n" target "\n"
 *               agent-id "\n" timestamp "\n" body
 *   mac       = AES-CMAC(agent-key, canonical)        (16 bytes -> 32 hex)
 *   Authorization: Wazuh <agent-id>:<timestamp>:<mac>
 *   protocol-version: 1
 *
 * Uses OpenSSL 3.x EVP_MAC ("CMAC"), which is available in the vendored
 * external/openssl (verified: cmac.h + EVP_MAC_fetch/EVP_MAC_init). The mock
 * manager verifies the same MAC via the `openssl mac` CLI — so a matching run
 * proves cross-implementation interop, not just self-consistency.
 */

#include "hc_cmac.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int hex2bin(const char *hex, unsigned char *out, size_t out_len)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

int hc_cmac_hex(const char *key_hex,
                const unsigned char *msg, size_t msg_len,
                char out_hex[33])
{
    unsigned char key[16];
    if (hex2bin(key_hex, key, sizeof key) != 0) return -1;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = -1;
    if (ctx) {
        char cipher[] = "AES-128-CBC";
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string("cipher", cipher, 0),
            OSSL_PARAM_END
        };
        unsigned char tag[16];
        size_t taglen = 0;
        if (EVP_MAC_init(ctx, key, sizeof key, params) == 1 &&
            EVP_MAC_update(ctx, msg, msg_len) == 1 &&
            EVP_MAC_final(ctx, tag, &taglen, sizeof tag) == 1 &&
            taglen == 16) {
            for (int i = 0; i < 16; i++) sprintf(out_hex + 2 * i, "%02x", tag[i]);
            out_hex[32] = '\0';
            rc = 0;
        }
        EVP_MAC_CTX_free(ctx);
    }
    EVP_MAC_free(mac);
    return rc;
}

/* Build the canonical request into a freshly malloc'd buffer (caller frees). */
unsigned char *hc_canonical_request(const char *method, const char *target,
                                    const char *agent_id, long timestamp,
                                    const unsigned char *body, size_t body_len,
                                    size_t *out_len)
{
    char head[512];
    int hn = snprintf(head, sizeof head,
                      "WAZUH-REQUEST\n1\n%s\n%s\n%s\n%ld\n",
                      method, target, agent_id, timestamp);
    if (hn < 0 || (size_t)hn >= sizeof head) return NULL;

    size_t total = (size_t)hn + body_len;
    unsigned char *buf = malloc(total);
    if (!buf) return NULL;
    memcpy(buf, head, (size_t)hn);
    if (body_len) memcpy(buf + hn, body, body_len);
    *out_len = total;
    return buf;
}
