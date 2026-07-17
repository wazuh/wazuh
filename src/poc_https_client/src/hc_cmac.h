/* AES-CMAC request signing — SPIKE #37738 PoC. See hc_cmac.c. */
#ifndef HC_CMAC_H
#define HC_CMAC_H

#include <stddef.h>

/* AES-CMAC(key, msg) -> 32 lowercase hex chars + NUL. Returns 0 on success. */
int hc_cmac_hex(const char *key_hex,
                const unsigned char *msg, size_t msg_len,
                char out_hex[33]);

/* Build "WAZUH-REQUEST\n1\nMETHOD\ntarget\nid\nts\n" + body. Caller frees. */
unsigned char *hc_canonical_request(const char *method, const char *target,
                                    const char *agent_id, long timestamp,
                                    const unsigned char *body, size_t body_len,
                                    size_t *out_len);

#endif
