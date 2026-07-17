/*
 * Wazuh agent HTTPS client — SPIKE #37738 proof of concept
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This is a self-contained spike artifact. It is NOT wired into any daemon and
 * is not part of the agent build. It exists to exercise the proposed HTTPS
 * transport contract (#37732 auth, #37733 tasks, #37738 flows) end to end
 * against a mock manager, and to be the runnable form of deliverable D10/T12.
 *
 * The public shape mirrors the D3 interface strawman
 * (pages/design-architecture.html §G): an opaque handle, an injected config and
 * callback table, and submit/lifecycle calls. The PoC implements the subset
 * needed to prove the mechanics.
 */

#ifndef HC_CLIENT_H
#define HC_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ---- verification modes (DEC-6: CA file + hostname; no native OS stores) ---- */
typedef enum {
    HC_VERIFY_NONE = 0,   /* SSL_VERIFYPEER 0                 */
    HC_VERIFY_CERT,       /* peer only  (VERIFYHOST 0)        */
    HC_VERIFY_FULL        /* peer + hostname (VERIFYHOST 2)   */
} hc_verify_mode_t;

/* ---- connection state, surfaced to the C core for the .state metrics ---- */
typedef enum {
    HC_STATE_STARTING = 0,
    HC_STATE_REGISTERED,
    HC_STATE_REJECTED,
    HC_STATE_AUTH_ERROR,   /* persistent 401 (clock skew / key)         */
    HC_STATE_STOPPED
} hc_conn_state_t;

/* ---- config parsed from <client> (single <server>, IR2) ---- */
typedef struct {
    const char *base_url;           /* e.g. https://127.0.0.1:27840        */
    /* auth (#37732): pre-shared AES key, hex; agent id from client.keys    */
    const char *agent_id;
    const char *agent_key_hex;      /* 16-byte AES-128 key as 32 hex chars  */
    /* TLS (DEC-6)                                                          */
    hc_verify_mode_t verify_mode;
    const char *ca_path;            /* certificate_authorities              */
    const char *client_cert;        /* optional mTLS (FR11.3)               */
    const char *client_key;
    /* batching (FR10)                                                      */
    size_t   batch_size_bytes;      /* <batch><size>   default 1 MB         */
    uint32_t batch_interval_ms;     /* <batch><interval> default 10 s       */
    /* control                                                             */
    const char *version;            /* product version for Startup          */
    const char *config_checksum;    /* merged.mg md5 for Startup/Notify     */
    /* retry/back-off (D9)                                                  */
    uint32_t backoff_base_ms;       /* 1000                                 */
    uint32_t backoff_cap_ms;        /* 60000                                */
    uint32_t request_timeout_ms;    /* per request; /stateful gets a longer one */
} hc_config_t;

/* ---- environment injected by the C core (P1/P2 hybrid) ---- */
typedef struct {
    void (*log)(int level, const char *msg);                         /* -> mt* */
    void (*on_startup_result)(bool accepted, const char *metadata_json);
    void (*on_task)(const char *type, const char *task_id,
                    const char *payload_json);                       /* A6 */
    void (*on_state_change)(hc_conn_state_t state);
} hc_callbacks_t;

typedef struct hc_handle hc_handle;

/* ---- lifecycle ---- */
hc_handle *hc_create(const hc_config_t *cfg, const hc_callbacks_t *cb);
void       hc_destroy(hc_handle *h);

/* ---- data plane (called from agentd's EventForward seam; D-a) ---- */
/* frame = the local "queue:location:message" bytes; becomes one H/E "E " line */
bool hc_submit_event(hc_handle *h, const uint8_t *frame, size_t len);

/* stateful: a whole sync session already assembled by the STREAM/spool path
 * (#37738 §6). buf may be large; the client streams it as one POST. */
int  hc_submit_sync_session(hc_handle *h, const uint8_t *buf, size_t len,
                            const char *session_id, char **result_json_out);

/* ---- control plane ---- */
int  hc_startup(hc_handle *h);              /* POST /control startup       */
int  hc_notify(hc_handle *h);               /* POST /control notify (pull) */
int  hc_flush_events(hc_handle *h);         /* POST /stateless if due      */

hc_conn_state_t hc_state(const hc_handle *h);

/* result codes */
enum { HC_OK = 0, HC_RETRYABLE = 1, HC_BACKPRESSURE = 2, HC_AUTH_FAIL = 3,
       HC_PERMANENT = 4, HC_ERROR = 5 };

#endif /* HC_CLIENT_H */
