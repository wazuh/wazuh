/*
 * PoC driver — SPIKE #37738.
 *
 * Stands in for the agentd seams (D-a/E-a): it feeds events, assembles a
 * stateful session, runs the control loop, dispatches tasks, and exercises the
 * D9 retry loop (full-jitter back-off, re-sign each attempt). It is NOT a
 * daemon; it runs a short scripted scenario and exits so the run is observable.
 *
 * Usage: hc_poc <base_url> <agent_id> <key_hex> <ca_path> [scenario]
 *   scenario: happy (default) | tamper (send a bad key -> 401) | big (large /stateful)
 */

#include "hc_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *lvlname(int l){ return l==0?"INFO":l==1?"WARN":l==2?"WARN":"ERR"; }
static void on_log(int level, const char *msg){ printf("   [%s] %s\n", lvlname(level), msg); }
static void on_startup(bool ok, const char *meta){
    printf("   >> startup %s; manager metadata: %s\n", ok?"ACCEPTED":"REJECTED", meta?meta:"(none)");
}
static void on_task(const char *type, const char *id, const char *payload){
    (void)id;
    printf("   >> notify response received (%s): %s\n", type, payload?payload:"(empty)");
    printf("      -> would dispatch tasks[] to execd / modules / restart handlers,\n");
    printf("         dedupe by task_id, then POST /control response with results.\n");
}
static const char *statename(hc_conn_state_t s){
    switch(s){case HC_STATE_STARTING:return"STARTING";case HC_STATE_REGISTERED:return"REGISTERED";
    case HC_STATE_REJECTED:return"REJECTED";case HC_STATE_AUTH_ERROR:return"AUTH_ERROR";default:return"STOPPED";}
}
static void on_state(hc_conn_state_t s){ printf("   ~~ state -> %s\n", statename(s)); }

/* D9 retry loop: retry on RETRYABLE/BACKPRESSURE with full-jitter back-off,
 * bounded attempts. Each call re-signs (handled inside the client). */
static int with_retry(const char *what, hc_handle *h, int (*fn)(hc_handle*), int max_attempts)
{
    uint32_t backoff = 1000;
    for (int a = 1; a <= max_attempts; a++) {
        int rc = fn(h);
        if (rc == HC_OK || rc == HC_PERMANENT || rc == HC_AUTH_FAIL) return rc;
        uint32_t cap = 8000; if (backoff > cap) backoff = cap;
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        uint32_t jitter = (uint32_t)((now.tv_nsec) % (backoff ? backoff : 1)); /* full jitter */
        printf("   .. %s rc=%d, attempt %d/%d, back-off %u ms (jittered)\n", what, rc, a, max_attempts, jitter);
        struct timespec t = { jitter/1000, (long)(jitter%1000)*1000000L }; nanosleep(&t, NULL);
        backoff *= 2;
    }
    return HC_RETRYABLE;
}

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: %s <base_url> <agent_id> <key_hex> <ca_path> [scenario]\n", argv[0]); return 2; }
    const char *base = argv[1], *id = argv[2], *key = argv[3], *ca = argv[4];
    const char *scenario = argc > 5 ? argv[5] : "happy";

    hc_config_t cfg = {
        .base_url = base, .agent_id = id, .agent_key_hex = key,
        .verify_mode = HC_VERIFY_FULL, .ca_path = ca,
        .batch_size_bytes = 1u<<20, .batch_interval_ms = 10000,
        .version = "5.1.0", .config_checksum = "d41d8cd98f00b204e9800998ecf8427e",
        .backoff_base_ms = 1000, .backoff_cap_ms = 60000, .request_timeout_ms = 10000,
    };
    if (strcmp(scenario, "tamper") == 0) cfg.agent_key_hex = "ffffffffffffffffffffffffffffffff"; /* wrong key -> 401 */

    hc_callbacks_t cb = { .log=on_log, .on_startup_result=on_startup, .on_task=on_task, .on_state_change=on_state };
    hc_handle *h = hc_create(&cfg, &cb);
    if (!h) { fprintf(stderr, "hc_create failed\n"); return 1; }

    printf("\n== 1. /control startup (with AES-CMAC auth over TLS) ==\n");
    int rc = with_retry("startup", h, hc_startup, 4);
    if (rc == HC_AUTH_FAIL) { printf("   result: 401 as expected for scenario '%s'.\n", scenario);
        if (strcmp(scenario,"tamper")==0){ printf("\n== tamper scenario proved: bad MAC -> 401, request refused ==\n"); hc_destroy(h); return 0; } }

    printf("\n== 2. /stateless (H/E batch) ==\n");
    hc_submit_event(h, (const uint8_t*)"1:/var/log/syslog:sshd: Accepted publickey for root", 51);
    hc_submit_event(h, (const uint8_t*)"1:/var/log/auth.log:session opened for user root", 48);
    hc_submit_event(h, (const uint8_t*)"v:vulnerability-scanner:{\"cve\":\"CVE-2024-1234\"}", 46);
    with_retry("flush", h, hc_flush_events, 4);

    printf("\n== 3. /stateful (FullSession, streamed from a spooled file) ==\n");
    size_t n = strcmp(scenario,"big")==0 ? (size_t)(3*1024*1024) : 4096;
    unsigned char *sess = malloc(n);
    /* fake FlatBuffer-ish payload: header + filler standing in for Start+Data+End */
    memcpy(sess, "FULLSESSION:syscollector:", 25);
    memset(sess+25, 'D', n-25);
    char *result = NULL;
    int scls = hc_submit_sync_session(h, sess, n, "sess-0001", &result);
    if (scls == HC_OK) printf("   >> /stateful result: %s\n", result ? result : "(empty)");
    /* prove same-session-id retry dedup: send it again */
    printf("   .. re-sending the SAME session id (simulating a client retry after timeout):\n");
    char *result2 = NULL;
    hc_submit_sync_session(h, sess, n, "sess-0001", &result2);
    printf("   >> manager should return the CACHED result (dedup via 10-min LRU).\n");
    free(sess); free(result); free(result2);

    printf("\n== 4. /control notify (pull tasks + dispatch + response) ==\n");
    with_retry("notify", h, hc_notify, 4);

    printf("\n== done (scenario: %s) ==\n", scenario);
    hc_destroy(h);
    return 0;
}
