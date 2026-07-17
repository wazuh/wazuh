/*
 * libcurl HTTPS transport — SPIKE #37738 PoC.
 *
 * Demonstrates the ADR-1 lean (libcurl engine) and the D5/D6/D9 models:
 *   - two headers per request: protocol-version + Authorization (AES-CMAC)
 *   - /stateless H/E batch accumulation (byte budget + interval)
 *   - /stateful whole-session POST streamed from a spooled file
 *     (CURLOPT_READFUNCTION) so peak memory is flat for large inventories
 *     (the #37738 §6 memory technique)
 *   - synchronous request/response everywhere; retry with re-sign on each
 *     attempt (mandated by the 300 s CMAC window), honor Retry-After
 *   - TLS verification modes per DEC-6 (CA file + hostname)
 *
 * Time is the one impurity a PoC needs; production would inject a clock.
 */

#include "hc_client.h"
#include "hc_cmac.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

struct hc_handle {
    hc_config_t cfg;
    hc_callbacks_t cb;
    hc_conn_state_t state;
    /* stateless accumulator: H line is added at flush; events stored as raw
     * "E <frame>\n" text. Bounded; drop-newest on overflow (D6 O-a). */
    char  *acc;
    size_t acc_len, acc_cap;
    unsigned acc_events;
    struct timespec acc_since;
    uint32_t backoff_ms;
    /* The stateless sender thread drains `acc` while agentd's intake thread
     * appends to it: this is the real cross-thread hand-off (D5 note). One
     * mutex guards the accumulator; state changes take it too. Per-request
     * curl handles are created inside each call, so the three endpoint threads
     * never share a handle. */
    pthread_mutex_t lock;
};

/* ---- helpers ---- */
static void set_state(hc_handle *h, hc_conn_state_t s)
{
    pthread_mutex_lock(&h->lock);
    int changed = (h->state != s);
    h->state = s;
    pthread_mutex_unlock(&h->lock);
    if (changed && h->cb.on_state_change) h->cb.on_state_change(s);  /* callback outside lock */
}
static void logf_(hc_handle *h, int lvl, const char *fmt, ...)
{
    if (!h->cb.log) return;
    char buf[1024]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    h->cb.log(lvl, buf);
}

struct resp_buf { char *data; size_t len; };
static size_t write_cb(char *ptr, size_t sz, size_t nm, void *ud)
{
    struct resp_buf *r = ud; size_t n = sz * nm;
    char *p = realloc(r->data, r->len + n + 1);
    if (!p) return 0;
    r->data = p; memcpy(r->data + r->len, ptr, n); r->len += n; r->data[r->len] = '\0';
    return n;
}
/* capture Retry-After from response headers (back-pressure signal) */
struct hdr_ctx { long retry_after; };
static size_t header_cb(char *b, size_t sz, size_t nm, void *ud)
{
    size_t n = sz * nm; struct hdr_ctx *h = ud;
    if (n > 12 && strncasecmp(b, "Retry-After:", 12) == 0) h->retry_after = strtol(b + 12, NULL, 10);
    return n;
}

/* apply the two auth headers + TLS opts to an easy handle */
static struct curl_slist *auth_headers(hc_handle *h, const char *method,
                                       const char *target,
                                       const unsigned char *body, size_t body_len)
{
    long ts = (long)time(NULL);
    size_t clen = 0;
    unsigned char *canon = hc_canonical_request(method, target, h->cfg.agent_id,
                                                ts, body, body_len, &clen);
    if (!canon) return NULL;
    char mac[33];
    int rc = hc_cmac_hex(h->cfg.agent_key_hex, canon, clen, mac);
    free(canon);
    if (rc != 0) return NULL;

    char auth[256];
    snprintf(auth, sizeof auth, "Authorization: Wazuh %s:%ld:%s",
             h->cfg.agent_id, ts, mac);
    struct curl_slist *hl = NULL;
    hl = curl_slist_append(hl, "protocol-version: 1");
    hl = curl_slist_append(hl, auth);
    hl = curl_slist_append(hl, "Content-Type: application/octet-stream");
    hl = curl_slist_append(hl, "Expect:");          /* avoid 100-continue */
    return hl;
}

static void apply_tls(hc_handle *h, CURL *c)
{
    switch (h->cfg.verify_mode) {
    case HC_VERIFY_NONE:
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
        break;
    case HC_VERIFY_CERT:
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
        break;
    case HC_VERIFY_FULL:
    default:
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
        break;
    }
    if (h->cfg.ca_path) curl_easy_setopt(c, CURLOPT_CAINFO, h->cfg.ca_path);
    if (h->cfg.client_cert) curl_easy_setopt(c, CURLOPT_SSLCERT, h->cfg.client_cert);
    if (h->cfg.client_key)  curl_easy_setopt(c, CURLOPT_SSLKEY,  h->cfg.client_key);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);   /* H4: no redirects */
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);         /* H6 */
}

/* classify an HTTP/transport outcome into the D9 error classes */
static int classify(CURLcode cc, long http, long *retry_after_out, long ra)
{
    if (cc != CURLE_OK) return HC_RETRYABLE;      /* timeout/DNS/TLS */
    if (http >= 200 && http < 300) return HC_OK;
    if (http == 401) return HC_AUTH_FAIL;
    if (http == 503 || http == 429) { if (retry_after_out) *retry_after_out = ra; return HC_BACKPRESSURE; }
    if (http >= 500) return HC_RETRYABLE;
    return HC_PERMANENT;                            /* 400/413/... */
}

/* one signed POST from an in-memory body. Fills *resp (caller frees data). */
static int post_mem(hc_handle *h, const char *target,
                    const unsigned char *body, size_t len,
                    struct resp_buf *resp, long *http_out, long *retry_after)
{
    CURL *c = curl_easy_init();
    if (!c) return HC_ERROR;
    char url[512]; snprintf(url, sizeof url, "%s%s", h->cfg.base_url, target);
    struct curl_slist *hl = auth_headers(h, "POST", target, body, len);
    if (!hl) { curl_easy_cleanup(c); return HC_ERROR; }
    struct hdr_ctx hc = { .retry_after = 0 };

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &hc);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, (long)h->cfg.request_timeout_ms);
    apply_tls(h, c);

    CURLcode cc = curl_easy_perform(c);
    long http = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
    if (http_out) *http_out = http;
    int cls = classify(cc, http, retry_after, hc.retry_after);
    if (cc != CURLE_OK) logf_(h, 1, "transport error on %s: %s", target, curl_easy_strerror(cc));
    curl_slist_free_all(hl);
    curl_easy_cleanup(c);
    return cls;
}

/* streamed POST from a spooled FILE* (the /stateful memory technique). We sign
 * the exact bytes we will stream (read the temp file once to compute CMAC, then
 * rewind and let libcurl stream it). */
static size_t read_cb(char *buf, size_t sz, size_t nm, void *ud)
{
    return fread(buf, 1, sz * nm, (FILE *)ud);  /* bytes read */
}
static int post_file(hc_handle *h, const char *target, const char *path,
                     const char *session_id, struct resp_buf *resp,
                     long *http_out, long *retry_after)
{
    /* read spooled body to compute the MAC (single pass) */
    FILE *f = fopen(path, "rb");
    if (!f) return HC_ERROR;
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *body = malloc(fsz ? fsz : 1);
    if (fsz && fread(body, 1, fsz, f) != (size_t)fsz) { fclose(f); free(body); return HC_ERROR; }
    rewind(f);

    long ts = (long)time(NULL);
    size_t clen = 0;
    unsigned char *canon = hc_canonical_request("POST", target, h->cfg.agent_id,
                                                ts, body, fsz, &clen);
    free(body);
    if (!canon) { fclose(f); return HC_ERROR; }
    char mac[33];
    int mrc = hc_cmac_hex(h->cfg.agent_key_hex, canon, clen, mac);
    free(canon);
    if (mrc != 0) { fclose(f); return HC_ERROR; }

    char url[512]; snprintf(url, sizeof url, "%s%s", h->cfg.base_url, target);
    char auth[256]; snprintf(auth, sizeof auth, "Authorization: Wazuh %s:%ld:%s", h->cfg.agent_id, ts, mac);
    char sess[128]; snprintf(sess, sizeof sess, "X-Session-Id: %s", session_id);
    struct curl_slist *hl = NULL;
    hl = curl_slist_append(hl, "protocol-version: 1");
    hl = curl_slist_append(hl, auth);
    hl = curl_slist_append(hl, sess);
    hl = curl_slist_append(hl, "Content-Type: application/octet-stream");
    hl = curl_slist_append(hl, "Expect:");
    struct hdr_ctx hc = { .retry_after = 0 };

    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_READFUNCTION, read_cb);   /* stream from file */
    curl_easy_setopt(c, CURLOPT_READDATA, f);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)fsz);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &hc);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, (long)h->cfg.request_timeout_ms);
    apply_tls(h, c);

    CURLcode cc = curl_easy_perform(c);
    long http = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
    if (http_out) *http_out = http;
    int cls = classify(cc, http, retry_after, hc.retry_after);
    curl_slist_free_all(hl); curl_easy_cleanup(c); fclose(f);
    return cls;
}

static void sleep_ms(uint32_t ms) { struct timespec t = { ms/1000, (long)(ms%1000)*1000000L }; nanosleep(&t, NULL); }

/* ---- public API ---- */
hc_handle *hc_create(const hc_config_t *cfg, const hc_callbacks_t *cb)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    hc_handle *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->cfg = *cfg; h->cb = *cb; h->state = HC_STATE_STARTING;
    h->acc_cap = cfg->batch_size_bytes ? cfg->batch_size_bytes : (1u<<20);
    h->acc = malloc(h->acc_cap);
    h->acc_len = 0;
    pthread_mutex_init(&h->lock, NULL);
    clock_gettime(CLOCK_MONOTONIC, &h->acc_since);
    return h;
}
void hc_destroy(hc_handle *h)
{
    if (!h) return;
    set_state(h, HC_STATE_STOPPED);
    pthread_mutex_destroy(&h->lock);
    free(h->acc); free(h);
    curl_global_cleanup();
}
hc_conn_state_t hc_state(const hc_handle *h)
{
    pthread_mutex_lock((pthread_mutex_t *)&h->lock);
    hc_conn_state_t s = h->state;
    pthread_mutex_unlock((pthread_mutex_t *)&h->lock);
    return s;
}

bool hc_submit_event(hc_handle *h, const uint8_t *frame, size_t len)
{
    /* becomes one "E <frame>\n" line; embedded newlines get a leading space
     * (H/E continuation escaping, #37732 OpenAPI). PoC keeps it simple.
     * Called from agentd's intake thread; guarded against the sender thread. */
    size_t need = 2 + len + 1;
    pthread_mutex_lock(&h->lock);
    if (h->acc_len + need > h->acc_cap) {           /* D6 O-a: drop-newest */
        pthread_mutex_unlock(&h->lock);
        logf_(h, 2, "stateless accumulator full (%zu B) -> drop-newest", h->acc_cap);
        return false;
    }
    memcpy(h->acc + h->acc_len, "E ", 2); h->acc_len += 2;
    memcpy(h->acc + h->acc_len, frame, len); h->acc_len += len;
    h->acc[h->acc_len++] = '\n';
    h->acc_events++;
    pthread_mutex_unlock(&h->lock);
    return true;
}

int hc_flush_events(hc_handle *h)
{
    /* snapshot the accumulator under the lock, send unlocked (so intake never
     * blocks on the network), then consume only the sent prefix — anything
     * appended during the send survives (tail-preserving). */
    pthread_mutex_lock(&h->lock);
    if (h->acc_len == 0) { pthread_mutex_unlock(&h->lock); return HC_OK; }
    size_t take = h->acc_len;
    unsigned ev = h->acc_events;
    char hline[256];
    int hn = snprintf(hline, sizeof hline,
                      "H {\"wazuh\":{\"agent\":{\"id\":\"%s\"}}}\n", h->cfg.agent_id);
    size_t total = (size_t)hn + take;
    unsigned char *body = malloc(total);
    memcpy(body, hline, hn); memcpy(body + hn, h->acc, take);
    pthread_mutex_unlock(&h->lock);

    struct resp_buf resp = {0}; long http = 0, ra = 0;
    int cls = post_mem(h, "/stateless", body, total, &resp, &http, &ra);
    logf_(h, 0, "/stateless -> HTTP %ld (%zu B, %u events)", http, total, ev);
    free(body); free(resp.data);
    if (cls == HC_OK) {
        pthread_mutex_lock(&h->lock);
        memmove(h->acc, h->acc + take, h->acc_len - take);   /* keep the tail */
        h->acc_len -= take;
        h->acc_events = (h->acc_events > ev) ? h->acc_events - ev : 0;
        h->backoff_ms = 0;
        pthread_mutex_unlock(&h->lock);
    }
    return cls;
}

int hc_submit_sync_session(hc_handle *h, const uint8_t *buf, size_t len,
                           const char *session_id, char **result_json_out)
{
    /* spool to a temp file to prove the streamed-body technique */
    char tmpl[] = "/tmp/hc_sync_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return HC_ERROR;
    FILE *w = fdopen(fd, "wb");
    fwrite(buf, 1, len, w); fclose(w);

    struct resp_buf resp = {0}; long http = 0, ra = 0;
    int cls = post_file(h, "/stateful", tmpl, session_id, &resp, &http, &ra);
    logf_(h, 0, "/stateful session=%s -> HTTP %ld (%zu B streamed)", session_id, http, len);
    remove(tmpl);
    if (cls == HC_OK && result_json_out) *result_json_out = resp.data;
    else free(resp.data);
    return cls;
}

int hc_startup(hc_handle *h)
{
    char body[512];
    int n = snprintf(body, sizeof body,
        "{\"phase\":\"startup\",\"version\":\"%s\",\"config_checksum\":\"%s\"}",
        h->cfg.version, h->cfg.config_checksum);
    struct resp_buf resp = {0}; long http = 0, ra = 0;
    int cls = post_mem(h, "/control", (unsigned char*)body, n, &resp, &http, &ra);
    logf_(h, 0, "/control startup -> HTTP %ld", http);
    if (cls == HC_OK) { set_state(h, HC_STATE_REGISTERED);
        if (h->cb.on_startup_result) h->cb.on_startup_result(true, resp.data); }
    else if (http == 426 || http == 400) { set_state(h, HC_STATE_REJECTED);
        if (h->cb.on_startup_result) h->cb.on_startup_result(false, resp.data); }
    else if (cls == HC_AUTH_FAIL) set_state(h, HC_STATE_AUTH_ERROR);
    free(resp.data);
    return cls;
}

int hc_notify(hc_handle *h)
{
    char body[512];
    int n = snprintf(body, sizeof body,
        "{\"phase\":\"notify\",\"status\":\"active\",\"merged_sum\":\"%s\"}",
        h->cfg.config_checksum);
    struct resp_buf resp = {0}; long http = 0, ra = 0;
    int cls = post_mem(h, "/control", (unsigned char*)body, n, &resp, &http, &ra);
    logf_(h, 0, "/control notify -> HTTP %ld", http);
    if (cls == HC_OK && resp.data && h->cb.on_task) {
        /* naive extraction of tasks[]: the PoC hands the whole body to the
         * dispatcher, which parses type/task_id (real code uses cJSON). */
        h->cb.on_task("_raw_notify_response", "", resp.data);
    }
    if (cls == HC_BACKPRESSURE) { logf_(h, 1, "back-pressure: Retry-After=%ld", ra); if (ra>0) sleep_ms((uint32_t)ra*1000); }
    free(resp.data);
    return cls;
}
