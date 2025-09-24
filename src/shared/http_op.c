#include "http_op.h"
#include "shared.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // strncasecmp

/* ------------------------------- Global state ------------------------------- */
/* Thread-safe, one-time libcurl initialization using pthread_once. */
static _Atomic int g_curl_state = UHTTP_UNINIT;

static void uhttp_atexit_cleanup(void)
{
    curl_global_cleanup();
}

/**
 * @brief Initialize libcurl globally (idempotent, thread-safe).
 * @return 0 on success, -1 on failure.
 */
int uhttp_global_init(void)
{
    int expected = UHTTP_UNINIT;

    // If it is the first thread, it goes to INITING atomically.
    if (atomic_compare_exchange_strong_explicit(
            &g_curl_state, &expected, UHTTP_INITING, memory_order_acq_rel, memory_order_acquire))
    {

        // Only this thread executes the actual init
        CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (rc == CURLE_OK)
        {
            atexit(uhttp_atexit_cleanup); // Cleanup only once per process
            atomic_store_explicit(&g_curl_state, UHTTP_INITED, memory_order_release);
            return 0;
        }
        else
        {
            atomic_store_explicit(&g_curl_state, UHTTP_FAILED, memory_order_release);
            return -1;
        }
    }

    // Another thread is initializing or has already initialized: wait without blocking.
    for (;;)
    {
        int s = atomic_load_explicit(&g_curl_state, memory_order_acquire);
        if (s == UHTTP_INITED)
            return 0;
        if (s == UHTTP_FAILED)
            return -1;
        sched_yield();
    }
}

/**
 * @brief No-op; global cleanup is registered via atexit().
 * Provided for API symmetry only.
 */
void uhttp_global_cleanup(void)
{
    /* no-op */
}

/* ---------------------------- Per-client state ---------------------------- */

struct uhttp_client
{
    CURL* easy;                 ///< libcurl easy handle
    struct curl_slist* headers; ///< owned list of extra headers
    char url[512];              ///< current URL
    char sock[512];             ///< current UNIX socket path
    long timeout_ms;            ///< total transfer timeout (ms)
    long connect_timeout_ms;    ///< connect timeout (ms)
    char* resp_buf;             ///< optional caller-provided response buffer
    size_t resp_cap;            ///< capacity of resp_buf
    size_t resp_used;           ///< bytes written into resp_buf
    int keepalive;              ///< 1 = send "Connection: keep-alive"
};

/* --------------------------- libcurl write callback --------------------------- */
/**
 * @brief libcurl write callback: copy into caller-provided buffer if set.
 *
 * We return the full `n` to libcurl even if we truncated into resp_buf. This
 * treats response capture as best-effort and prevents libcurl from failing the
 * transfer due to partial consumption in the callback.
 */
static size_t _write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    uhttp_client_t* c = (uhttp_client_t*)userdata;
    size_t n = size * nmemb;
    if (!c || !c->resp_buf || c->resp_cap == 0)
        return n; // discard if not capturing
    size_t space = c->resp_cap - c->resp_used;
    size_t copy = (n <= space) ? n : space;
    if (copy)
    {
        memcpy(c->resp_buf + c->resp_used, ptr, copy);
        c->resp_used += copy;
    }
    return n; // IMPORTANT: report “consumed” to libcurl
}

/* ------------------------------ Internal helpers ------------------------------ */

static void _apply_timeouts(uhttp_client_t* c)
{
    if (!c)
        return;
    if (c->timeout_ms > 0)
        curl_easy_setopt(c->easy, CURLOPT_TIMEOUT_MS, c->timeout_ms);
    if (c->connect_timeout_ms > 0)
        curl_easy_setopt(c->easy, CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);
}

static void uhttp_client_free_partial(uhttp_client_t* c, struct curl_slist* hdrs)
{
    if (hdrs)
        curl_slist_free_all(hdrs);
    if (c)
    {
        if (c->easy)
            curl_easy_cleanup(c->easy);
        os_free(c);
    }
}

/* ------------------------------- Client lifecycle ------------------------------- */

uhttp_client_t* uhttp_client_new(const uhttp_options_t* opt)
{
    // This implementation currently requires both the URL and the UNIX socket path.
    if (!opt || !opt->unix_socket_path || !opt->url)
        return NULL;
    if (uhttp_global_init() != 0)
        return NULL;

    uhttp_client_t* c;
    os_calloc(1, sizeof(*c), c);
    if (!c)
        return NULL;

    c->easy = curl_easy_init();
    if (!c->easy)
    {
        os_free(c);
        return NULL;
    }

    snprintf(c->sock, sizeof(c->sock), "%s", opt->unix_socket_path);
    snprintf(c->url, sizeof(c->url), "%s", opt->url);
    c->timeout_ms = opt->timeout_ms;
    c->connect_timeout_ms = opt->connect_timeout_ms;
    c->keepalive = opt->keepalive ? 1 : 0;

    // Build initial headers into a temporary list; take ownership only on success.
    struct curl_slist* hdrs = NULL;

    if (opt->content_type && *opt->content_type)
    {
        if (strncasecmp(opt->content_type, "Content-Type:", 13) == 0)
        {
            hdrs = curl_slist_append(hdrs, opt->content_type);
            if (!hdrs)
            {
                uhttp_client_free_partial(c, hdrs);
                return NULL;
            }
        }
        else
        {
            char line[160];
            snprintf(line, sizeof(line), "Content-Type: %s", opt->content_type);
            hdrs = curl_slist_append(hdrs, line);
            if (!hdrs)
            {
                uhttp_client_free_partial(c, hdrs);
                return NULL;
            }
        }
    }
    else
    {
        // Default to a binary content type if none provided
        hdrs = curl_slist_append(hdrs, "Content-Type: application/octet-stream");
        if (!hdrs)
        {
            uhttp_client_free_partial(c, hdrs);
            return NULL;
        }
    }

    // Disable "Expect: 100-continue" to avoid an extra round-trip on small posts
    hdrs = curl_slist_append(hdrs, "Expect:");
    if (!hdrs)
    {
        uhttp_client_free_partial(c, hdrs);
        return NULL;
    }

    if (c->keepalive)
    {
        // HTTP/1.1 defaults to keep-alive; being explicit is harmless and can help with proxies.
        hdrs = curl_slist_append(hdrs, "Connection: keep-alive");
        if (!hdrs)
        {
            uhttp_client_free_partial(c, hdrs);
            return NULL;
        }
    }

    // Configure the easy handle
    if (curl_easy_setopt(c->easy, CURLOPT_HTTPHEADER, hdrs) != CURLE_OK ||
        curl_easy_setopt(c->easy, CURLOPT_URL, c->url) != CURLE_OK ||
        curl_easy_setopt(c->easy, CURLOPT_UNIX_SOCKET_PATH, c->sock) != CURLE_OK ||
        curl_easy_setopt(c->easy, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(c->easy, CURLOPT_NOSIGNAL, 1L) != CURLE_OK || // multi-thread safe
        curl_easy_setopt(c->easy, CURLOPT_WRITEFUNCTION, _write_cb) != CURLE_OK ||
        curl_easy_setopt(c->easy, CURLOPT_WRITEDATA, c) != CURLE_OK)
    {
        uhttp_client_free_partial(c, hdrs);
        return NULL;
    }

    if (opt->user_agent && *opt->user_agent)
    {
        if (curl_easy_setopt(c->easy, CURLOPT_USERAGENT, opt->user_agent) != CURLE_OK)
        {
            uhttp_client_free_partial(c, hdrs);
            return NULL;
        }
    }

    _apply_timeouts(c);

    // Success: take ownership of the header list
    c->headers = hdrs;
    return c;
}

void uhttp_client_free(uhttp_client_t* c)
{
    if (!c)
        return;
    if (c->headers)
        curl_slist_free_all(c->headers);
    if (c->easy)
        curl_easy_cleanup(c->easy);
    os_free(c);
}

/* -------------------------------- Headers API -------------------------------- */

/**
 * @brief Append an extra header (full line, without CRLF).
 * Example: "X-Token: abc123"
 * @return 0 on success, -1 on allocation or setopt failure.
 */
int uhttp_client_add_header(uhttp_client_t* c, const char* header_line)
{
    if (!c || !header_line)
        return -1;
    struct curl_slist* h = curl_slist_append(c->headers, header_line);
    if (!h)
        return -1;
    c->headers = h;
    curl_easy_setopt(c->easy, CURLOPT_HTTPHEADER, c->headers);
    return 0;
}

/**
 * @brief Clear all previously added headers.
 * Also clears the list attached to libcurl.
 */
void uhttp_client_clear_headers(uhttp_client_t* c)
{
    if (!c)
        return;
    if (c->headers)
    {
        curl_slist_free_all(c->headers);
        c->headers = NULL;
    }
    curl_easy_setopt(c->easy, CURLOPT_HTTPHEADER, c->headers);
}

/* ---------------------------- Response capture API ---------------------------- */

/**
 * @brief Provide a buffer to capture the response body (best effort).
 * No NUL terminator is appended; track `resp_used` if you need one.
 */
void uhttp_client_set_response_buffer(uhttp_client_t* c, char* buf, size_t cap)
{
    if (!c)
        return;
    c->resp_buf = buf;
    c->resp_cap = cap;
    c->resp_used = 0;
}

/* ---------------------------- Dynamic destination ---------------------------- */

int uhttp_client_set_url(uhttp_client_t* c, const char* url)
{
    if (!c || !url)
        return -1;
    snprintf(c->url, sizeof(c->url), "%s", url);
    return curl_easy_setopt(c->easy, CURLOPT_URL, c->url) == CURLE_OK ? 0 : -1;
}

int uhttp_client_set_unix_sock(uhttp_client_t* c, const char* sock_path)
{
    if (!c || !sock_path)
        return -1;
    snprintf(c->sock, sizeof(c->sock), "%s", sock_path);
    return curl_easy_setopt(c->easy, CURLOPT_UNIX_SOCKET_PATH, c->sock) == CURLE_OK ? 0 : -1;
}

/* ----------------------------------- POST ----------------------------------- */

/**
 * @brief Perform an HTTP POST over a UNIX domain socket.
 *
 * @param c       Client handle.
 * @param data    Payload pointer.
 * @param len     Payload size.
 * @param out     Optional result struct: HTTP status and CURLcode.
 * @return 0 on success; negative for libcurl errors; positive HTTP status on non-2xx.
 */
int uhttp_post(uhttp_client_t* c, const void* data, size_t len, uhttp_result_t* out)
{
    if (!c || !c->easy || !data || len == 0)
        return -1;

#if CURL_AT_LEAST_VERSION(7, 58, 0)
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
#else
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDSIZE, (long)len);
#endif

    _apply_timeouts(c);
    c->resp_used = 0;

    CURLcode rc = curl_easy_perform(c->easy);

    // Defensive reset of payload pointers on the handle
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDS, NULL);
#if CURL_AT_LEAST_VERSION(7, 58, 0)
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)0);
#else
    curl_easy_setopt(c->easy, CURLOPT_POSTFIELDSIZE, 0L);
#endif

    long http = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(c->easy, CURLINFO_RESPONSE_CODE, &http);

    if (out)
    {
        out->http_status = http;
        out->curl_code = rc;
    }

    if (rc != CURLE_OK)
        return -rc; // libcurl error (negative)
    if (http < 200 || http >= 300)
        return (int)http; // HTTP status as positive code
    return 0;             // success
}
