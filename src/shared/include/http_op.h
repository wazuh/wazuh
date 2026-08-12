#ifndef HTTP_OP_H
#define HTTP_OP_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @file http_op.h
 * @brief Minimal HTTP client (thin libcurl wrapper) with optional
 *        UNIX domain socket routing and per-thread client handles.
 *
 * ### Overview
 * - Call `uhttp_global_init()` **once per process** before creating clients,
 *   and `uhttp_global_cleanup()` on shutdown.
 * - Create **one `uhttp_client_t` per thread** for best performance and to
 *   avoid libcurl handle sharing.
 * - Supports standard HTTP(S) URLs and HTTP over UNIX domain sockets
 *   (via libcurl's `CURLOPT_UNIX_SOCKET_PATH`) when `unix_socket_path` is set.
 * - `uhttp_post()` sends a single-buffer POST request; optional response
 *   capture can be enabled with `uhttp_client_set_response_buffer()`.
 *
 * ### Thread-safety
 * - Global init/cleanup are process-wide and should not be called concurrently.
 * - A `uhttp_client_t` is **not** thread-safe; do not share a client across threads.
 */

/** Opaque per-thread client handle. */
typedef struct uhttp_client uhttp_client_t;

/**
 * @brief Client configuration options.
 *
 * All fields are optional unless otherwise specified. Strings must remain
 * valid for the lifetime of the client unless replaced via setters.
 */
typedef struct
{
    /**
     * UNIX domain socket path (e.g., "/var/run/engine/enriched.sock").
     * When set, requests are routed through this socket while still using
     * the scheme/host/path from `url`. Set to NULL to disable.
     */
    const char* unix_socket_path;

    /**
     * Target URL (e.g., "http://localhost/events/enriched").
     * Must be a valid absolute URL; required for POST operations.
     */
    const char* url;

    /**
     * Content-Type header to send with POST requests
     * (e.g., "application/x-wev1" or "application/json").
     * If NULL, no explicit Content-Type is added unless provided via headers.
     */
    const char* content_type;

    /**
     * Optional User-Agent string.
     * If NULL, libcurl's default User-Agent is used.
     */
    const char* user_agent;

    /**
     * Total transfer timeout in milliseconds (0 = libcurl default).
     * Applies to the entire request lifecycle.
     */
    long timeout_ms;

    /**
     * Connect timeout in milliseconds (0 = libcurl default).
     */
    long connect_timeout_ms;

    /**
     * Whether to enable HTTP keep-alive (persistent connections).
     * Default is true.
     */
    bool keepalive;
} uhttp_options_t;

/**
 * @brief Result metadata from the most recent request.
 */
typedef struct
{
    long http_status; /**< Final HTTP status code (e.g., 200, 404). 0 if unavailable. */
    int curl_code;    /**< libcurl `CURLE_*` result code from the transfer. */
} uhttp_result_t;

enum uhttp_init_state
{
    UHTTP_UNINIT = 0,
    UHTTP_INITING,
    UHTTP_INITED,
    UHTTP_FAILED
};

/**
 * @brief Initialize global HTTP state (libcurl).
 * @return 0 on success; non-zero on failure.
 *
 * Must be called before creating any `uhttp_client_t`.
 */
int uhttp_global_init(void);

/**
 * @brief Tear down global HTTP state initialized by `uhttp_global_init()`.
 * Safe to call once when the process is shutting down.
 */
void uhttp_global_cleanup(void);

/**
 * @brief Create a new HTTP client with the given options.
 * @param opt Optional pointer to options; if NULL, sensible defaults are used.
 * @return Pointer to a new client, or NULL on error.
 */
uhttp_client_t* uhttp_client_new(const uhttp_options_t* opt);

/**
 * @brief Destroy a client and release all associated resources.
 */
void uhttp_client_free(uhttp_client_t* c);

/**
 * @brief Add an extra header line to be sent with requests.
 * @param c            Client handle.
 * @param header_line  Full header line without CRLF, e.g. "X-Token: abc".
 * @return 0 on success; non-zero on error.
 *
 * Multiple headers may be added; duplicates are allowed and sent in order.
 */
int uhttp_client_add_header(uhttp_client_t* c, const char* header_line);

/**
 * @brief Remove ALL headers from the client, including the ones the constructor installed
 *        (`Content-Type`, the `Expect: 100-continue` suppression and, when enabled,
 *        `Connection: keep-alive`).
 *
 * Use uhttp_client_reset_headers() instead when the intent is "start this request's headers over":
 * clearing and then adding only a per-request header leaves the client without its constructor
 * defaults for the rest of its life.
 */
void uhttp_client_clear_headers(uhttp_client_t* c);

/**
 * @brief Restore the header list the constructor installed, dropping any per-request additions.
 *
 * The list to build from is remembered at construction time, so this reproduces the original
 * `Content-Type`, the `Expect:` suppression and the keep-alive exactly. Intended for a client
 * reused across requests that differ by one header: reset, then add that header.
 *
 * @return 0 on success; non-zero on failure (the previous list is left in place).
 */
int uhttp_client_reset_headers(uhttp_client_t* c);

/**
 * @brief Set a caller-provided buffer to capture the response body.
 * @param c    Client handle.
 * @param buf  Byte buffer owned by the caller.
 * @param cap  Buffer capacity in bytes.
 *
 * When set, `uhttp_post()` will write the response body into `buf`
 * (up to `cap` bytes, truncating if necessary). No NUL terminator is added.
 * Call again with `buf = NULL, cap = 0` to disable capture.
 */
void uhttp_client_set_response_buffer(uhttp_client_t* c, char* buf, size_t cap);

/**
 * @brief Send a POST request with a single contiguous payload buffer.
 * @param c      Client handle.
 * @param data   Pointer to payload bytes. May be NULL for a body-less POST (with `len` 0).
 * @param len    Payload length in bytes. 0 sends `Content-Length: 0` and no body.
 * @param out    Optional: result metadata (HTTP status, curl code).
 * @return 0 on success; non-zero on failure. Refuses only the contradictory combination of a
 *         NULL `data` with a positive `len`.
 *
 * On return, if `out` is provided, `out->curl_code` contains the libcurl
 * transfer result (CURLE_OK on success). `out->http_status` contains the
 * server's HTTP status if available (0 otherwise).
 *
 * NOTE for callers checking the outcome: because CURLE_OK is 0, `curl_code` alone cannot tell
 * success from "never attempted" -- the argument-validation failures above return non-zero WITHOUT
 * writing `out`. Treat `out->curl_code == 0 && out->http_status == 0` together with a non-zero
 * return as "the request was never sent", not as a transport error.
 */
int uhttp_post(uhttp_client_t* c, const void* data, size_t len, uhttp_result_t* out);

/**
 * @brief Change the target URL for subsequent requests.
 * @return 0 on success; non-zero on error (e.g., invalid URL).
 */
int uhttp_client_set_url(uhttp_client_t* c, const char* url);

/**
 * @brief Change the UNIX socket path for subsequent requests.
 * @param sock_path New socket path, or NULL to disable UNIX socket routing.
 * @return 0 on success; non-zero on error.
 */
int uhttp_client_set_unix_sock(uhttp_client_t* c, const char* sock_path);

#endif // HTTP_OP_H
