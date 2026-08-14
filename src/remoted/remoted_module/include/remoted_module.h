/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_H
#define _REMOTED_MODULE_H

/*
 * C-ABI bridge for the remoted C++ module.
 *
 * This is the ONLY header shared between remoted's C code and the C++ module.
 * It exposes a POD configuration struct plus start/stop entry points, so the
 * C daemon can launch and configure the C++ worker without ever seeing any C++
 * type. remoted links the module directly (see src/remoted/CMakeLists.txt).
 */

// Define EXPORTED for any platform
#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h" // full_log_fnc_t

    /**
     * @brief <remote><https><verification_mode> values.
     *
     * Kept in sync by hand with the config-parser mirror in
     * src/config/include/remote-config.h (REMOTED_HTTPS_VERIFY_*), since the value
     * crosses the C-ABI boundary as a plain int.
     */
    enum
    {
        REMOTED_MODULE_HTTPS_VERIFY_UNSET = -1,
        REMOTED_MODULE_HTTPS_VERIFY_NONE = 0,
        REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE = 1,
        REMOTED_MODULE_HTTPS_VERIFY_FULL = 2
    };

    /**
     * @brief <remote><https><dual_stack> values.
     *
     * Only meaningful when the listener binds to an IPv6 address: controls the
     * IPV6_V6ONLY socket option, i.e. whether the same socket also accepts IPv4
     * clients. Kept in sync by hand with the config-parser mirror in
     * src/config/include/remote-config.h (REMOTED_HTTPS_DUAL_STACK_*).
     */
    enum
    {
        REMOTED_MODULE_HTTPS_DUAL_STACK_UNSET = 0, ///< Not configured -> module defaults to IPv6-only. Kept distinct
                                                   ///< from _NO so the "dual_stack only applies to an IPv6
                                                   ///< bind_addr" warning doesn't fire when unconfigured
                                                   ///< (see resolveDualStackMode()/RestinioHttpServer.cpp).
        REMOTED_MODULE_HTTPS_DUAL_STACK_YES = 1,   ///< Force dual-stack on (also accept IPv4).
        REMOTED_MODULE_HTTPS_DUAL_STACK_NO = 2     ///< Force IPv6-only.
    };

    /**
     * @brief Configuration passed from remoted (C) to the C++ module.
     *
     * POD struct with fixed-size buffers so the ABI is stable and it compiles
     * cleanly both as C99 (remoted) and C++17 (the module). The struct is owned
     * by the caller; the module copies whatever it needs during start().
     */
    typedef struct remoted_module_config_t
    {
        int port;                        ///< HTTPS listening port. Regular <remote> setting (wazuh-manager.conf),
                                         ///< not an internal option. <=0 -> module default.
        bool worker_node;                ///< true if this manager is a cluster worker node.
        char cluster_name[256];          ///< Cluster name.
        char certificate_path[512];      ///< TLS certificate chain (PEM) path (empty -> module default).
        char private_key_path[512];      ///< TLS private key (PEM) path (empty -> module default).
        int io_threads;                  ///< HTTPS I/O threads. <=0 -> module default (see remoted.http_io_threads).
        int http_worker_threads;         ///< HTTPS handler worker-pool size. <=0 -> module default
                                         ///< (see remoted.http_worker_threads).
        long http_max_body_size;         ///< Transport body cap, bytes. Regular <remote><https> setting
                                         ///< (wazuh-manager.conf), not an internal option. <=0 -> module
                                         ///< default.
        int http_read_timeout;           ///< Seconds to wait for a full request on a connection (also covers
                                         ///< the TLS handshake window). <=0 -> module default
                                         ///< (see remoted.http_read_timeout).
        int http_write_timeout;          ///< Seconds to wait for a response write to complete. <=0 -> module
                                         ///< default (see remoted.http_write_timeout).
        int http_request_timeout;        ///< Seconds a request may take to be handled end-to-end. <=0 ->
                                         ///< module default (see remoted.http_request_timeout).
        int http_max_url_size;           ///< Max URL size, bytes. <=0 -> module default
                                         ///< (see remoted.http_max_url_size).
        int http_max_header_name_size;   ///< Max HTTP header name size, bytes. <=0 -> module default
                                         ///< (see remoted.http_max_header_name_size).
        int http_max_header_value_size;  ///< Max HTTP header value size, bytes. <=0 -> module default
                                         ///< (see remoted.http_max_header_value_size).
        int http_max_header_count;       ///< Max number of HTTP headers per request. <=0 -> module default
                                         ///< (see remoted.http_max_header_count).
        int http_max_pipelined_requests; ///< Max in-flight unanswered requests per connection. <=0 ->
                                         ///< module default (see remoted.http_max_pipelined_requests).
        int http_concurrent_accepts;     ///< Max concurrent in-progress TCP accepts. <=0 -> module
                                         ///< default (see remoted.http_concurrent_accepts).
        int http_buffer_size;            ///< Socket read buffer size, bytes. <=0 -> module default
                                         ///< (see remoted.http_buffer_size).
        int http_stream_chunk_size;      ///< Bytes per chunk when streaming a response body
                                         ///< (POST /download). <=0 -> module default, 64 KiB
                                         ///< (see remoted.http_stream_chunk_size). Larger chunks
                                         ///< trade memory per in-flight transfer for fewer
                                         ///< read/write round trips, which is where the CPU per
                                         ///< byte goes.
        /// Whether `Content-Encoding: zstd` request bodies are accepted
        /// (see remoted.http_content_encoding_enabled). Unlike the int fields here, this has no
        /// "unset" sentinel: getDefine_Int_default() always resolves the final 0/1 value (defaulting
        /// to enabled) on the C side, so this field always carries the real value.
        bool http_content_encoding_enabled;
        long long max_inflight_bytes;    ///< Max in-flight request payload bytes; 503 over it (<=0 -> module default).
        int max_parallel_connections;    ///< HTTPS max simultaneous connections (<=0 -> module default).
        int max_deferred_requests; ///< Max requests parked awaiting a downstream service; 503 over it (<=0 -> default).

        // Downstream (async UDS client to the engine's event ingress) tunables. <=0 -> module default
        // (see remoted.downstream_*).
        int downstream_connect_timeout;              ///< Seconds to wait for the UDS connect to complete.
        int downstream_write_timeout;                ///< Seconds to wait for the request body write to complete.
        int downstream_response_timeout;             ///< Seconds to wait for the downstream response after the write.
        int downstream_stateful_response_timeout;    ///< Seconds to wait for the /stateful downstream response. A
                                                     ///< dedicated (longer) deadline: inventory sync sessions are
                                                     ///< validated, indexed and flushed WITHIN the request, unlike
                                                     ///< the enqueue-and-answer endpoints the global default serves.
        int downstream_io_threads;                   ///< Threads running the downstream client's io_context. <=0 ->
                                                     ///< cpp_get_nproc() (see shared_modules/utils/proc.hpp).
        int downstream_post_process_threads;         ///< Threads running the per-endpoint post-processors. <=0 ->
                                                     ///< cpp_get_nproc().
        long long downstream_max_response_body_size; ///< Cap on a downstream response body, bytes (<=0 -> default).

        // Auth middleware (AES-CMAC request verification) tunables. <=0 -> module default (see remoted.auth_*).
        int auth_max_request_age;     ///< Seconds a request timestamp may lag behind now.
        int auth_max_future_skew;     ///< Seconds a request timestamp may lead ahead of now.
        long long auth_max_body_size; ///< Hard cap on the authenticated request body, bytes (<=0 -> default).

        int keystore_refresh_interval; ///< Seconds between client.keys change checks (hot-reload).
                                       ///< <=0 -> module default (10 s)
        char bind_address[256];        ///< HTTPS listen address (empty -> module default).
        char ca_path[512];             ///< CA bundle (PEM) for client-certificate verification (empty -> disabled).
        char ciphers[256];             ///< TLS 1.3 ciphersuite override (SSL_CTX_set_ciphersuites() naming scheme;
                                       ///< empty -> library default).
        int verification_mode;         ///< REMOTED_MODULE_HTTPS_VERIFY_* (client-certificate verification).
        int dual_stack;                ///< REMOTED_MODULE_HTTPS_DUAL_STACK_*; only applies to an IPv6 bind address.

        // Control endpoint configuration. Defaults apply when <=0 or empty.
        char manager_version[64];        ///< Manager version string.
        bool allow_higher_versions;      ///< Allow agents with version > manager version.
        char limits_json[4096];          ///< Limits JSON (rendered from <remote><limits> in manager conf).
        int groups_refresh_interval_sec; ///< Group refresh interval in seconds (<=0 -> 60).
        int wdb_request_connections;     ///< Wazuh-DB request connection pool size (<=0 -> 4).
        int wdb_roundtrip_deadline_ms;   ///< Wazuh-DB roundtrip deadline in milliseconds (<=0 -> 2000).
        int wdb_max_queue_size;          ///< Wazuh-DB request queue high-water mark; QueueFull over it (<=0 -> 10000).
        int tm_concurrency;              ///< Task Manager concurrency limit (<=0 -> 10).
        int tm_deadline_ms;              ///< Task Manager per-request deadline in milliseconds (<=0 -> 200).
        int tm_max_queue_size; ///< Task Manager request queue high-water mark; QueueFull over it (<=0 -> 10000).
    } remoted_module_config_t;

    /**
     * @brief Start the C++ module: brings up the HTTPS transport synchronously
     *        and, only on success, launches the worker thread that owns its
     *        lifecycle.
     *
     * @param callbackLog   Logging callback (remoted passes mtLoggingFunctionsWrapper).
     * @param configuration Module configuration (may be NULL -> defaults are used).
     */
    EXPORTED void remoted_module_start(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration);

    /**
     * @brief Stop the C++ module. Signals the worker thread and joins it.
     *        Safe to call even if the module was never started.
     */
    EXPORTED void remoted_module_stop(void);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs, useful if the module is ever loaded via dlopen/dlsym.
typedef void (*remoted_module_start_func)(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration);
typedef void (*remoted_module_stop_func)(void);

#endif // _REMOTED_MODULE_H
