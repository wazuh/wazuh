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
 * type. remoted links the module directly (see src/remoted/CMakeLists.txt),
 * mirroring how it already consumes librouter.so.
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
        char node_name[256];             ///< Cluster node name.
        char certificate_path[512];      ///< TLS certificate chain (PEM) path (empty -> module default).
        char private_key_path[512];      ///< TLS private key (PEM) path (empty -> module default).
        int io_threads;                  ///< HTTPS I/O threads. <=0 -> module default (see remoted.http_io_threads).
        int http_worker_threads;         ///< HTTPS handler worker-pool size. <=0 -> module default
                                         ///< (see remoted.http_worker_threads).
        int http_max_body_size;          ///< Transport body cap, bytes. Regular <remote> setting
                                         ///< (wazuh-manager.conf), not an internal option. <=0 -> module default.
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
        long long max_inflight_bytes;    ///< Max in-flight request payload bytes; 503 over it (<=0 -> module default).
        int max_parallel_connections;    ///< HTTPS max simultaneous connections (<=0 -> module default).
        int max_deferred_requests; ///< Max requests parked awaiting a downstream service; 503 over it (<=0 -> default).

        // Downstream (async UDS client to the engine's event ingress) tunables. <=0 -> module default
        // (see remoted.downstream_*).
        int downstream_connect_timeout;              ///< Seconds to wait for the UDS connect to complete.
        int downstream_write_timeout;                ///< Seconds to wait for the request body write to complete.
        int downstream_response_timeout;             ///< Seconds to wait for the downstream response after the write.
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
