/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SERVER_H
#define _INVENTORY_SYNC_SERVER_H

/*
 * C-ABI bridge for the inventory_sync_server C++ module.
 *
 * This is the ONLY header shared between modulesd's C code and the C++ module.
 * modulesd resolves the two entry points below with dlopen/dlsym
 * (so_get_module_handle/so_get_function_sym, see src/shared/include/sym_load.h),
 * so the function-pointer typedefs at the bottom are load-bearing, not optional.
 *
 * TRANSITIONAL MODULE: this exists alongside inventory_sync while the router-based
 * ingress is replaced by an HTTP/1.1-over-Unix-domain-socket one. When the migration
 * completes, inventory_sync is removed and this becomes the only inventory sync module.
 * See the module README for the resources the two must not share.
 */

// Define EXPORTED for any platform
#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h" // full_log_fnc_t, and cJSON.h (needed by the indexer field)

    /**
     * @brief Configuration passed from modulesd (C) to the C++ module.
     *
     * POD struct with fixed-size buffers so the ABI is stable and it compiles cleanly
     * both as C99 (modulesd) and C++20 (the module). The struct is owned by the caller;
     * the module copies whatever it needs during start().
     *
     * Deliberately a typed struct rather than the `const cJSON*` blob inventory_sync
     * takes (see wazuh_modules/inventory_sync/include/inventory_sync.h): every field
     * below is a scalar or a path, so a struct costs no parse step and cannot carry a
     * silent typo in a key name. The one exception is `indexer` -- see its comment.
     *
     * Sentinel convention, uniform across every field: an int/long long <= 0 or an
     * empty string means "the caller has no opinion, use the module default". modulesd
     * fills the numeric fields from getDefine_Int_default() with a 0 fallback precisely
     * so the defaults live in ONE place: this module.
     */
    typedef struct inventory_sync_server_config_t
    {
        /* ---- Cluster identity ---- */
        char cluster_name[256]; ///< Cluster name (empty -> "").
        char node_name[256];    ///< Cluster node name (empty -> "").

        /* ---- Transport: the listening socket ---- */
        char socket_path[512]; ///< UDS path to listen on, RELATIVE to the install dir (modulesd
                               ///< chdir()s there and remoted chroot()s into it, so a relative
                               ///< path is the only form both resolve identically).
                               ///< empty -> module default.
        int socket_mode;       ///< Octal mode applied to the socket file after bind(), which
                               ///< applies the umask and so cannot be relied on. <=0 -> 0660.

        /* ---- Transport: threads and buffers ---- */
        int io_threads;         ///< Threads running the server's io_context. These never block
                                ///< (handlers are non-blocking by contract), so there is nothing
                                ///< to oversubscribe. <=0 -> cpp_get_nproc().
        int concurrent_accepts; ///< Accept operations kept in flight. <=0 -> module default.
        int buffer_size;        ///< Per-connection read buffer, bytes. <=0 -> module default.

        /* ---- Transport: request limits (llhttp has none of its own) ---- */
        int max_body_size;         ///< Request body cap, bytes; over it -> 413. <=0 -> default.
        int max_url_size;          ///< Max request-target size, bytes; over it -> 414. <=0 -> default.
        int max_header_name_size;  ///< Max header name size, bytes; over it -> 431. <=0 -> default.
        int max_header_value_size; ///< Max header value size, bytes; over it -> 431. <=0 -> default.
        int max_header_count;      ///< Max headers per request; over it -> 431. <=0 -> default.

        /* ---- Transport: timeouts, seconds. One timer per phase, so no phase can hold an fd
         *      forever. <=0 -> module default for each. ---- */
        int header_timeout;   ///< Accept -> full request head received.
        int body_timeout;     ///< Head received -> full body received.
        int response_timeout; ///< Handler dispatch -> response delivered. This is a LEAK BACKSTOP,
                              ///< not a quality-of-service deadline: the caller sets its own,
                              ///< shorter, per-target deadline and gives up first.
        int write_timeout;    ///< Time allowed to write one response.
        int drain_timeout;    ///< stop(): how long to wait for already-dispatched requests to
                              ///< answer before their connections are force-closed. Keep it
                              ///< SHORT -- modulesd calls every module's stop() sequentially
                              ///< before joining them under one shared budget, so a long drain
                              ///< here delays every other module's teardown.

        /* ---- Transport: admission control. Both reject explicitly rather than queueing
         *      silently, so the caller sees a status instead of a stalled socket. ---- */
        long long max_inflight_bytes; ///< Total in-flight request payload bytes; over it -> 503.
                                      ///< Reserved from the declared Content-Length at
                                      ///< headers-complete, BEFORE the body is read, so this
                                      ///< bounds the read-phase peak too. <=0 -> default.
        int max_parallel_connections; ///< Max simultaneous connections; over it -> 503 and close.
                                      ///< One deferred response costs one fd, so this is the
                                      ///< knob that bounds fd usage. <=0 -> default.

        /* ---- Indexer connector tuning: overlaid onto the <indexer> block below before it is
         *      handed to IndexerConnectorSync -- the same connector class inventory_sync (the
         *      module this one will eventually replace) already uses, so these mirror its own
         *      tunables exactly. <=0 -> module default. ---- */
        int indexer_bulk_size_bytes; ///< Bulk-request size threshold, bytes, before a flush is
                                     ///< forced. Maps to `max_bulk_size` -- the same key
                                     ///< inventory_sync overlays via its own `indexerBulkSize`
                                     ///< option. <=0 -> 10 MiB.
        int indexer_flush_interval;  ///< Periodic flush interval, seconds, forced even if the
                                     ///< bulk-size threshold has not been reached. Maps to
                                     ///< `flush_interval_seconds`. <=0 -> 20 s.

        /* ---- Nested, opaque ---- */
        /**
         * @brief The <indexer> configuration block, verbatim, as nested cJSON.
         *
         * NOT a POD field, on purpose. The indexer connector consumes nested JSON with
         * arrays -- hosts[], ssl.certificate_authorities[], plus ssl.certificate,
         * ssl.key, max_bulk_size, flush_interval_seconds, max_retry_delay_seconds -- which
         * a fixed-size C struct cannot express without flattening it here and re-nesting
         * it on the other side. Passing the subtree through untouched keeps this header
         * from having to track the indexer connector's schema at all.
         *
         * `indexer_bulk_size_bytes`/`indexer_flush_interval` above are overlaid onto this
         * subtree by the module before construction; they are not expected to already be
         * present in it.
         *
         * OWNERSHIP: BORROWED for the duration of the start() call only. The module
         * deep-copies whatever it needs before returning, so the caller may free it as
         * soon as start() returns. May be NULL, which is treated as {}.
         */
        const cJSON* indexer;
    } inventory_sync_server_config_t;

    /**
     * @brief Start the C++ module. Launches its worker thread and returns immediately;
     *        the module owns the thread's lifecycle.
     *
     * All exceptions are caught at the boundary, so this never throws into C.
     *
     * @param callbackLog   Logging callback (modulesd passes mtLoggingFunctionsWrapper).
     * @param configuration Module configuration (may be NULL -> defaults are used).
     */
    EXPORTED void inventory_sync_server_start(full_log_fnc_t callbackLog,
                                              const inventory_sync_server_config_t* configuration);

    /**
     * @brief Stop the C++ module. Signals the worker thread and joins it.
     *        Safe to call even if the module was never started, and idempotent.
     *
     * Runs from modulesd's signal handler, so it returns promptly and never blocks on I/O.
     */
    EXPORTED void inventory_sync_server_stop(void);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs. REQUIRED: modulesd loads this module via dlopen and resolves
// both symbols with dlsym (see wazuh_modules/src/wm_inventory_sync_server.c).
typedef void (*inventory_sync_server_start_func)(full_log_fnc_t callbackLog,
                                                 const inventory_sync_server_config_t* configuration);
typedef void (*inventory_sync_server_stop_func)(void);

#endif // _INVENTORY_SYNC_SERVER_H
