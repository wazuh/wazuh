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

        /* ---- SYNC indexer connector (IndexerConnectorSync) tuning. Overlaid onto the <indexer>
         *      block below by buildSyncConnectorConfig() before construction. This is the same
         *      connector class inventory_sync (the module this one will eventually replace) uses,
         *      so these mirror its own tunables exactly.
         *
         *      Each field is named `indexer_sync_<the connector's own key name>`, so comparing this
         *      block against the builder shows the mapping 1:1 and crossing the two families
         *      produces a visible name mismatch instead of a silent no-op. <=0 -> connector
         *      default. ---- */
        int indexer_sync_max_bulk_size;           ///< Bulk size threshold, bytes, before a flush is
                                                  ///< forced. -> `max_bulk_size`. <=0 -> 10 MiB.
        int indexer_sync_flush_interval_seconds;  ///< Periodic flush interval, seconds, forced even if
                                                  ///< the size threshold was not reached.
                                                  ///< -> `flush_interval_seconds`. <=0 -> 20 s.
        int indexer_sync_max_retry_delay_seconds; ///< Ceiling for the exponential retry backoff.
                                                  ///< -> `max_retry_delay_seconds`. <=0 -> 15 s.
                                                  ///< The connector's constructor REJECTS a value
                                                  ///< below its base retry delay of 1, so modulesd
                                                  ///< also enforces a minimum of 1 on the option.
                                                  ///< Between that and the <=0 sentinel above, a
                                                  ///< rejecting value cannot reach the connector
                                                  ///< from configuration at all.

        /* ---- ASYNC indexer connector (IndexerConnectorAsync) tuning. Overlaid by
         *      buildAsyncConnectorConfig().
         *
         *      CAUTION: `bulk_max_bytes` below is THE SAME CONCEPT as the sync connector's
         *      `max_bulk_size` above, under a DIFFERENT key name. Handing either connector the
         *      other's key is IGNORED SILENTLY -- no throw, no log, the built-in default applies
         *      instead. That is exactly why the two families are separate fields fed by separate
         *      internal options, and why each builder emits only the keys its own connector reads.
         *      <=0 -> connector default. ---- */
        int indexer_async_bulk_max_bytes;          ///< Bulk size threshold, bytes.
                                                   ///< -> `bulk_max_bytes`. <=0 -> 4 MiB.
        int indexer_async_flush_interval_seconds;  ///< Periodic flush interval, seconds.
                                                   ///< -> `flush_interval_seconds`. <=0 -> 20 s.
        int indexer_async_max_retry_delay_seconds; ///< Ceiling for the exponential retry backoff.
                                                   ///< -> `max_retry_delay_seconds`. <=0 -> 15 s.
                                                   ///< Same minimum-of-1 story as the sync one.
        int indexer_async_logger_queue_size;       ///< Bounded queue, in elements, for the async
                                                   ///< error logger. -> `logger_queue_size`.
                                                   ///< <=0 -> 8.
        int indexer_async_logger_threads;          ///< Threads draining that error-logger queue.
                                                   ///< -> `logger_threads`. <=0 -> 1.

        /**
         * @brief Cap on the async connector's in-memory pending-bulk queue, bytes.
         *
         * Maps to `max_queue_bytes`. THE ONE EXCEPTION to this header's sentinel rule: `0` here
         * means the connector's own documented "unlimited", not "use the module default". modulesd
         * therefore ships a real bounded default (64 MiB, matching what the engine uses for the
         * same key) rather than a 0 placeholder, and an operator who genuinely wants an unbounded
         * queue has to write `0` explicitly.
         *
         * The reason it cannot follow the usual `min=1` convention: getDefine_Int_default() calls
         * merror_exit() on an out-of-range value, so a minimum of 1 would turn a documented, legal
         * setting into a fatal modulesd abort.
         *
         * An unbounded queue is the only unbounded allocation this module can be configured to make
         * -- see max_inflight_bytes above for how the transport side is bounded.
         */
        long long indexer_async_max_queue_bytes;

        /* ---- Nested, opaque ---- */
        /**
         * @brief The <indexer> configuration block, verbatim, as nested cJSON.
         *
         * NOT a POD field, on purpose. The indexer connector consumes nested JSON with
         * arrays -- hosts[], ssl.certificate_authorities[], plus ssl.certificate and
         * ssl.key -- which a fixed-size C struct cannot express without flattening it here
         * and re-nesting it on the other side. Passing the subtree through untouched keeps
         * this header from having to track the indexer connector's schema at all.
         *
         * The `indexer_sync_*`/`indexer_async_*` fields above are overlaid onto a COPY of
         * this subtree by the module before construction -- once per connector, each with
         * only the keys its own connector reads. They are not expected to already be
         * present in it. `hosts` and `ssl.*` are shared by both connectors and by the
         * IndexerSession they are built from.
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
