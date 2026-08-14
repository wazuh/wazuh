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
     * Sentinel convention: an int <= 0 or an empty string means "the caller has no
     * opinion, use the module default", and modulesd passes a 0 fallback for those
     * precisely so their defaults live in ONE place, this module. Two exceptions, both
     * documented on the field itself: `max_inflight_bytes` (where 0 is a real setting,
     * so absent is signalled with a negative) and the nine indexer fields (where the
     * default belongs to the shared connector library, not here, and modulesd mirrors it).
     *
     * The ALLOWED RANGE of each field is enforced by modulesd, not here, and it is stated
     * per field below. That is not documentation for its own sake: an out-of-range internal
     * option makes getDefine_Int_default() abort the daemon, so an operator needs the bound
     * from somewhere. Ranges live in wm_inventory_sync_server_read_tunables().
     */
    typedef struct inventory_sync_server_config_t
    {
        /* ---- Cluster identity ---- */
        char cluster_name[256]; ///< Cluster name (empty -> "").

        /* ---- Transport: the listening socket ---- */
        /**
         * UDS path to listen on, RELATIVE to the install dir (modulesd chdir()s there and remoted
         * chroot()s into it, so a relative path is the only form both resolve identically).
         *
         * NOT CONFIGURABLE, and modulesd always leaves it empty: internal options can only carry
         * ints, so there is no mechanism to set a path. The field stays because it is how a test --
         * or a future caller with a real string source -- points the server somewhere else.
         * empty -> module default ("queue/sockets/inventory-sync.sock").
         */
        char socket_path[512];
        /**
         * Mode applied to the socket file after bind(), which applies the umask and so cannot be
         * relied on.
         *
         * NOT CONFIGURABLE, and modulesd always leaves it 0 -> the module's 0660. Do not turn it
         * into an internal option: those are parsed with atoi() (decimal), so an operator writing
         * an octal mode would silently get the wrong permissions.
         */
        int socket_mode;

        /* ---- Transport: threads and buffers ---- */
        int io_threads;         ///< Threads running the server's io_context. Each connection's I/O
                                ///< runs on its own strand, so these do parallelise -- but a handler
                                ///< that blocks still occupies one. Range 0..128.
                                ///< <=0 -> cpp_get_nproc().
        int concurrent_accepts; ///< Accept operations kept in flight. Range 0..64. <=0 -> 2.
        int buffer_size;        ///< Per-connection read buffer, bytes. Range 0..1048576. <=0 -> 8192.

        /* ---- Transport: request limits (llhttp has none of its own) ---- */
        int max_body_size;         ///< Request body cap, bytes; over it -> 413.
                                   ///< Range 0..536870912. <=0 -> NO own cap: a whole sync session
                                   ///< is one request, so the effective session limit is the
                                   ///< in-flight byte budget (max_inflight_bytes), and a request
                                   ///< declaring more than that whole budget gets 413 at
                                   ///< headers-complete (the agent must split the session).
        int max_url_size;          ///< Max request-target size, bytes; over it -> 414.
                                   ///< Range 0..65536. <=0 -> 2048.
        int max_header_name_size;  ///< Max header name size, bytes; over it -> 431.
                                   ///< Range 0..65536. <=0 -> 256.
        int max_header_value_size; ///< Max header value size, bytes; over it -> 431.
                                   ///< Range 0..1048576. <=0 -> 8192.
        /**
         * Max header LINES per request; over it -> 431.
         *
         * NOT CONFIGURABLE, and modulesd always leaves it 0 -> the module's 32.
         *
         * Fixed because it is a term of the memory ceiling the in-flight byte budget charges for:
         * the worst-case head is `max_header_count * (max_header_name_size + max_header_value_size)`,
         * and the budget derives its per-request overhead from exactly that product. Letting an
         * operator raise the count while the overhead stayed a constant is what made the budget
         * under-charge by more than an order of magnitude.
         */
        int max_header_count;

        /* ---- Transport: timeouts, seconds. One timer per phase, so no phase can hold an fd
         *      forever. <=0 -> module default for each. ---- */
        int header_timeout;   ///< Accept -> full request head received. Range 0..3600. <=0 -> 10.
        int body_timeout;     ///< Head received -> full body received. Range 0..3600. <=0 -> 30.
        int response_timeout; ///< Handler dispatch -> response delivered. This is a LEAK BACKSTOP,
                              ///< not a quality-of-service deadline: the caller sets its own,
                              ///< shorter, per-target deadline and gives up first.
                              ///< Range 0..3600. <=0 -> 300.
        int write_timeout;    ///< Time allowed to write one response. Range 0..3600. <=0 -> 10.
        int drain_timeout;    ///< stop(): how long to wait for already-dispatched requests to
                              ///< answer before their connections are force-closed. Keep it
                              ///< SHORT -- modulesd calls every module's stop() sequentially
                              ///< before joining them under one shared budget, so a long drain
                              ///< here delays every other module's teardown. Its range is capped
                              ///< at 10 for that reason. Range 0..10. <=0 -> 2.

        /* ---- Transport: admission control. Both reject explicitly rather than queueing
         *      silently, so the caller sees a status instead of a stalled socket. ---- */
        /**
         * Total in-flight request payload bytes; over it -> 503. Reserved from the declared
         * Content-Length at headers-complete, BEFORE the body is read, so this bounds the read-phase
         * peak too.
         *
         * Follows the usual sentinel, plus one extra state:
         *   > 0  -> that many bytes, clamped up to at least one maximum-size request so a too-small
         *           value cannot reject everything.
         *   == 0 -> no opinion, use the module default (256 MiB).
         *   < 0  -> effectively unlimited (admit regardless of size).
         *
         * The negative exists because the internal option's own range starts at 0, where 0 means
         * "unlimited" to an operator -- indistinguishable from the option being absent. modulesd makes
         * that distinction and passes a negative for the unlimited case, so that 0 keeps meaning "no
         * opinion" here and a zero-filled struct still resolves to every default.
         * Range 0..2147483647 as an internal option.
         */
        long long max_inflight_bytes;
        int max_parallel_connections; ///< Max simultaneous connections; over it -> 503 and close.
                                      ///< One deferred response costs one fd, so this is the
                                      ///< knob that bounds fd usage -- out of a limit shared with
                                      ///< every other module ('wazuh_modules.rlimit_nofile'), which
                                      ///< modulesd warns about if this exceeds it.
                                      ///< Range 0..65536. <=0 -> 1024.

        /* ---- Sync pipeline (the POST /stateful ingestion path) ---- */
        int sync_workers;           ///< Worker threads applying sessions to the indexer, sharded by
                                    ///< agent id (FIFO per agent). Each worker owns one
                                    ///< IndexerConnectorSync built on the shared session.
                                    ///< Range 0..64. <=0 -> nproc/2, minimum 1.
        long long sync_queue_bytes; ///< Early-rejection cap on payload bytes queued in the pipeline;
                                    ///< over it -> 503. A refinement UNDER max_inflight_bytes (which
                                    ///< already bounds the memory): this one sheds before the
                                    ///< transport budget is exhausted so probes/other routes keep
                                    ///< admitting. Range 1048576..1073741824. <=0 -> 64 MiB.
        int vd_feed_retry_after_seconds; ///< Value of the `Retry-After` header attached to the 503
                                         ///< returned for vulnerability-detection sessions while
                                         ///< the CVE feed is still downloading.
                                         ///< Range 10..1800. <=0 -> 60.
        int vd_workers;                  ///< Workers of the vulnerability-detection scan lane
                                         ///< (scan -> index -> respond, one connector each). The
                                         ///< scanner serializes scans globally, so more than 1
                                         ///< only helps once that changes. Range 0..16. <=0 -> 1.
        int vd_scan_queue_slots;         ///< Short admission queue of the scan lane; full -> 503
                                         ///< "scan capacity exhausted". Range 0..256.
                                         ///< <=0 -> 2x vd_workers.

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
     *
     * @return 0 when the module started, non-zero when it CANNOT start and no retry loop exists to
     *         recover it: a socket path the server could never bind (missing or unwritable parent
     *         directory, or a non-socket file already sitting there), or an exception before the
     *         worker thread was launched (allocation or thread-spawn failure). modulesd treats
     *         non-zero as fatal and refuses to run without inventory ingress.
     *
     * @note An unreachable INDEXER is deliberately not fatal and returns 0: the indexer is allowed to
     *       start after modulesd, and the module retries on its own heartbeat. Only conditions the
     *       heartbeat can never fix abort the daemon.
     */
    EXPORTED int inventory_sync_server_start(full_log_fnc_t callbackLog,
                                             const inventory_sync_server_config_t* configuration);

    /**
     * @brief Stop the C++ module. Signals the worker thread and joins it.
     *        Safe to call even if the module was never started, and idempotent.
     *
     * Runs from modulesd's signal handler. Every wait it performs is BOUNDED, but it does block: it
     * joins the worker (which may be inside the indexer's synchronous per-host health checks) and
     * drains the transport. The ceilings are sized to fit the daemon's shared shutdown budget.
     */
    EXPORTED void inventory_sync_server_stop(void);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs. REQUIRED: modulesd loads this module via dlopen and resolves
// both symbols with dlsym (see wazuh_modules/src/wm_inventory_sync_server.c).
typedef int (*inventory_sync_server_start_func)(full_log_fnc_t callbackLog,
                                                const inventory_sync_server_config_t* configuration);
typedef void (*inventory_sync_server_stop_func)(void);

#endif // _INVENTORY_SYNC_SERVER_H
