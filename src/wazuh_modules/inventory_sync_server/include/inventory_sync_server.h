/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
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
     * so absent is signalled with a negative) and the indexer fields (whose defaults
     * modulesd mirrors; see each one).
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
         * UDS path to listen on, RELATIVE to the installation directory, which is the working
         * directory of remoted and modulesd, so both resolve it identically.
         *
         * NOT CONFIGURABLE, and modulesd always leaves it empty: internal options can only carry
         * ints, so there is no mechanism to set a path. The field stays because it is how a test --
         * or a future caller with a real string source -- points the server somewhere else.
         * empty -> module default ("queue/sockets/inventory-sync-http.sock").
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
        int sync_workers;                ///< Worker threads applying sessions to the indexer, sharded by
                                         ///< agent id (FIFO per agent). Each worker owns one
                                         ///< IndexerConnectorSync built on the shared session.
                                         ///< Range 0..64. <=0 -> nproc/2, minimum 1.
        long long sync_queue_bytes;      ///< Early-rejection cap on payload bytes queued in the pipeline;
                                         ///< over it -> 503. A refinement UNDER max_inflight_bytes (which
                                         ///< already bounds the memory): this one sheds before the
                                         ///< transport budget is exhausted so probes/other routes keep
                                         ///< admitting. Range 1048576..1073741824. <=0 -> 64 MiB.
        int vd_feed_retry_after_seconds; ///< Value of the `Retry-After` header attached to the 503
                                         ///< returned for vulnerability-detection sessions while
                                         ///< the CVE feed is still downloading.
                                         ///< Range 10..1800. <=0 -> 10.
        int vd_workers;                  ///< Workers of the vulnerability-detection scan lane
                                         ///< (scan -> index -> respond, one connector each). The
                                         ///< scanner has its own matching per-slot pool, so
                                         ///< raising this is safe. An explicit value is clamped
                                         ///< to 0..64; <=0 resolves to nproc/2, minimum 1 and
                                         ///< uncapped -- same convention as sync_workers above.
        int vd_scan_queue_slots;         ///< Short admission queue of the scan lane; full -> 503
                                         ///< "scan capacity exhausted". Range 0..256.
                                         ///< <=0 -> 2x vd_workers.
        int max_sessions_per_agent;      ///< Sessions one agent may have admitted and not yet answered,
                                         ///< across the pipeline and the scan lane; over it -> 503.
                                         ///< Range 1..1024. <=0 -> 2.

        /* ---- SYNC half tuning. Since E7b these feed the indexer_client `inventory` bucket
         *      (indexer/indexerClientSyncAdapter.hpp: inventoryBucketSpec(), budgets()):
         *      max_bulk_size stays the pipeline's group-commit threshold, connector_max_bulk_size is
         *      the bucket's bytes per _bulk, the retry fields its retry policy and the module's time
         *      budgets; flush_interval_seconds and request_timeout_seconds are accepted but ignored
         *      (a WARN names the replacement). <=0 -> default, except where a field says 0 is a
         *      real setting. ---- */
        int indexer_sync_max_bulk_size;           ///< Group-commit threshold of the pipeline, request
                                                  ///< bytes, before a batch is flushed. <=0 -> 10 MiB.
        int indexer_sync_flush_interval_seconds;  ///< Accepted but ignored since E7b (the adapter has no
                                                  ///< timer flush); a non-default value is WARNed.
        int indexer_sync_max_retry_delay_seconds; ///< Ceiling of the `inventory` bucket's retry backoff
                                                  ///< (`retry.cap`). <=0 -> 15 s. modulesd enforces a
                                                  ///< minimum of 1 on the option.

        /* ---- ASYNC half tuning. Since E7c these feed the indexer_client `agent-state` bucket of
         *      POST /stats, POST /config and the deletion's by-id deletes
         *      (indexer/indexerClientSyncAdapter.hpp: agentStateBucketSpec(); I149): bulk_max_bytes
         *      is the bucket's bytes per _bulk, max_retry_delay_seconds its retry cap and
         *      max_queue_bytes its quota; flush_interval_seconds, logger_queue_size and
         *      logger_threads are accepted but ignored (a WARN names them when not at their
         *      default). <=0 -> default. ---- */
        int indexer_async_bulk_max_bytes;          ///< `agent-state` bytes per _bulk (`bulk.maxBytes`),
                                                   ///< clipped to fit its quota. <=0 -> 4 MiB.
        int indexer_async_flush_interval_seconds;  ///< Accepted but ignored since E7c; a non-default
                                                   ///< value is WARNed.
        int indexer_async_max_retry_delay_seconds; ///< Ceiling of the `agent-state` bucket's retry
                                                   ///< backoff (`retry.cap`). <=0 -> 15 s.
                                                   ///< Same minimum-of-1 story as the sync one.
        int indexer_async_logger_queue_size;       ///< Accepted but ignored since E7c; a non-default
                                                   ///< value is WARNed.
        int indexer_async_logger_threads;          ///< Accepted but ignored since E7c; a non-default
                                                   ///< value is WARNed.

        /**
         * @brief Quota of the `agent-state` bucket, bytes (I149, I149b, I149c).
         *
         * Maps to the bucket's `quotaBytes`, bounded by the runtime's global quota: at most a quarter
         * of it (what is left goes to `inventory`), at least one bulk plus its reserve, and at least
         * 16 KiB so the two deletes of a deletion fit one Group. THE ONE EXCEPTION to this header's
         * sentinel rule: `0` is a legal value, read as "a quarter of the global quota" (it meant
         * "unlimited" for the retired async connector). modulesd ships a real default (64 MiB)
         * rather than a 0 placeholder.
         *
         * The reason it cannot follow the usual `min=1` convention: getDefine_Int_default() calls
         * merror_exit() on an out-of-range value, so a minimum of 1 would turn a documented, legal
         * setting into a fatal modulesd abort.
         */
        long long indexer_async_max_queue_bytes;

        /// Indexer search page size while draining a session. Larger pages mean fewer round trips
        /// per session at a proportionally larger response to hold in memory, so the right value
        /// follows the indexer's sizing rather than this module's. <=0 -> 1000.
        int session_query_batch_size;

        /* ---- Nested, opaque ---- */
        /**
         * @brief The <indexer> configuration block, verbatim, as nested cJSON.
         *
         * NOT a POD field, on purpose: nested JSON with arrays -- hosts[],
         * ssl.certificate_authorities[], plus ssl.certificate and ssl.key -- which a fixed-size
         * C struct cannot express without flattening it here and re-nesting it on the other side.
         *
         * Since E7c the module only summarises it in a DEBUG line (counts, never values): its
         * indexer_client Client takes hosts and ssl from the process runtime (`indexer_runtime`),
         * which modulesd builds from the same block. The field stays so the struct's layout, and
         * with it the ABI, does not change.
         *
         * OWNERSHIP: BORROWED for the duration of the start() call only. The module
         * deep-copies whatever it needs before returning, so the caller may free it as
         * soon as start() returns. May be NULL, which is treated as {}.
         */
        const cJSON* indexer;
        /* ---- Route-class admission (QoS): the data plane can shed, the control plane cannot -- APPENDED, never
         * inserted: this struct crosses a C/C++ build boundary and keeping existing offsets stable makes a stale object
         * a missing-feature bug instead of a garbage-pointer crash. ---- */
        int reserved_control_connections; ///< Accept headroom the data plane can never consume: the
                                          ///< data class's session cap resolves to
                                          ///< max_parallel_connections minus this, so /stateful alone
                                          ///< can never fill the accept queue. Clamped to at most a
                                          ///< quarter of the connection cap.
                                          ///< Range 0..256. <=0 -> 64.
        int control_max_body_bytes;       ///< Declared-length cap of control-class routes (the
                                          ///< agent-deletion plane; id in a header, body empty);
                                          ///< over it -> 413. Range 0..1048576. <=0 -> 65536.
        int control_max_sessions;         ///< Concurrent control-class sessions; over it -> 503.
                                          ///< Range 0..1024. <=0 -> 256.

        /* ---- Per-request bound of the retired indexer connectors -- APPENDED, same ABI rule as
         *      above. Accepted but ignored since E7b (sync) and E7c (async): the per-request timeout
         *      is the process runtime's `wazuh_modules.indexer_client_request_timeout_ms`. A value
         *      other than the default (60) is WARNed once per start. ---- */
        int indexer_sync_request_timeout_seconds;  ///< Ignored (I138). <=0 or 60 -> silent.
        int indexer_async_request_timeout_seconds; ///< Ignored (I149). <=0 or 60 -> silent.

        /* ---- Health-monitor polling period of the retired indexer session -- APPENDED, same ABI
         *      rule as above. Accepted but ignored since E7c: node health belongs to the process's
         *      indexer client runtime. A value other than the default (10) is WARNed once. ---- */
        int indexer_monitoring_interval_seconds; ///< Ignored (I149). Range 1..3600. <=0 or 10 -> silent.

        /* ---- Retry budget of the SYNC indexer connector -- APPENDED, same ABI rule as above.
         *      Bounds every retry loop of one operation by attempts and by wall-clock time;
         *      without it a persistent 429 or an unreachable indexer blocks the flushing worker
         *      -- and the shard behind it -- forever. The connector accepts 0 (no bound), but
         *      that is the unbounded-blocking bug this option exists to prevent, so it is not
         *      reachable from here: minimum 1 and <=0 means "use the connector default". ---- */
        int indexer_sync_max_retry_attempts;         ///< Failed attempts before one operation gives
                                                     ///< up. -> `max_retry_attempts`. <=0 -> 5.
        int indexer_sync_max_retry_duration_seconds; ///< Wall-clock deadline, seconds, for one
                                                     ///< operation's retries.
                                                     ///< -> `max_retry_duration_seconds`. <=0 -> 15 s.

        /* ---- SYNC connector `_bulk` request cap -- APPENDED, same ABI rule as above. Separate
         *      from `indexer_sync_max_bulk_size` on purpose: that older option is the ingestion
         *      pipeline's group-commit threshold (wire FlatBuffer bytes), while this one caps the
         *      serialized NDJSON of one `_bulk` request. One knob driving both let raising the
         *      group-commit threshold silently raise the request size past the indexer's
         *      `http.max_content_length`. ---- */
        int indexer_sync_connector_max_bulk_size; ///< NDJSON bytes staged before the connector cuts
                                                  ///< a `_bulk` request. -> `max_bulk_size`.
                                                  ///< <=0 -> 10 MiB.

        /* ---- Vulnerability-detection scan-lane readiness -- APPENDED, same ABI rule as above. ---- */
        bool vd_configured_enabled; ///< Whether `<vulnerability-detection>` is present and
                                    ///< enabled in THIS node's own configuration -- read
                                    ///< directly from the vulnerability_scanner wmodule's
                                    ///< parsed config, which wm_config() populates before any
                                    ///< module thread runs, so it is available before that
                                    ///< module's own start() begins. Lets the scan lane defer
                                    ///< (retryable 503) a session that arrives in the narrow
                                    ///< window before the scanner's start() has run, instead
                                    ///< of treating "hasn't started yet" the same as "will
                                    ///< never run here".

        /* ---- The process's indexer_client runtime -- APPENDED, same ABI rule as above. ---- */
        const void* indexer_runtime; ///< Opaque `const indexer_client::RuntimeRef*` published by
                                     ///< modulesd (wm_indexer_runtime_ref()); stable for the life of
                                     ///< the process. NULL = no runtime: the sync stage of the
                                     ///< startup gate fails and retries on the heartbeat.
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
