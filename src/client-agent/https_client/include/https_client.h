/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HTTPS_CLIENT_H
#define _HTTPS_CLIENT_H

/*
 * C-ABI bridge for the agent HTTPS client C++ module.
 *
 * This is the ONLY header shared between the agent's C code and the C++
 * module, mirroring the manager-side remoted_module contract: a POD
 * configuration struct with fixed-size buffers, an injected callback table,
 * and an opaque handle. All exceptions are caught at this boundary; nothing
 * ever throws into C. agentd links the module directly (see
 * src/client-agent/CMakeLists.txt).
 *
 * The transport contract implemented behind this ABI covers AES-CMAC request signing, the
 * H/E stateless format, status codes, task delivery via /control Notify, and single-request
 * /stateful sessions.
 */

// Define EXPORTED for any platform
#if __GNUC__ >= 4
#define HC_EXPORTED __attribute__((visibility("default")))
#else
#define HC_EXPORTED
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h" // full_log_fnc_t

/* TLS verification modes (DEC-6: configured CA file + hostname).
 * HC_VERIFY_FULL is deliberately 0 so that a zero-initialized configuration
 * fails closed instead of silently disabling verification. */
typedef enum hc_verify_mode_t
{
    HC_VERIFY_FULL = 0, ///< Verify peer against the CA and check the hostname.
    HC_VERIFY_CERT = 1, ///< Verify peer against the CA only.
    HC_VERIFY_NONE = 2  ///< No TLS verification (explicit opt-out).
} hc_verify_mode_t;

/* Connection state, surfaced to the C core (feeds the .state metrics). */
typedef enum hc_conn_state_t
{
    HC_STATE_STOPPED = 0,  ///< Not started, or stopped.
    HC_STATE_STARTING,     ///< Started; Startup not accepted yet.
    HC_STATE_REGISTERED,   ///< Startup accepted; streams running.
    HC_STATE_REJECTED,     ///< Startup rejected (e.g. version); slow retry.
    HC_STATE_AUTH_ERROR    ///< Credential rejected (401): all traffic paused
    ///< until hc_set_agent_key() supplies a new key.
} hc_conn_state_t;

/* Occupancy level of the stateless accumulator. Replaces the legacy client
 * buffer levels so the manager-side flood alerts (rules 202-205 analogues)
 * keep working. */
typedef enum hc_buffer_level_t
{
    HC_BUFFER_NORMAL = 0,
    HC_BUFFER_WARNING,
    HC_BUFFER_FULL,
    HC_BUFFER_FLOOD
} hc_buffer_level_t;

/* Outcome classes of a request/submission (D9 classification), part of the
 * stable ABI surface. on_sync_response no longer carries this type (see its
 * own doc comment): the /stateful contract needs the real HTTP status code,
 * not this coarser classification, so retry/backoff decisions inside the
 * transport layer use the internal (C++-only) OutcomeClass instead. */
typedef enum hc_result_t
{
    HC_RESULT_OK = 0,
    HC_RESULT_RETRYABLE,
    HC_RESULT_BACKPRESSURE,
    HC_RESULT_AUTH_FAIL,
    HC_RESULT_PERMANENT,
    HC_RESULT_ERROR
} hc_result_t;

#define HC_MAX_HOST 256
#define HC_MAX_ID 16
#define HC_MAX_KEY 256
#define HC_MAX_PATH 1024
#define HC_MAX_CIPHERS 256
#define HC_MAX_VERSION 64
#define HC_MAX_CHECKSUM 128 /* fits a SHA-256 hex (64) + NUL with room */

/**
 * @brief Configuration passed from the agent (C) to the C++ module.
 *
 * POD struct with fixed-size buffers so the ABI is stable and it compiles
 * cleanly both as C99 and C++17. The struct is owned by the caller; the
 * module deep-copies it during hc_create(). Numeric fields left at 0 take
 * the module defaults (documented per field).
 */
typedef struct hc_config_t
{
    char server_host[HC_MAX_HOST]; ///< Manager address (single server, IR2).
    uint16_t server_port;          ///< Manager HTTPS port.
    char agent_id[HC_MAX_ID];      ///< Agent id from client.keys.
    char agent_key[HC_MAX_KEY];    ///< The raw client.keys key as hex. Decode verbatim,
    ///< AES-128/192/256-CMAC by byte length
    ///< (16/24/32; a real key is 64 hex = 32).
    int verify_mode;               ///< hc_verify_mode_t; 0 = full (fail closed).
    char ca_path[HC_MAX_PATH];     ///< certificate_authorities file path.
    char client_cert[HC_MAX_PATH]; ///< Optional mTLS certificate (FR11.3).
    char client_key[HC_MAX_PATH];  ///< Optional mTLS private key.
    char ciphers[HC_MAX_CIPHERS];  ///< Optional cipher list.

    uint64_t batch_size_bytes;      ///< Max /stateless payload per request
    ///< (adaptive: halves on 413, ramps back on
    ///< success); 0 -> 1 MiB.
    uint32_t batch_interval_ms;     ///< <batch><interval>; 0 -> 10000.
    uint32_t buffer_cap_multiplier; ///< Accumulator cap = N x batch size; 0 -> 4.

    /* Occupancy ladder, mirroring the legacy client buffer's internal options
     * so the manager-side flood rules keep firing on the same thresholds.
     * Note the struct's zero-means-default convention: agent.normal_level and
     * agent.tolerance accept a literal 0, which is indistinguishable from
     * "unset" here and takes the default instead. */
    uint32_t buffer_warn_level;        ///< agent.warn_level, percent; 0 -> 90.
    uint32_t buffer_normal_level;      ///< agent.normal_level, percent; 0 -> 70.
    uint32_t buffer_flood_tolerance_s; ///< agent.tolerance: seconds FULL must
    ///< hold before FLOOD; 0 -> 15.

    uint32_t notify_interval_s;         ///< notify_time; 0 -> 10.
    uint32_t rejected_retry_interval_s; ///< Slow re-Startup cadence; 0 -> 60.

    /// Safety bound for a remote_upgrade WPK download; 0 -> 200 MiB.
    uint64_t wpk_max_download_bytes;

    char version[HC_MAX_VERSION];       ///< Product version for Startup.
    char config_checksum[HC_MAX_CHECKSUM]; ///< Local merged.mg SHA-256 seed. Compared
    ///< against the manager-reported
    ///< agent.config_hash on every Notify;
    ///< a mismatch triggers /download.

    uint32_t request_timeout_ms;  ///< Per request; 0 -> 10000.
    uint32_t stateful_timeout_ms; ///< Large transfers (/stateful, /download);
    ///< 0 -> 120000.
    uint32_t backoff_base_ms;     ///< Full-jitter base; 0 -> 1000.
    uint32_t backoff_cap_ms;      ///< Full-jitter cap; 0 -> 60000.
    uint32_t drain_timeout_ms;    ///< Shutdown drain window; 0 -> 5000.

    char spool_dir[HC_MAX_PATH];  ///< Spool dir for temp files; empty -> system tmp.

    /// Local STREAM socket for the stateful sync intake (large sessions bypass
    /// the 64 KB DGRAM event queue). Empty -> the intake is not started.
    char sync_socket_path[HC_MAX_PATH];

    /// Periodic reporters (#37843), both OFF by default. When on, the module
    /// collects the corresponding snapshot on its interval, stamps agent_id +
    /// the manager-authoritative cluster, signs and POSTs to /stats resp.
    /// /config.
    bool stats_enabled;
    uint32_t stats_interval_s;         ///< 0 -> 60.
    bool config_report_enabled;
    uint32_t config_report_interval_s; ///< 0 -> 3600.

    /// zstd-compress in-memory request bodies before signing/sending.
    /// internal_options.conf (agent.https_compression_enabled), not a <client>
    /// XML setting -- OFF by default.
    bool https_compression_enabled;
} hc_config_t;

/**
 * @brief Environment injected by the C core.
 *
 * Every callback except log fires from the module's single dispatcher
 * thread, serialized in submission order; callbacks must not block for
 * long and must not call back into hc_* functions. log follows the
 * remoted_module contract (agentd passes mtLoggingFunctionsWrapper) and
 * may fire from any module thread.
 */
/// Synchronous check-and-record against the durable agent-info task_id
/// registry. Called on the CONTROL thread (not the dispatcher),
/// once per fresh task_id in a Notify batch, before batch planning and
/// before any dispatch -- this ordering is what makes remote_upgrade
/// idempotent across the restart it triggers. Must be fast and bounded (a
/// local IPC round-trip with its own timeout): it briefly delays the next
/// Notify, which is judged acceptable against agent-info (a local,
/// normally-responsive process) -- unlike task EXECUTION, which stays off
/// this thread via on_task/on_remote_upgrade_ready.
/// @return 1 the id is new (now durably recorded); 0 it is a duplicate;
///         -1 the registry could not be reached/confirmed (treat as
///         non-dispatchable -- fail closed).
typedef int (*hc_check_and_record_task_fn)(const char* task_id, void* user_data);

/// Observe a VD feed offset reported by the manager (a /control Notify's
/// vd_feed_offset field), persisting it in agent-info's durable `vd_feed_state`
/// table and deciding -- via agent-info's own VDFirst-completion check --
/// whether a /scan/vd request is actually needed. Monotonic: an offset not
/// newer than the stored one is a no-op that still reports the current
/// pending state, which is what lets a restart resume an outstanding request
/// for free (no separate recovery call needed).
/// Called on the CONTROL thread, synchronously, once per accepted Notify that
/// carries the field. Must be fast and bounded (a local IPC round-trip with
/// its own timeout).
/// @param offset The offset value received from the manager.
/// @param out_changed Set to 1 if the offset advanced, 0 otherwise.
/// @param out_pending Set to 1 if a /scan/vd request is now outstanding, 0 otherwise.
/// @param out_pending_offset Set to the offset a pending request refers to
///        (valid only when *out_pending is 1).
typedef void (*hc_vd_offset_observe_fn)(uint64_t offset, int* out_changed, int* out_pending,
                                        uint64_t* out_pending_offset, void* user_data);

/// Clear the pending VD re-scan flag, but only if it is still pending for
/// exactly this offset (a stale confirmation is a no-op). Call only after a
/// /scan/vd request for `offset` returns 200 OK -- never on a 409 or
/// transport failure, so the request stays durable across a restart until it
/// actually succeeds.
/// @return 1 if the pending flag was cleared, 0 otherwise (stale / nothing
///         pending / registry unreachable).
typedef int (*hc_vd_offset_clear_pending_fn)(uint64_t offset, void* user_data);

typedef struct hc_callbacks_t
{
    full_log_fnc_t log;
    void (*on_startup_result)(bool accepted, const char* handshake_json, void* user_data);
    /// The signing credential was rejected (401 on any endpoint), so the
    /// module has paused all outbound traffic and entered HC_STATE_AUTH_ERROR.
    /// Fired once per incident from the dispatcher thread. Re-enroll out of
    /// band (the authd flow, caller-owned retries) and call hc_set_agent_key()
    /// with the new key to resume.
    void (*on_reenroll_required)(void* user_data);
    void (*on_task)(const char* task_id, const char* task_type, const char* payload_json,
                    void* user_data);
    /// See hc_check_and_record_task_fn. Mandatory in practice: a null value
    /// makes every task look non-dispatchable (fail closed), same as an
    /// error return.
    hc_check_and_record_task_fn check_and_record_task;
    /// See hc_vd_offset_observe_fn / hc_vd_offset_clear_pending_fn. Optional: a
    /// null observe callback makes every Notify's vd_feed_offset a no-op
    /// (VdOffsetStoreAdapter reports no change, nothing pending), so this
    /// feature degrades to "never re-scans on offset change" rather than
    /// failing, on a build/config where agent-info's VD support isn't wired up.
    hc_vd_offset_observe_fn vd_offset_observe;
    hc_vd_offset_clear_pending_fn vd_offset_clear_pending;
    /// A remote_upgrade task's WPK was downloaded via /download and its
    /// wpk_sha1 verified: wpk_path is ready to hand to the upgrade
    /// module together with installer. Fires from the dispatcher thread,
    /// same as on_task; wpk_path is a module-owned temp file valid ONLY
    /// until this callback returns (copy/move it inside the callback, same
    /// convention as on_config_downloaded). The task_id was already durably
    /// recorded (check_and_record_task) before this ever fires, so the
    /// installer this callback goes on to run is safe to execute even though
    /// it restarts the agent: a post-restart re-delivery is discarded
    /// upstream and never reaches here again.
    void (*on_remote_upgrade_ready)(const char* task_id, const char* wpk_file,
                                    const char* wpk_path, const char* installer, void* user_data);
    /// A task's durable record already happened (check_and_record_task), but it will NEVER
    /// reach on_task/on_remote_upgrade_ready: its payload was malformed, or (remote_upgrade
    /// only) the WPK download/sha1 verification failed. Distinct from a duplicate, so a
    /// consumer can count it as a real failure. Optional: a null value just means this
    /// category of failure goes uncounted.
    void (*on_task_failed)(const char* task_id, const char* task_type, const char* reason,
                           void* user_data);
    /// A Notify reported a merged-config hash differing from the local one;
    /// the module fetched the new configuration via POST /download and
    /// verified its SHA-256. file_path is a module-owned temp file valid ONLY
    /// until this callback returns (the module deletes it afterwards):
    /// read/copy it inside the callback. Writing merged.mg, unmerging and
    /// reloading is the consumer's job. If applying fails, call
    /// hc_set_config_hash() with the hash actually on disk.
    void (*on_config_downloaded)(const char* config_hash, const char* file_path,
                                 void* user_data);
    /// The config hash the manager reported on the last accepted Notify,
    /// whether or not it differed from ours. Fired on every Notify so a
    /// consumer holding a gate on the manager-validated configuration (the
    /// agent's startup hash gate) can reconcile it even when nothing needs
    /// downloading. Empty when the manager reported none.
    void (*on_manager_config_hash)(const char* config_hash, void* user_data);
    /// The agent's current group set as the manager reported it on the last
    /// accepted Notify (comma-joined, manager's own order) -- fired only when it
    /// differs from what was last reported (Startup included), so a consumer
    /// doesn't republish identity data on every Notify for nothing. Empty is a
    /// valid, meaningful value (no groups), not a placeholder for "default": do
    /// not substitute a fallback here the way /download's group selector does.
    void (*on_agent_groups)(const char* groups_csv, void* user_data);
    /// The HTTP outcome for a /stateful session. Unlike every other outcome in this
    /// header, `result` here is the RAW HTTP status code the manager answered with
    /// (200, 400, 403, 409, 413, 500, 503...), not an hc_result_t - the /stateful
    /// contract's numeric-code meanings are its own (a 409 means checksum mismatch,
    /// not the version-rejection a control-plane 409 would mean) and are interpreted
    /// by the sync protocol module, not by this transport layer. `result == 0` means
    /// no HTTP response was received at all (timeout/connect/TLS failure/abort);
    /// treat it like a 503. `body` carries the raw JSON response body and may be
    /// empty.
    void (*on_sync_response)(const char* session_id, int result, const char* body,
                             size_t body_len, void* user_data);
    void (*on_state_change)(int state, void* user_data);  ///< hc_conn_state_t
    void (*on_buffer_level)(int level, void* user_data);  ///< hc_buffer_level_t
    /// Periodic collectors for the /stats and /config reporters (#37843).
    /// Unlike every other callback these run on the module's REPORTER thread
    /// (not the dispatcher): they must return promptly and must NOT call hc_*
    /// functions. Return either NULL (skip this cycle) or a NUL-terminated
    /// JSON OBJECT allocated with malloc() from the module's C runtime; the
    /// module takes ownership and frees it. Before sending, the module stamps
    /// "agent_id" and the manager-authoritative "cluster" {"name"} into
    /// the object (overwriting same-named members). A non-object return is
    /// logged and the cycle skipped.
    char* (*collect_stats)(void* user_data);
    char* (*collect_config)(void* user_data);

    /// Fills json_out (capacity cap, NUL-terminated) with the host metadata JSON
    /// object for the /control Notify: {"hostname":..,"architecture":..,"ip":..,
    /// "os":{"name":..,"version":..,"platform":..,"type":..}}. Write an empty
    /// string when metadata is not yet available; the Notify then omits host.
    /// Called on the control thread before each Notify (not the dispatcher), so
    /// it must be a fast, non-blocking read. Null means no host block is sent.
    void (*on_collect_host)(char* json_out, size_t cap, void* user_data);

    /// Fills json_out (capacity cap, NUL-terminated) with the host metadata JSON
    /// object for the /stateless H line: {"agent":{"name":..,"version":..,
    /// "groups":[..],"host":{"hostname":..,"architecture":..,"os":{"name":..,
    /// "version":..,"platform":..,"type":..}}},"cluster":{"name":..}}.
    /// This exact nesting -- groups/host/os under agent, cluster as agent's
    /// sibling -- is not arbitrary: it mirrors what the legacy manager's own
    /// append_header() (remoted/src/secure.c) already builds and indexes
    /// today, and the indexer's wazuh.* mapping is strict_allow_templates
    /// (an unmapped path is rejected, not ignored), so this is the only shape
    /// that will actually index. cluster.name comes from the same
    /// agent_metadata_t cluster_name that /stateful's Start table
    /// uses, so the two transports never disagree on cluster identity. A
    /// separate callback from on_collect_host (not reused) so the /stateless
    /// and /control host blocks can carry different fields without either
    /// risking the other's already-shipped contract. Write an empty string
    /// when metadata is not yet available; the H line then carries only
    /// agent.id, as it always has. Called on the stateless sender thread
    /// before each flush (not the dispatcher), so it must be a fast,
    /// non-blocking read. Null means the H line carries only agent.id.
    void (*on_collect_stateless_host)(char* json_out, size_t cap, void* user_data);

    /// /control has been unreachable at the TRANSPORT level for a threshold
    /// number of consecutive attempts (paused=true), or has succeeded again
    /// (paused=false). The consumer arms/disarms its producer lock so modules
    /// stop generating events they cannot deliver.
    void (*on_producer_pause)(bool paused, void* user_data);
    void* user_data;
} hc_callbacks_t;

typedef struct hc_handle hc_handle;

/* ---- lifecycle (the module owns its threads; stop is cooperative + join) ---- */

/**
 * @brief Create a client instance. Copies the configuration and callback
 *        table; spawns nothing yet. Returns NULL on invalid arguments or
 *        internal failure.
 */
HC_EXPORTED hc_handle* hc_create(const hc_config_t* config, const hc_callbacks_t* callbacks);

/**
 * @brief Start the client: validates the configuration (TLS settings fail
 *        closed) and launches the worker threads. Returns false and starts
 *        nothing when validation fails. A second start while running is
 *        ignored (true). Single-shot: once hc_stop() has run, start returns
 *        false -- create a new instance to run again.
 */
HC_EXPORTED bool hc_start(hc_handle* handle);

/**
 * @brief Stop the client: drains within the configured window (stateless
 *        flush + final Notify), aborts in-flight requests explicitly and
 *        joins every thread. No callback fires after this returns. Terminal
 *        (single-shot): the instance cannot be restarted afterwards. Safe
 *        without a prior start.
 */
HC_EXPORTED void hc_stop(hc_handle* handle);

/** @brief Destroy the instance. Implies hc_stop(). NULL-safe. */
HC_EXPORTED void hc_destroy(hc_handle* handle);

/* ---- data plane (called from agentd's EventForward seam) ---- */

/**
 * @brief Submit one event frame ("queue:location:message" bytes) for the
 *        /stateless batch. Returns false when the client is not running
 *        or the accumulator is full (drop-newest; the occupancy ladder is
 *        surfaced via on_buffer_level).
 */
HC_EXPORTED bool hc_submit_event(hc_handle* handle, const uint8_t* frame, size_t length);

/**
 * @brief Submit a whole sync session for /stateful. Asynchronous: the
 *        outcome arrives via on_sync_response with the same session_id.
 *        Returns false when the client is not running or the session
 *        queue is full.
 */
HC_EXPORTED bool hc_submit_sync_session(hc_handle* handle, const char* session_id,
                                        const uint8_t* buffer, size_t length);

/**
 * @brief Submit a whole sync session that is ALREADY spooled to a file (the
 *        intake streamed it off the local sync socket, so a multi-MB session
 *        never sat in memory). The module adopts the file and deletes it once
 *        the session is sent. Asynchronous, like hc_submit_sync_session.
 *        Returns false when the client is not running or the queue is full.
 */
HC_EXPORTED bool hc_submit_sync_session_file(hc_handle* handle, const char* session_id,
                                             const char* file_path, uint64_t size);

/**
 * @brief Producer-side helper: stream a whole sync session to the agent's
 *        sync intake socket (the STREAM socket that bypasses the 64 KB DGRAM
 *        cap). Standalone (no handle) — a producer process calls this in place
 *        of chunked DGRAM sends. Returns false on connect/write failure.
 *        Unix-only.
 */
HC_EXPORTED bool hc_send_sync_session(const char* socket_path, const char* session_id,
                                      const uint8_t* body, size_t length);

/* ---- control plane ---- */

/** @brief Force an out-of-cycle Notify (config change, restart...). */
HC_EXPORTED void hc_notify_now(hc_handle* handle);

/**
 * @brief Correct the module's view of the local merged-config hash (after a
 *        failed or divergent apply of a downloaded configuration). Unlike the
 *        other hc_* functions this one IS safe to call from inside callbacks:
 *        it only touches an internal guarded string. Returns false on a NULL
 *        handle or hash.
 */
HC_EXPORTED bool hc_set_config_hash(hc_handle* handle, const char* config_hash);

/**
 * @brief Swap the AES-CMAC credential at runtime (hex; 16/24/32 bytes decoded)
 *        after a re-enrollment. Like hc_set_config_hash this is callback-safe
 *        (it only touches an internal guarded key). It clears the auth pause
 *        and forces a fresh Startup (re-registration). Returns false on a NULL
 *        handle or invalid key material, leaving the previous key in place.
 */
HC_EXPORTED bool hc_set_agent_key(hc_handle* handle, const char* key_hex);

/** @brief Current connection state (hc_conn_state_t). NULL -> STOPPED. */
HC_EXPORTED int hc_get_state(const hc_handle* handle);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs, useful if the module is ever loaded via dlopen/dlsym.
typedef hc_handle* (*hc_create_func)(const hc_config_t* config, const hc_callbacks_t* callbacks);
typedef bool (*hc_start_func)(hc_handle* handle);
typedef void (*hc_stop_func)(hc_handle* handle);
typedef void (*hc_destroy_func)(hc_handle* handle);

#endif // _HTTPS_CLIENT_H
