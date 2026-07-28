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
 * The transport contract implemented behind this ABI is the one proposed in
 * #37732 (AES-CMAC request signing, H/E stateless format, status codes) and
 * #37733 (task delivery via /control Notify, single-request /stateful
 * sessions), as consolidated in the #37738 spike.
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

/* Outcome classes of a request/submission (D9 classification). */
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
    char agent_key[HC_MAX_KEY];    ///< The raw client.keys key as hex. The
    ///< recipe (settled by the manager's
    ///< resolver, PR #37821): decode verbatim,
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

    uint32_t notify_interval_s;         ///< notify_time; 0 -> 20.
    uint32_t rejected_retry_interval_s; ///< Slow re-Startup cadence; 0 -> 60.

    /// Interim task-dedup bounds (TODO #37833: replaced by the durable
    /// agent-info task_id registry). Max ids kept; 0 -> 4096.
    uint32_t task_dedup_max;
    /// Interim task-dedup TTL in seconds; a duplicate re-delivered after this
    /// is accepted again; 0 -> 3600 (TODO #37833).
    uint32_t task_dedup_ttl_s;

    char version[HC_MAX_VERSION];       ///< Product version for Startup.
    char config_checksum[HC_MAX_CHECKSUM]; ///< Local merged.mg SHA-256 seed. Compared
    ///< against the manager-reported
    ///< agent.config_hash on every Notify;
    ///< a mismatch triggers /download.

    uint32_t request_timeout_ms;  ///< Per request; 0 -> 10000.
    uint32_t stateful_timeout_ms; ///< Large transfers (/download); 0 -> 120000.
    uint32_t backoff_base_ms;     ///< Full-jitter base; 0 -> 1000.
    uint32_t backoff_cap_ms;      ///< Full-jitter cap; 0 -> 60000.
    uint32_t drain_timeout_ms;    ///< Shutdown drain window; 0 -> 5000.

    char spool_dir[HC_MAX_PATH];  ///< Spool dir for temp files; empty -> system tmp.
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
    void (*on_state_change)(int state, void* user_data);  ///< hc_conn_state_t
    void (*on_buffer_level)(int level, void* user_data);  ///< hc_buffer_level_t
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
