#ifndef _AGENT_INFO_H
#define _AGENT_INFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "agent_sync_protocol_c_interface_types.h"
#include "logging_helper.h"

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

// Forward declarations
struct wm_agent_info_t;

typedef void (*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag);
typedef int (*report_callback_t)(const char* message);
typedef int (*query_module_callback_t)(const char* module_name, const char* query, char** response);
typedef bool (*is_shutting_down_callback_t)(void);

EXPORTED void agent_info_start(const struct wm_agent_info_t* agent_info_config);

EXPORTED void agent_info_stop();

EXPORTED void agent_info_cleanup();

EXPORTED void agent_info_set_log_function(log_callback_t log_callback);

EXPORTED void agent_info_set_report_function(report_callback_t report_callback);

EXPORTED void agent_info_init_sync_protocol(const char* module_name);

EXPORTED bool agent_info_parse_response(const uint8_t* data, size_t data_len);

EXPORTED void agent_info_set_query_module_function(query_module_callback_t query_module_callback);

/**
 * @brief Set the predicate used to detect that a shutdown is in progress
 *
 * The implementation uses it to log expected shutdown-time synchronization/coordination
 * failures at a lower level (DEBUG or INFO, depending on the message) instead of
 * WARNING/ERROR.
 *
 * @param is_shutting_down_callback Predicate returning true while a shutdown is requested
 */
EXPORTED void agent_info_set_is_shutting_down_function(is_shutting_down_callback_t is_shutting_down_callback);

/**
 * @brief Set the cluster name received from the manager during handshake
 *
 * This function stores the cluster name that will be used when populating
 * agent metadata. Should be called from start_agent.c after parsing the
 * handshake response.
 *
 * @param cluster_name The cluster name string (will be copied internally)
 */
EXPORTED void agent_info_set_cluster_name(const char* cluster_name);

/**
 * @brief Get the cluster name received from the manager during handshake
 *
 * @return The cluster name string (empty string if not set)
 */
EXPORTED const char* agent_info_get_cluster_name(void);

/**
 * @brief Set the agent groups received from the manager during handshake
 *
 * This function stores the agent groups (as CSV) that will be used when populating
 * agent metadata. Should be called from start_agent.c after parsing the
 * handshake response.
 *
 * @param agent_groups The agent groups as CSV string (will be copied internally)
 */
EXPORTED void agent_info_set_agent_groups(const char* agent_groups);

/**
 * @brief Get the agent groups received from the manager during handshake
 *
 * @return The agent groups as CSV string (empty string if not set)
 */
EXPORTED const char* agent_info_get_agent_groups(void);

/**
 * @brief Clear the agent groups received from the manager during handshake
 *
 * This function should be called after the handshake groups have been consumed
 * (used once in populateAgentMetadata) to allow subsequent metadata updates
 * to read from merged.mg instead.
 */
EXPORTED void agent_info_clear_agent_groups(void);

/**
 * @brief Callback type used to query agentd for fresh handshake data (cluster_name,
 * agent_groups) on demand, instead of relying on a one-time cached copy.
 *
 * Matches the signature of wm_agent_info_query_agentd_handshake() in wm_agent_info.c,
 * so it can be registered directly with no adapter function.
 *
 * @return true if the query succeeded (output buffers may still be empty if the
 * corresponding value is legitimately unset), false if the query itself failed.
 */
typedef bool (*query_handshake_callback_t)(char* cluster_name,
                                           size_t cluster_name_size,
                                           char* agent_groups,
                                           size_t agent_groups_size);

/**
 * @brief Set the function used to query agentd for fresh handshake data on every
 * agent metadata population cycle (instead of only once at module startup).
 *
 * @param callback The handshake query callback
 */
EXPORTED void agent_info_set_query_handshake_function(query_handshake_callback_t callback);

/**
 * @brief Configure the durable task_id registry: the `tasks` table in agent-info's
 * own agent_info.db (not a private flat file -- see AgentInfoImpl::checkAndRecordTask/
 * cleanupExpiredTasks/setTaskRegistryLimits).
 *
 * Constructs agent_info.db if needed (via agent_info_ensure_database()) and configures its
 * ttl/max_entries bounds. Cleanup itself is NOT triggered by this call or any other exported
 * function -- it runs automatically, once per iteration, from within AgentInfoImpl::start()'s
 * own loop, instead of a dedicated cleanup thread that would otherwise have no synchronization
 * against this same instance's destruction. Task dispatch is gated on agent_info.db being
 * available (see agent_info_task_check_and_record), which in production becomes true as soon
 * as this function runs -- an accepted trade-off for sharing agent-info's single database
 * rather than keeping a registry independent of AgentInfoImpl's own lifecycle.
 *
 * @param max_entries Bound on remembered task_ids (oldest-first eviction).
 * @param ttl_seconds How long a task_id is remembered before a re-delivery
 *        is treated as new again.
 */
EXPORTED void agent_info_task_registry_init(uint32_t max_entries, uint32_t ttl_seconds);

/**
 * @brief Atomically check-and-record a task_id against the durable `tasks` table.
 *
 * This is the whole point of the durable registry: agentd calls this (over IPC) before
 * dispatching a /control task, and a remote_upgrade's task_id must be
 * recorded here BEFORE its installer runs, so a post-restart re-delivery is
 * discarded.
 *
 * @return 1 if `task_id` is new (now recorded); 0 if it is a duplicate;
 *         -1 on error (including: agent_info.db not yet available, null/empty id).
 */
EXPORTED int agent_info_task_check_and_record(const char* task_id);

/**
 * @brief Observe a VD feed offset reported by the manager (e.g. via a /control notify
 * response). Monotonic: a value not newer than the currently stored offset is a no-op.
 * When the offset advances it is persisted immediately; a re-scan is marked pending only
 * if syscollector's VDFirst has already completed -- otherwise VDFirst's own full scan
 * will cover the new offset via Start.feed_offset, so no /scan/vd request is needed yet
 * (see AgentInfoImpl::observeVdFeedOffset).
 *
 * @param offset The offset value received from the manager.
 * @param out_changed Set to 1 if the offset advanced, 0 otherwise. May be NULL.
 * @param out_pending Set to 1 if a /scan/vd request is now outstanding, 0 otherwise. May be NULL.
 * @param out_pending_offset Set to the offset a pending request refers to (valid only when
 *        *out_pending is 1). May be NULL.
 * @return 0 on success, -1 on error (agent_info.db not yet available, or a NULL required
 *         output isn't the issue -- out_* pointers are all optional).
 */
EXPORTED int agent_info_vd_offset_observe(uint64_t offset,
                                          int* out_changed,
                                          int* out_pending,
                                          uint64_t* out_pending_offset);

/**
 * @brief Clear the pending VD re-scan flag, but only if it is still pending for exactly this
 * offset (a stale confirmation -- nothing pending, or a newer offset has since superseded
 * this one -- is a no-op). Call this only after a /scan/vd request for `offset` returns
 * 200 OK; never on a 409 or transport failure, so the request stays durable across a
 * restart until it actually succeeds.
 *
 * @param offset The offset the /scan/vd request succeeded for.
 * @return 1 if the pending flag was cleared, 0 if it was not (stale / nothing pending),
 *         -1 on error (agent_info.db not yet available).
 */
EXPORTED int agent_info_vd_offset_clear_pending(uint64_t offset);

/**
 * @brief Current durable VD feed state, so agentd can resume any outstanding pending
 * re-scan request after its own restart without waiting for the next detected offset
 * change.
 *
 * @param out_has_offset Set to 1 if an offset has ever been observed, 0 otherwise. May be NULL.
 * @param out_offset Set to the last observed offset (valid only when *out_has_offset is 1).
 *        May be NULL.
 * @param out_pending Set to 1 if a /scan/vd request is currently outstanding, 0 otherwise.
 *        May be NULL.
 * @param out_pending_offset Set to the offset a pending request refers to (valid only when
 *        *out_pending is 1). May be NULL.
 * @return 0 on success, -1 on error (agent_info.db not yet available).
 */
EXPORTED int agent_info_vd_offset_get_state(int* out_has_offset,
                                            uint64_t* out_offset,
                                            int* out_pending,
                                            uint64_t* out_pending_offset);

/**
 * @brief Ensure agent_info.db (and thus the `tasks` table) is constructed, without running
 * the metadata sync loop that agent_info_start() would otherwise block on.
 *
 * Idempotent (a no-op if already constructed). Exists so tests that only exercise the task
 * registry (not metadata sync) can make agent_info.db available without engaging
 * AgentInfoImpl::start()'s blocking loop; production always goes through the full
 * agent_info_start() instead, which constructs the same instance and additionally starts
 * that loop.
 */
EXPORTED void agent_info_ensure_database(void);

#ifdef __cplusplus
}
#endif

typedef void (*agent_info_start_func)(const struct wm_agent_info_t* agent_info_config);
typedef void (*agent_info_stop_func)();
typedef void (*agent_info_cleanup_func)();
typedef void (*agent_info_set_log_function_func)(log_callback_t log_callback);
typedef void (*agent_info_set_report_function_func)(report_callback_t report_callback);
typedef void (*agent_info_init_sync_protocol_func)(const char* module_name);
typedef bool (*agent_info_parse_response_func)(const uint8_t* data, size_t data_len);
typedef void (*agent_info_set_query_module_function_func)(query_module_callback_t query_module_callback);
typedef void (*agent_info_set_is_shutting_down_function_func)(is_shutting_down_callback_t is_shutting_down_callback);
typedef void (*agent_info_set_cluster_name_func)(const char* cluster_name);
typedef const char* (*agent_info_get_cluster_name_func)(void);
typedef void (*agent_info_set_agent_groups_func)(const char* agent_groups);
typedef const char* (*agent_info_get_agent_groups_func)(void);
typedef void (*agent_info_clear_agent_groups_func)(void);
typedef void (*agent_info_set_query_handshake_function_func)(query_handshake_callback_t callback);
typedef void (*agent_info_task_registry_init_func)(uint32_t max_entries, uint32_t ttl_seconds);
typedef int (*agent_info_task_check_and_record_func)(const char* task_id);
typedef int (*agent_info_vd_offset_observe_func)(uint64_t offset,
                                                 int* out_changed,
                                                 int* out_pending,
                                                 uint64_t* out_pending_offset);
typedef int (*agent_info_vd_offset_clear_pending_func)(uint64_t offset);
typedef int (*agent_info_vd_offset_get_state_func)(int* out_has_offset,
                                                   uint64_t* out_offset,
                                                   int* out_pending,
                                                   uint64_t* out_pending_offset);

#endif //_AGENT_INFO_H
