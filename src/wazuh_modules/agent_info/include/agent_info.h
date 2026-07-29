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
 * @brief Set the cluster node received from the manager during handshake
 *
 * This function stores the cluster node (manager node name) that will be used when populating
 * agent metadata. Should be called from start_agent.c after parsing the
 * handshake response.
 *
 * @param cluster_node The cluster node string (will be copied internally)
 */
EXPORTED void agent_info_set_cluster_node(const char* cluster_node);

/**
 * @brief Get the cluster node received from the manager during handshake
 *
 * @return The cluster node string (empty string if not set)
 */
EXPORTED const char* agent_info_get_cluster_node(void);

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
 * @brief Configure the durable task_id registry (#37833): the `tasks` table in agent-info's
 * own agent_info.db (not a private flat file -- see AgentInfoImpl::checkAndRecordTask/
 * cleanupExpiredTasks).
 *
 * Only stores the max_entries/ttl_seconds config; does not itself touch the database. Task
 * dispatch is gated on agent_info.db being available (see agent_info_task_check_and_record),
 * which in production becomes true partway through agent_info_start() -- an accepted
 * trade-off for sharing agent-info's single database rather than keeping a registry
 * independent of AgentInfoImpl's own lifecycle.
 *
 * @param max_entries Bound on remembered task_ids (oldest-first eviction).
 * @param ttl_seconds How long a task_id is remembered before a re-delivery
 *        is treated as new again.
 */
EXPORTED void agent_info_task_registry_init(uint32_t max_entries, uint32_t ttl_seconds);

/**
 * @brief Atomically check-and-record a task_id against the durable `tasks` table.
 *
 * This is the whole point of #37833: agentd calls this (over IPC) before
 * dispatching a /control task, and a remote_upgrade's task_id must be
 * recorded here BEFORE its installer runs, so a post-restart re-delivery is
 * discarded.
 *
 * @return 1 if `task_id` is new (now recorded); 0 if it is a duplicate;
 *         -1 on error (including: agent_info.db not yet available, null/empty id).
 */
EXPORTED int agent_info_task_check_and_record(const char* task_id);

/**
 * @brief Prune TTL-expired and over-cap entries from the `tasks` table.
 *        A no-op if agent_info.db is not yet available. Intended to be called
 *        periodically from a background thread.
 */
EXPORTED void agent_info_task_registry_cleanup(void);

/**
 * @brief Current number of remembered task_ids. For tests/diagnostics.
 * @return 0 if agent_info.db is not yet available.
 */
EXPORTED size_t agent_info_task_registry_count(void);

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
typedef void (*agent_info_set_cluster_node_func)(const char* cluster_node);
typedef const char* (*agent_info_get_cluster_node_func)(void);
typedef void (*agent_info_set_agent_groups_func)(const char* agent_groups);
typedef const char* (*agent_info_get_agent_groups_func)(void);
typedef void (*agent_info_clear_agent_groups_func)(void);
typedef void (*agent_info_task_registry_init_func)(uint32_t max_entries, uint32_t ttl_seconds);
typedef int (*agent_info_task_check_and_record_func)(const char* task_id);
typedef void (*agent_info_task_registry_cleanup_func)(void);
typedef size_t (*agent_info_task_registry_count_func)(void);

#endif //_AGENT_INFO_H
