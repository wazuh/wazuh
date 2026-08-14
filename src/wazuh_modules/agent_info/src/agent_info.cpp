#include "agent_info.h"

#include "agent_info_impl.hpp"
#include "wm_agent_info.h"
#include "wmodules.h"

#include <dbsync.hpp>

#include <atomic>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

// Forward declare the direct C function
extern "C" {
    int agent_info_query_module_direct(const char* module_name, const char* query, char** response);
}

/* Agent Info db directory */
#ifndef WAZUH_UNIT_TESTING
#define AGENT_INFO_DB_DISK_PATH "queue/agent_info/db/agent_info.db"
#else
#ifndef WIN32
#define AGENT_INFO_DB_DISK_PATH    "./agent_info.db"
#else
#define AGENT_INFO_DB_DISK_PATH    ".\\agent_info.db"
#endif // WIN32
#endif // WAZUH_UNIT_TESTING

#ifdef __cplusplus
extern "C"
{
#endif

// Global instance
static std::unique_ptr<AgentInfoImpl> g_agent_info_impl;

// Durable task_id registry: applied against the `tasks` table in
// g_agent_info_impl's own agent_info.db (see AgentInfoImpl::checkAndRecordTask/
// cleanupExpiredTasks). Task dispatch is intentionally coupled to g_agent_info_impl's own
// availability: if AgentInfoImpl/DBSync fails to start, /control task dispatch fails closed
// too (same as every other agent_info.db-backed feature), which is an accepted trade-off for
// sharing agent-info's single database instead of a private, independent flat file.
// The ttl/max_entries bounds themselves live on the AgentInfoImpl instance (see
// setTaskRegistryLimits()), configured once by agent_info_task_registry_init() below;
// cleanup itself now runs automatically from within AgentInfoImpl::start()'s own loop,
// not a separate thread here.

// Global callback function pointers
static report_callback_t g_report_callback = nullptr;
static log_callback_t g_log_callback = nullptr;
static query_module_callback_t g_query_module_callback = nullptr;
static is_shutting_down_callback_t g_is_shutting_down_callback = nullptr;

// Global sync protocol parameters
static const char* g_module_name = nullptr;

// Global cluster name storage (set from handshake, used by agent_info_impl)
static char g_cluster_name[256] = {0};

// Global agent groups storage (set from handshake, used by agent_info_impl)
// Uses OS_SIZE_65536 to accommodate multiple groups
static char g_agent_groups[65536] = {0};

// Global handshake query callback (queries agentd for fresh handshake data on demand)
static query_handshake_callback_t g_query_handshake_callback = nullptr;

// Internal wrapper functions that capture the callbacks
static std::function<void(const std::string&)> g_report_function_wrapper;
static std::function<void(const modules_log_level_t, const std::string&)> g_log_function_wrapper;
static std::function<int(const std::string&, const std::string&, char**)> g_query_module_function_wrapper;
static std::function<bool()> g_is_shutting_down_wrapper;
static std::function<bool(char*, size_t, char*, size_t)> g_query_handshake_function_wrapper;

void agent_info_set_log_function(log_callback_t log_callback)
{
    g_log_callback = log_callback;

    if (g_log_callback)
    {
        g_log_function_wrapper = [](const modules_log_level_t level, const std::string & msg)
        {
            if (g_log_callback)
            {
                g_log_callback(level, msg.c_str(), "agent-info");
            }
        };
    }
}

void agent_info_set_report_function(report_callback_t report_callback)
{
    g_report_callback = report_callback;

    if (g_report_callback)
    {
        g_report_function_wrapper = [](const std::string & data)
        {
            if (g_report_callback)
            {
                g_report_callback(data.c_str());
            }
        };
    }
}

void agent_info_set_query_module_function(query_module_callback_t query_module_callback)
{
    g_query_module_callback = query_module_callback;

    if (g_query_module_callback)
    {
        g_query_module_function_wrapper = [](const std::string & module_name, const std::string & query, char** response)
        {
            if (g_query_module_callback)
            {
                return g_query_module_callback(module_name.c_str(), query.c_str(), response);
            }

            return -1;
        };
    }

}

void agent_info_set_is_shutting_down_function(is_shutting_down_callback_t is_shutting_down_callback)
{
    g_is_shutting_down_callback = is_shutting_down_callback;

    if (g_is_shutting_down_callback)
    {
        g_is_shutting_down_wrapper = []()
        {
            return g_is_shutting_down_callback ? g_is_shutting_down_callback() : false;
        };
    }

    if (g_agent_info_impl)
    {
        g_agent_info_impl->setIsShuttingDownFunction(g_is_shutting_down_wrapper);
    }
}

void agent_info_set_cluster_name(const char* cluster_name)
{
    if (cluster_name)
    {
        strncpy(g_cluster_name, cluster_name, sizeof(g_cluster_name) - 1);
        g_cluster_name[sizeof(g_cluster_name) - 1] = '\0';

        if (g_log_callback)
        {
            g_log_callback(LOG_DEBUG, "Cluster name set", "agent-info");
        }
    }
    else
    {
        g_cluster_name[0] = '\0';
    }
}

const char* agent_info_get_cluster_name()
{
    return g_cluster_name;
}

void agent_info_set_agent_groups(const char* agent_groups)
{
    if (agent_groups)
    {
        strncpy(g_agent_groups, agent_groups, sizeof(g_agent_groups) - 1);
        g_agent_groups[sizeof(g_agent_groups) - 1] = '\0';

        if (g_log_callback)
        {
            g_log_callback(LOG_DEBUG, "Agent groups set", "agent-info");
        }
    }
    else
    {
        g_agent_groups[0] = '\0';
    }
}

const char* agent_info_get_agent_groups()
{
    return g_agent_groups;
}

void agent_info_clear_agent_groups()
{
    g_agent_groups[0] = '\0';

    if (g_log_callback)
    {
        g_log_callback(LOG_DEBUG, "Agent groups cleared (consumed)", "agent-info");
    }
}

void agent_info_set_query_handshake_function(query_handshake_callback_t callback)
{
    g_query_handshake_callback = callback;

    if (g_query_handshake_callback)
    {
        g_query_handshake_function_wrapper = [](char* cluster_name,
                                                size_t cluster_name_size,
                                                char* agent_groups,
                                                size_t agent_groups_size)
        {
            if (g_query_handshake_callback)
            {
                return g_query_handshake_callback(
                           cluster_name, cluster_name_size, agent_groups, agent_groups_size);
            }

            return false;
        };
    }
    else
    {
        g_query_handshake_function_wrapper = nullptr;
    }
}

void agent_info_ensure_database(void)
{
    if (g_agent_info_impl)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_DEBUG, "agent_info_ensure_database: instance already exists, reusing it", "agent-info");
        }

        return;
    }

    try
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_DEBUG, "agent_info_ensure_database: creating AgentInfoImpl instance", "agent-info");
        }

        DBSync::initialize(
            [](const std::string & msg)
        {
            if (g_log_callback)
            {
                g_log_callback(LOG_DEBUG, msg.c_str(), "agent-info");
            }
        });

        // The four nullptrs are the injectable dbSync/sysInfo/fileIO/fileSystem seams, left at
        // their defaults here; the last argument is the on-demand handshake query, which must be
        // passed because construction now funnels through this function rather than
        // agent_info_start().
        g_agent_info_impl =
            std::make_unique<AgentInfoImpl>(AGENT_INFO_DB_DISK_PATH,
                                            g_report_function_wrapper,
                                            g_log_function_wrapper,
                                            g_query_module_function_wrapper,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            g_query_handshake_function_wrapper);
        g_agent_info_impl->setIsShuttingDownFunction(g_is_shutting_down_wrapper);
    }
    catch (const std::exception& ex)
    {
        if (g_log_callback)
        {
            std::string error_msg = "agent_info_ensure_database: Failed to initialize agent_info's database: ";
            error_msg += ex.what();
            g_log_callback(LOG_ERROR, error_msg.c_str(), "agent-info");
        }

        g_agent_info_impl.reset();
    }
}

void agent_info_start(const struct wm_agent_info_t* agent_info_config)
{
    if (!agent_info_config)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_ERROR, "agent_info_config is null", "agent-info");
        }

        return;
    }

    // Construction is unified through agent_info_ensure_database(): whether this call is the
    // first to ever touch g_agent_info_impl, or agent_info_task_registry_init() already
    // constructed it earlier (to make agent_info.db available for task dispatch before this
    // blocking call runs), the instance either already exists or gets created here.
    agent_info_ensure_database();

    if (!g_agent_info_impl)
    {
        // agent_info_ensure_database() already logged the failure reason.
        return;
    }

    // Always (re)apply sync configuration, regardless of whether the instance was just
    // constructed above or is being reused. Previously this only ran inside the "just
    // constructed" branch, so a reused instance (constructed early by
    // agent_info_task_registry_init()) silently ran with no sync protocol at all --
    // metadata/groups synchronization was disabled without any error.
    try
    {
        if (g_module_name)
        {
            if (g_log_callback)
            {
                g_log_callback(LOG_DEBUG, "agent_info_start: Initializing sync protocol", "agent-info");
            }

            g_agent_info_impl->initSyncProtocol(std::string(g_module_name));
        }
        else
        {
            if (g_log_callback)
            {
                g_log_callback(LOG_WARNING,
                               "agent_info_start: Sync protocol parameters not set, skipping initialization",
                               "agent-info");
            }
        }
    }
    catch (const std::exception& ex)
    {
        if (g_log_callback)
        {
            std::string error_msg = "agent_info_start: Failed to configure sync protocol: ";
            error_msg += ex.what();
            g_log_callback(LOG_ERROR, error_msg.c_str(), "agent-info");
        }

        // Clean up on failure -- same behavior as a construction failure: the module fails
        // gracefully without crashing wazuh-modulesd.
        g_agent_info_impl.reset();
        return;
    }

    try
    {
        g_agent_info_impl->start(agent_info_config->interval, agent_info_config->integrity_interval);
    }
    catch (const std::exception& ex)
    {
        if (g_log_callback)
        {
            std::string error_msg = "agent_info_start: Failed to start agent_info module: ";
            error_msg += ex.what();
            g_log_callback(LOG_ERROR, error_msg.c_str(), "agent-info");
        }

        // Clean up on start failure
        g_agent_info_impl.reset();
    }
}

void agent_info_stop()
{
    if (g_agent_info_impl)
    {
        g_agent_info_impl->stop();
    }
}

void agent_info_cleanup()
{
    g_agent_info_impl.reset();
}

void agent_info_init_sync_protocol(const char* module_name)
{
    g_module_name = module_name;
}

bool agent_info_parse_response(const uint8_t* data, size_t data_len)
{
    if (g_agent_info_impl && data)
    {
        return g_agent_info_impl->parseResponseBuffer(data, data_len);
    }

    if (g_log_callback)
    {
        g_log_callback(LOG_ERROR, "Agent-info sync protocol not initialized or invalid data", "agent-info");
    }

    return false;
}

void agent_info_task_registry_init(uint32_t max_entries, uint32_t ttl_seconds)
{
    // Construct agent_info.db here (as early as wm_agent_info.c's own startup sequence allows
    // -- well before the blocking agent_info_start_ptr() call), rather than leaving task
    // dispatch fail-closed until agent_info_start() eventually runs. agent_info_start() will
    // see this instance already exists and simply reuse it (its own existing idempotent path).
    agent_info_ensure_database();

    if (g_agent_info_impl)
    {
        g_agent_info_impl->setTaskRegistryLimits(ttl_seconds, max_entries);
    }

    if (g_log_callback)
    {
        g_log_callback(LOG_DEBUG, "Durable task_id registry configured (agent_info.db-backed)", "agent-info");
    }
}

int agent_info_task_check_and_record(const char* task_id)
{
    if (!task_id || !*task_id)
    {
        return -1;
    }

    if (!g_agent_info_impl)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_WARNING,
                           "task_check_and_record called before agent_info's database is available",
                           "agent-info");
        }

        return -1;
    }

    return g_agent_info_impl->checkAndRecordTask(task_id) ? 1 : 0;
}

int agent_info_vd_offset_observe(uint64_t offset, int* out_changed, int* out_pending, uint64_t* out_pending_offset)
{
    if (!g_agent_info_impl)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_WARNING,
                           "vd_offset_observe called before agent_info's database is available",
                           "agent-info");
        }

        return -1;
    }

    const AgentInfoImpl::VdOffsetObserveResult result = g_agent_info_impl->observeVdFeedOffset(offset);

    if (out_changed)
    {
        *out_changed = result.changed ? 1 : 0;
    }

    if (out_pending)
    {
        *out_pending = result.pending ? 1 : 0;
    }

    if (out_pending_offset)
    {
        *out_pending_offset = result.pendingOffset;
    }

    return 0;
}

int agent_info_vd_offset_clear_pending(uint64_t offset)
{
    if (!g_agent_info_impl)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_WARNING,
                           "vd_offset_clear_pending called before agent_info's database is available",
                           "agent-info");
        }

        return -1;
    }

    return g_agent_info_impl->clearVdRescanPending(offset) ? 1 : 0;
}

int agent_info_vd_offset_get_state(int* out_has_offset,
                                   uint64_t* out_offset,
                                   int* out_pending,
                                   uint64_t* out_pending_offset)
{
    if (!g_agent_info_impl)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_WARNING,
                           "vd_offset_get_state called before agent_info's database is available",
                           "agent-info");
        }

        return -1;
    }

    const AgentInfoImpl::VdFeedState state = g_agent_info_impl->getVdFeedState();

    if (out_has_offset)
    {
        *out_has_offset = state.hasOffset ? 1 : 0;
    }

    if (out_offset)
    {
        *out_offset = state.offset;
    }

    if (out_pending)
    {
        *out_pending = state.pending ? 1 : 0;
    }

    if (out_pending_offset)
    {
        *out_pending_offset = state.pendingOffset;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
