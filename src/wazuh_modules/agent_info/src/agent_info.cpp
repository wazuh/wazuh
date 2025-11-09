#include "agent_info.h"

#include "agent_info_impl.hpp"
#include "wm_agent_info.h"
#include "wmodules.h"

#include <dbsync.hpp>

#include <functional>
#include <memory>
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

// Global callback function pointers
static report_callback_t g_report_callback = nullptr;
static log_callback_t g_log_callback = nullptr;
static query_module_callback_t g_query_module_callback = nullptr;

// Global sync protocol parameters
static const char* g_module_name = nullptr;
static const char* g_sync_db_path = nullptr;
static const MQ_Functions* g_mq_functions = nullptr;

// Internal wrapper functions that capture the callbacks
static std::function<void(const std::string&)> g_report_function_wrapper;
static std::function<void(const modules_log_level_t, const std::string&)> g_log_function_wrapper;
static std::function<int(const std::string&, const std::string&, char**)> g_query_module_function_wrapper;

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

    if (!g_agent_info_impl)
    {
        try
        {
            if (g_log_callback)
            {
                g_log_callback(LOG_DEBUG, "agent_info_start: Creating AgentInfoImpl instance", "agent-info");
            }

            // Initialize DBSync logging before creating DBSync instances
            DBSync::initialize(
                [](const std::string & msg)
            {
                if (g_log_callback)
                {
                    g_log_callback(LOG_DEBUG, msg.c_str(), "agent-info");
                }
            });

            g_agent_info_impl =
                std::make_unique<AgentInfoImpl>(AGENT_INFO_DB_DISK_PATH, g_report_function_wrapper, g_log_function_wrapper, g_query_module_function_wrapper);

            // Set agent mode
            g_agent_info_impl->setIsAgent(agent_info_config->is_agent);

            // Set sync parameters from configuration
            g_agent_info_impl->setSyncParameters(agent_info_config->sync.sync_end_delay,
                                                 agent_info_config->sync.sync_response_timeout,
                                                 agent_info_config->sync.sync_retries,
                                                 agent_info_config->sync.sync_max_eps);

            // Initialize sync protocol immediately after creating instance
            if (g_module_name && g_sync_db_path && g_mq_functions)
            {
                if (g_log_callback)
                {
                    g_log_callback(LOG_DEBUG, "agent_info_start: Initializing sync protocol", "agent-info");
                }

                g_agent_info_impl->initSyncProtocol(
                    std::string(g_module_name), std::string(g_sync_db_path), *g_mq_functions);
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
                std::string error_msg = "agent_info_start: Failed to initialize agent_info module: ";
                error_msg += ex.what();
                g_log_callback(LOG_ERROR, error_msg.c_str(), "agent-info");
            }

            // Clean up partial initialization
            g_agent_info_impl.reset();

            // Module fails gracefully without crashing wazuh-modulesd
            return;
        }
    }
    else
    {
        if (g_log_callback)
        {
            g_log_callback(
                LOG_DEBUG, "agent_info_start: AgentInfoImpl instance already exists, reusing it", "agent-info");
        }
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
        g_agent_info_impl.reset();
    }
}

void agent_info_init_sync_protocol(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs)
{
    g_module_name = module_name;
    g_sync_db_path = sync_db_path;
    g_mq_functions = mq_funcs;
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

#ifdef __cplusplus
}
#endif
