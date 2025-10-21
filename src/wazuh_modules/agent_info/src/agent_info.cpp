#include "agent_info.h"

#include "agent_info_impl.hpp"
#include "wm_agent_info.h"

#include <dbsync.hpp>

#include <functional>
#include <memory>
#include <string>

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

// Global sync protocol parameters
static const char* g_module_name = nullptr;
static const char* g_sync_db_path = nullptr;
static const MQ_Functions* g_mq_functions = nullptr;

// Internal wrapper functions that capture the callbacks
static std::function<void(const std::string&)> g_report_function_wrapper;
static std::function<void(const modules_log_level_t, const std::string&)> g_log_function_wrapper;

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
            std::make_unique<AgentInfoImpl>(AGENT_INFO_DB_DISK_PATH, g_report_function_wrapper, g_log_function_wrapper);

        // Set agent mode
        g_agent_info_impl->setIsAgent(agent_info_config->is_agent);

        // Set sync parameters from configuration
        g_agent_info_impl->setSyncParameters(agent_info_config->sync.sync_response_timeout,
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
    else
    {
        if (g_log_callback)
        {
            g_log_callback(
                LOG_DEBUG, "agent_info_start: AgentInfoImpl instance already exists, reusing it", "agent-info");
        }
    }

    g_agent_info_impl->start(agent_info_config->interval);
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

size_t agent_info_query(const char* query, char** output)
{
    if (!query || !output)
    {
        if (g_log_callback)
        {
            g_log_callback(LOG_ERROR, "agent_info_query: Invalid parameters", "agent-info");
        }

        static const char* error_msg = "err Invalid parameters";
        *output = strdup(error_msg);
        return strlen(*output);
    }

    if (g_log_callback)
    {
        std::string logMsg = std::string("agent_info_query: Received query: ") + query;
        g_log_callback(LOG_DEBUG, logMsg.c_str(), "agent-info");
    }

    try
    {
        std::string query_str(query);

        if (query_str == "get_metadata")
        {
            if (!g_agent_info_impl)
            {
                static const char* error_msg = "err Agent info module not initialized";
                *output = strdup(error_msg);
                return strlen(*output);
            }

            // Call C++ implementation
            nlohmann::json metadata = g_agent_info_impl->getMetadata();
            std::string response = metadata.dump();

            // Prepend "ok " to successful responses
            if (metadata.contains("status") && metadata["status"] == "ok")
            {
                response = "ok " + response;
            }
            else
            {
                response = "err " + response;
            }

            *output = strdup(response.c_str());
            return strlen(*output);
        }
        else
        {
            std::string error_response = "err Unknown query command: " + query_str;
            *output = strdup(error_response.c_str());
            return strlen(*output);
        }
    }
    catch (const std::exception& ex)
    {
        if (g_log_callback)
        {
            std::string errorMsg = std::string("agent_info_query: Exception: ") + ex.what();
            g_log_callback(LOG_ERROR, errorMsg.c_str(), "agent-info");
        }

        std::string error_response = std::string("err Exception: ") + ex.what();
        *output = strdup(error_response.c_str());
        return strlen(*output);
    }
}

#ifdef __cplusplus
}
#endif
