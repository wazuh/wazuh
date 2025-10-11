#include "agent_info.h"
#include "agent_info_impl.hpp"
#include <dbsync.hpp>

#include <memory>

/* Agent Info db directory */
#ifndef WAZUH_UNIT_TESTING
#define AGENT_INFO_DB_DISK_PATH "queue/agent_info/agent_info.db"
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
static persist_callback_t g_persist_callback = nullptr;
static log_callback_t g_log_callback = nullptr;

// Internal wrapper functions that capture the callbacks
static std::function<void(const std::string&)> g_report_function_wrapper;
static std::function<void(const std::string&, Operation, const std::string&, const std::string&)> g_persist_function_wrapper;
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

void agent_info_set_persist_function(persist_callback_t persist_callback)
{
    g_persist_callback = persist_callback;

    if (g_persist_callback)
    {
        g_persist_function_wrapper = [](const std::string & id, Operation operation, const std::string & index, const std::string & data)
        {
            if (g_persist_callback)
            {
                // Convert C++ Operation enum to C Operation_t enum
                Operation_t c_operation = (operation == Operation::CREATE) ? OPERATION_CREATE :
                                          (operation == Operation::MODIFY) ? OPERATION_MODIFY :
                                          (operation == Operation::DELETE_) ? OPERATION_DELETE :
                                          OPERATION_NO_OP;
                g_persist_callback(id.c_str(), c_operation, index.c_str(), data.c_str());
            }
        };
    }
}

void agent_info_start(const struct wm_agent_info_t* agent_info_config)
{
    (void)agent_info_config; // Mark as unused for now

    if (!g_agent_info_impl)
    {
        // Initialize DBSync logging before creating DBSync instances
        DBSync::initialize(
            [](const std::string & msg)
        {
            if (g_log_callback)
            {
                g_log_callback(LOG_DEBUG, msg.c_str(), "agent-info");
            }
        });

        g_agent_info_impl = std::make_unique<AgentInfoImpl>(
                                AGENT_INFO_DB_DISK_PATH, g_report_function_wrapper, g_persist_function_wrapper, g_log_function_wrapper);
    }

    g_agent_info_impl->start();
}

void agent_info_stop()
{
    if (g_agent_info_impl)
    {
        g_agent_info_impl->stop();
        g_agent_info_impl.reset();
    }
}

void agent_info_persist_diff(const char* id, Operation_t operation, const char* index, const char* data)
{
    if (id && index && data && g_agent_info_impl)
    {
        // Convert C Operation_t enum to C++ Operation enum
        Operation cppOperation = (operation == OPERATION_CREATE) ? Operation::CREATE :
                                 (operation == OPERATION_MODIFY) ? Operation::MODIFY :
                                 (operation == OPERATION_DELETE) ? Operation::DELETE_ :
                                 Operation::NO_OP;

        // Call the persistDifference method on the AgentInfoImpl instance
        g_agent_info_impl->persistDifference(std::string(id), cppOperation, std::string(index), std::string(data));
    }
}

#ifdef __cplusplus
}
#endif