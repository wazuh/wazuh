#include "agent_info.h"
#include "agent_info_impl.hpp"
#include "logging_helper.hpp"

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

    void agent_info_start(const struct wm_agent_info_t* agent_info_config)
    {
        (void)agent_info_config; // Mark as unused for now

        if (!g_agent_info_impl)
        {
            g_agent_info_impl = std::make_unique<AgentInfoImpl>(AGENT_INFO_DB_DISK_PATH);
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

    void agent_info_set_log_function(log_callback_t log_callback)
    {
        if (log_callback)
        {
            LoggingHelper::setLogCallback([log_callback](const modules_log_level_t level, const char* log) {
                log_callback(level, log, "agent-info");
            });
        }
    }

#ifdef __cplusplus
}
#endif