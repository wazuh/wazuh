#include "agent_info.h"
#include "agent_info_impl.hpp"

#include <memory>

#ifdef __cplusplus
extern "C"
{
#endif

    // Global instance
    static std::unique_ptr<AgentInfoImpl> g_agent_info_impl;

    void agent_info_start(const struct wm_agent_info_t* agent_info_config)
    {
        if (!g_agent_info_impl)
        {
            g_agent_info_impl = std::make_unique<AgentInfoImpl>();
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

#ifdef __cplusplus
}
#endif