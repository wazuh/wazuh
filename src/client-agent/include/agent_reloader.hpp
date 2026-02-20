/**
 * @file agent_reloader.hpp
 * @brief C++17 replacement for reload_agent.c
 *
 * Handles agent self-reload (via execd/com socket) and
 * verification of received remote configuration.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_AGENT_RELOADER_HPP
#define AGENTD_AGENT_RELOADER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Handles agent reload and remote-config verification.
     *
     * Replaces the C functions: reloadAgent(), verifyRemoteConf().
     */
    class AgentReloader
    {
    public:
        AgentReloader() = default;
        ~AgentReloader() = default;

        AgentReloader(const AgentReloader&) = delete;
        AgentReloader& operator=(const AgentReloader&) = delete;

        /** Trigger a reload via execd (Unix) or wcom_dispatch (Windows). */
        void* reload();

        /** Verify that the received remote configuration is valid.
         *  @return 0 on success, OS_INVALID on failure. */
        int verifyRemoteConf();

        /** Access the singleton. */
        static AgentReloader& instance();
    };

} // namespace agentd

#endif // AGENTD_AGENT_RELOADER_HPP
