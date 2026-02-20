/**
 * @file agent_daemon.hpp
 * @brief C++17 replacement for agentd.c
 *
 * Encapsulates the AgentdStart() main daemon loop, signal handling,
 * configuration reloading, and the uninstall-permission API helpers.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_AGENT_DAEMON_HPP
#define AGENTD_AGENT_DAEMON_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Main daemon class — replaces agentd.c.
     *
     * Owns the select() event loop, signal handling, config reload,
     * and the uninstall-validation API helpers.
     */
    class AgentDaemon
    {
    public:
        AgentDaemon() = default;
        ~AgentDaemon() = default;

        AgentDaemon(const AgentDaemon&) = delete;
        AgentDaemon& operator=(const AgentDaemon&) = delete;

        /** Main daemon entry — never returns. */
        [[noreturn]] void start(int uid, int gid, const char* user, const char* group);

        /** Check uninstall permission against the manager API. */
        bool checkUninstallPermission(const char* token, const char* host, bool ssl_verify);

        /** Authenticate against the manager API and return an allocated token (caller frees). */
        char* authenticateAndGetToken(const char* userpass, const char* host, bool ssl_verify);

        /** Full uninstall validation workflow. */
        bool packageUninstallValidation(const char* uninstall_auth_token,
                                        const char* uninstall_auth_login,
                                        const char* uninstall_auth_host,
                                        bool ssl_verify);

        /** Access the singleton. */
        static AgentDaemon& instance();

    private:
        /** Handle configuration reload triggered by SIGUSR1. */
        void handleConfigReload();
    };

} // namespace agentd

#endif // AGENTD_AGENT_DAEMON_HPP
