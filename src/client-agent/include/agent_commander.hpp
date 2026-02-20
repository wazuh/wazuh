/**
 * @file agent_commander.hpp
 * @brief C++17 replacement for agcom.c
 *
 * Handles local agent command dispatching: getconfig, getstate,
 * gethandshake, getdoclimits. On Unix, also runs the local
 * Unix-domain socket listener thread.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_AGENT_COMMANDER_HPP
#define AGENTD_AGENT_COMMANDER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Dispatches local agent commands.
     *
     * Replaces the C functions: agcom_dispatch(), agcom_getconfig(),
     * agcom_gethandshake(), getDocumentLimits(), agcom_main().
     */
    class AgentCommander
    {
    public:
        AgentCommander() = default;
        ~AgentCommander() = default;

        AgentCommander(const AgentCommander&) = delete;
        AgentCommander& operator=(const AgentCommander&) = delete;

        /** Dispatch a command string. */
        size_t dispatch(char* command, char** output);

        /** Handle "getconfig <section>" command. */
        size_t getConfig(const char* section, char** output);

        /** Handle "gethandshake" command. */
        size_t getHandshake(char** output);

        /** Return document-limits JSON for a specific module, or nullptr. */
        cJSON* getDocumentLimits(const char* module);

#ifndef WIN32
        /** Unix-only: local socket listener thread. */
        void* mainThread();
#endif

        /** Access the singleton. */
        static AgentCommander& instance();
    };

} // namespace agentd

#endif // AGENTD_AGENT_COMMANDER_HPP
