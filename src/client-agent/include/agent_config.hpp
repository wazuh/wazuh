/**
 * @file agent_config.hpp
 * @brief C++17 replacement for config.c
 *
 * Wraps the agent configuration reading and JSON serialisation
 * functions in a singleton class.  Provides extern "C" trampolines
 * so that the preserved C headers (agentd.h) continue to expose
 * the original API (ClientConf, getClientConfig, etc.).
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_AGENT_CONFIG_HPP
#define AGENTD_AGENT_CONFIG_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Agent configuration reader and JSON serialiser.
     *
     * Replaces config.c.  Reads the XML configuration via the C
     * ReadConfig() function and exposes JSON views of the running
     * config for agcom / internal queries.
     */
    class AgentConfig
    {
    public:
        AgentConfig() = default;
        ~AgentConfig() = default;

        AgentConfig(const AgentConfig&) = delete;
        AgentConfig& operator=(const AgentConfig&) = delete;

        /** Parse the main ossec.conf for the remote-client section. */
        int readClientConf(const char* cfgfile);

        /** Return the client config as a cJSON tree. Caller owns. */
        cJSON* getClientConfig();

        /** Return buffer settings as a cJSON tree. Caller owns. */
        cJSON* getBufferConfig();

        /** Return label list as a cJSON tree. Caller owns. */
        cJSON* getLabelsConfig();

        /** Return agent internal options as a cJSON tree. Caller owns. */
        cJSON* getAgentInternalOptions();

#ifndef WIN32
        /** Return anti-tampering settings as a cJSON tree. Caller owns. */
        cJSON* getAntiTamperingConfig();
#endif

        /** Access the singleton. */
        static AgentConfig& instance();
    };

} // namespace agentd

#endif // AGENTD_AGENT_CONFIG_HPP
