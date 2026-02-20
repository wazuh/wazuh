/**
 * @file agcom.cpp
 * @brief C++17 implementation of local agent command dispatching.
 *
 * Replaces agcom.c. Encapsulates command dispatching in
 * AgentCommander and provides extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "agent_commander.hpp"

extern "C"
{
#include "state.h"
}

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────

    AgentCommander& AgentCommander::instance()
    {
        static AgentCommander inst;
        return inst;
    }

    // ── dispatch ─────────────────────────────────────────────────────

    size_t AgentCommander::dispatch(char* command, char** output)
    {
        char* rcv_comm = command;
        char* rcv_args = nullptr;

        if ((rcv_args = strchr(rcv_comm, ' ')) != nullptr)
        {
            *rcv_args = '\0';
            rcv_args++;
        }

        if (strcmp(rcv_comm, "getconfig") == 0)
        {
            if (!rcv_args)
            {
                mdebug1("AGCOM getconfig needs arguments.");
                os_strdup("err AGCOM getconfig needs arguments", *output);
                return strlen(*output);
            }
            return getConfig(rcv_args, output);
        }
        else if (strcmp(rcv_comm, "getstate") == 0)
        {
            *output = w_agentd_state_get();
            return strlen(*output);
        }
        else if (strcmp(rcv_comm, "gethandshake") == 0)
        {
            return getHandshake(output);
        }
        else if (strcmp(rcv_comm, "getdoclimits") == 0)
        {
            if (!rcv_args)
            {
                mdebug1("AGCOM getdoclimits needs arguments (module name).");
                os_strdup("err AGCOM getdoclimits needs arguments", *output);
                return strlen(*output);
            }

            cJSON* cfg = getDocumentLimits(rcv_args);
            if (cfg)
            {
                os_strdup("ok", *output);
                char* json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                os_free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                mdebug1("AGCOM Module limits not configured for module '%s'.", rcv_args);
                os_strdup("err Module limits not configured", *output);
                return strlen(*output);
            }
        }
        else
        {
            mdebug1("AGCOM Unrecognized command '%s'.", rcv_comm);
            os_strdup("err Unrecognized command", *output);
            return strlen(*output);
        }
    }

    // ── getConfig ────────────────────────────────────────────────────

    size_t AgentCommander::getConfig(const char* section, char** output)
    {
        cJSON* cfg {nullptr};
        char* json_str {nullptr};

        if (strcmp(section, "client") == 0)
        {
            if ((cfg = getClientConfig()) != nullptr)
            {
                *output = strdup("ok");
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                goto error;
            }
        }
        else if (strcmp(section, "buffer") == 0)
        {
            if ((cfg = getBufferConfig()) != nullptr)
            {
                *output = strdup("ok");
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                goto error;
            }
        }
        else if (strcmp(section, "labels") == 0)
        {
            if ((cfg = getLabelsConfig()) != nullptr)
            {
                *output = strdup("ok");
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                goto error;
            }
        }
        else if (strcmp(section, "internal") == 0)
        {
            if ((cfg = getAgentInternalOptions()) != nullptr)
            {
                *output = strdup("ok");
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                goto error;
            }
        }
#ifndef WIN32
        else if (strcmp(section, "anti_tampering") == 0)
        {
            if ((cfg = getAntiTamperingConfig()) != nullptr)
            {
                os_strdup("ok", *output);
                json_str = cJSON_PrintUnformatted(cfg);
                wm_strcat(output, json_str, ' ');
                os_free(json_str);
                cJSON_Delete(cfg);
                return strlen(*output);
            }
            else
            {
                goto error;
            }
        }
#endif
        else
        {
            goto error;
        }

    error:
        mdebug1("At AGCOM getconfig: Could not get '%s' section", section);
        os_strdup("err Could not get requested section", *output);
        return strlen(*output);
    }

    // ── getHandshake ─────────────────────────────────────────────────

    size_t AgentCommander::getHandshake(char** output)
    {
        if (agent_cluster_name[0] == '\0')
        {
            mdebug1("Cluster name not received yet from manager.");
            os_strdup("err Cluster name not received yet from manager", *output);
            return strlen(*output);
        }

        if (agent_cluster_node[0] == '\0')
        {
            mdebug1("Cluster node not received yet from manager.");
            os_strdup("err Cluster node not received yet from manager", *output);
            return strlen(*output);
        }

        /* Empty agent_groups is allowed - fallback to merge.mg will be used */

        char* json_str = nullptr;
        cJSON* root = cJSON_CreateObject();

        if (root)
        {
            cJSON_AddStringToObject(root, "cluster_name", agent_cluster_name);
            cJSON_AddStringToObject(root, "cluster_node", agent_cluster_node);
            cJSON_AddStringToObject(root, "agent_groups", agent_agent_groups);
            json_str = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
        }

        if (json_str)
        {
            os_strdup(json_str, *output);
            os_free(json_str);
        }
        else
        {
            mdebug1("Failed to create handshake JSON response.");
            os_strdup("err Failed to create handshake JSON response", *output);
            return strlen(*output);
        }

        mdebug1("Returning handshake JSON response: %s", *output);
        return strlen(*output);
    }

    // ── getDocumentLimits ────────────────────────────────────────────

    cJSON* AgentCommander::getDocumentLimits(const char* module)
    {
        if (!module)
        {
            return nullptr;
        }

        if (!agent_module_limits.limits_received)
        {
            return nullptr;
        }

        cJSON* cfg = cJSON_CreateObject();
        if (!cfg)
        {
            return nullptr;
        }

        if (strcmp(module, "fim") == 0)
        {
            cJSON_AddNumberToObject(cfg, "file", agent_module_limits.fim.file);
            cJSON_AddNumberToObject(cfg, "registry_key", agent_module_limits.fim.registry_key);
            cJSON_AddNumberToObject(cfg, "registry_value", agent_module_limits.fim.registry_value);
        }
        else if (strcmp(module, "syscollector") == 0)
        {
            cJSON_AddNumberToObject(cfg, "hotfixes", agent_module_limits.syscollector.hotfixes);
            cJSON_AddNumberToObject(cfg, "packages", agent_module_limits.syscollector.packages);
            cJSON_AddNumberToObject(cfg, "processes", agent_module_limits.syscollector.processes);
            cJSON_AddNumberToObject(cfg, "ports", agent_module_limits.syscollector.ports);
            cJSON_AddNumberToObject(cfg, "network_iface", agent_module_limits.syscollector.network_iface);
            cJSON_AddNumberToObject(cfg, "network_protocol", agent_module_limits.syscollector.network_protocol);
            cJSON_AddNumberToObject(cfg, "network_address", agent_module_limits.syscollector.network_address);
            cJSON_AddNumberToObject(cfg, "hardware", agent_module_limits.syscollector.hardware);
            cJSON_AddNumberToObject(cfg, "os_info", agent_module_limits.syscollector.os_info);
            cJSON_AddNumberToObject(cfg, "users", agent_module_limits.syscollector.users);
            cJSON_AddNumberToObject(cfg, "groups", agent_module_limits.syscollector.groups);
            cJSON_AddNumberToObject(cfg, "services", agent_module_limits.syscollector.services);
            cJSON_AddNumberToObject(cfg, "browser_extensions", agent_module_limits.syscollector.browser_extensions);
        }
        else if (strcmp(module, "sca") == 0)
        {
            cJSON_AddNumberToObject(cfg, "checks", agent_module_limits.sca.checks);
        }
        else
        {
            cJSON_Delete(cfg);
            return nullptr;
        }

        return cfg;
    }

#ifndef WIN32
    // ── agcom_main (Unix socket listener) ────────────────────────────

    void* AgentCommander::mainThread()
    {
        int sock {-1};
        int peer {-1};
        char* buffer = nullptr;
        char* response = nullptr;
        ssize_t length {0};
        fd_set fdset;

        mdebug1("Local requests thread ready");

        // Bind socket
        if ((sock = OS_BindUnixDomain(AG_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR)) < 0)
        {
            merror("Unable to bind to socket '%s': (%d) %s.", AG_LOCAL_SOCK, errno, strerror(errno));
            return nullptr;
        }

        // Main loop
        while (true)
        {
            // Select
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);

            switch (select(sock + 1, &fdset, nullptr, nullptr, nullptr))
            {
                case -1:
                    if (errno != EINTR)
                    {
                        merror_exit("At agcom_main(): select(): %s", strerror(errno));
                    }
                    continue;
                case 0: continue;

                default: break;
            }

            // Accept
            if ((peer = accept(sock, nullptr, nullptr)) < 0)
            {
                if (errno != EINTR)
                {
                    merror("At agcom_main(): accept(): %s", strerror(errno));
                }
                continue;
            }

            // Receive
            buffer = static_cast<char*>(calloc(OS_MAXSTR, sizeof(char)));
            length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR);
            switch (length)
            {
                case OS_SOCKTERR:
                    merror("At agcom_main(): OS_RecvSecureTCP(): response size is bigger than "
                           "expected");
                    break;
                case -1: merror("At agcom_main(): OS_RecvSecureTCP(): %s", strerror(errno)); break;
                case 0:
                    mdebug1("Empty message from local client.");
                    close(peer);
                    os_free(buffer);
                    continue;
                case OS_MAXLEN:
                    merror("Received message > %i", MAX_DYN_STR);
                    close(peer);
                    os_free(buffer);
                    continue;
                default:
                    // Dispatch
                    length = static_cast<ssize_t>(dispatch(buffer, &response));
                    // Send
                    OS_SendSecureTCP(peer, static_cast<uint32_t>(length), response);
                    os_free(response);
                    close(peer);
            }
            os_free(buffer);
        }

        close(sock);
        return nullptr;
    }
#endif

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    size_t agcom_dispatch(char* command, char** output)
    {
        return agentd::AgentCommander::instance().dispatch(command, output);
    }

    size_t agcom_getconfig(const char* section, char** output)
    {
        return agentd::AgentCommander::instance().getConfig(section, output);
    }

    size_t agcom_gethandshake(char** output)
    {
        return agentd::AgentCommander::instance().getHandshake(output);
    }

    cJSON* getDocumentLimits(const char* module)
    {
        return agentd::AgentCommander::instance().getDocumentLimits(module);
    }

#ifndef WIN32
    void* agcom_main(__attribute__((unused)) void* arg)
    {
        return agentd::AgentCommander::instance().mainThread();
    }
#endif

} // extern "C"
