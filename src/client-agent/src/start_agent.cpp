/**
 * @file start_agent.cpp
 * @brief C++17 implementation of agent ↔ manager connection lifecycle.
 *
 * Replaces start_agent.c. Encapsulates connection, handshake,
 * enrollment, and JSON parsing in ServerConnection and provides
 * extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "server_connection.hpp"

extern "C"
{
#include "sendmsg.h"
}

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
extern "C"
{
#include "../../unit_tests/wrappers/wazuh/client-agent/start_agent.h"
#define recv wrap_recv
}
#endif
#undef __ossec_version
#define __ossec_version "v4.5.0"
#endif

// ── Global variable (declared in agentd.h) ──────────────────────────
extern "C"
{
    int timeout = 0; // seconds waiting for a server reply
}

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────

    ServerConnection& ServerConnection::instance()
    {
        static ServerConnection inst;
        return inst;
    }

    // ══════════════════════════════════════════════════════════════════
    //  JSON parsing helpers (static)
    // ══════════════════════════════════════════════════════════════════

    bool ServerConnection::getRequiredInt(const cJSON* parent, const char* name, int* value)
    {
        cJSON* field = cJSON_GetObjectItem(parent, name);
        if (!field || !cJSON_IsNumber(field))
        {
            mdebug1("Missing or invalid required field '%s' in handshake JSON", name);
            return false;
        }
        *value = field->valueint;
        return true;
    }

    bool ServerConnection::parseFimLimits(const cJSON* root, fim_limits_t* fim)
    {
        cJSON* module = cJSON_GetObjectItem(root, "fim");
        if (!module || !cJSON_IsObject(module))
        {
            mdebug1("Missing or invalid 'fim' object in handshake JSON");
            return false;
        }

        return getRequiredInt(module, "file", &fim->file) &&
               getRequiredInt(module, "registry_key", &fim->registry_key) &&
               getRequiredInt(module, "registry_value", &fim->registry_value);
    }

    bool ServerConnection::parseSyscollectorLimits(const cJSON* root, syscollector_limits_t* syscollector)
    {
        cJSON* module = cJSON_GetObjectItem(root, "syscollector");
        if (!module || !cJSON_IsObject(module))
        {
            mdebug1("Missing or invalid 'syscollector' object in handshake JSON");
            return false;
        }

        return getRequiredInt(module, "hotfixes", &syscollector->hotfixes) &&
               getRequiredInt(module, "packages", &syscollector->packages) &&
               getRequiredInt(module, "processes", &syscollector->processes) &&
               getRequiredInt(module, "ports", &syscollector->ports) &&
               getRequiredInt(module, "network_iface", &syscollector->network_iface) &&
               getRequiredInt(module, "network_protocol", &syscollector->network_protocol) &&
               getRequiredInt(module, "network_address", &syscollector->network_address) &&
               getRequiredInt(module, "hardware", &syscollector->hardware) &&
               getRequiredInt(module, "os_info", &syscollector->os_info) &&
               getRequiredInt(module, "users", &syscollector->users) &&
               getRequiredInt(module, "groups", &syscollector->groups) &&
               getRequiredInt(module, "services", &syscollector->services) &&
               getRequiredInt(module, "browser_extensions", &syscollector->browser_extensions);
    }

    bool ServerConnection::parseScaLimits(const cJSON* root, sca_limits_t* sca)
    {
        cJSON* module = cJSON_GetObjectItem(root, "sca");
        if (!module || !cJSON_IsObject(module))
        {
            mdebug1("Missing or invalid 'sca' object in handshake JSON");
            return false;
        }

        return getRequiredInt(module, "checks", &sca->checks);
    }

    bool ServerConnection::parseLimits(const cJSON* root, module_limits_t* limits)
    {
        cJSON* limits_obj = cJSON_GetObjectItem(root, "limits");
        if (!limits_obj || !cJSON_IsObject(limits_obj))
        {
            mdebug1("Missing or invalid 'limits' object in handshake JSON");
            return false;
        }

        if (!parseFimLimits(limits_obj, &limits->fim) || !parseSyscollectorLimits(limits_obj, &limits->syscollector) ||
            !parseScaLimits(limits_obj, &limits->sca))
        {
            return false;
        }

        limits->limits_received = true;
        return true;
    }

    bool ServerConnection::parseClusterName(const cJSON* root, char* cluster_name, size_t cluster_name_size)
    {
        if (!cluster_name || cluster_name_size == 0)
        {
            return true;
        }

        cJSON* cluster = cJSON_GetObjectItem(root, "cluster_name");
        if (!cluster || !cJSON_IsString(cluster) || !cluster->valuestring || cluster->valuestring[0] == '\0')
        {
            mdebug1("Missing or empty 'cluster_name' in handshake JSON");
            return false;
        }

        strncpy(cluster_name, cluster->valuestring, cluster_name_size - 1);
        cluster_name[cluster_name_size - 1] = '\0';
        return true;
    }

    bool ServerConnection::parseClusterNode(const cJSON* root, char* cluster_node, size_t cluster_node_size)
    {
        if (!cluster_node || cluster_node_size == 0)
        {
            return true;
        }

        cJSON* node = cJSON_GetObjectItem(root, "cluster_node");
        if (!node || !cJSON_IsString(node) || !node->valuestring || node->valuestring[0] == '\0')
        {
            mdebug1("Missing or empty 'cluster_node' in handshake JSON");
            return false;
        }

        strncpy(cluster_node, node->valuestring, cluster_node_size - 1);
        cluster_node[cluster_node_size - 1] = '\0';
        return true;
    }

    bool ServerConnection::parseAgentGroups(const cJSON* root, char* agent_groups, size_t agent_groups_size)
    {
        if (!agent_groups || agent_groups_size == 0)
        {
            return true;
        }

        agent_groups[0] = '\0';

        cJSON* groups_array = cJSON_GetObjectItem(root, "agent_groups");
        if (!groups_array || !cJSON_IsArray(groups_array))
        {
            mdebug1("Missing or invalid 'agent_groups' array in handshake JSON");
            return false;
        }

        size_t offset = 0;
        int valid_groups = 0;
        cJSON* group_item = nullptr;

        cJSON_ArrayForEach(group_item, groups_array)
        {
            if (cJSON_IsString(group_item) && group_item->valuestring && group_item->valuestring[0] != '\0')
            {
                size_t group_len = strlen(group_item->valuestring);
                /* Check if there's space: group + comma + null terminator */
                if (offset + group_len + 2 < agent_groups_size)
                {
                    if (offset > 0)
                    {
                        agent_groups[offset++] = ',';
                    }
                    strcpy(agent_groups + offset, group_item->valuestring);
                    offset += group_len;
                    valid_groups++;
                }
            }
        }
        agent_groups[offset] = '\0';

        /* Empty agent_groups is allowed - fallback to merge.mg will be used */
        if (valid_groups == 0)
        {
            mdebug1("Empty 'agent_groups' array, will use fallback");
        }

        return true;
    }

    int ServerConnection::parseHandshakeJson(const char* json_str,
                                             module_limits_t* limits,
                                             char* cluster_name,
                                             size_t cluster_name_size,
                                             char* cluster_node,
                                             size_t cluster_node_size,
                                             char* agent_groups,
                                             size_t agent_groups_size)
    {
        if (!json_str || !limits)
        {
            return -1;
        }

        cJSON* root = cJSON_Parse(json_str);
        if (!root)
        {
            mdebug1("Failed to parse handshake JSON");
            return -1;
        }

        if (!parseLimits(root, limits) || !parseClusterName(root, cluster_name, cluster_name_size) ||
            !parseClusterNode(root, cluster_node, cluster_node_size) ||
            !parseAgentGroups(root, agent_groups, agent_groups_size))
        {
            cJSON_Delete(root);
            return -1;
        }

        cJSON_Delete(root);
        return 0;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Private helpers
    // ══════════════════════════════════════════════════════════════════

    void ServerConnection::keysInit()
    {
        if (keys.keysize == 0)
        {
            /* Check if we can auto-enroll */
            if (agt->enrollment_cfg && agt->enrollment_cfg->enabled)
            {
                int registration_status = -1;
                int delay_sleep = 0;
                while (registration_status != 0)
                {
                    int rc = 0;
                    if (agt->enrollment_cfg->target_cfg->manager_name)
                    {
                        /* Configured enrollment server */
                        registration_status = tryEnrollToServer(agt->enrollment_cfg->target_cfg->manager_name,
                                                                agt->enrollment_cfg->target_cfg->network_interface);
                    }

                    /* Try to enroll to server list */
                    while (agt->server[rc].rip && (registration_status != 0))
                    {
                        registration_status = tryEnrollToServer(agt->server[rc].rip, agt->server[rc].network_interface);
                        rc++;
                    }

                    /* Sleep between retries */
                    if (registration_status != 0)
                    {
                        if (delay_sleep < kEnrollmentRetryTimeMax)
                        {
                            delay_sleep += kEnrollmentRetryTimeDelta;
                        }
                        mdebug1("Sleeping %d seconds before trying to enroll again", delay_sleep);
                        std::this_thread::sleep_for(std::chrono::seconds(delay_sleep));
                    }
                }
            }
            /* If autoenrollment is disabled, stop daemon */
            else
            {
                merror_exit(AG_NOKEYS_EXIT);
            }
        }
        else
        {
            /* If the key store was empty, the counters will already be
             * initialized in the enrollment process */
            OS_StartCounter(&keys);
        }

        os_write_agent_info(keys.keyentries[0]->name, nullptr, keys.keyentries[0]->id, agt->profile);

        /* Set the crypto method for the agent */
        os_set_agent_crypto_method(&keys, W_METH_AES);
        minfo("Using AES as encryption method.");
    }

    ssize_t ServerConnection::receiveMessage(char* buffer, unsigned int max_length)
    {
        ssize_t recv_b = 0;
        /* Read received reply */
        switch (wnet_select(agt->sock, timeout))
        {
            case -1: merror(SELECT_ERROR, errno, strerror(errno)); break;

            case 0:
                // Timeout
                break;

            default:
                /* Receive response TCP */
                recv_b = OS_RecvSecureTCP(agt->sock, buffer, max_length);

                /* Successful response */
                if (recv_b > 0)
                {
                    return recv_b;
                }
                /* Error response */
                else
                {
                    switch (recv_b)
                    {
                        case OS_SOCKTERR: merror("Corrupt payload (exceeding size) received."); break;
                        default:
                            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                            {
                                minfo("Unable to receive start response: Timeout reached");
                            }
                            else
                            {
#ifdef WIN32
                                mdebug1(
                                    "Connection socket: %s (%d)", win_strerror(WSAGetLastError()), WSAGetLastError());
#else
                                mdebug1("Connection socket: %s (%d)", strerror(errno), errno);
#endif
                            }
                    }
                }
        }
        return 0;
    }

    bool ServerConnection::handshakeToServer(int server_id, bool is_startup)
    {
        size_t msg_length {0};
        ssize_t recv_b = 0;

        char* tmp_msg {nullptr};
        char msg[OS_MAXSTR + 2] {};
        char buffer[OS_MAXSTR + 1] {};
        char cleartext[OS_MAXSTR + 1] {};

        cJSON* agent_info = cJSON_CreateObject();
        cJSON_AddStringToObject(agent_info, "version", __ossec_version);
        char* agent_info_string = cJSON_PrintUnformatted(agent_info);
        cJSON_Delete(agent_info);

        snprintf(msg, OS_MAXSTR, "%s%s%s", CONTROL_HEADER, HC_STARTUP, agent_info_string);
        os_free(agent_info_string);

        if (connectServer(server_id, true))
        {
            /* Send start up message */
            send_msg(msg, -1);

            /* Read until our reply comes back */
            recv_b = receiveMessage(buffer, OS_MAXSTR);

            if (recv_b > 0)
            {
                /* Id of zero -- only one key allowed */
                if (ReadSecMSG(
                        &keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->server[server_id].rip, &tmp_msg) !=
                    KS_VALID)
                {
                    mwarn(MSG_ERROR, agt->server[server_id].rip);
                }
                else
                {
                    /* Check for commands */
                    if (IsValidHeader(tmp_msg))
                    {
                        /* If it is an ack reply */
                        if (strncmp(tmp_msg, HC_ACK, strlen(HC_ACK)) == 0)
                        {
                            available_server = time(nullptr);

                            /* Check for JSON payload after HC_ACK */
                            const char* json_start = strchr(tmp_msg, '{');
                            if (json_start)
                            {
                                char cluster_name_buffer[256] {};
                                char cluster_node_buffer[256] {};
                                char agent_groups_buffer[OS_SIZE_65536] {};

                                /* Save previous limits to detect changes */
                                module_limits_t previous_limits = agent_module_limits;

                                if (parseHandshakeJson(json_start,
                                                       &agent_module_limits,
                                                       cluster_name_buffer,
                                                       sizeof(cluster_name_buffer),
                                                       cluster_node_buffer,
                                                       sizeof(cluster_node_buffer),
                                                       agent_groups_buffer,
                                                       sizeof(agent_groups_buffer)) == 0)
                                {
                                    minfo("Module limits received from manager");

                                    mdebug2("Received FIM limits: file=%d, registry_key=%d, registry_value=%d",
                                            agent_module_limits.fim.file,
                                            agent_module_limits.fim.registry_key,
                                            agent_module_limits.fim.registry_value);
                                    mdebug2("Received Syscollector limits: hotfixes=%d, packages=%d, "
                                            "processes=%d, ports=%d",
                                            agent_module_limits.syscollector.hotfixes,
                                            agent_module_limits.syscollector.packages,
                                            agent_module_limits.syscollector.processes,
                                            agent_module_limits.syscollector.ports);
                                    mdebug2("Received Syscollector limits: net_iface=%d, net_proto=%d, "
                                            "net_addr=%d",
                                            agent_module_limits.syscollector.network_iface,
                                            agent_module_limits.syscollector.network_protocol,
                                            agent_module_limits.syscollector.network_address);
                                    mdebug2("Received Syscollector limits: hw=%d, os=%d, users=%d, "
                                            "groups=%d, services=%d, browser_ext=%d",
                                            agent_module_limits.syscollector.hardware,
                                            agent_module_limits.syscollector.os_info,
                                            agent_module_limits.syscollector.users,
                                            agent_module_limits.syscollector.groups,
                                            agent_module_limits.syscollector.services,
                                            agent_module_limits.syscollector.browser_extensions);
                                    mdebug2("Received SCA limits: checks=%d", agent_module_limits.sca.checks);

                                    /* Store cluster_name */
                                    strncpy(agent_cluster_name, cluster_name_buffer, sizeof(agent_cluster_name) - 1);
                                    agent_cluster_name[sizeof(agent_cluster_name) - 1] = '\0';
                                    minfo("Connected to cluster: %s", agent_cluster_name);

                                    /* Store cluster_node */
                                    strncpy(agent_cluster_node, cluster_node_buffer, sizeof(agent_cluster_node) - 1);
                                    agent_cluster_node[sizeof(agent_cluster_node) - 1] = '\0';
                                    minfo("Connected to node: %s", agent_cluster_node);

                                    /* Store agent_groups */
                                    strncpy(agent_agent_groups, agent_groups_buffer, sizeof(agent_agent_groups) - 1);
                                    agent_agent_groups[sizeof(agent_agent_groups) - 1] = '\0';
                                    minfo("Agent groups: %s", agent_agent_groups);

                                    /* Check if limits changed and reload if auto_restart */
                                    if (previous_limits.limits_received &&
                                        module_limits_changed(&previous_limits, &agent_module_limits))
                                    {
                                        if (agt->flags.auto_restart)
                                        {
                                            minfo("Agent is reloading due to document limits changes.");
                                            reloadAgent();
                                        }
                                        else
                                        {
                                            minfo("Document limits have been updated.");
                                        }
                                    }
                                }
                                else
                                {
                                    mwarn("Error parsing handshake JSON, will retry handshake");
                                    return false;
                                }
                            }
                            else
                            {
                                minfo("No handshake JSON after ACK, using defaults");
                            }

                            minfo(AG_CONNECTED, agt->server[server_id].rip, agt->server[server_id].port, "tcp");

                            if (is_startup)
                            {
                                sendMsgOnStartup();
                            }

                            return true;
                        }
                        else if (strncmp(tmp_msg, HC_ERROR, strlen(HC_ERROR)) == 0)
                        {
                            cJSON* error_msg = nullptr;
                            cJSON* error_info = nullptr;
                            if ((error_msg = cJSON_Parse(strchr(tmp_msg, '{'))) != nullptr)
                            {
                                if ((error_info = cJSON_GetObjectItem(error_msg, "message")) != nullptr &&
                                    cJSON_IsString(error_info))
                                {
                                    mwarn("Couldn't connect to server '%s': '%s'",
                                          agt->server[server_id].rip,
                                          error_info->valuestring);
                                }
                                else
                                {
                                    merror("Error getting message from server '%s'", agt->server[server_id].rip);
                                }
                            }
                            else
                            {
                                merror("Error getting message from server '%s'", agt->server[server_id].rip);
                            }
                            cJSON_Delete(error_msg);
                        }
                    }
                }
            }
        }

        return false;
    }

    void ServerConnection::sendMsgOnStartup()
    {
        char msg[OS_MAXSTR + 2] {};
        char fmsg[OS_MAXSTR + 1] {};

        /* Send log message about start up */
        snprintf(msg, OS_MAXSTR, OS_AG_STARTED, keys.keyentries[0]->name, keys.keyentries[0]->ip->ip);
        os_snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", msg);

        send_msg(fmsg, -1);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Public methods
    // ══════════════════════════════════════════════════════════════════

    bool ServerConnection::connectServer(int server_id, bool verbose)
    {
        timeout = getDefine_Int("agent", "recv_timeout", 1, 600);

        /* Close socket if available */
        if (agt->sock >= 0)
        {
            OS_CloseSocket(agt->sock);
            agt->sock = -1;

            if (agt->server[agt->rip_id].rip)
            {
                if (verbose)
                {
                    minfo("Closing connection to server ([%s]:%d/%s).",
                          agt->server[agt->rip_id].rip,
                          agt->server[agt->rip_id].port,
                          "tcp");
                }
            }
        }

        char* ip_address = nullptr;
        char* tmp_str = strchr(agt->server[server_id].rip, '/');
        if (tmp_str)
        {
            // server address comes in {hostname}/{ip} format
            ip_address = strdup(++tmp_str);
        }
        if (!ip_address)
        {
            // server address is either a host or an ip
            ip_address = OS_GetHost(agt->server[server_id].rip, 3);
        }

        /* The hostname was not resolved correctly */
        if (ip_address == nullptr || *ip_address == '\0')
        {
            if (agt->server[server_id].rip != nullptr)
            {
                const int rip_l = static_cast<int>(strlen(agt->server[server_id].rip));
                minfo("Could not resolve hostname '%.*s'",
                      agt->server[server_id].rip[rip_l - 1] == '/' ? rip_l - 1 : rip_l,
                      agt->server[server_id].rip);
            }
            else
            {
                minfo("Could not resolve hostname");
            }
            os_free(ip_address);
            return false;
        }

        if (verbose)
        {
            minfo("Trying to connect to server ([%s]:%d/%s).",
                  agt->server[server_id].rip,
                  agt->server[server_id].port,
                  "tcp");
        }

        agt->sock = OS_ConnectTCP(agt->server[server_id].port,
                                  ip_address,
                                  strchr(ip_address, ':') != nullptr ? 1 : 0,
                                  agt->server[server_id].network_interface);

        if (agt->sock < 0)
        {
            agt->sock = -1;

            if (verbose)
            {
#ifdef WIN32
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, "tcp", win_strerror(WSAGetLastError()));
#else
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, "tcp", strerror(errno));
#endif
            }
        }
        else
        {
            agt->rip_id = server_id;
            last_connection_time = time(nullptr);
            os_free(ip_address);
            return true;
        }
        os_free(ip_address);
        return false;
    }

    void ServerConnection::startAgent(int is_startup)
    {
        if (is_startup)
        {
            keysInit();
        }

        int current_server_id = agt->rip_id;
        while (true)
        {
            // (max_retries - 1) attempts
            for (int attempts = 0; attempts < agt->server[current_server_id].max_retries - 1; attempts++)
            {
                if (handshakeToServer(current_server_id, is_startup != 0))
                {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::seconds(agt->server[current_server_id].retry_interval));
            }

            // Last attempt
            if (handshakeToServer(current_server_id, is_startup != 0))
            {
                return;
            }

            // Try to enroll and extra attempt
            if (agt->enrollment_cfg && agt->enrollment_cfg->enabled)
            {
                if (tryEnrollToServer(agt->server[current_server_id].rip,
                                      agt->server[current_server_id].network_interface) == 0)
                {
                    if (handshakeToServer(current_server_id, is_startup != 0))
                    {
                        return;
                    }
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(agt->server[current_server_id].retry_interval));

            /* Wait for server reply */
            mwarn(AG_WAIT_SERVER, agt->server[current_server_id].rip, __ossec_version);

            /* If there is a next server, try it */
            if (agt->server[current_server_id + 1].rip)
            {
                current_server_id++;
                minfo("Trying next server ip in the line: '%s'.", agt->server[current_server_id].rip);
            }
            else
            {
                current_server_id = 0;
                mwarn("Unable to connect to any server.");
            }
        }
    }

    void ServerConnection::sendAgentStoppedMessage()
    {
        char msg[OS_SIZE_32] {};

        snprintf(msg, OS_SIZE_32, "%s%s", CONTROL_HEADER, HC_SHUTDOWN);

        /* Send shutdown message */
        send_msg(msg, -1);
    }

    int ServerConnection::tryEnrollToServer(const char* server_rip, uint32_t network_interface)
    {
        int enroll_result = w_enrollment_request_key(agt->enrollment_cfg, server_rip, network_interface);
        if (enroll_result == 0)
        {
            /* Wait for key update on agent side */
            minfo("Waiting %ld seconds before server connection",
                  static_cast<long>(agt->enrollment_cfg->delay_after_enrollment));
            std::this_thread::sleep_for(std::chrono::seconds(agt->enrollment_cfg->delay_after_enrollment));
            /* Successful enroll, read keys */
            OS_UpdateKeys(&keys);
            /* Set the crypto method for the agent */
            os_set_agent_crypto_method(&keys, W_METH_AES);
        }
        return enroll_result;
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    bool connect_server(int initial_id, bool verbose)
    {
        return agentd::ServerConnection::instance().connectServer(initial_id, verbose);
    }

    void start_agent(int is_startup)
    {
        agentd::ServerConnection::instance().startAgent(is_startup);
    }

    void send_agent_stopped_message(void)
    {
        agentd::ServerConnection::instance().sendAgentStoppedMessage();
    }

    int try_enroll_to_server(const char* server_rip, uint32_t network_interface)
    {
        return agentd::ServerConnection::instance().tryEnrollToServer(server_rip, network_interface);
    }

} // extern "C"
