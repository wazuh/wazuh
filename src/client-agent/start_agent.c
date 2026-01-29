/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

#ifdef WAZUH_UNIT_TESTING
    // Remove static qualifier when unit testing
    #define STATIC
    #ifdef WIN32
            #include "unit_tests/wrappers/wazuh/client-agent/start_agent.h"
            #define recv wrap_recv
    #endif

    // Redefine ossec_version
    #undef __ossec_version
    #define __ossec_version "v4.5.0"
#else
    #define STATIC static
#endif

#define ENROLLMENT_RETRY_TIME_MAX   60
#define ENROLLMENT_RETRY_TIME_DELTA 5

int timeout;    //timeout in seconds waiting for a server reply

static ssize_t receive_message(char *buffer, unsigned int max_lenght);
static void w_agentd_keys_init (void);
STATIC bool agent_handshake_to_server(int server_id, bool is_startup);
STATIC void send_msg_on_startup(void);

/**
 * @brief Parse JSON payload from handshake ACK response
 * @param json_str JSON string to parse
 * @param limits Pointer to module limits structure to populate
 * @param cluster_name Buffer to store cluster name (min 256 bytes)
 * @param cluster_name_size Size of cluster_name buffer
 * @param cluster_node Buffer to store cluster node (min 256 bytes)
 * @param cluster_node_size Size of cluster_node buffer
 * @param agent_groups Buffer to store agent groups as CSV (can be NULL)
 * @param agent_groups_size Size of agent_groups buffer
 * @return 0 on success, -1 on error
 */
STATIC int parse_handshake_json(const char *json_str, module_limits_t *limits,
                                char *cluster_name, size_t cluster_name_size,
                                char *cluster_node, size_t cluster_node_size,
                                char *agent_groups, size_t agent_groups_size) {
    cJSON *root = NULL;
    cJSON *limits_obj = NULL;
    cJSON *module = NULL;
    cJSON *field = NULL;

    if (!json_str || !limits) {
        return -1;
    }

    root = cJSON_Parse(json_str);
    if (!root) {
        merror("Failed to parse limits JSON");
        return -1;
    }

    /* Parse limits object */
    limits_obj = cJSON_GetObjectItem(root, "limits");
    if (!limits_obj) {
        mdebug1("No 'limits' object in handshake JSON");
        cJSON_Delete(root);
        return -1;
    }

    /* Parse FIM limits */
    module = cJSON_GetObjectItem(limits_obj, "fim");
    if (module) {
        if (field = cJSON_GetObjectItem(module, "file"), cJSON_IsNumber(field)) {
            limits->fim.file = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "registry_key"), cJSON_IsNumber(field)) {
            limits->fim.registry_key = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "registry_value"), cJSON_IsNumber(field)) {
            limits->fim.registry_value = field->valueint;
        }
    }

    /* Parse Syscollector limits */
    module = cJSON_GetObjectItem(limits_obj, "syscollector");
    if (module) {
        if (field = cJSON_GetObjectItem(module, "hotfixes"), cJSON_IsNumber(field)) {
            limits->syscollector.hotfixes = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "packages"), cJSON_IsNumber(field)) {
            limits->syscollector.packages = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "processes"), cJSON_IsNumber(field)) {
            limits->syscollector.processes = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "ports"), cJSON_IsNumber(field)) {
            limits->syscollector.ports = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "network_iface"), cJSON_IsNumber(field)) {
            limits->syscollector.network_iface = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "network_protocol"), cJSON_IsNumber(field)) {
            limits->syscollector.network_protocol = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "network_address"), cJSON_IsNumber(field)) {
            limits->syscollector.network_address = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "hardware"), cJSON_IsNumber(field)) {
            limits->syscollector.hardware = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "os_info"), cJSON_IsNumber(field)) {
            limits->syscollector.os_info = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "users"), cJSON_IsNumber(field)) {
            limits->syscollector.users = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "groups"), cJSON_IsNumber(field)) {
            limits->syscollector.groups = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "services"), cJSON_IsNumber(field)) {
            limits->syscollector.services = field->valueint;
        }
        if (field = cJSON_GetObjectItem(module, "browser_extensions"), cJSON_IsNumber(field)) {
            limits->syscollector.browser_extensions = field->valueint;
        }
    }

    /* Parse SCA limits */
    module = cJSON_GetObjectItem(limits_obj, "sca");
    if (module) {
        if (field = cJSON_GetObjectItem(module, "checks"), cJSON_IsNumber(field)) {
            limits->sca.checks = field->valueint;
        }
    }

    limits->limits_received = true;

    /* Parse cluster_name (separate from limits) */
    if (cluster_name && cluster_name_size > 0) {
        cJSON *cluster = cJSON_GetObjectItem(root, "cluster_name");
        if (cluster && cJSON_IsString(cluster) && cluster->valuestring) {
            strncpy(cluster_name, cluster->valuestring, cluster_name_size - 1);
            cluster_name[cluster_name_size - 1] = '\0';
        }
    }

    /* Parse cluster_node (separate from limits) */
    if (cluster_node && cluster_node_size > 0) {
        cJSON *node = cJSON_GetObjectItem(root, "cluster_node");
        if (node && cJSON_IsString(node) && node->valuestring) {
            strncpy(cluster_node, node->valuestring, cluster_node_size - 1);
            cluster_node[cluster_node_size - 1] = '\0';
        }
    }

    /* Parse agent_groups array and convert to CSV */
    if (agent_groups && agent_groups_size > 0) {
        agent_groups[0] = '\0';
        cJSON *groups_array = cJSON_GetObjectItem(root, "agent_groups");
        if (groups_array && cJSON_IsArray(groups_array)) {
            size_t offset = 0;
            cJSON *group_item = NULL;
            cJSON_ArrayForEach(group_item, groups_array) {
                if (cJSON_IsString(group_item) && group_item->valuestring) {
                    size_t group_len = strlen(group_item->valuestring);
                    /* Check if there's space: group + comma + null terminator */
                    if (offset + group_len + 2 < agent_groups_size) {
                        if (offset > 0) {
                            agent_groups[offset++] = ',';
                        }
                        strcpy(agent_groups + offset, group_item->valuestring);
                        offset += group_len;
                    }
                }
            }
            agent_groups[offset] = '\0';
        }
    }

    cJSON_Delete(root);
    return 0;
}

/**
 * @brief Connects to a specified server
 * @param server_id index of the specified server from agt servers list
 * @param verbose Be verbose or not.
 * @post The remote IP id (rip_id) is set to server_id if and only if this function succeeds.
 * @retval true on success
 * @retval false when failed
 * */
bool connect_server(int server_id, bool verbose)
{
    timeout = getDefine_Int("agent", "recv_timeout", 1, 600);

    /* Close socket if available */
    if (agt->sock >= 0) {
        OS_CloseSocket(agt->sock);
        agt->sock = -1;

        if (agt->server[agt->rip_id].rip) {
            if (verbose) {
                minfo("Closing connection to server ([%s]:%d/%s).",
                    agt->server[agt->rip_id].rip,
                    agt->server[agt->rip_id].port,
                    "tcp");
            }
        }
    }

    char *ip_address = NULL;
    char *tmp_str = strchr(agt->server[server_id].rip, '/');
    if (tmp_str) {
        // server address comes in {hostname}/{ip} format
        ip_address = strdup(++tmp_str);
    }
    if (!ip_address) {
        // server address is either a host or a ip
        ip_address = OS_GetHost(agt->server[server_id].rip, 3);
    }

    /* The hostname was not resolved correctly */
    if (ip_address == NULL || *ip_address == '\0') {
        if (agt->server[server_id].rip != NULL) {
            const int rip_l = strlen(agt->server[server_id].rip);
            minfo("Could not resolve hostname '%.*s'", agt->server[server_id].rip[rip_l - 1] == '/' ? rip_l - 1 : rip_l, agt->server[server_id].rip);
        } else {
            minfo("Could not resolve hostname");
        }
        os_free(ip_address);
        return false;
    }

    if (verbose) {
        minfo("Trying to connect to server ([%s]:%d/%s).",
            agt->server[server_id].rip,
            agt->server[server_id].port,
            "tcp");
    }

    agt->sock = OS_ConnectTCP(agt->server[server_id].port, ip_address, strchr(ip_address, ':') != NULL ? 1 : 0, agt->server[server_id].network_interface);

    if (agt->sock < 0) {
        agt->sock = -1;

        if (verbose) {
            #ifdef WIN32
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, "tcp", win_strerror(WSAGetLastError()));
            #else
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, "tcp", strerror(errno));
            #endif
        }
    } else {
        agt->rip_id = server_id;
        last_connection_time = (int)time(NULL);
        os_free(ip_address);
        return true;
    }
    os_free(ip_address);
    return false;
}

/* Send synchronization message to the server and wait for the ack */
void start_agent(int is_startup)
{

    if (is_startup) {
        w_agentd_keys_init();
    }

    #ifdef ONEWAY_ENABLED
        return;
    #endif
    int current_server_id = agt->rip_id;
    while (1) {
        // (max_retries - 1) attempts

        for (int attempts = 0; attempts < agt->server[current_server_id].max_retries - 1; attempts++) {
            if (agent_handshake_to_server(current_server_id, is_startup)) {
                return;
            }

            sleep(agt->server[current_server_id].retry_interval);
        }

        // Last attempt

        if (agent_handshake_to_server(current_server_id, is_startup)) {
            return;
        }

        // Try to enroll and extra attempt

        if (agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
            if (try_enroll_to_server(agt->server[current_server_id].rip, agt->server[current_server_id].network_interface) == 0) {
                if (agent_handshake_to_server(current_server_id, is_startup)) {
                    return;
                }
            }
        }

        sleep(agt->server[current_server_id].retry_interval);

        /* Wait for server reply */
        mwarn(AG_WAIT_SERVER, agt->server[current_server_id].rip, __ossec_version);

        /* If there is a next server, try it */
        if (agt->server[current_server_id + 1].rip) {
            current_server_id++;
            minfo("Trying next server ip in the line: '%s'.", agt->server[current_server_id].rip);
        } else {
            current_server_id = 0;
            mwarn("Unable to connect to any server.");
        }
    }
}

/**
 * @brief Initialize keys structure, counter, agent info and crypto method.
 * Keys are read from client.keys. If no valid entry is found:
 *  -If autoenrollment is enabled, a new key is requested to server and execution is blocked until a valid key is received.
 *  -If autoenrollment is disabled, daemon is stoped
 * */
static void w_agentd_keys_init (void) {

    if (keys.keysize == 0) {
        /* Check if we can auto-enroll */
        if (agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
            int registration_status = -1;
            int delay_sleep = 0;
            while (registration_status != 0) {
                int rc = 0;
                if (agt->enrollment_cfg->target_cfg->manager_name) {
                    /* Configured enrollment server */
                    registration_status = try_enroll_to_server(agt->enrollment_cfg->target_cfg->manager_name, agt->enrollment_cfg->target_cfg->network_interface);
                }

                /* Try to enroll to server list */
                while (agt->server[rc].rip && (registration_status != 0)) {
                    registration_status = try_enroll_to_server(agt->server[rc].rip, agt->server[rc].network_interface);
                    rc++;
                }

                /* Sleep between retries */
                if (registration_status != 0) {
                    if (delay_sleep < ENROLLMENT_RETRY_TIME_MAX) {
                        delay_sleep += ENROLLMENT_RETRY_TIME_DELTA;
                    }
                    mdebug1("Sleeping %d seconds before trying to enroll again", delay_sleep);
                    sleep(delay_sleep);
                }
            }
        }
        /* If autoenrollment is disabled, stop daemon */
        else {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }
    else {
        /* If the key store was empty, the counters will already be initialized in the enrollment process */
        OS_StartCounter(&keys);
    }

    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id,
                        agt->profile);

    /* Set the crypto method for the agent */
    os_set_agent_crypto_method(&keys, W_METH_AES);
    minfo("Using AES as encryption method.");
}

/**
 * @brief Holds the message reception logic for TCP
 * @param buffer pointer to buffer where the information will be stored
 * @param max_length size of buffer
 * @return Integer value indicating the status code.
 * @retval message_size on success
 * @retval 0 when retries failed
 * */
static ssize_t receive_message(char *buffer, unsigned int max_lenght) {

    ssize_t recv_b = 0;
    /* Read received reply */
    switch (wnet_select(agt->sock, timeout)) {
        case -1:
            merror(SELECT_ERROR, errno, strerror(errno));
            break;

        case 0:
            // Timeout
            break;

        default:
            /* Receive response TCP*/
            recv_b = OS_RecvSecureTCP(agt->sock, buffer, max_lenght);

            /* Successful response */
            if (recv_b > 0) {
                return recv_b;
            }
            /* Error response */
            else {
                switch (recv_b) {
                case OS_SOCKTERR:
                    merror("Corrupt payload (exceeding size) received.");
                    break;
                default:
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                        minfo("Unable to receive start response: Timeout reached");
                    } else {
                        #ifdef WIN32
                            mdebug1("Connection socket: %s (%d)", win_strerror(WSAGetLastError()), WSAGetLastError());
                        #else
                            mdebug1("Connection socket: %s (%d)", strerror(errno), errno);
                        #endif
                    }
                }
            }
    }
    return 0;
}

int try_enroll_to_server(const char * server_rip, uint32_t network_interface) {
    int enroll_result = w_enrollment_request_key(agt->enrollment_cfg, server_rip, network_interface);
    if (enroll_result == 0) {
        /* Wait for key update on agent side */
        minfo("Waiting %ld seconds before server connection", (long)agt->enrollment_cfg->delay_after_enrollment);
        sleep(agt->enrollment_cfg->delay_after_enrollment);
        /* Successfull enroll, read keys */
        OS_UpdateKeys(&keys);
        /* Set the crypto method for the agent */
        os_set_agent_crypto_method(&keys, W_METH_AES);
    }
    return enroll_result;
}

/**
 * @brief Holds handshake logic for an attempt to connect to server
 * @param server_id index of the specified server from agt servers list
 * @param is_startup The agent is starting up.
 * @post If is_startup is set to true, the startup message is sent on success.
 * @retval true on success
 * @retval false when failed
 * */
STATIC bool agent_handshake_to_server(int server_id, bool is_startup) {
    size_t msg_length;
    ssize_t recv_b = 0;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2] = { '\0' };
    char buffer[OS_MAXSTR + 1] = { '\0' };
    char cleartext[OS_MAXSTR + 1] = { '\0' };

    cJSON* agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "version", __ossec_version);
    char *agent_info_string = cJSON_PrintUnformatted(agent_info);
    cJSON_Delete(agent_info);

    snprintf(msg, OS_MAXSTR, "%s%s%s", CONTROL_HEADER, HC_STARTUP, agent_info_string);
    os_free(agent_info_string);

    if (connect_server(server_id, true)) {
        /* Send start up message */
        send_msg(msg, -1);

        /* Read until our reply comes back */
        recv_b = receive_message(buffer, OS_MAXSTR);

        if (recv_b > 0) {
            /* Id of zero -- only one key allowed */
            if (ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->server[server_id].rip, &tmp_msg) != KS_VALID) {
                mwarn(MSG_ERROR, agt->server[server_id].rip);
            }
            else {
                /* Check for commands */
                if (IsValidHeader(tmp_msg)) {
                    /* If it is an ack reply */
                    if (strncmp(tmp_msg, HC_ACK, strlen(HC_ACK)) == 0) {
                        available_server = time(0);

                        /* Check for JSON payload after HC_ACK */
                        const char *json_start = strchr(tmp_msg, '{');
                        if (json_start) {
                            char cluster_name_buffer[256] = {0};
                            char cluster_node_buffer[256] = {0};
                            char agent_groups_buffer[OS_SIZE_65536] = {0};
                            if (parse_handshake_json(json_start, &agent_module_limits,
                                                      cluster_name_buffer, sizeof(cluster_name_buffer),
                                                      cluster_node_buffer, sizeof(cluster_node_buffer),
                                                      agent_groups_buffer, sizeof(agent_groups_buffer)) == 0) {
                                minfo("Module limits received from manager");

                                mdebug2("Received FIM limits: file=%d, registry_key=%d, registry_value=%d",
                                        agent_module_limits.fim.file, agent_module_limits.fim.registry_key,
                                        agent_module_limits.fim.registry_value);
                                mdebug2("Received Syscollector limits: hotfixes=%d, packages=%d, processes=%d, ports=%d",
                                        agent_module_limits.syscollector.hotfixes,
                                        agent_module_limits.syscollector.packages,
                                        agent_module_limits.syscollector.processes,
                                        agent_module_limits.syscollector.ports);
                                mdebug2("Received Syscollector limits: net_iface=%d, net_proto=%d, net_addr=%d",
                                        agent_module_limits.syscollector.network_iface,
                                        agent_module_limits.syscollector.network_protocol,
                                        agent_module_limits.syscollector.network_address);
                                mdebug2("Received Syscollector limits: hw=%d, os=%d, users=%d, groups=%d, services=%d, browser_ext=%d",
                                        agent_module_limits.syscollector.hardware,
                                        agent_module_limits.syscollector.os_info,
                                        agent_module_limits.syscollector.users,
                                        agent_module_limits.syscollector.groups,
                                        agent_module_limits.syscollector.services,
                                        agent_module_limits.syscollector.browser_extensions);
                                mdebug2("Received SCA limits: checks=%d", agent_module_limits.sca.checks);

                                /* Store cluster_name in global for agent-info module to query via agcom */
                                if (cluster_name_buffer[0] != '\0') {
                                    strncpy(agent_cluster_name, cluster_name_buffer,
                                            sizeof(agent_cluster_name) - 1);
                                    agent_cluster_name[sizeof(agent_cluster_name) - 1] = '\0';
                                    minfo("Connected to cluster: %s", agent_cluster_name);
                                } else {
                                    mwarn("No cluster name received from manager");
                                }

                                /* Store cluster_node in global for agent-info module to query via agcom */
                                if (cluster_node_buffer[0] != '\0') {
                                    strncpy(agent_cluster_node, cluster_node_buffer,
                                            sizeof(agent_cluster_node) - 1);
                                    agent_cluster_node[sizeof(agent_cluster_node) - 1] = '\0';
                                    minfo("Connected to node: %s", agent_cluster_node);
                                } else {
                                    mwarn("No cluster node received from manager");
                                }

                                /* Store agent_groups in global for agent-info module to query via agcom */
                                if (agent_groups_buffer[0] != '\0') {
                                    strncpy(agent_agent_groups, agent_groups_buffer,
                                            sizeof(agent_agent_groups) - 1);
                                    agent_agent_groups[sizeof(agent_agent_groups) - 1] = '\0';
                                    minfo("Received agent groups from manager: %s", agent_agent_groups);
                                } else {
                                    mwarn("No agent groups received from manager");
                                }
                            } else {
                                mwarn("Error parsing handshake JSON, using defaults");
                            }
                        } else {
                            minfo("No handshake JSON after ACK, using defaults");
                        }

                        minfo(AG_CONNECTED, agt->server[server_id].rip,
                                agt->server[server_id].port, "tcp");

                        if (is_startup) {
                            send_msg_on_startup();
                        }

                        return true;
                    } else if (strncmp(tmp_msg, HC_ERROR, strlen(HC_ERROR)) == 0) {
                        cJSON *error_msg = NULL;
                        cJSON *error_info = NULL;
                        if (error_msg = cJSON_Parse(strchr(tmp_msg, '{')), error_msg) {
                            if (error_info = cJSON_GetObjectItem(error_msg, "message"), cJSON_IsString(error_info)) {
                                mwarn("Couldn't connect to server '%s': '%s'", agt->server[server_id].rip, error_info->valuestring);
                            } else {
                                merror("Error getting message from server '%s'", agt->server[server_id].rip);
                            }
                        } else {
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

/**
 * @brief Sends log message about start up
 * */
STATIC void send_msg_on_startup(void) {

    char msg[OS_MAXSTR + 2] = { '\0' };
    char fmsg[OS_MAXSTR + 1] = { '\0' };

    /* Send log message about start up */
    snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
            keys.keyentries[0]->name,
            keys.keyentries[0]->ip->ip);
    os_snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", msg);

    send_msg(fmsg, -1);
}

/**
 * @brief Send agent stopped message to server before exit
 * */
void send_agent_stopped_message() {
    char msg[OS_SIZE_32] = { '\0' };

    snprintf(msg, OS_SIZE_32, "%s%s", CONTROL_HEADER, HC_SHUTDOWN);

    /* Send shutdown message */
    send_msg(msg, -1);
}
