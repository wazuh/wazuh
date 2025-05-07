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
STATIC bool agent_handshake_to_server(int server_id, bool is_startup, bool *should_enroll);
STATIC void send_msg_on_startup(void);

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
                    agt->server[agt->rip_id].protocol == IPPROTO_UDP ? "udp" : "tcp");
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
            agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp");
    }
    if (agt->server[server_id].protocol == IPPROTO_UDP) {
        agt->sock = OS_ConnectUDP(agt->server[server_id].port, ip_address, strchr(ip_address, ':') != NULL ? 1 : 0, agt->server[server_id].network_interface);
    } else {
        agt->sock = OS_ConnectTCP(agt->server[server_id].port, ip_address, strchr(ip_address, ':') != NULL ? 1 : 0, agt->server[server_id].network_interface);
    }

    if (agt->sock < 0) {
        agt->sock = -1;

        if (verbose) {
            #ifdef WIN32
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp", win_strerror(WSAGetLastError()));
            #else
                merror(CONNS_ERROR, ip_address, agt->server[server_id].port, agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp", strerror(errno));
            #endif
        }
    } else {
        #ifdef WIN32
            if (agt->server[server_id].protocol == IPPROTO_UDP) {
                int bmode = 1;

                /* Set socket to non-blocking */
                ioctlsocket(agt->sock, FIONBIO, (u_long FAR *) &bmode);
            }
        #endif
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
        // Trying to connect to the server

        bool should_enroll = false;

        for (int attempts = 0; attempts < agt->server[current_server_id].max_retries; attempts++) {
            if (agent_handshake_to_server(current_server_id, is_startup, &should_enroll)) {
                return;
            }

            if (should_enroll) {
                break;
            }

            if (attempts < agt->server[current_server_id].max_retries - 1) {
                sleep(agt->server[current_server_id].retry_interval);
            }
        }

        // Try to enroll and extra attempt

        if (should_enroll && agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
            if (try_enroll_to_server(agt->server[current_server_id].rip, agt->server[current_server_id].network_interface) == 0) {
                if (agent_handshake_to_server(current_server_id, is_startup, &should_enroll)) {
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
    os_set_agent_crypto_method(&keys,agt->crypto_method);

    switch (agt->crypto_method) {
        case W_METH_AES:
            minfo("Using AES as encryption method.");
            break;
        case W_METH_BLOWFISH:
            minfo("Using Blowfish as encryption method.");
            break;
        default:
            merror("Invalid encryption method.");
    }
}

/**
 * @brief Holds the message reception logic for UDP and TCP
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
            if (agt->server[agt->rip_id].protocol == IPPROTO_UDP) {
                /* Receive response UDP*/
                recv_b = recv(agt->sock, buffer, max_lenght, MSG_DONTWAIT);
            } else {
                /* Receive response TCP*/
                recv_b = OS_RecvSecureTCP(agt->sock, buffer, max_lenght);
            }

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
        os_set_agent_crypto_method(&keys,agt->crypto_method);
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
STATIC bool agent_handshake_to_server(int server_id, bool is_startup, bool *should_enroll) {
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

    *should_enroll = false;

    if (connect_server(server_id, true)) {
        /* Send start up message */
        send_msg(msg, -1);

        /* Read until our reply comes back */
        recv_b = receive_message(buffer, OS_MAXSTR);

        if (recv_b > 0) {
            /* Id of zero -- only one key allowed */
            if (ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->server[server_id].rip, &tmp_msg) != KS_VALID) {
                if (strncmp(buffer, "#unauthorized", 13) == 0) {
                    *should_enroll = true;
                } else {
                    mwarn(MSG_ERROR, agt->server[server_id].rip);
                }
            }
            else {
                /* Check for commands */
                if (IsValidHeader(tmp_msg)) {
                    /* If it is an ack reply */
                    if (strcmp(tmp_msg, HC_ACK) == 0) {
                        available_server = time(0);

                        minfo(AG_CONNECTED, agt->server[server_id].rip,
                                agt->server[server_id].port, agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp");

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
