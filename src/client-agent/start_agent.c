/* Copyright (C) 2015-2020, Wazuh Inc.
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
    #define static
    #ifdef WIN32
            #include "unit_tests/wrappers/client-agent/start_agent.h"
            #undef CloseSocket
            #define CloseSocket wrap_closesocket
            #define recv wrap_recv
    #endif
#endif

#define ENROLLMENT_RETRY_TIME_MAX   60
#define ENROLLMENT_RETRY_TIME_DELTA 5

int timeout;    //timeout in seconds waiting for a server reply

static ssize_t receive_message(char *buffer, unsigned int max_lenght);
static void w_agentd_keys_init (void);
static bool agent_handshake_to_server(int server_id, bool is_startup);
static void send_msg_on_startup(void);

/**
 * @brief Connects to a specified server
 * @param server_id index of the specified server from agt servers list
 * @post The remote IP id (rip_id) is set to server_id if and only if this function succeeds.
 * @retval true on success
 * @retval false when failed
 * */
bool connect_server(int server_id)
{
    timeout = getDefine_Int("agent", "recv_timeout", 1, 600);

    /* Close socket if available */
    if (agt->sock >= 0) {
        CloseSocket(agt->sock);
        agt->sock = -1;

        if (agt->server[agt->rip_id].rip) {
            minfo("Closing connection to server (%s:%d/%s).",
                    agt->server[agt->rip_id].rip,
                    agt->server[agt->rip_id].port,
                    agt->server[agt->rip_id].protocol == IPPROTO_UDP ? "udp" : "tcp");
        }
    }

    char *tmp_str;

    /* Check if we have a hostname */
    tmp_str = strchr(agt->server[server_id].rip, '/');
    if (tmp_str) {
        /* Resolve hostname */
        if (!isChroot()) {
            resolveHostname(&agt->server[server_id].rip, 5);

            tmp_str = strchr(agt->server[server_id].rip, '/');
            if (tmp_str) {
                tmp_str++;
            }
        } else {
            tmp_str++;
        }
    } else {
        tmp_str = agt->server[server_id].rip;
    }

    /* The hostname was not resolved correctly */
    if (tmp_str == NULL || *tmp_str == '\0') {
        int rip_l = strlen(agt->server[server_id].rip);
        mdebug2("Could not resolve hostname '%.*s'", agt->server[server_id].rip[rip_l - 1] == '/' ? rip_l - 1 : rip_l, agt->server[server_id].rip);

        return false;
    }

    minfo("Trying to connect to server (%s:%d/%s).",
            agt->server[server_id].rip,
            agt->server[server_id].port,
            agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp");

    if (agt->server[server_id].protocol == IPPROTO_UDP) {
        agt->sock = OS_ConnectUDP(agt->server[server_id].port, tmp_str, strchr(tmp_str, ':') != NULL);
    } else {
        agt->sock = OS_ConnectTCP(agt->server[server_id].port, tmp_str, strchr(tmp_str, ':') != NULL);
    }

    if (agt->sock < 0) {
        agt->sock = -1;
        #ifdef WIN32
            merror(CONNS_ERROR, tmp_str, win_strerror(WSAGetLastError()));
        #else
            merror(CONNS_ERROR, tmp_str, strerror(errno));
        #endif
    } else {
        #ifdef WIN32
            if (agt->server[server_id].protocol == IPPROTO_UDP) {
                int bmode = 1;

                /* Set socket to non-blocking */
                ioctlsocket(agt->sock, FIONBIO, (u_long FAR *) &bmode);
            }
        #endif
        agt->rip_id = server_id;
        return true;
    }
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
        for (int attempts = 0; attempts < agt->server[current_server_id].max_retries; attempts++) {
            if (agent_handshake_to_server(current_server_id, is_startup)) {
                return;
            }

            sleep(agt->server[current_server_id].retry_interval);
        }

        if (agt->enrollment_cfg && agt->enrollment_cfg->enabled && try_enroll_to_server(agt->server[current_server_id].rip) == 0) {
            if (agent_handshake_to_server(current_server_id, is_startup)) {
                return;
            }

            sleep(agt->server[current_server_id].retry_interval);
        }

        /* Wait for server reply */
        mwarn(AG_WAIT_SERVER, agt->server[current_server_id].rip);

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
                    registration_status = try_enroll_to_server(agt->enrollment_cfg->target_cfg->manager_name);
                }

                /* Try to enroll to server list */
                while (agt->server[rc].rip && (registration_status != 0)) {
                    registration_status = try_enroll_to_server(agt->server[rc].rip);
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

    OS_StartCounter(&keys);

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

int try_enroll_to_server(const char * server_rip) {
    int enroll_result = w_enrollment_request_key(agt->enrollment_cfg, server_rip);
    if (enroll_result == 0) {
        /* Wait for key update on agent side */
        minfo("Waiting %d seconds before server connection", agt->enrollment_cfg->delay_after_enrollment);
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
static bool agent_handshake_to_server(int server_id, bool is_startup) {
    size_t msg_length;
    ssize_t recv_b = 0;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2] = { '\0' };
    char buffer[OS_MAXSTR + 1] = { '\0' };
    char cleartext[OS_MAXSTR + 1] = { '\0' };

    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);

    if (connect_server(server_id)) {
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
                    if (strcmp(tmp_msg, HC_ACK) == 0) {
                        available_server = time(0);

                        minfo(AG_CONNECTED, agt->server[server_id].rip,
                                agt->server[server_id].port, agt->server[server_id].protocol == IPPROTO_UDP ? "udp" : "tcp");

                        if (is_startup) {
                            send_msg_on_startup();
                        }

                        return true;
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
static void send_msg_on_startup(void){

    char msg[OS_MAXSTR + 2] = { '\0' };
    char fmsg[OS_MAXSTR + 1] = { '\0' };

    /* Send log message about start up */
    snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
            keys.keyentries[0]->name,
            keys.keyentries[0]->ip->ip);
    os_snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
            "ossec", msg);

    send_msg(fmsg, -1);
}
