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

int timeout;    //timeout in seconds waiting for a server reply

static ssize_t receive_message_udp(const char *msg, char *buffer, unsigned int max_lenght);
static ssize_t receive_message_tcp(const char *msg, char *buffer, unsigned int max_lenght);

/* Attempt to connect to all configured servers */
int connect_server(int initial_id)
{
    int attempts = 2;
    int rc = initial_id;

    timeout = getDefine_Int("agent", "recv_timeout", 1, 600);

    /* Checking if the initial is zero, meaning we have to
     * rotate to the beginning
     */
    if (agt->server[initial_id].rip == NULL) {
        rc = 0;
    }

    /* Close socket if available */
    if (agt->sock >= 0) {
        sleep(1);
        CloseSocket(agt->sock);
        agt->sock = -1;

        if (agt->server[1].rip) {
            minfo("Closing connection to server (%s:%d/%s).",
                    agt->server[rc].rip,
                    agt->server[rc].port,
                    agt->server[rc].protocol == IPPROTO_UDP ? "udp" : "tcp");
        }
    }

    while (agt->server[rc].rip) {
        char *tmp_str;

        /* Check if we have a hostname */
        tmp_str = strchr(agt->server[rc].rip, '/');
        if (tmp_str) {
            // Resolve hostname
            if (!isChroot()) {
                resolveHostname(&agt->server[rc].rip, 5);

                tmp_str = strchr(agt->server[rc].rip, '/');
                if(tmp_str) {
                    tmp_str++;
                }
            } else {
                tmp_str++;
            }
        } else {
            tmp_str = agt->server[rc].rip;
        }

        // The hostname was not resolved correctly
        if (tmp_str == NULL || *tmp_str == '\0') {
            int rip_l = strlen(agt->server[rc].rip);
            mdebug2("Could not resolve hostname '%.*s'", agt->server[rc].rip[rip_l - 1] == '/' ? rip_l - 1 : rip_l, agt->server[rc].rip);
            rc++;
            if (agt->server[rc].rip == NULL) {
                attempts += 10;
                if (agt->server[1].rip) {
                    merror("Unable to connect to any server.");
                }
                sleep(attempts < agt->notify_time ? attempts : agt->notify_time);
                rc = 0;
            }
            continue;
        }

        minfo("Trying to connect to server (%s:%d/%s).",
                agt->server[rc].rip,
                agt->server[rc].port,
                agt->server[rc].protocol == IPPROTO_UDP ? "udp" : "tcp");

        if (agt->server[rc].protocol == IPPROTO_UDP) {
            agt->sock = OS_ConnectUDP(agt->server[rc].port, tmp_str, strchr(tmp_str, ':') != NULL);
        } else {
            if (agt->sock >= 0) {
                close(agt->sock);
                agt->sock = -1;
            }

            agt->sock = OS_ConnectTCP(agt->server[rc].port, tmp_str, strchr(tmp_str, ':') != NULL);
        }

        if (agt->sock < 0) {
            agt->sock = -1;
#ifdef WIN32
            merror(CONNS_ERROR, tmp_str, win_strerror(WSAGetLastError()));
#else
            merror(CONNS_ERROR, tmp_str, strerror(errno));
#endif
            rc++;

            if (agt->server[rc].rip == NULL) {
                attempts += 10;

                /* Only log that if we have more than 1 server configured */
                if (agt->server[1].rip) {
                    merror("Unable to connect to any server.");
                }

                sleep(attempts < agt->notify_time ? attempts : agt->notify_time);
                rc = 0;
            }
        } else {
            if (agt->server[rc].protocol == IPPROTO_TCP) {
                if (OS_SetRecvTimeout(agt->sock, timeout, 0) < 0){
                    switch (errno) {
                    case ENOPROTOOPT:
                        mdebug1("Cannot set network timeout: operation not supported by this OS.");
                        break;
                    default:
                        merror("Cannot set network timeout: %s (%d)", strerror(errno), errno);
                        return EXIT_FAILURE;
                    }
                }
            }

#ifdef WIN32
            if (agt->server[rc].protocol == IPPROTO_UDP) {
                int bmode = 1;

                /* Set socket to non-blocking */
                ioctlsocket(agt->sock, FIONBIO, (u_long FAR *) &bmode);
            }
#endif

            agt->rip_id = rc;
            return (1);
        }
    }

    return (0);
}

/* Send synchronization message to the server and wait for the ack */
void start_agent(int is_startup)
{
    size_t msg_length;
    int delay = 1;
    ssize_t recv_b = 0;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2];
    char buffer[OS_MAXSTR + 1];
    char cleartext[OS_MAXSTR + 1];
    char fmsg[OS_MAXSTR + 1];

    memset(msg, '\0', OS_MAXSTR + 2);
    memset(buffer, '\0', OS_MAXSTR + 1);
    memset(cleartext, '\0', OS_MAXSTR + 1);
    memset(fmsg, '\0', OS_MAXSTR + 1);
    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);

    #ifdef ONEWAY_ENABLED
        return;
    #endif

    while (1) {
        connect_server(agt->rip_id);
        /* Send start up message */
        send_msg(msg, -1);

        /* Read until our reply comes back */
        if (agt->server[agt->rip_id].protocol == IPPROTO_UDP) {
            recv_b = receive_message_udp(msg, buffer, OS_MAXSTR);
        } else {
            recv_b = receive_message_tcp(msg, buffer, OS_MAXSTR);
        }
        
        if (recv_b > 0) {
            /* Id of zero -- only one key allowed */
            if (ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->server[agt->rip_id].rip, &tmp_msg) != KS_VALID) {
                mwarn(MSG_ERROR, agt->server[agt->rip_id].rip);
            } else {
                /* Check for commands */
                if (IsValidHeader(tmp_msg)) {
                    /* If it is an ack reply */
                    if (strcmp(tmp_msg, HC_ACK) == 0) {
                        available_server = time(0);

                        minfo(AG_CONNECTED, agt->server[agt->rip_id].rip,
                                agt->server[agt->rip_id].port, agt->server[agt->rip_id].protocol == IPPROTO_UDP ? "udp" : "tcp");

                        if (is_startup) {
                            /* Send log message about start up */
                            snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                                    keys.keyentries[0]->name,
                                    keys.keyentries[0]->ip->ip);
                            snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                                    "ossec", msg);
                            send_msg(fmsg, -1);
                        }
                        return;
                    }
                }
            }
        }

        /* If there is a next server, try it */
        if (agt->server[agt->rip_id + 1].rip) {
            agt->rip_id++;
            minfo("Trying next server ip in the line: '%s'.", agt->server[agt->rip_id].rip);
            delay += 5;
            sleep(delay < agt->notify_time ? delay : agt->notify_time);
        } else {
            agt->rip_id = 0;
            delay += (5 * 3);
            sleep(delay < agt->notify_time ? delay : agt->notify_time);
        }
    }

    return;
}


/**
 * Holds the message reception logic for udp
 * @param msg message to be sent
 * @param buffer pointer to buffer where the information will be stored
 * @param max_length size of buffer
 * @return message_size on success
 *         0 when all retries failed
 * */
static ssize_t receive_message_udp(const char *msg, char *buffer, unsigned int max_lenght) {
    int attempts = 0;
    ssize_t recv_b = 0;

    /* Wait for server reply */
    mwarn(AG_WAIT_SERVER, agt->server[agt->rip_id].rip);
    sleep(1);

    while (attempts <= 5){
        /* Receive response */
        recv_b = recv(agt->sock, buffer, max_lenght, MSG_DONTWAIT);
        
        if (recv_b <= 0 ) {
            switch (recv_b) {
            case OS_SOCKTERR:
                merror("Corrupt payload (exceeding size) received.");
                break;
            default:
                #ifdef WIN32
                    mdebug1("Connection socket: %s (%d)", win_strerror(WSAGetLastError()), WSAGetLastError());
                #else
                    mdebug1("Connection socket: %s (%d)", strerror(errno), errno);
                #endif
                break;
            }
            attempts++;
            sleep(attempts);

            /* Send message again (after three attempts) */
            if (attempts >= 3 || recv_b == OS_SOCKTERR) {
                if (attempts == 3 && agt->enrollment_cfg && agt->enrollment_cfg->enabled) { // Only one enrollment attemp
                    try_enroll_to_server(agt->server[agt->rip_id].rip);
                }
                if (connect_server(agt->rip_id)) {
                    // if enroll is successfull reconnect and re-send message
                    send_msg(msg, -1);
                    // After sending message wait before response
                    sleep(attempts);
                }
            }
        } else {
            return recv_b;
        }   
    }
    return 0;
}

/**
 * Holds the message reception logic for tcp
 * @param msg message to be sent
 * @param buffer pointer to buffer where the information will be stored
 * @param max_length size of buffer
 * @return 1 on success
 *         0 when all retries failed
 * */
static ssize_t receive_message_tcp(const char *msg, char *buffer, unsigned int max_lenght) {
    ssize_t recv_b = 0;
    int attempts = 0;
    bool enrollment_attemp = false;
    
    while ((attempts <= 5) && (recv_b <= 0)) {
        int sock = wnet_select(agt->sock, timeout);
        if (sock < 0) {
            merror(SELECT_ERROR, errno, strerror(errno));
        } else if( sock > 0) {
            recv_b = OS_RecvSecureTCP(agt->sock, buffer, max_lenght);

            switch (recv_b) {
                case OS_SOCKTERR:
                    merror("Corrupt payload (exceeding size) received.");
                    break;
                case 0:
                    // Peer performed orderly shutdown (connection refused by manager)
                    if (agt->enrollment_cfg && agt->enrollment_cfg->enabled && !enrollment_attemp) {
                        if (try_enroll_to_server(agt->server[agt->rip_id].rip) == 0) {
                            if (connect_server(agt->rip_id)) {
                                send_msg(msg, -1);
                            }
                        }
                        enrollment_attemp = true; // Only attemp enrolling once
                    }
                    break;
                case -1:
                    #ifdef WIN32
                        mdebug1("Connection socket: %s (%d)", win_strerror(WSAGetLastError()), WSAGetLastError());
                    #else
                        mdebug1("Connection socket: %s (%d)", strerror(errno), errno);
                    #endif
                    // Connection timeout, try to reconnect
                    if (connect_server(agt->rip_id)) {
                        send_msg(msg, -1);
                    }
                    break;
            }
        }
        
        attempts++;

        
    }
    return recv_b > 0 ? recv_b : 0;
}

int try_enroll_to_server(const char * server_rip) {
    int enroll_result = w_enrollment_request_key(agt->enrollment_cfg, server_rip);
    if (enroll_result == 0) {
        // Wait for key update on agent side
        mdebug1("Sleeping %d seconds to allow manager key file updates", agt->enrollment_cfg->delay_after_enrollment);
        sleep(agt->enrollment_cfg->delay_after_enrollment);
        // Successfull enroll, read keys
        OS_UpdateKeys(&keys);
        // Set the crypto method for the agent
        os_set_agent_crypto_method(&keys,agt->crypto_method);
    }
    return enroll_result;
}