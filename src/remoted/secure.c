/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"


/* Handle secure connections */
void HandleSecure()
{
    int agentid;
    char buffer[OS_MAXSTR + 1];
    char cleartext_msg[OS_MAXSTR + 1];
    char srcip[IPSIZE + 1];
    char *tmp_msg;
    char srcmsg[OS_FLSIZE + 1];
    ssize_t recv_b;
    struct sockaddr_in peer_info;
    socklen_t peer_size;

    /* Send msg init */
    send_msg_init();

    /* Initialize key mutex */
    keyupdate_init();

    /* Initialize manager */
    manager_init(0);

    /* Create Active Response forwarder thread */
    if (CreateThread(AR_Forward, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Create wait_for_msgs thread */
    if (CreateThread(wait_for_msgs, (void *)NULL) != 0) {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Connect to the message queue
     * Exit if it fails.
     */
    if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    verbose(AG_AX_AGENTS, ARGV0, MAX_AGENTS);

    /* Read authentication keys */
    verbose(ENC_READ, ARGV0);

    OS_ReadKeys(&keys);

    debug1("%s: DEBUG: OS_StartCounter.", ARGV0);
    OS_StartCounter(&keys);
    debug1("%s: DEBUG: OS_StartCounter completed.", ARGV0);

    /* Set up peer size */
    peer_size = sizeof(peer_info);
    logr.peer_size = sizeof(peer_info);

    /* Initialize some variables */
    memset(buffer, '\0', OS_MAXSTR + 1);
    memset(cleartext_msg, '\0', OS_MAXSTR + 1);
    memset(srcmsg, '\0', OS_FLSIZE + 1);
    tmp_msg = NULL;

    while (1) {
        /* Receive message  */
        recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0,
                          (struct sockaddr *)&peer_info, &peer_size);

        /* Nothing received */
        if (recv_b <= 0) {
            continue;
        }

        /* Set the source IP */
        strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
        srcip[IPSIZE] = '\0';

        /* Get a valid agent id */
        if (buffer[0] == '!') {
            tmp_msg = buffer;
            tmp_msg++;

            /* We need to make sure that we have a valid id
             * and that we reduce the recv buffer size
             */
            while (isdigit((int)*tmp_msg)) {
                tmp_msg++;
                recv_b--;
            }

            if (*tmp_msg != '!') {
                merror(ENCFORMAT_ERROR, __local_name, srcip);
                continue;
            }

            *tmp_msg = '\0';
            tmp_msg++;
            recv_b -= 2;

            agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);
            if (agentid == -1) {
                if (check_keyupdate()) {
                    agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);
                    if (agentid == -1) {
                        merror(ENC_IP_ERROR, ARGV0, srcip);
                        continue;
                    }
                } else {
                    merror(ENC_IP_ERROR, ARGV0, srcip);
                    continue;
                }
            }
        } else {
            agentid = OS_IsAllowedIP(&keys, srcip);
            if (agentid < 0) {
                if (check_keyupdate()) {
                    agentid = OS_IsAllowedIP(&keys, srcip);
                    if (agentid == -1) {
                        merror(DENYIP_WARN, ARGV0, srcip);
                        continue;
                    }
                } else {
                    merror(DENYIP_WARN, ARGV0, srcip);
                    continue;
                }
            }
            tmp_msg = buffer;
        }

        /* Decrypt the message */
        tmp_msg = ReadSecMSG(&keys, tmp_msg, cleartext_msg,
                             agentid, recv_b - 1);
        if (tmp_msg == NULL) {
            /* If duplicated, a warning was already generated */
            continue;
        }

        /* Check if it is a control message */
        if (IsValidHeader(tmp_msg)) {
            /* We need to save the peerinfo if it is a control msg */
            memcpy(&keys.keyentries[agentid]->peer_info, &peer_info, peer_size);
            keys.keyentries[agentid]->rcvd = time(0);

            save_controlmsg((unsigned)agentid, tmp_msg);

            continue;
        }

        /* Generate srcmsg */
        snprintf(srcmsg, OS_FLSIZE, "(%s) %s", keys.keyentries[agentid]->name,
                 keys.keyentries[agentid]->ip->ip);

        /* If we can't send the message, try to connect to the
         * socket again. If it not exit.
         */
        if (SendMSG(logr.m_queue, tmp_msg, srcmsg,
                    SECURE_MQ) < 0) {
            merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
            }
        }
    }
}

