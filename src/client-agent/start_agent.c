/* @(#) $Id: ./src/client-agent/start_agent.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "agentd.h"

#include "os_net/os_net.h"


/** void connect_server()
 *  Attempts to connect to all configured servers.
 */
int connect_server(int initial_id)
{
    int attempts = 2;
    int rc = initial_id;


    /* Checking if the initial is zero, meaning we have to rotate to the
     * beginning.
     */
    if(logr->rip[initial_id] == NULL)
    {
        rc = 0;
        initial_id = 0;
    }


    /* Closing socket if available. */
    if(logr->sock >= 0)
    {
        sleep(1);
        CloseSocket(logr->sock);
        logr->sock = -1;

        if(logr->rip[1])
        {
            verbose("%s: INFO: Closing connection to server (%s:%s).",
                    ARGV0,
                    logr->rip[rc],
                    logr->port);
        }

    }


    while(logr->rip[rc])
    {
        char *tmp_str;

        /* Checking if we have a hostname. */
        tmp_str = strchr(logr->rip[rc], '/');
        if(tmp_str)
        {
            char *f_ip;
            *tmp_str = '\0';

            f_ip = OS_GetHost(logr->rip[rc], 5);
            if(f_ip)
            {
                char ip_str[128];
                ip_str[127] = '\0';

                snprintf(ip_str, 127, "%s/%s", logr->rip[rc], f_ip);

                free(f_ip);
                free(logr->rip[rc]);

                os_strdup(ip_str, logr->rip[rc]);
                tmp_str = strchr(logr->rip[rc], '/');
                tmp_str++;
            }
            else
            {
                merror("%s: WARN: Unable to get hostname for '%s'.",
                       ARGV0, logr->rip[rc]);
                *tmp_str = '/';
                tmp_str++;
            }
        }
        else
        {
            tmp_str = logr->rip[rc];
        }


        verbose("%s: INFO: Trying to connect to server (%s:%s).", ARGV0,
                logr->rip[rc],
                logr->port);

        /* IPv6 address: */
        if(strchr(tmp_str,':') != NULL)
        {
            verbose("%s: INFO: Using IPv6 for: %s .", ARGV0, tmp_str);
            logr->sock = OS_ConnectUDP(logr->port, tmp_str);
        }
        else
        {
            verbose("%s: INFO: Using IPv4 for: %s .", ARGV0, tmp_str);
            logr->sock = OS_ConnectUDP(logr->port, tmp_str);
        }

        if(logr->sock < 0)
        {
            logr->sock = -1;
            merror(CONNS_ERROR, ARGV0, tmp_str);
            rc++;

            if(logr->rip[rc] == NULL)
            {
                attempts += 10;

                /* Only log that if we have more than 1 server configured. */
                if(logr->rip[1])
                    merror("%s: ERROR: Unable to connect to any server.",ARGV0);

                sleep(attempts);
                rc = 0;
            }
        }
        else
        {
            /* Setting socket non-blocking on HPUX */
            #ifdef HPUX
            //fcntl(logr->sock, O_NONBLOCK);
            #endif

            #ifdef WIN32
            int bmode = 1;

            /* Setting socket to non-blocking */
            ioctlsocket(logr->sock, FIONBIO, (u_long FAR*) &bmode);
            #endif

            logr->rip_id = rc;
            return(1);
        }
    }

    return(0);
}



/* start_agent: Sends the synchronization message to
 * the server and waits for the ack.
 */
void start_agent(int is_startup)
{
    int recv_b = 0, attempts = 0, g_attempts = 1;

    char *tmp_msg;
    char msg[OS_MAXSTR +2];
    char buffer[OS_MAXSTR +1];
    char cleartext[OS_MAXSTR +1];
    char fmsg[OS_MAXSTR +1];


    memset(msg, '\0', OS_MAXSTR +2);
    memset(buffer, '\0', OS_MAXSTR +1);
    memset(cleartext, '\0', OS_MAXSTR +1);
    memset(fmsg, '\0', OS_MAXSTR +1);
    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);


    #ifdef ONEWAY
    return;
    #endif


    /* Sending start message and waiting for the ack */	
    while(1)
    {
        /* Sending start up message */
        send_msg(0, msg);
        attempts = 0;


        /* Read until our reply comes back */
        while(((recv_b = recv(logr->sock, buffer, OS_MAXSTR,
                              MSG_DONTWAIT)) >= 0) || (attempts <= 5))
        {
            if(recv_b <= 0)
            {
                /* Sleep five seconds before trying to get the reply from
                 * the server again.
                 */
                attempts++;
                sleep(attempts);

                /* Sending message again (after three attempts) */
                if(attempts >= 3)
                {
                    send_msg(0, msg);
                }

                continue;
            }

            /* Id of zero -- only one key allowed */
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b -1);
            if(tmp_msg == NULL)
            {
                merror(MSG_ERROR, ARGV0, logr->rip[logr->rip_id]);
                continue;
            }


            /* Check for commands */
            if(IsValidHeader(tmp_msg))
            {
                /* If it is an ack reply */
                if(strcmp(tmp_msg, HC_ACK) == 0)
                {
                    available_server = time(0);

                    verbose(AG_CONNECTED, ARGV0, logr->rip[logr->rip_id],
                                                 logr->port);

                    if(is_startup)
                    {
                        /* Send log message about start up */
                        snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                                keys.keyentries[0]->name,
                                keys.keyentries[0]->ip->ip);
                        snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                                                  "ossec", msg);
                        send_msg(0, fmsg);
                    }
                    return;
                }
            }
        }

        /* Waiting for servers reply */
        merror(AG_WAIT_SERVER, ARGV0, logr->rip[logr->rip_id]);


        /* If we have more than one server, try all. */
        if(logr->rip[1])
        {
            int curr_rip = logr->rip_id;
            merror("%s: INFO: Trying next server ip in the line: '%s'.", ARGV0,
                   logr->rip[logr->rip_id + 1] != NULL?logr->rip[logr->rip_id + 1]:logr->rip[0]);
            connect_server(logr->rip_id +1);

            if(logr->rip_id == curr_rip)
            {
                sleep(g_attempts);
                g_attempts+=(attempts * 3);
            }
            else
            {
                g_attempts+=5;
                sleep(g_attempts);
            }
        }
        else
        {
            sleep(g_attempts);
            g_attempts+=(attempts * 3);

            connect_server(0);
        }
    }


    return;
}



/* EOF */
