/* @(#) $Id$ */

/* Copyright (C) 2006, 2007 Daniel B. Cid <dcid@ossec.net>
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
    
    
    /* Sending start message and waiting for the ack */	
    while(1)
    {
        /* Sending start up message */
        send_msg(0, msg);
        attempts = 0;

        /* Read until our reply comes back */
        while(((recv_b = recv(logr->sock, buffer, OS_MAXSTR,
                              MSG_DONTWAIT)) >= 0)|| (attempts < 5))
        {
            if(recv_b <= 0)
            {
                /* Sleep five seconds before trying to get the reply from
                 * the server again.
                 */
                attempts++;
                sleep(attempts);

                /* Sending message again (after three attempts) */
                if(attempts == 3)
                {
                    send_msg(0, msg);
                }
                
                continue;
            }
            
            /* Id of zero -- only one key allowed */
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b -1);
            if(tmp_msg == NULL)
            {
                merror(MSG_ERROR,ARGV0,logr->rip);
                continue;
            }


            /* Check for commands */
            if(IsValidHeader(tmp_msg))
            {
                /* If it is an ack reply */
                if(strcmp(tmp_msg, HC_ACK) == 0)
                {
                    available_server = time(0);
                    if(is_startup)
                    {
                        verbose(AG_CONNECTED, ARGV0);

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
        merror(AG_WAIT_SERVER, ARGV0);
        sleep(g_attempts);
        g_attempts+=(attempts * 3);
    }
    
    return;
}



/* EOF */
