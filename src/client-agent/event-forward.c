/* @(#) $Id: ./src/client-agent/event-forward.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */


#include "shared.h"
#include "agentd.h"

#include "os_net/os_net.h"

#include "sec.h"



/* Receives a message locally on the agent and forwards to the
 * manager.
 */
void *EventForward()
{
    int recv_b;
    char msg[OS_MAXSTR +1];


    /* Initializing variables */
    msg[0] = '\0';
    msg[OS_MAXSTR] = '\0';


    while((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
    {
        msg[recv_b] = '\0';

        send_msg(0, msg);

        run_notify();
    }

    return(NULL);
}



/* EOF */
