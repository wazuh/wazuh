/*   $OSSEC, event-forward.c, v0.1, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agentd.h"

#include "os_net/os_net.h"

#include "shared.h"
#include "sec.h"



/* EventForward v0.1, 2005/11/09
 * Receives a message in the internal queue
 * and forward it to the analysis server.
 */
void EventForward()
{
    int _ssize;    
    char crypt_msg[OS_MAXSTR +1];
    char *msg = NULL;
        
    
    /* Initializing variables */
    _ssize = 0;
    memset(crypt_msg, '\0', OS_MAXSTR +1);
    
    
    /* daemon loop */	
    while(1)
    {
        /* Receiving from the unix queue */
        if((msg = OS_RecvUnix(logr->m_queue, OS_MAXSTR)) != NULL)
        {
            _ssize = CreateSecMSG(&keys, msg, crypt_msg, 0);
            
            /* Returns NULL if can't create encrypted message */
            if(_ssize == 0)
            {
                merror(SEC_ERROR,ARGV0);
                free(msg);
                continue;
            }

            /* Send _ssize of crypt_msg */
            if(OS_SendUDPbySize(logr->sock, _ssize, crypt_msg) < 0)
                merror(SEND_ERROR,ARGV0);

            /* No need to set them to null */
            free(msg);
        }
    }
    
    return;
}



/* EOF */
