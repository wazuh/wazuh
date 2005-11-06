/*   $OSSEC, exec.c, v0.2, 2005/02/10, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic e-mailing operations */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "alerts.h"

#include "shared.h"
#include "rules.h"
#include "config.h"
#include "active-response.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"

#include "eventinfo.h"


/* OS_Exec v0.1 
 */
void OS_Exec(int *execq, int *arq, Eventinfo *lf, active_response *ar)
{
    char exec_msg[OS_MAXSTR +1];


    /* active response on the server */         
    if(ar->AS && Config.local_ar)
    {
        snprintf(exec_msg, OS_MAXSTR,
                "%s %s %s",
                ar->command,
                lf->user,
                lf->srcip);

        if(OS_SendUnix(*execq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with execd", ARGV0);
        }
    }
   
    /* active response to the forwarder */ 
    if(Config.remote_ar)
    {
        snprintf(exec_msg, OS_MAXSTR,
                "%s %s %s %s %s",
                lf->location,
                ar->location,
                ar->command,
                lf->user,
                lf->srcip);
        
        if(OS_SendUnix(*arq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with arq", ARGV0);
        }
    }
    
    return;
}

/* EOF */
