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

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/debug_op.h"
#include "rules.h"
#include "headers/mq_op.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"

#include "eventinfo.h"


/* OS_Exec v0.1 
 */
void OS_Exec(int *execq, short int *notify, int position, 
		Eventinfo *lf, char *msgtolog)
{
    ExecdMsg msg;

    if(*notify < 0)
        return;
    else if(*notify == 0)
    {
        merror("%s: Command execution configured, but impossible to send.",
                ARGV0);
        *notify=-1;
        return;
    }
    else if(*notify > 10)
    {
        merror("%s: Command execution  disabled. Too many errors.",ARGV0);
        *notify=-1;
        return;
    }


#ifdef DEBUG	
    if(position >= 0)
        debug2("analysisd_os_execd: Matching rule: %d, comment:%s",
                currently_rule->sigid,currently_rule->comment);	
#endif

    msg.type=0;
    msg.args_size=0;
    msg.args=NULL;
    msg.name=strdup("ls1");
    msg.name_size=strlen(msg.name);    
    
    if(OS_SendExecQ(*execq, &msg) < 0)
    {
        /* Impossible to send. Trying again.. */
        if((*execq = StartMQ(EXECQUEUE,WRITE)) < 0)
        {
            *notify+=1;
        }
        if(OS_SendExecQ(*execq, &msg) < 0)
            *notify+=1;
        else
        {
            OS_FreeExecdMsg(&msg);
        }
    }
    else
        *notify=1;
    return;
}
