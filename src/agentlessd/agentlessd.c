/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "agentlessd.h"


/* send integrity checking message. */
int send_intcheck_msg(char *host, char *msg)
{
    char sys_location[1024 +1];

    sys_location[1024] = '\0';
    snprintf(sys_location, 1024, "%s->%s", host, SYSCHECK);
    
    if(SendMSG(lessdc.queue, msg, sys_location, SYSCHECK_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);

        if((lessdc.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* If we reach here, we can try to send it again */
        SendMSG(lessdc.queue, msg, sys_location, SYSCHECK_MQ);
    }

    return(0);
}



/* Run periodic commands. */
int run_periodic_cmd(agentlessd_entries *entry, int test_it)
{
    int i = 0;
    char *tmp_str;
    char buf[OS_SIZE_2048 +1];
    char command[OS_SIZE_1024 +1];
    FILE *fp;
    
    
    buf[0] = '\0';
    command[0] = '\0';
    command[OS_SIZE_1024] = '\0'; 
    
    
    while(entry->server[i])
    {
        snprintf(command, OS_SIZE_1024, "%s/%s \"%s\" %s 2>&1", 
                AGENTLESSDIRPATH, entry->type, entry->server[i], 
                entry->options);


        fp = popen(command, "r");
        if(fp)
        {
            while(fgets(buf, OS_SIZE_2048, fp) != NULL)
            {
                /* Removing new lines or carriage returns. */
                tmp_str = strchr(buf, '\r');
                if(tmp_str)
                    *tmp_str = '\0';
                tmp_str = strchr(buf, '\n');
                if(tmp_str)
                    *tmp_str = '\0';
                    
                if(strncmp(buf, "ERROR: ", 7) == 0)
                {
                    merror("%s: ERROR: from '%s': %s", ARGV0, entry->type, buf);
                    entry->error_flag++;
                    break;
                }
                else if(strncmp(buf, "FWD: ", 4) == 0)
                {
                    tmp_str = buf + 5;
                    send_intcheck_msg(entry->server[i], tmp_str);
                }
                else
                {
                    debug1("%s: DEBUG: buffer: %s", ARGV0, buf);
                }
            }

            pclose(fp);
        }
        else
        {
            merror("%s: ERROR: popen failed on '%s' for '%s'.", ARGV0, 
                   entry->type, entry->server[i]);
            entry->error_flag++;
        }

        i++;
    }

    return(0);
}






/* Main agentlessd */
void Agentlessd()
{
    time_t tm;     
    struct tm *p;       

    int today = 0;		        
    int thismonth = 0;
    int thisyear = 0;

    char str[OS_SIZE_1024 +1];


    /* Waiting a few seconds to settle */
    sleep(2);
    memset(str, '\0', OS_SIZE_1024 +1);
    
    
    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	
    
    today = p->tm_mday;
    thismonth = p->tm_mon;
    thisyear = p->tm_year+1900;
                

    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((lessdc.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0)
    {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }



    /* Main monitor loop */
    while(1)
    {
        int i = 0;
        tm = time(NULL);
        p = localtime(&tm);


        /* Day changed, deal with log files */
        if(today != p->tm_mday)
        {
            today = p->tm_mday;
            thismonth = p->tm_mon;
            thisyear = p->tm_year+1900;
        }


        while(lessdc.entries[i])
        {
            if(lessdc.entries[i]->error_flag >= 10)
            {
                if(lessdc.entries[i]->error_flag == 99)
                    continue;

                merror("%s: ERROR: Too many failures for '%s'. Ignoring it.",
                       ARGV0, lessdc.entries[i]->type); 
                lessdc.entries[i]->error_flag = 99;
            }

            
            /* Run the check again if the frequency has elapsed. */
            if((lessdc.entries[i]->state == LESSD_STATE_PERIODIC) &&
               ((lessdc.entries[i]->current_state + 
                 lessdc.entries[i]->frequency) < tm))
            {
                lessdc.entries[i]->current_state = tm;

                run_periodic_cmd(lessdc.entries[i], 0);
            }
            
            i++;
        }
        
        /* We only check every minute */
        sleep(60);
    }
}

/* EOF */
