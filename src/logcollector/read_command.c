/* @(#) $Id: ./src/logcollector/read_command.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the syslog */


#include "shared.h"
#include "logcollector.h"



/* Read Output of commands */
void *read_command(int pos, int *rc, int drop_it)
{
    size_t cmd_size = 0;
    char *p;
    char str[OS_MAXSTR+1];

    FILE *cmd_output;

    str[OS_MAXSTR]= '\0';
    *rc = 0;


    debug2("%s: DEBUG: Running command '%s'", ARGV0, logff[pos].command);


    cmd_output = popen(logff[pos].command, "r");
    if(!cmd_output)
    {
        merror("%s: ERROR: Unable to execute command: '%s'.",
               ARGV0, logff[pos].command);

        logff[pos].command = NULL;
    }


    snprintf(str, 256, "ossec: output: '%s': ",
             (NULL != logff[pos].alias)
             ? logff[pos].alias
             : logff[pos].command);
    cmd_size = strlen(str);


    while(fgets(str + cmd_size, OS_MAXSTR - OS_LOG_HEADER - 256, cmd_output) != NULL)
    {
        /* Getting the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL)
        {
            *p = '\0';
        }

        /* Removing empty lines. */
        #ifdef WIN32
        if(str[0] == '\r' && str[1] == '\0')
        {
            continue;
        }
        #endif
        if(str[0] == '\0')
        {
            continue;
        }


        debug2("%s: DEBUG: Reading command message: '%s'", ARGV0, str);


        /* Sending message to queue */
        if(drop_it == 0)
        {
            if(SendMSG(logr_queue,str,
                        (NULL != logff[pos].alias) ? logff[pos].alias : logff[pos].command,
                        LOCALFILE_MQ) < 0)
            {
                merror(QUEUE_SEND, ARGV0);
                if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        continue;
    }

    pclose(cmd_output);

    return(NULL);
}

/* EOF */
