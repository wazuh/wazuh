/*  $OSSEC, exec.c, v0.1, 2005/03/18, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "execd.h"

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/debug_op.h"
#include "headers/file_op.h"

#include "os_regex/os_regex.h"

char *_getexec(execd_config *config,char *name)
{
    if(!name)
        return(NULL);
    if((config) && (config->name))
    {
        int i=0;
        while(config->name[i])
        {
            if(strcmp(config->name[i],name) == 0)
            {
                if(config->cmd[i])
                {
                    char *ret=NULL;
                    ret=strdup(config->cmd[i]);
                    if(ret == NULL)
                        return(NULL);
                    return(ret);    
                }
            }
            i++;
        }
    }
    return(NULL);
}


/* OS_Execd v0.1: 2005/03/18
 */
int OS_Execd(execd_config *config, ExecdMsg *msg)
{
	char cmdexec[256];
	extern int errno;
	pid_t pid;
	
	memset(cmdexec,'\0',256);
	
	/* Forking and leaving it running */
	pid = fork();
	if(pid == 0)
    {
        /* Getting cmd to exec */
        char *exec = _getexec(config,msg->name);
        if(exec == NULL)
        {
            merror("%s: No command for exec name: %s",ARGV0,msg->name);
            exit(1);
        }
        /* Checking if the file exists */
        if(File_DateofChange(exec) < 0)
        {
            merror("File \"%s\" does not exist. Impossible to execute",exec);
            exit (1);
        }
        
        if(execv(exec,NULL) < 0)
        {
            merror("Error executing %s: %d -> %s\n",cmdexec,errno,strerror(errno));
            exit(1);
        }
        exit(0);
    }
	else
		return (0);
}
