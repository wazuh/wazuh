/* @(#) $Id: ./src/rootcheck/unix-process.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/main/license/ .
 */


#include "shared.h"
#include "rootcheck.h"

#ifndef WIN32

static char *_os_get_runps(const char *ps, int mpid)
{
    char *tmp_str, *nbuf;
    char buf[OS_SIZE_2048 +1];
    char command[OS_SIZE_1024 +1];
    FILE *fp;


    buf[0] = '\0';
    command[0] = '\0';
    command[OS_SIZE_1024] = '\0';


    snprintf(command, OS_SIZE_1024, "%s -p %d 2> /dev/null", ps, mpid);

    fp = popen(command, "r");
    if(fp)
    {
        while(fgets(buf, OS_SIZE_2048, fp) != NULL)
        {
            tmp_str = strchr(buf, ':');
            if(!tmp_str)
            {
                continue;
            }

            nbuf = tmp_str++;

            tmp_str = strchr(nbuf, ' ');
            if(!tmp_str)
            {
                continue;
            }
            tmp_str++;


            /* Removing white spaces. */
            while(*tmp_str == ' ')
                 tmp_str++;


            nbuf = tmp_str;


            tmp_str = strchr(nbuf, '\n');
            if(tmp_str)
            {
                *tmp_str = '\0';
            }

            pclose(fp);
            return(strdup(nbuf));
        }

        pclose(fp);
    }

    return(NULL);
}



/* os_get_unix_process_list: Get list of Unix processes */
OSList *os_get_process_list()
{
    int i = 1;
    pid_t max_pid = MAX_PID;
    OSList *p_list = NULL;

    char ps[OS_SIZE_1024 +1];


    /* Checking where ps is */
    memset(ps, '\0', OS_SIZE_1024 +1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if(!is_file(ps))
    {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if(!is_file(ps))
        {
            merror("%s: ERROR: 'ps' not found.", ARGV0);
            return(NULL);
        }
    }


    /* Creating process list */
    p_list = OSList_Create();
    if(!p_list)
    {
        merror(LIST_ERROR, ARGV0);
        return(NULL);
    }



    for(i = 1; i<= max_pid; i++)
    {
        /* Checking if the pid is present. */
        if((!((getsid(i) == -1)&&(errno == ESRCH))) &&
          (!((getpgid(i) == -1)&&(errno == ESRCH))))
         {
             Proc_Info *p_info;
             char *p_name;

             p_name = _os_get_runps(ps, (int)i);
             if(!p_name)
             {
                 continue;
             }

             os_calloc(1, sizeof(Proc_Info), p_info);
             p_info->p_path = p_name;
             p_info->p_name = NULL;
             OSList_AddData(p_list, p_info);
         }
    }

    return(p_list);
}


#endif

/* EOF */
