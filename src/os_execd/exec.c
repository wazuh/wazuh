/* @(#) $Id: ./src/os_execd/exec.c, 2011/09/08 dcid Exp $
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
#include "os_regex/os_regex.h"
#include "execd.h"

static char exec_names[MAX_AR +1][OS_FLSIZE +1];
static char exec_cmd[MAX_AR +1][OS_FLSIZE +1];
static int  exec_timeout[MAX_AR +1];
static int  exec_size = 0;
static int  f_time_reading = 1;


/** int ReadExecConfig() v0.1:
 * Reads the shared exec config.
 * Returns 1 on success or 0 on failure.
 * Format of the file is 'name - command - timeout'
 */
int ReadExecConfig()
{
    int i = 0, j = 0, dup_entry = 0;
    FILE *fp;
    FILE *process_file;
    char buffer[OS_MAXSTR +1];

    /* Cleaning up */
    for(i = 0;i <= exec_size+1; i++)
    {
        memset(exec_names[i], '\0', OS_FLSIZE +1);
        memset(exec_cmd[i], '\0', OS_FLSIZE +1);
        exec_timeout[i] = 0;
    }
    exec_size = 0;


    /* Opening file */
    fp = fopen(DEFAULTARPATH, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return(0);
    }


    /* Reading config */
    while(fgets(buffer, OS_MAXSTR, fp) != NULL)
    {
        char *str_pt;
        char *tmp_str;

        str_pt = buffer;

        /* Cleaning up the buffer */
        tmp_str = strchr(buffer, ' ');
        if(!tmp_str)
        {
            merror(EXEC_INV_CONF, ARGV0, DEFAULTARPATH);
            continue;
        }
        *tmp_str = '\0';
        tmp_str++;


        /* Searching for ' ' and - */
        if(*tmp_str == '-')
        {
            tmp_str+=2;
        }
        else
        {
            merror(EXEC_INV_CONF, ARGV0, DEFAULTARPATH);
            continue;
        }



        /* Setting the name */
        strncpy(exec_names[exec_size], str_pt, OS_FLSIZE);
        exec_names[exec_size][OS_FLSIZE] = '\0';


        str_pt = tmp_str;

        tmp_str = strchr(tmp_str, ' ');
        if(!tmp_str)
        {
            merror(EXEC_INV_CONF, ARGV0, DEFAULTARPATH);
            continue;
        }
        *tmp_str = '\0';


        /* Writting the full command path */
        snprintf(exec_cmd[exec_size], OS_FLSIZE,
                                      "%s/%s",
                                      AR_BINDIRPATH,
                                      str_pt);
        process_file = fopen(exec_cmd[exec_size], "r");
        if(!process_file)
        {
            if(f_time_reading)
            {
                verbose("%s: INFO: Active response command not present: '%s'. "
                        "Not using it on this system.",
                        ARGV0, exec_cmd[exec_size]);
            }

            exec_cmd[exec_size][0] = '\0';
        }
        else
        {
            fclose(process_file);
        }


        /* Searching for ' ' and - */
        tmp_str++;
        if(*tmp_str == '-')
        {
            tmp_str+=2;
        }
        else
        {
            merror(EXEC_INV_CONF, ARGV0, DEFAULTARPATH);
            continue;
        }


        str_pt = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
        if(tmp_str)
            *tmp_str = '\0';


        /* Getting the exec timeout */
        exec_timeout[exec_size] = atoi(str_pt);


        /* Checking if name is duplicated. */
        dup_entry = 0;
        for(j = 0; j< exec_size; j++)
        {
            if(strcmp(exec_names[j], exec_names[exec_size]) == 0)
            {
                if(exec_cmd[j][0] == '\0')
                {
                    strncpy(exec_cmd[j], exec_cmd[exec_size], OS_FLSIZE);
                    exec_cmd[j][OS_FLSIZE] = '\0';
                    dup_entry = 1;
                    break;
                }
                else if(exec_cmd[exec_size][0] == '\0')
                {
                    dup_entry = 1;
                }
            }
        }

        if(dup_entry)
        {
            exec_cmd[exec_size][0] = '\0';
            exec_names[exec_size][0] = '\0';
            exec_timeout[exec_size] = 0;
        }
        else
        {
            exec_size++;
        }
    }

    fclose(fp);
    f_time_reading = 0;

    return(1);
}



/** char *GetCommandbyName(char *name, int *timeout) v0.2
 * Returns a pointer to the command name (full path)
 * Returns NULL if name cannot be found
 * If timeout is not NULL, write the timeout for that
 * command to it.
 */
char *GetCommandbyName(const char *name, int *timeout)
{
    int i = 0;

    for(;i < exec_size; i++)
    {
        if(strcmp(name, exec_names[i]) == 0)
        {
            *timeout = exec_timeout[i];
            return(exec_cmd[i]);
        }
    }

    return(NULL);
}

#ifndef WIN32
/** void ExecCmd(char **cmd, char *extra_data) v0.1
 * Execute command given. Must be a argv** NULL terminated.
 * Void. Prints error to log message in case of problems.
 */
void ExecCmd(char *const *cmd)
{

    pid_t pid;


    /* Forking and leaving it running */
    pid = fork();
    if(pid == 0)
    {
        if(execv(*cmd, cmd) < 0)
        {
            merror(EXEC_CMDERROR, ARGV0, *cmd, strerror(errno));
            exit(1);
        }

        exit(0);
    }

    return;
}

#else

void ExecCmd_Win32(char *cmd)
{
    /* Windows code now. */

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                      &si, &pi))
    {
        merror("%s: ERROR: Unable to create active response process. ", ARGV0);
        return;
    }


    /* Wait until process exits. */
    WaitForSingleObject(pi.hProcess, INFINITE );

    /* Close process and thread */
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );

    return;
}
#endif

/* EOF */
