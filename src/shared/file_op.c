/*      $OSSEC, file_op.c, v0.2, 2004/08/03, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS.
 * Available at http://www.ossec.net/hids/
 */

/* Functions to handle operation with files 
 */


#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <fcntl.h>

#include "headers/file_op.h"
#include "headers/defs.h"
#include "headers/debug_op.h"

#include "error_messages/error_messages.h"

int File_DateofChange(char *file)
{
    struct stat file_status;
    if(stat(file, &file_status) < 0)
        return(-1);

    return (file_status.st_mtime);
}

int IsDir(char *file)
{
    struct stat file_status;
    if(stat(file,&file_status) < 0)
        return(-1);
    if(S_ISDIR(file_status.st_mode))
        return(0);
    return(-1);
}


int CreatePID(char *name, int pid)
{
    char file[256];
    FILE *fp;
    
    if(isChroot())
    {
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,pid);
    }
    else
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,pid);
    }

    fp = fopen(file,"a");
    if(!fp)
        return(-1);
        
    fprintf(fp,"%d\n",pid);
    
    fclose(fp);
    
    return(0);
}

int DeletePID(char *name)
{
    char file[256];
    
    if(isChroot())
    {
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,(int)getpid());
    }
    else
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,(int)getpid());
    }

    if(File_DateofChange(file) < 0)
        return(-1);
    
    unlink(file);	
    
    return(0);
}

/* getuname; Get uname and returns a string with it.
 * Memory must be freed after use
 */
char *getuname()
{
    struct utsname uts_buf;

    if(uname(&uts_buf) == 0)
    {
        char *ret;

        ret = calloc(256, sizeof(char));
        if(ret == NULL)
            return(NULL);

        snprintf(ret, 255, "%s %s %s %s %s", 
                                 uts_buf.sysname,
                                 uts_buf.nodename,
                                 uts_buf.release,
                                 uts_buf.version,
                                 uts_buf.machine);

        return(ret);
    }

    return(NULL);
}

/* goDaemon: Daemonize a process..
 *
 */
void goDaemon()
{
    pid_t pid;

    pid = fork();

    if(pid < 0)
    {
        merror(FORK_ERROR, ARGV0);
        return;
    }
    else if(pid)
    {
        exit(0);
    }

    /* becoming session leader */
    if(setsid() < 0)
    {
        merror(SETSID_ERROR, ARGV0);
        return;
    }

    /* forking again */
    pid = fork();
    if(pid < 0)
    {
        merror(FORK_ERROR, ARGV0);
        return;
    }
    else if(pid)
    {
        exit(0);
    }

    /* Closing stdin, stdout and stderr */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);


    /* Openining stdin, stdout and stderr to dev null */
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    
    return;
}



/* EOF */
