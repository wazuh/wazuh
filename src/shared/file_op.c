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


#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "headers/file_op.h"
#include "headers/defs.h"

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
    
    /* Must be defined on the main file */
    extern short int chroot_flag;
    
    if(chroot_flag == 0)
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,pid);
    }
    else
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,pid);

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
    
    extern short int chroot_flag;
    
    if(chroot_flag == 0)
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,(int)getpid());
    }
    else
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,(int)getpid());

    if(File_DateofChange(file) < 0)
        return(-1);
    
    unlink(file);	
    
    return(0);
}

/* EOF */
