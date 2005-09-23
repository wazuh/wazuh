/*      $OSSEC, debug_op.c, v0.2, 2004/08/02, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

/* Functions to generate debug/verbose/error messages.
 * Right now, we have two debug levels: 1,2,
 * a verbose mode and a error (merror) function.
 * To see these messages, use the "-d","-v" options
 * (or "-d" twice to see debug2). The merror is printed
 * by default when an important error occur.
 * 
 */

extern short int dbg_flag;
extern short int chroot_flag;
short int log_flag;

/* For internal logs */
#ifndef LOGFILE
   #define LOGFILE   "/logs/ossec.log"
#endif

/* _log function */
void _log(const char * msg,va_list args)
{
    time_t tm;
    struct tm *p;
    tm = time(NULL);
    p = localtime(&tm);

    if(log_flag == 1)
    {
        FILE *fp;

        /* If under chroot, log directly to /logs/ossec.log */
        if(chroot_flag == 1)
            fp = fopen(LOGFILE,"a");
        else
        {
            char _logfile[128];
            memset(_logfile,'\0',128);
            snprintf(_logfile,127,"%s%s",DEFAULTDIR,LOGFILE);
            fp = fopen(_logfile, "a");
        }
        	
        if(fp)
        {
            (void)fprintf(fp,"%d/%02d/%02d %02d:%02d:%02d ",
                          p->tm_year+1900,p->tm_mon+1, 
                          p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
            (void)vfprintf(fp, msg, args);
            (void)fprintf(fp, "\n");
            fclose(fp);
        }
    }
    
    /* Print to stderr */		
    (void)fprintf(stderr,"%d/%02d/%02d %02d:%02d:%02d ",
                  p->tm_year+1900,p->tm_mon+1 ,p->tm_mday,
                  p->tm_hour,p->tm_min,p->tm_sec);
    (void)vfprintf(stderr, msg, args);
    (void)fprintf(stderr, "\n");
}


void debug1(const char * msg,...)
{
    if(dbg_flag >= 1)
    {
        va_list args;
        log_flag=0;
        va_start(args, msg);

        _log(msg, args);

        va_end(args);
    }
}

void debug2(const char * msg,...)
{
    if(dbg_flag >= 2)
    {
        va_list args;
        log_flag=0;
        va_start(args, msg);
        _log(msg, args);
        va_end(args);
    }
}

void merror(const char * msg,... )
{
    va_list args;
    log_flag=1;
    va_start(args, msg);
    _log(msg, args);
    va_end(args);
}

void verbose(const char * msg,... )
{
    va_list args;
    log_flag=0;
    va_start(args, msg);
    _log(msg, args);
    va_end(args);
}

void ErrorExit(const char *msg, ...)
{
    va_list args;
    log_flag=1;
    va_start(args, msg);
    _log(msg, args);
    va_end(args);
    exit(1);
}

/* EOF */			
