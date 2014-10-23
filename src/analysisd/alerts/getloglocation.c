/* @(#) $Id: ./src/analysisd/alerts/getloglocation.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Get the log directory/file based on the day/month/year */


/* analysisd headers */
#include "getloglocation.h"

int __crt_day;
char __elogfile[OS_FLSIZE+1];
char __alogfile[OS_FLSIZE+1];
char __flogfile[OS_FLSIZE+1];

/* OS_InitLog */
void OS_InitLog()
{
    OS_InitFwLog();

    __crt_day = 0;

    /* alerts and events log file */
    memset(__alogfile,'\0',OS_FLSIZE +1);
    memset(__elogfile,'\0',OS_FLSIZE +1);
    memset(__flogfile,'\0',OS_FLSIZE +1);

    _eflog = NULL;
    _aflog = NULL;
    _fflog = NULL;

    /* Setting the umask */
    umask(0027);
}


/* gzips a log file
int OS_CompressLog(int yesterday, char *prev_month, int prev_year)

  -- moved to monitord.
*/




/* OS_GetLogLocation: v0.1, 2005/04/25 */
int OS_GetLogLocation(Eventinfo *lf)
{
    /* Checking what directories to create
     * Checking if the year directory is there.
     * If not, create it. Same for the month directory.
     */

    /* For the events */
    if(_eflog)
    {
        if(ftell(_eflog) == 0)
            unlink(__elogfile);
        fclose(_eflog);
        _eflog = NULL;
    }

    snprintf(__elogfile,OS_FLSIZE,"%s/%d/", EVENTS, lf->year);
    if(IsDir(__elogfile) == -1)
        if(mkdir(__elogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__elogfile, errno, strerror(errno));
        }

    snprintf(__elogfile,OS_FLSIZE,"%s/%d/%s", EVENTS, lf->year,lf->mon);

    if(IsDir(__elogfile) == -1)
        if(mkdir(__elogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__elogfile, errno, strerror(errno));
        }


    /* Creating the logfile name */
    snprintf(__elogfile,OS_FLSIZE,"%s/%d/%s/ossec-%s-%02d.log",
            EVENTS,
            lf->year,
            lf->mon,
            "archive",
            lf->day);


    _eflog = fopen(__elogfile,"a");
    if(!_eflog)
        ErrorExit("%s: Error opening logfile: '%s'",ARGV0,__elogfile);

    /* Creating a symlink */
    unlink(EVENTS_DAILY);

    if(link(__elogfile, EVENTS_DAILY) == -1)
    {
        ErrorExit(LINK_ERROR, ARGV0, __elogfile, EVENTS_DAILY, errno, strerror(errno));
    }


    /* for the alerts logs */
    if(_aflog)
    {
        if(ftell(_aflog) == 0)
            unlink(__alogfile);
        fclose(_aflog);
        _aflog = NULL;
    }

    snprintf(__alogfile,OS_FLSIZE,"%s/%d/", ALERTS, lf->year);
    if(IsDir(__alogfile) == -1)
        if(mkdir(__alogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__alogfile, errno, strerror(errno));
        }

    snprintf(__alogfile,OS_FLSIZE,"%s/%d/%s", ALERTS, lf->year,lf->mon);

    if(IsDir(__alogfile) == -1)
        if(mkdir(__alogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__alogfile, errno, strerror(errno));
        }


    /* Creating the logfile name */
    snprintf(__alogfile,OS_FLSIZE,"%s/%d/%s/ossec-%s-%02d.log",
            ALERTS,
            lf->year,
            lf->mon,
            "alerts",
            lf->day);

    _aflog = fopen(__alogfile,"a");

    if(!_aflog)
        ErrorExit("%s: Error opening logfile: '%s'",ARGV0,__alogfile);

    /* Creating a symlink */
    unlink(ALERTS_DAILY);

    if(link(__alogfile, ALERTS_DAILY) == -1)
    {
        ErrorExit(LINK_ERROR, ARGV0, __alogfile, ALERTS_DAILY, errno, strerror(errno));
    }


    /* For the firewall events */
    if(_fflog)
    {
        if(ftell(_fflog) == 0)
            unlink(__flogfile);
        fclose(_fflog);
        _fflog = NULL;
    }

    snprintf(__flogfile,OS_FLSIZE,"%s/%d/", FWLOGS, lf->year);
    if(IsDir(__flogfile) == -1)
        if(mkdir(__flogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__flogfile, errno, strerror(errno));
        }

    snprintf(__flogfile,OS_FLSIZE,"%s/%d/%s", FWLOGS, lf->year,lf->mon);

    if(IsDir(__flogfile) == -1)
        if(mkdir(__flogfile,0770) == -1)
        {
            ErrorExit(MKDIR_ERROR,ARGV0,__flogfile, errno, strerror(errno));
        }


    /* Creating the logfile name */
    snprintf(__flogfile,OS_FLSIZE,"%s/%d/%s/ossec-%s-%02d.log",
            FWLOGS,
            lf->year,
            lf->mon,
            "firewall",
            lf->day);

    _fflog = fopen(__flogfile,"a");

    if(!_fflog)
        ErrorExit("%s: Error opening logfile: '%s'",ARGV0,__flogfile);


    /* Creating a symlink */
    unlink(FWLOGS_DAILY);

    if(link(__flogfile, FWLOGS_DAILY) == -1)
    {
        ErrorExit(LINK_ERROR, ARGV0, __flogfile, FWLOGS_DAILY, errno, strerror(errno));
    }


    /* Setting the new day */
    __crt_day = lf->day;

    return(0);
}

/* EOF */
