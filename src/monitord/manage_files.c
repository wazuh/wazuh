/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */


#include "shared.h"
#include "monitord.h"

char *(months[])={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug",
                  "Sep","Oct","Nov","Dec"};


/* OS_GetLogLocation: v0.1, 2005/04/25 */
void manage_files(int cday, int cmon, int cyear)
{
    time_t tm_old;
    struct tm *p_old;
            
    char elogfile[OS_FLSIZE +1];
    char elogfile_old[OS_FLSIZE +1];
    
    char alogfile[OS_FLSIZE +1];
    char alogfile_old[OS_FLSIZE +1];
    
    char flogfile[OS_FLSIZE +1];
    char flogfile_old[OS_FLSIZE +1];


    /* Getting time from the day before (for log signing) */
    tm_old = time(NULL) - 90000;
    p_old = localtime(&tm_old);
    

    memset(elogfile, '\0', OS_FLSIZE +1);
    memset(elogfile_old, '\0', OS_FLSIZE +1);
    memset(alogfile, '\0', OS_FLSIZE +1);
    memset(alogfile_old, '\0', OS_FLSIZE +1);
    memset(flogfile, '\0', OS_FLSIZE +1);
    memset(flogfile_old, '\0', OS_FLSIZE +1);


    /* When the day changes, we wait up to day_wait
     * before compressing the file.
     */
    sleep(mond.day_wait);
    

    /* Event logfile */
    snprintf(elogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            EVENTS,
            cyear,
            months[cmon],
            "archive",
            cday);
    /* Event log file old */
    snprintf(elogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            EVENTS,
            p_old->tm_year+1900,
            months[p_old->tm_mon],
            "archive",
            p_old->tm_mday);

    OS_SignLog(elogfile, elogfile_old);
    OS_CompressLog(elogfile);


    /* alert logfile  */
    snprintf(alogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            ALERTS,
            cyear,
            months[cmon],
            "alerts",
            cday);
    /* alert logfile old  */ 
    snprintf(alogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            ALERTS,
            p_old->tm_year+1900,
            months[p_old->tm_mon],
            "alerts",
            p_old->tm_mday);
    OS_SignLog(alogfile, alogfile_old);
    OS_CompressLog(alogfile);


    /* firewall events */
    snprintf(flogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            FWLOGS,
            cyear,
            months[cmon],
            "firewall",
            cday);
    /* firewall events old */
    snprintf(flogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            FWLOGS,
            p_old->tm_year+1900,
            months[p_old->tm_mon],
            "firewall",
            p_old->tm_mday);
    OS_SignLog(flogfile, flogfile_old);
    OS_CompressLog(flogfile);

    return;
}

/* EOF */
