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
                  "Sept","Oct","Nov","Dec"};


/* OS_GetLogLocation: v0.1, 2005/04/25 */
void manage_files(int cday, int cmon, int cyear)
{
    char elogfile[OS_FLSIZE +1];
    char alogfile[OS_FLSIZE +1];
    char flogfile[OS_FLSIZE +1];


    memset(elogfile, '\0', OS_FLSIZE +1);
    memset(alogfile, '\0', OS_FLSIZE +1);
    memset(flogfile, '\0', OS_FLSIZE +1);


    /* When the day changes, we wait up to day_wait
     * before compressing the file.
     */
    sleep(mond.day_wait);

    /* event logfile */
    snprintf(elogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            EVENTS,
            cyear,
            months[cmon],
            "archive",
            cday);
    OS_CompressLog(elogfile);

    /* alert logfile  */
    snprintf(alogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            ALERTS,
            cyear,
            months[cmon],
            "alerts",
            cday);
    OS_CompressLog(alogfile);

    /* firewall events */
    snprintf(flogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
            FWLOGS,
            cyear,
            months[cmon],
            "firewall",
            cday);
    OS_CompressLog(flogfile);

    return;
}

/* EOF */
