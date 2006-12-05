/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include "shared.h"
#include "active-response.h"


/** void AR_Init()
 * Initializing active response.
 */
void AR_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();
    ar_flag = 0;

    if(!ar_commands || !active_responses)
    {
        ErrorExit(LIST_ERROR, ARGV0);
    }
}


/** int AR_ReadConfig(int test_config, char *cfgfile)
 * Reads active response configuration and write them
 * to the appropriate lists.
 */
int AR_ReadConfig(int test_config, char *cfgfile)
{
    FILE *fp;
    int modules = 0;

    modules|= CAR;


    /* Cleaning ar file */
    fp = fopen(DEFAULTARPATH, "w");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH);
        return(OS_INVALID);
    }
    fclose(fp);


    /* Setting right permission */
    chmod(DEFAULTARPATH, 0444);


    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, ar_commands, active_responses) < 0)
    {
        return(OS_INVALID);
    }


    return(0);
}

/* EOF */
