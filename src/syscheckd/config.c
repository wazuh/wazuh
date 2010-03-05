/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "syscheck.h"
#include "config/config.h"

int Read_Syscheck_Config(char * cfgfile)
{
    int modules = 0;

    modules|= CSYSCHECK;

    syscheck.rootcheck = 0;
    syscheck.disabled = 0;
    syscheck.scan_on_start = 1;
    syscheck.time = SYSCHECK_WAIT * 2;
    syscheck.ignore = NULL;
    syscheck.ignore_regex = NULL;
    syscheck.scan_day = NULL;
    syscheck.scan_time = NULL;
    syscheck.dir = NULL;
    syscheck.opts = NULL;
    syscheck.realtime = NULL;
    #ifdef WIN32
    syscheck.registry = NULL;
    syscheck.reg_fp = NULL;
    #endif


    /* Reading config */
    if(ReadConfig(modules, cfgfile, &syscheck, NULL) < 0)
        return(OS_INVALID);


    #ifdef CLIENT
    /* Reading shared config */
    modules|= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &syscheck, NULL);
    #endif
              

    /* We must have at least one directory to check */
    if(!syscheck.dir || syscheck.dir[0] == NULL)
    {
        return(1);
    }
                                        

    return(0);
}
