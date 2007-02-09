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
#include "syscheck.h"
#include "config/config.h"

int Read_Syscheck_Config(char * cfgfile)
{
    int modules = 0;
    int i = 0;

    modules|= CSYSCHECK;

    syscheck.rootcheck = 0;
    syscheck.time = SYSCHECK_WAIT*2;
    syscheck.ignore = NULL;
    syscheck.ignore_regex = NULL;
    
    #ifdef WIN32
    syscheck.reg_fp = NULL;
    #endif


    /* Cleaning up the dirs */
    for(i = 0; i<= MAX_DIR_ENTRY; i++)
    {
        syscheck.dir[i] = NULL;
        syscheck.opts[i] = 0;

        #ifdef WIN32
        syscheck.registry[i] = NULL;
        #endif
    }


    /* Reading config */
    if(ReadConfig(modules, cfgfile, &syscheck, NULL) < 0)
        return(OS_INVALID);


    /* We must have at least one directory to check */
    if(syscheck.dir[0] == NULL)
    {
        merror(SK_NO_DIR, ARGV0);
        return(1);
    }
                                        

    return(0);
}
