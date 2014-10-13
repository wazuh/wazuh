/* @(#) $Id: ./src/rootcheck/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef OSSECHIDS
#include "shared.h"
#include "rootcheck.h"
#include "config/config.h"



/* Read_Rootcheck_Config: Reads the rootcheck config
 */
int Read_Rootcheck_Config(const char * cfgfile)
{
    int modules = 0;

    modules|= CROOTCHECK;

    if(ReadConfig(modules, cfgfile, &rootcheck, NULL) < 0)
        return(OS_INVALID);


    #ifdef CLIENT
    /* Reading shared config */
    modules|= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &rootcheck, NULL);
    #endif

    return(0);
}

/* EOF */
#endif
