/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3 (2005/08/23): Using the new OS_XML syntax and changing some usage 
 * v0.2 (2005/01/17)
 */
 

#include "shared.h" 

#include "logcollector.h"


/* LogCollectorConfig v0.3, 2005/03/03
 * Read the config file (the localfiles)
 * v0.3: Changed for the new OS_XML
 */
int LogCollectorConfig(char * cfgfile)
{
    int modules = 0;

    logreader_config log_config;

    modules|= CLOCALFILE;

    log_config.config = NULL;
    log_config.agent_cfg = 0;

    if(ReadConfig(modules, cfgfile, &log_config, NULL) < 0)
        return(OS_INVALID);
    
    #ifdef CLIENT
    modules|= CAGENT_CONFIG;
    log_config.agent_cfg = 1;
    ReadConfig(modules, AGENTCONFIG, &log_config, NULL);
    log_config.agent_cfg = 0;
    #endif

    logff = log_config.config;       

    return(1);


}

/* EOF */
