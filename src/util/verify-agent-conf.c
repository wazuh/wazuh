/* @(#) $Id$ */

/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"
#include "logcollector/logcollector.h"


#undef ARGV0
#define ARGV0 "verify-agent-conf"



/* main: v0.3: 2005/04/04 */
int main(int argc, char **argv)
{
    int modules = 0;
    logreader_config log_config;


    /* Setting the name */
    OS_SetName(ARGV0);
        

    modules|= CLOCALFILE;
    modules|= CAGENT_CONFIG;
    log_config.config = NULL;
    if(ReadConfig(modules, AGENTCONFIG, &log_config, NULL) < 0)
    {
        return(OS_INVALID);
    }

    logff = log_config.config;       

    return(0);


}

/* EOF */
