/* Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "integrator.h"
#include "config/global-config.h"
#include "config/config.h"

void **OS_ReadIntegratorConf(char *cfgfile, IntegratorConfig ***integrator_config)
{
    int modules = 0;

    /* Modules for the configuration */
    modules |= CINTEGRATORD;

    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, integrator_config, NULL) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfgfile);
        return(NULL);
    }

    return (void**)*integrator_config;
}
