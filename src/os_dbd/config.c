/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "dbd.h"
#include "config/global-config.h"
#include "config/config.h"


int OS_ReadDBConf(int test_config, char *cfgfile, DBConfig *db_config)
{
    int modules = 0;
    _Config *tmp_config;


    /* Modules for the configuration */
    modules|= CDBD;
    modules|= CRULES;

    
    /* Allocating config just to get the rules. */
    os_calloc(1, sizeof(_Config), tmp_config);


    /* Clearing configuration variables */
    tmp_config->includes = NULL;
    db_config->includes = NULL;
    db_config->host = NULL;
    db_config->user = NULL;
    db_config->pass = NULL;
    db_config->db = NULL;


    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, tmp_config, db_config) < 0)
        return(OS_INVALID);

    
    /* Here, we assign the rules to db_config and free the rest
     * of the Config.
     */
    db_config->includes = tmp_config->includes;
    free(tmp_config);


    /* Checking for a valid config. */
    if(!db_config->host ||
       !db_config->user ||
       !db_config->pass ||
       !db_config->db)
    {
        merror(DB_MISS_CONFIG, ARGV0);
        return(OS_INVALID);
    }
                                        
    
    return(0);
}

/* EOF */
