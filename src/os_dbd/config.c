/* @(#) $Id: ./src/os_dbd/config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "dbd.h"
#include "config/global-config.h"
#include "config/config.h"


/** int OS_ReadDBConf(int test_config, char *cfgfile, DBConfig *db_config)
 * Reads database configuration.
 */
int OS_ReadDBConf(__attribute__((unused)) int test_config, const char *cfgfile, DBConfig *db_config)
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
    db_config->port = 0;
    db_config->sock = NULL;
    db_config->db_type = 0;
    db_config->maxreconnect = 0;


    /* Reading configuration */
    if(ReadConfig(modules, cfgfile, tmp_config, db_config) < 0)
        return(OS_INVALID);


    /* Here, we assign the rules to db_config and free the rest
     * of the Config.
     */
    db_config->includes = tmp_config->includes;
    free(tmp_config);


    /* Checking if dbd isn't supposed to run. */
    if(!db_config->host &&
       !db_config->user &&
       !db_config->pass &&
       !db_config->db &&
       !db_config->sock &&
       !db_config->port &&
       !db_config->db_type)
    {
        return(0);
    }


    /* Checking for a valid config. */
    if(!db_config->host ||
       !db_config->user ||
       !db_config->pass ||
       !db_config->db ||
       !db_config->db_type)
    {
        merror(DB_MISS_CONFIG, ARGV0);
        return(OS_INVALID);
    }

    osdb_connect = NULL;

    /* Assigning the proper location for the function calls */
    #ifdef MYSQL_DATABASE_ENABLED
    if(db_config->db_type == MYSQLDB)
    {
        osdb_connect = mysql_osdb_connect;
        osdb_query_insert = mysql_osdb_query_insert;
        osdb_query_select = mysql_osdb_query_select;
        osdb_close = mysql_osdb_close;
    }
    #endif

    #ifdef PGSQL_DATABASE_ENABLED
    if(db_config->db_type == POSTGDB)
    {
        osdb_connect = postgresql_osdb_connect;
        osdb_query_insert = postgresql_osdb_query_insert;
        osdb_query_select = postgresql_osdb_query_select;
        osdb_close = postgresql_osdb_close;
    }
    #endif



    /* Checking for config errros (moving from config.c).
     */
    if(db_config->db_type == MYSQLDB)
    {
        #ifndef MYSQL_DATABASE_ENABLED
        merror(DB_COMPILED, ARGV0, "mysql");
        return(OS_INVALID);
        #endif
    }
    else if(db_config->db_type == POSTGDB)
    {
        #ifndef PGSQL_DATABASE_ENABLED
        merror(DB_COMPILED, ARGV0, "postgresql");
        return(OS_INVALID);
        #endif
    }


    if(osdb_connect == NULL)
    {
        merror("%s: Invalid DB configuration (Internal error?). ", ARGV0);
        return(OS_INVALID);
    }

    return(1);
}

/* EOF */
