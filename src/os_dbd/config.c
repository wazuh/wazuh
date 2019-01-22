/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbd.h"
#include "config/global-config.h"
#include "config/config.h"


/* Read database configuration */
int OS_ReadDBConf(__attribute__((unused)) int test_config, const char *cfgfile, DBConfig *db_config)
{
    int modules = 0;
    _Config *tmp_config;

    /* Modules for the configuration */
    modules |= CDBD;
    modules |= CRULES;

    /* Allocate config just to get the rules */
    os_calloc(1, sizeof(_Config), tmp_config);

    /* Clear configuration variables */
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

    /* Read configuration */
    if (ReadConfig(modules, cfgfile, tmp_config, db_config) < 0) {
        free(tmp_config);
        return (OS_INVALID);
    }

    /* Assign the rules to db_config and free the rest of the Config */
    db_config->includes = tmp_config->includes;
    free(tmp_config);

    /* Check if dbd isn't supposed to run */
    if (!db_config->host &&
            !db_config->user &&
            !db_config->pass &&
            !db_config->db &&
            !db_config->sock &&
            !db_config->port &&
            !db_config->db_type) {
        return (0);
    }

    /* Check for a valid config */
    if (!db_config->host ||
            !db_config->user ||
            !db_config->pass ||
            !db_config->db ||
            !db_config->db_type) {
        merror(DB_MISS_CONFIG);
        return (OS_INVALID);
    }

    osdb_connect = NULL;

    /* Assign the proper location for the function calls */

#ifdef MYSQL_DATABASE_ENABLED
    if (db_config->db_type == MYSQLDB) {
        osdb_connect = mysql_osdb_connect;
        osdb_query_insert = mysql_osdb_query_insert;
        osdb_query_select = mysql_osdb_query_select;
        osdb_close = mysql_osdb_close;
    }
#endif

#ifdef PGSQL_DATABASE_ENABLED
    if (db_config->db_type == POSTGDB) {
        osdb_connect = postgresql_osdb_connect;
        osdb_query_insert = postgresql_osdb_query_insert;
        osdb_query_select = postgresql_osdb_query_select;
        osdb_close = postgresql_osdb_close;
    }
#endif

    /* Check for config errors */
    if (db_config->db_type == MYSQLDB) {
#ifndef MYSQL_DATABASE_ENABLED
        merror(DB_COMPILED, "mysql");
        return (OS_INVALID);
#endif
    } else if (db_config->db_type == POSTGDB) {
#ifndef PGSQL_DATABASE_ENABLED
        merror(DB_COMPILED, "postgresql");
        return (OS_INVALID);
#endif
    }

    if (osdb_connect == NULL) {
        merror("Invalid DB configuration (Internal error?). ");
        return (OS_INVALID);
    }

    return (1);
}
