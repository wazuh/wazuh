/* @(#) $Id: ./src/os_dbd/alert.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "dbd.h"
#include "config/config.h"
#include "rules_op.h"

static int __DBSelectLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));
static int __DBInsertLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));

/** int OS_SelectMaxID(DBConfig *db_config)
 * Selects the maximum ID from the alert table.
 * Returns 0 if not found.
 */
int OS_SelectMaxID(const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);


    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "SELECT MAX(id) FROM "
            "alert WHERE server_id = '%u'",
            db_config->server_id);


    /* Checking return code. */
    result = osdb_query_select(db_config->conn, sql_query);

    return(result);
}


/** int __DBSelectLocation(char *locaton, DBConfig *db_config)
 * Selects the location ID from the db.
 * Returns 0 if not found.
 */
static int __DBSelectLocation(const char *location, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);


    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "SELECT id FROM "
            "location WHERE name = '%s' AND server_id = '%d' "
            "LIMIT 1",
            location, db_config->server_id);


    /* Checking return code. */
    result = osdb_query_select(db_config->conn, sql_query);

    return(result);
}


/** int __DBInsertLocation(char *location, DBConfig *db_config)
 * Inserts location in to the db.
 */
static int __DBInsertLocation(const char *location, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "INSERT INTO "
            "location(server_id, name) "
            "VALUES ('%u', '%s')",
            db_config->server_id, location);


    /* Checking return code. */
    if(!osdb_query_insert(db_config->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }

    return(0);
}



/** int OS_Alert_InsertDB(DBConfig *db_config)
 * Insert alert into to the db.
 * Returns 1 on success or 0 on error.
 */
int OS_Alert_InsertDB(const alert_data *al_data, DBConfig *db_config)
{
    int i;
    unsigned int location_id = 0;
    unsigned short s_port = 0, d_port = 0;
    int *loc_id;
    char sql_query[OS_SIZE_8192 +1];
    char *fulllog = NULL;


    /* Clearing the memory before insert */
    sql_query[0] = '\0';
    sql_query[OS_SIZE_8192] = '\0';


    /* Source Port */
    s_port = al_data->srcport;

    /* Destination Port */
    d_port = al_data->dstport;


    /* Escaping strings */
    osdb_escapestr(al_data->user);


    /* We first need to insert the location */
    loc_id = (int *) OSHash_Get(db_config->location_hash, al_data->location);


    /* If we dont have location id, we must select and/or insert in the db */
    if(!loc_id)
    {
        location_id = __DBSelectLocation(al_data->location, db_config);
        if(location_id == 0)
        {
            /* Insert it */
            __DBInsertLocation(al_data->location, db_config);
            location_id = __DBSelectLocation(al_data->location, db_config);
        }

        if(!location_id)
        {
            merror("%s: Unable to insert location: '%s'.",
                   ARGV0, al_data->location);
            return(0);
        }


        /* Adding to hash */
        os_calloc(1, sizeof(int), loc_id);
        *loc_id = location_id;
        OSHash_Add(db_config->location_hash, al_data->location, loc_id);
    }


    i = 0;
    while(al_data->log[i])
    {
        size_t len = strlen(al_data->log[i]);
        char templog[len+2];
        if (al_data->log[i+1]) {
            snprintf(templog, len+2, "%s\n", al_data->log[i]);
        }
        else {
            snprintf(templog, len+1, "%s", al_data->log[i]);
        }
        fulllog = os_LoadString(fulllog, templog);
        i++;
    }

    if(fulllog == NULL)
    {
        merror("%s: Unable to process log.", ARGV0);
        return(0);
    }

    osdb_escapestr(fulllog);
    if(strlen(fulllog) >  7456)
    {
        fulllog[7454] = '.';
        fulllog[7455] = '.';
        fulllog[7456] = '\0';
    }


    /* Generating final SQL */
    snprintf(sql_query, OS_SIZE_8192,
            "INSERT INTO "
            "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,user,full_log) "
            "VALUES ('%u', '%u','%u','%u', '%u', '%s', '%u', '%s', '%u', '%s', '%s', '%s')",
            db_config->server_id, al_data->rule,
	    al_data->level,
            (unsigned int)time(0), *loc_id,
            al_data->srcip, (unsigned short)s_port,
            al_data->dstip, (unsigned short)d_port,
            al_data->alertid,
            al_data->user, fulllog);



    free(fulllog);
    fulllog = NULL;


    /* Inserting into the db */
    if(!osdb_query_insert(db_config->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }


    db_config->alert_id++;
    return(1);
}


/* EOF */
