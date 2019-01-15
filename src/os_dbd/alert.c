/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dbd.h"
#include "config/config.h"
#include "config/dbd-config.h"
#include "rules_op.h"

/* Prototypes */
static int __DBSelectLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));
static int __DBInsertLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));


/* Select the maximum ID from the alert table
 * Returns 0 if not found
 */
int OS_SelectMaxID(const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT MAX(id) FROM "
             "alert WHERE server_id = '%u'",
             db_config->server_id);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}


/* Select the location ID from the db
 * Returns 0 if not found
 */
static int __DBSelectLocation(const char *location, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id FROM "
             "location WHERE name = '%s' AND server_id = '%d' "
             "LIMIT 1",
             location, db_config->server_id);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}

/* Insert location in to the db */
static int __DBInsertLocation(const char *location, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "INSERT INTO "
             "location(server_id, name) "
             "VALUES ('%u', '%s')",
             db_config->server_id, location);

    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR);
    }

    return (0);
}

/* Insert alert into to the db
 * Returns 1 on success or 0 on error
 */
int OS_Alert_InsertDB(const alert_data *al_data, DBConfig *db_config)
{
    int i;
    unsigned int s_ip = 0, d_ip = 0, location_id = 0;
    unsigned short s_port = 0, d_port = 0;
    int *loc_id;
    char sql_query[OS_SIZE_8192 + 1];
    char *fulllog = NULL;
    char user[OS_SIZE_128];

    /* Clear the memory before insert */
    sql_query[0] = '\0';
    sql_query[OS_SIZE_8192] = '\0';

    /* Converting srcip to int */
    if(al_data->srcip) {
        struct in_addr net;

        /* Extracting ip address */
        if(inet_aton(al_data->srcip, &net)) {
            s_ip = net.s_addr;
        }
    }

    /* Converting dstip to int */
    if(al_data->dstip) {
        struct in_addr net;

        /* Extracting ip address */
        if(inet_aton(al_data->dstip, &net)) {
            d_ip = net.s_addr;
        }
    }


    /* Source Port */
    s_port = al_data->srcport;

    /* Destination Port */
    d_port = al_data->dstport;

    /* Escape strings */
    osdb_escapestr(al_data->user);
    osdb_escapestr(al_data->location);

    if (!al_data->user) {
        snprintf(user, OS_SIZE_128, "NULL");
    } else {
        snprintf(user, OS_SIZE_128, "'%s'", al_data->user);
    }


    /* We first need to insert the location */
    loc_id = (int *) OSHash_Get(db_config->location_hash, al_data->location);

    /* If we dont have location id, we must select and/or insert in the db */
    if (!loc_id) {
        location_id = __DBSelectLocation(al_data->location, db_config);
        if (location_id == 0) {
            /* Insert it */
            __DBInsertLocation(al_data->location, db_config);
            location_id = __DBSelectLocation(al_data->location, db_config);
        }

        if (!location_id) {
            merror("Unable to insert location: '%s'.", al_data->location);
            return (0);
        }

        /* Add to hash */
        os_calloc(1, sizeof(int), loc_id);
        *loc_id = location_id;
        OSHash_Add(db_config->location_hash, al_data->location, loc_id);
    }

    i = 0;
    while (al_data->log[i]) {
        size_t len = strlen(al_data->log[i]);
        char templog[len + 2];
        if (al_data->log[i + 1]) {
            snprintf(templog, len + 2, "%s\n", al_data->log[i]);
        } else {
            snprintf(templog, len + 1, "%s", al_data->log[i]);
        }
        fulllog = os_LoadString(fulllog, templog);
        i++;
    }

    if (fulllog == NULL) {
        merror("Unable to process log.");
        return (0);
    }

    osdb_escapestr(fulllog);
    if (strlen(fulllog) >  7456) {
        fulllog[7454] = '.';
        fulllog[7455] = '.';
        fulllog[7456] = '\0';
    }

    /* Generate final SQL */
    switch (db_config->db_type) {
      case MYSQLDB:
        snprintf(sql_query, OS_SIZE_8192,
                 "INSERT INTO "
                 "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,user,full_log,tld) "
                 "VALUES ('%u', '%u','%u','%u', '%u', '%lu', '%u', '%lu', '%u', '%s', %s, '%s','%.2s')",
                 db_config->server_id, al_data->rule,
                 al_data->level,
                 (unsigned int)time(0), *loc_id,
                 (unsigned long)ntohl(s_ip), (unsigned short)s_port,
                 (unsigned long)ntohl(d_ip), (unsigned short)d_port,
                 al_data->alertid,
                 user, fulllog, al_data->srcgeoip);
	break;

      case POSTGDB:
        snprintf(sql_query, OS_SIZE_8192,
                 "INSERT INTO "
                 "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,\"user\",full_log) "
                 "VALUES ('%u', '%u','%u','%u', '%u', '%s', '%u', '%s', '%u', '%s', %s, '%s')",
                 db_config->server_id, al_data->rule,
                 al_data->level,
                 (unsigned int)time(0), *loc_id,
                 al_data->srcip, (unsigned short)s_port,
                 al_data->dstip, (unsigned short)d_port,
                 al_data->alertid,
                 user, fulllog);
	break;
    }

    free(fulllog);
    fulllog = NULL;

    /* Insert into the db */
    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR);
    }

    db_config->alert_id++;
    return (1);
}
