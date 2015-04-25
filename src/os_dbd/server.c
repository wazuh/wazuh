/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dbd.h"
#include "config/config.h"
#include "rules_op.h"

/* Prototypes */
static int __DBSelectServer(const char *server, const DBConfig *db_config) __attribute__((nonnull));
static int __DBInsertServer(const char *server, const char *info, const DBConfig *db_config) __attribute__((nonnull));

/* System hostname */
static char __shost[512];


/* Select the server ID from the db
 * Returns 0 if not found
 */
static int __DBSelectServer(const char *server, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id FROM "
             "server WHERE hostname = '%s'",
             server);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}

/* Inserts server in to the db */
static int __DBInsertServer(const char *server, const char *info, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Check if the server is present */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id from server where hostname = '%s'",
             server);

    /* If not present, insert */
    if (osdb_query_select(db_config->conn, sql_query) == 0) {
        snprintf(sql_query, OS_SIZE_1024 - 1,
                 "INSERT INTO "
                 "server(last_contact, version, hostname, information) "
                 "VALUES ('%u', '%s', '%s', '%s')",
                 (unsigned int)time(0), __version, server, info);

        if (!osdb_query_insert(db_config->conn, sql_query)) {
            merror(DB_GENERROR, ARGV0);
        }
    }

    /* If present, update it */
    else {
        snprintf(sql_query, OS_SIZE_1024 - 1,
                 "UPDATE server SET "
                 "last_contact='%u',version='%s',information='%s' "
                 "WHERE hostname = '%s'",
                 (unsigned int)time(0), __version, info, server);

        if (!osdb_query_insert(db_config->conn, sql_query)) {
            merror(DB_GENERROR, ARGV0);
        }
    }

    return (0);
}

/* Insert server info to the db
 * Returns server ID or 0 on error
 */
int OS_Server_ReadInsertDB(const DBConfig *db_config)
{
    int server_id = 0;
    char *info;

    debug1("%s: DEBUG: entering OS_Server_ReadInsertDB()", ARGV0);

    /* Get server hostname */
    memset(__shost, '\0', 512);
    if (gethostname(__shost, 512 - 1) != 0) {
        merror("%s: Error: gethostname() failed", ARGV0);
        return (0);
    }

    /* Get system uname */
    info = getuname();
    if (!info) {
        merror(MEM_ERROR, ARGV0, errno, strerror(errno));
        return (0);
    }

    /* Escape strings */
    osdb_escapestr(info);
    osdb_escapestr(__shost);

    /* Insert server */
    __DBInsertServer(__shost, info, db_config);

    /* Get server id */
    server_id = __DBSelectServer(__shost, db_config);

    free(info);

    return (server_id);
}

