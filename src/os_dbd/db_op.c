/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common lib for dealing with databases */

#include "dbd.h"

/* Prototypes */
void *(*osdb_connect)(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
int (* osdb_query_insert)(void *db_conn, const char *query);
int (* osdb_query_select)(void *db_conn, const char *query);
void *(*osdb_close)(void *db_conn);
const unsigned char insert_map[256] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
};

#ifdef MYSQL_DATABASE_ENABLED
#include <mysql.h>
#endif

#ifdef PGSQL_DATABASE_ENABLED
#include <libpq-fe.h>
#endif

#if defined(MYSQL_DATABASE_ENABLED) || defined(PGSQL_DATABASE_ENABLED)
static void osdb_checkerror(void);
static void osdb_seterror(void);
#endif

/* Config pointer */
static DBConfig *db_config_pt = NULL;


/* Escapes a null terminated string before inserting into the database
 * We built a white list of allowed characters at insert_map. Everything
 * not allowed will become a space.
 */
void osdb_escapestr(char *str)
{
    if (!str) {
        return;
    }

    while (*str) {
        if (*str == '\'') {
            *str = '`';
        } else if (*str == '\\') {
            *str = '/';
        } else if (insert_map[(unsigned char)*str] != '\001') {
            *str = ' ';
        }
        str++;
    }

    /* It can not end with \\ */
    if (*(str - 1) == '\\') {
        *(str - 1) = '\0';
    }
}

#if defined(MYSQL_DATABASE_ENABLED) || defined(PGSQL_DATABASE_ENABLED)

/* Check for errors and handle them appropriately */
static void osdb_checkerror()
{
    if (!db_config_pt || db_config_pt->error_count > 20) {
        ErrorExit(DB_MAINERROR, ARGV0);
    }

    /* If error count is too large, we try to reconnect */
    if (db_config_pt->error_count > 0) {
        unsigned int i = 0, sleep_time = 2;

        if (db_config_pt->conn) {
            osdb_close(db_config_pt->conn);
            db_config_pt->conn = NULL;
        }

        while (i <= db_config_pt->maxreconnect) {
            merror(DB_ATTEMPT, ARGV0);
            db_config_pt->conn = osdb_connect(db_config_pt->host,
                                              db_config_pt->user,
                                              db_config_pt->pass,
                                              db_config_pt->db,
                                              db_config_pt->port,
                                              db_config_pt->sock);

            /* If we were able to reconnect, keep going */
            if (db_config_pt->conn) {
                break;
            }
            sleep(sleep_time);
            sleep_time *= 2;
            i++;
        }

        /* If we weren't able to connect, exit */
        if (!db_config_pt->conn) {
            ErrorExit(DB_MAINERROR, ARGV0);
        }

        verbose("%s: Connected to database '%s' at '%s'.",
                ARGV0, db_config_pt->db, db_config_pt->host);
    }
}

/* Set the error counter */
static void osdb_seterror()
{
    db_config_pt->error_count++;
    osdb_checkerror();
}

#endif


/* Create an internal pointer to the db configuration */
void osdb_setconfig(DBConfig *db_config)
{
    db_config_pt = db_config;
}

/** MySQL calls **/
#ifdef MYSQL_DATABASE_ENABLED

/* Create the database connection
 * Returns NULL on error
 */
void *mysql_osdb_connect(const char *host, const char *user, const char *pass, const char *db,
                         unsigned int port, const char *sock)
{
    MYSQL *conn;
    conn = mysql_init(NULL);
    if (conn == NULL) {
        merror(DBINIT_ERROR, ARGV0);
        return (NULL);
    }

    /* If host is 127.0.0.1 or localhost, use TCP socket */
    if ((strcmp(host, "127.0.0.1") == 0) ||
            (strcmp(host, "::1") == 0) ||
            (strcmp(host, "localhost") == 0)) {
        if (sock != NULL) {
            mysql_options(conn, MYSQL_OPT_NAMED_PIPE, NULL);
        } else {
            unsigned int p_type = MYSQL_PROTOCOL_TCP;
            mysql_options(conn, MYSQL_OPT_PROTOCOL, (char *)&p_type);
        }
    }
    if (mysql_real_connect(conn, host, user, pass, db,
                           port, sock, 0) == NULL) {
        merror(DBCONN_ERROR, ARGV0, host, db, mysql_error(conn));
        mysql_close(conn);
        return (NULL);
    }

    return (conn);
}

/* Close the database connection */
void *mysql_osdb_close(void *db_conn)
{
    merror(DB_CLOSING, ARGV0);
    mysql_close(db_conn);
    return (NULL);
}

/* Sends insert query to database */
int mysql_osdb_query_insert(void *db_conn, const char *query)
{
    if (mysql_query(db_conn, query) != 0) {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return (0);
    }

    return (1);
}

/* Sends a select query to database. Returns the value of it.
 * Returns 0 on error (not found).
 */
int mysql_osdb_query_select(void *db_conn, const char *query)
{
    int result_int = 0;
    MYSQL_RES *result_data;
    MYSQL_ROW result_row;

    /* Send the query. It can not fail. */
    if (mysql_query(db_conn, query) != 0) {
        /* Failure: report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return (0);
    }

    /* Get result */
    result_data = mysql_use_result(db_conn);
    if (result_data == NULL) {
        /* Failure: report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return (0);
    }

    /* Get row. We only care about the first result. */
    result_row = mysql_fetch_row(result_data);
    if (result_row && (result_row[0] != NULL)) {
        result_int = atoi(result_row[0]);
    }

    mysql_free_result(result_data);

    return (result_int);
}
#endif
/** End of MySQL calls **/

/** PostgreSQL Calls **/
#ifdef PGSQL_DATABASE_ENABLED

/* Create the PostgreSQL database connection
 * Returns NULL on error
 */
void *postgresql_osdb_connect(const char *host, const char *user, const char *pass, const char *db,
                              __attribute__((unused)) unsigned int port, __attribute__((unused)) const char *sock)
{
    PGconn *conn;

    conn = PQsetdbLogin(host, NULL, NULL, NULL, db, user, pass);
    if (PQstatus(conn) == CONNECTION_BAD) {
        merror(DBCONN_ERROR, ARGV0, host, db, PQerrorMessage(conn));
        PQfinish(conn);
        return (NULL);
    }

    return (conn);
}

/* Terminates db connection */
void *postgresql_osdb_close(void *db_conn)
{
    merror(DB_CLOSING, ARGV0);
    PQfinish(db_conn);
    return (NULL);
}

/* Send insert query to database */
int postgresql_osdb_query_insert(void *db_conn, const char *query)
{
    PGresult *result;

    result = PQexec(db_conn, query);
    if (!result) {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return (0);
    }

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        PQclear(result);
        osdb_seterror();
        return (0);
    }

    PQclear(result);

    return (1);
}

/* Send a select query to database. Returns the value of it.
 * Returns 0 on error (not found).
 */
int postgresql_osdb_query_select(void *db_conn, const char *query)
{
    int result_int = 0;
    PGresult *result;

    result = PQexec(db_conn, query);
    if (!result) {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return (0);
    }

    if ((PQresultStatus(result) == PGRES_TUPLES_OK)) {
        if (PQntuples(result) == 1) {
            result_int = atoi(PQgetvalue(result, 0, 0));
        }
    } else {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return (0);
    }

    /* Clear result */
    PQclear(result);

    return (result_int);
}
/** End of PostgreSQL calls **/
#endif

/* Everything else when db is not defined */
#if !defined(PGSQL_DATABASE_ENABLED) && !defined(MYSQL_DATABASE_ENABLED)

void *none_osdb_connect(__attribute__((unused)) const char *host, __attribute__((unused)) const char *user,
                        __attribute__((unused)) const char *pass, __attribute__((unused)) const char *db,
                        __attribute__((unused)) unsigned int port, __attribute__((unused)) const char *sock)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return (NULL);
}
void *none_osdb_close(__attribute__((unused)) void *db_conn)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return (NULL);
}
int none_osdb_query_insert(__attribute__((unused)) void *db_conn, __attribute__((unused)) const char *query)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return (0);
}
int none_osdb_query_select(__attribute__((unused)) void *db_conn, __attribute__((unused)) const char *query)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return (0);
}

#endif

