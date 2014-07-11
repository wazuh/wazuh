/* @(#) $Id: ./src/os_dbd/db_op.c, 2011/09/08 dcid Exp $
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


/* Common lib for dealing with databases */


#include "dbd.h"

/* Using Mysql */
#ifdef UMYSQL
#include <mysql.h>
#endif

/* Using PostgreSQL */
#ifdef UPOSTGRES
#include <libpq-fe.h>
#endif



/* Config pointer */
DBConfig *db_config_pt = NULL;



/** void osdb_escapestr
 * Escapes a null terminated string before inserting into the database.
 * We built a white list of allowed characters at insert_map. Everything
 * not allowed will become spaces.
 */
void osdb_escapestr(char *str)
{
    if(!str)
    {
        return;
    }

    while(*str)
    {
        if(*str == '\'')
        {
            *str = '`';
        }
        else if(*str == '\\')
        {
            *str = '/';
        }
        else if(insert_map[(unsigned char)*str] != '\001')
        {
            *str = ' ';
        }
        str++;
    }

    /* It can not end with \\ */
    if(*(str -1) == '\\')
    {
        *(str-1) = '\0';
    }
}



/** void osdb_checkerror()
 * Checks for errors and handle it appropriately.
 */
void osdb_checkerror()
{
    int sleep_time = 2;
    if(!db_config_pt || db_config_pt->error_count > 20)
    {
        ErrorExit(DB_MAINERROR, ARGV0);
    }


    /* If error count is too large, we try to reconnect. */
    if(db_config_pt->error_count > 0)
    {
        int i = 0;
        if(db_config_pt->conn)
        {
            osdb_close(db_config_pt->conn);
            db_config_pt->conn = NULL;
        }

        while(i <= db_config_pt->maxreconnect)
        {
            merror(DB_ATTEMPT, ARGV0);
            db_config_pt->conn = osdb_connect(db_config_pt->host,
                                              db_config_pt->user,
                                              db_config_pt->pass,
                                              db_config_pt->db,
                                              db_config_pt->port,
                                              db_config_pt->sock);

            /* If we were able to reconnect, keep going. */
            if(db_config_pt->conn)
            {
                break;
            }
            sleep(sleep_time);
            sleep_time *= 2;
            i++;
        }


        /* If we weren't able to connect, exit */
        if(!db_config_pt->conn)
        {
            ErrorExit(DB_MAINERROR, ARGV0);
        }


        verbose("%s: Connected to database '%s' at '%s'.",
                ARGV0, db_config_pt->db, db_config_pt->host);

    }
}


/** void osdb_seterror()
 * Sets the error counter.
 */
void osdb_seterror()
{
    db_config_pt->error_count++;
    osdb_checkerror();
}


/** void osdb_setconfig(DBConfig *db_config)
 * Creates an internal pointer to the db configuration.
 */
void osdb_setconfig(DBConfig *db_config)
{
    db_config_pt = db_config;
}



/** MySQL calls **/
#ifdef UMYSQL


/* Create the database connection.
 * Returns NULL on error
 */
void *mysql_osdb_connect(char *host, char *user, char *pass, char *db,
                         int port, char *sock)
{
    MYSQL *conn;
    conn = mysql_init(NULL);
    if (conn == NULL)
    {
        merror(DBINIT_ERROR, ARGV0);
        return(NULL);
    }


    /* If host is 127.0.0.1 or localhost, use tcp socket */
    if((strcmp(host, "127.0.0.1") == 0) ||
       (strcmp(host, "localhost") == 0))
    {
        if(sock != NULL)
        {
            mysql_options(conn, MYSQL_OPT_NAMED_PIPE, NULL);
        }
        else
        {
            unsigned int p_type = MYSQL_PROTOCOL_TCP;
            mysql_options(conn, MYSQL_OPT_PROTOCOL, (char *)&p_type);
        }
    }
    if(mysql_real_connect(conn, host, user, pass, db,
                          port, sock, 0) == NULL)
    {
        merror(DBCONN_ERROR, ARGV0, host, db, mysql_error(conn));
        mysql_close(conn);
        return(NULL);
    }

    return(conn);
}



/* Closes the database connection.
 */
void *mysql_osdb_close(void *db_conn)
{
    merror(DB_CLOSING, ARGV0);
    mysql_close(db_conn);
    return(NULL);
}



/** int mysql_osdb_query_insert(void *db_conn, char *query)
 * Sends insert query to database.
 */
int mysql_osdb_query_insert(void *db_conn, char *query)
{
    if(mysql_query(db_conn, query) != 0)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return(0);
    }

    return(1);
}



/** int mysql_osdb_query_select(void *db_conn, char *query)
 * Sends a select query to database. Returns the value of it.
 * Returns 0 on error (not found).
 */
int mysql_osdb_query_select(void *db_conn, char *query)
{
    int result_int = 0;
    MYSQL_RES *result_data;
    MYSQL_ROW result_row;


    /* Sending the query. It can not fail. */
    if(mysql_query(db_conn, query) != 0)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return(0);
    }


    /* Getting result */
    result_data = mysql_use_result(db_conn);
    if(result_data == NULL)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        osdb_seterror();
        return(0);
    }


    /* Getting row. We only care about the first result. */
    result_row = mysql_fetch_row(result_data);
    if(result_row && (result_row[0] != NULL))
    {
        result_int = atoi(result_row[0]);
    }


    mysql_free_result(result_data);


    return(result_int);
}
#endif
/** End of MYSQL calls **/




/** PostGRES Calls **/
#if defined UPOSTGRES


/** void *postgresql_osdb_connect(char *host, char *user, char *pass, char *db)
 * Create the PostgreSQL database connection.
 * Return NULL on error
 */
void *postgresql_osdb_connect(char *host, char *user, char *pass, char *db,
                              int port, char *sock)
{
    PGconn *conn;


    conn = PQsetdbLogin(host, NULL, NULL, NULL, db, user, pass);
    if(PQstatus(conn) == CONNECTION_BAD)
    {
        merror(DBCONN_ERROR, ARGV0, host, db, PQerrorMessage(conn));
        PQfinish(conn);
        return(NULL);
    }

    return(conn);
}



/** void postgresql_osdb_close(void *db_conn)
 * Terminates db connection.
 */
void *postgresql_osdb_close(void *db_conn)
{
    merror(DB_CLOSING, ARGV0);
    PQfinish(db_conn);
    return(NULL);
}



/** int postgresql_osdb_query_insert(void *db_conn, char *query)
 * Sends insert query to database.
 */
int postgresql_osdb_query_insert(void *db_conn, char *query)
{
    PGresult *result;


    result = PQexec(db_conn,query);
    if(!result)
    {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return(0);
    }


    if(PQresultStatus(result) != PGRES_COMMAND_OK)
    {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        PQclear(result);
        osdb_seterror();
        return(0);
    }


    PQclear(result);
    return(1);
}



/** int postgresql_osdb_query_select(void *db_conn, char *query)
 * Sends a select query to database. Returns the value of it.
 * Returns 0 on error (not found).
 */
int postgresql_osdb_query_select(void *db_conn, char *query)
{
    int result_int = 0;
    PGresult *result;

    result = PQexec(db_conn,query);
    if(!result)
    {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return(0);
    }

    if((PQresultStatus(result) == PGRES_TUPLES_OK))
    {
        if(PQntuples(result) == 1)
        {
            result_int = atoi(PQgetvalue(result,0,0));
        }
    }
    else
    {
        merror(DBQUERY_ERROR, ARGV0, query, PQerrorMessage(db_conn));
        osdb_seterror();
        return(0);
    }


    /* Clear result */
    PQclear(result);


    return(result_int);
}
/** End of PostGRES calls **/
#endif



/* Everything else when db is not defined. */
#if !defined(UPOSTGRES) && !defined(UMYSQL)



void *none_osdb_connect(char *host, char *user, char *pass, char *db,
                        int port, char *sock)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return(NULL);
}
void *none_osdb_close(void *db_conn)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return(NULL);
}
void *none_osdb_query_insert(void *db_conn, char *query)
{
   merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return(0);
}
void *none_osdb_query_select(void *db_conn, char *query)
{
    merror("%s: ERROR: Database support not enabled. Exiting.", ARGV0);
    return(0);
}




/** End of not defined db calls **/
#endif



/* EOF */
