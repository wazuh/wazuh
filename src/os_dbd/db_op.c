/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */
          

/* Common lib for dealing with databases */


#ifdef DBD
#include "shared.h"
#include "db_op.h"

/* Using Mysql */
#ifdef UMYSQL
#include <mysql.h>
#endif


/** void osdb_escapestr
 * Escapes a null terminated string before inserting into the database.
 * We built a white list of allowed characters at insert_map. Everything
 * not allowed will become spaces.
 */
void osdb_escapestr(char *str)
{
    while(*str)
    {
        if(*str == '\'')
        {
            *str = '`';
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


/* Create the tree 
 * Return NULL on error
 */
void *osdb_connect(char *host, char *user, char *pass, char *db)
{
    MYSQL *conn;
    conn = mysql_init(NULL);
    if (conn == NULL)
    {
        merror(DBINIT_ERROR, ARGV0);
        return(NULL);
    }
    if(mysql_real_connect(conn, host, user, pass, db, 0, NULL, 0) == NULL)
    {
        merror(DBCONN_ERROR, ARGV0, host, db, mysql_error(conn));
        mysql_close(conn);
        return(NULL);
    }

    return(conn);
}


void osdb_close(void *db_conn)
{
    mysql_close(db_conn);
}


/** int osdb_query_insert(void *db_conn, char *query)
 * Sends insert query to database. 
 */
int osdb_query_insert(void *db_conn, char *query)
{
    if(mysql_query(db_conn, query) != 0)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        return(0);
    }

    return(1);
}



/** int osdb_query_select(void *db_conn, char *query)
 * Sends a select query to database. Returns the value of it.
 * Returns 0 on error (not found).
 */
int osdb_query_select(void *db_conn, char *query)
{
    int result_int = 0;
    MYSQL_RES *result_data;
    MYSQL_ROW result_row;
    

    /* Sending the query. It can not fail. */
    if(mysql_query(db_conn, query) != 0)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
        return(0);
    }

    
    /* Getting result */
    result_data = mysql_use_result(db_conn);
    if(result_data == NULL)
    {
        /* failure; report error */
        merror(DBQUERY_ERROR, ARGV0, query, mysql_error(db_conn));
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


#endif /* DBD */



/* EOF */
