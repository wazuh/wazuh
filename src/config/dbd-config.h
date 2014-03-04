/* @(#) $Id: ./src/config/dbd-config.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef _DBDCONFIG__H
#define _DBDCONFIG__H


/* Database config structure */
typedef struct _DBConfig
{
    unsigned int db_type;
    unsigned int alert_id;
    unsigned int server_id;
    unsigned int error_count;
    unsigned int maxreconnect;
    unsigned int port;

    char *host;
    char *user;
    char *pass;
    char *db;
    char *sock;

    void *conn;
    void *location_hash;

    char **includes;
}DBConfig;


#define MYSQLDB 0x002
#define POSTGDB 0x004

#endif
