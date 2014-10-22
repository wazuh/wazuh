/* @(#) $Id: ./src/os_dbd/dbd.c, 2011/09/08 dcid Exp $
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

#ifndef ARGV0
   #define ARGV0 "ossec-dbd"
#endif

#include "shared.h"
#include "dbd.h"



/* OS_DBD: Monitor the alerts and insert them into the database.
 * Only return in case of error.
 */
void OS_DBD(DBConfig *db_config)
{
    time_t tm;
    struct tm *p;

    file_queue *fileq;
    alert_data *al_data;


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);


    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);


    /* Creating location hash */
    db_config->location_hash = OSHash_Create();
    if(!db_config->location_hash)
    {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }


    /* Getting maximum ID */
    db_config->alert_id = OS_SelectMaxID(db_config);
    db_config->alert_id++;


    /* Infinite loop reading the alerts and inserting them. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if(!al_data)
        {
            continue;
        }


        /* Inserting into the db */
        OS_Alert_InsertDB(al_data, db_config);


        /* Clearing the memory */
        FreeAlertData(al_data);
    }
}

/* EOF */
