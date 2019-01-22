/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dbd.h"

#ifndef ARGV0
#define ARGV0 "ossec-dbd"
#endif


/* Monitor the alerts and insert them into the database
 * Only returns in case of error
 */
void OS_DBD(DBConfig *db_config)
{
    time_t tm;
    struct tm *p;
    file_queue *fileq;
    alert_data *al_data;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    /* Initialize file queue to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);

    /* Get maximum ID */
    db_config->alert_id = OS_SelectMaxID(db_config);
    db_config->alert_id++;

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if (!al_data) {
            continue;
        }

        /* Insert into the db */
        OS_Alert_InsertDB(al_data, db_config);

        /* Clear the memory */
        FreeAlertData(al_data);
    }
}
