/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dbd.h"

#ifndef ARGV0
#define ARGV0 "wazuh-dbd"
#endif


/* Monitor the alerts and insert them into the database
 * Only returns in case of error
 */
void OS_DBD(DBConfig *db_config)
{
    time_t tm;
    file_queue *fileq;
    alert_data *al_data;
    struct tm tm_result = { .tm_sec = 0 };

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    /* Initialize file queue to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, &tm_result, 0);

    /* Get maximum ID */
    db_config->alert_id = OS_SelectMaxID(db_config);
    db_config->alert_id++;

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        tm = time(NULL);
        localtime_r(&tm, &tm_result);

        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, &tm_result, 5);
        if (!al_data) {
            continue;
        }

        /* Insert into the db */
        OS_Alert_InsertDB(al_data, db_config);

        /* Clear the memory */
        FreeAlertData(al_data);
    }
}
