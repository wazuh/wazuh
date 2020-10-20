/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ROOTCHECK_OP_H
#define ROOTCHECK_OP_H

/* Rootcheck fields */
#define RK_TITLE   0
#define RK_FILE    1
#define RK_NFIELDS 2

typedef struct rk_event_t {
    long date_last;
    long date_first;
    char *log;
} rk_event_t;

/* Get rootcheck title from log */
char* rk_get_title(const char *log);

/* Get rootcheck file from log */
char* rk_get_file(const char *log);

/**
 * Sends a rootcheck log through wazuh database
 * @param agent_id [In] string containing the agent id
 * @param date [In] timestamp of when the log has been updated
 * @param log [In] log entry string
 * @param response [Out] buffer to store the query response
 * @return error_code from query execution
 * @retval -2 Bad query
 * @retval -1 Error executing query
 * @retval >0 Successfull reponse
 * */
int send_rootcheck_log(const char* agent_id, long int date, const char* log, char* response);


#endif /* ROOTCHECK_OP_H */
