/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __ROOTCHECK_OP_H
#define __ROOTCHECK_OP_H

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

/* Extract time and event from Rootcheck log. It doesn't reserve memory. */
int rk_decode_event(char *buffer, rk_event_t *event);

#endif
