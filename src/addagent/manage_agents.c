/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Manage agents tool
 * Add/extract and remove agents from a server
 */

#include "manage_agents.h"
#include "debug_op.h"
#include "defs.h"
#include "os_crypto/md5/md5_op.h"
#include "external/cJSON/cJSON.h"
#include "os_err.h"
#include <stdio.h>
#include <stdlib.h>
#include "config/authd-config.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuh_db/wdb.h"

#if defined(__hppa__)
static int setenv(const char *name, const char *val, __attribute__((unused)) int overwrite)
{
    int len = strlen(name) + strlen(val) + 2;
    char *str = (char *)malloc(len);
    snprintf(str, len, "%s=%s", name, val);
    putenv(str);
    return 0;
}
#endif

/* Global variables */
time_t time1;
time_t time2;
time_t time3;
long int rand1;
long int rand2;

/* Remove spaces, newlines, etc from a string */
char *chomp(char *str)
{
    char *tmp_str;
    ssize_t size;

    /* Remove spaces from the beginning */
    while (*str == ' ' || *str == '\t') {
        str++;
    }

    /* Remove any trailing newlines or \r */
    do {
        tmp_str = strchr(str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
            continue;
        }

        tmp_str = strchr(str, '\r');
        if (tmp_str) {
            *tmp_str = '\0';
        }
    } while (tmp_str != NULL);

    /* Remove spaces at the end of the string */
    tmp_str = str;
    size = (ssize_t) strlen(str) - 1;

    while ((size >= 0) && (tmp_str[size] == ' ' || tmp_str[size] == '\t')) {
        tmp_str[size] = '\0';
        size--;
    }

    return (str);
}

