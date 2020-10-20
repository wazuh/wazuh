/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "rootcheck_op.h"
#include "wazuh_db/wdb.h"

/* Get rootcheck title from log */
char* rk_get_title(const char *log) {
    char *title = strdup(log);
    char *c;
    char *d;
    char *orig;

    if ((c = strstr(title, " {"))) {
        if (c == title) {
            free(title);
            return NULL;
        } else
            *c = '\0';
    }

    if ((c = strstr(title, "System Audit: ")) && (!(d = strstr(title, " - ")) || c < d )) {
        orig = title;
        title = strdup(c + 14);
        free(orig);
    }

    // Remove "\. .*"

    if ((c = strstr(title, ". "))) {
        c[1] = '\0';
    }

    // Remove "File: ('.*') "

    if (((c = strstr(title, "File '")) || (c = strstr(title, "file '"))) && (d = strstr(c + 6, "' "))) {
        memmove(c + 5, d + 2, strlen(d + 2) + 1);
    }

    return title;
}

/* Get rootcheck file from log */
char* rk_get_file(const char *log) {
    char *c;
    char *file, *found;
    size_t size;

    if ((found = strstr(log, "File: "))) {
        found += 6;
        os_strdup(found, file);
        size = strlen(file);

        if ((c = strstr(file, ". ")) || (size > 0 && *(c = file + size - 1) == '.')) {
            *c = '\0';
            return file;
        } else{
            free(file);
            return NULL;
        }
    } else if ((found = strstr(log, "File '")) || (found = strstr(log, "file '"))) {
        found += 6;
        os_strdup(found, file);
        size = strlen(file);

        if ((c = strstr(file, "' ")) || (size > 0 && *(c = file + size - 1) == '\'')) {
            *c = '\0';
            return file;
        } else {
            free(file);
            return NULL;
        }
    }

    return NULL;
}

int send_rootcheck_log(const char* agent_id, long int date, const char* log, char* response) {
    char wazuhdb_query[OS_SIZE_6144];
    int db_result;
    int socket = -1;

    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s rootcheck save %li %s", agent_id, date, log);
    db_result = wdbc_query_ex(&socket, wazuhdb_query, response, OS_SIZE_6144);
    close(socket);

    if (db_result == -2) {
        merror("Bad load query: '%s'.", wazuhdb_query);
    }

    return db_result;
}
