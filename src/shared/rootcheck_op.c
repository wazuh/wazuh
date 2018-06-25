/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2016 Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "rootcheck_op.h"

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

    os_strdup(log, file);

    if ((found = strstr(file, "File: "))) {
        found += 6;
        file = found;
        if ((c = strstr(file, ". "))) {
            *c = '\0';
            return file;
        } else
            goto end;
    } else if ((found = strstr(file, "File '")) || (found = strstr(file, "file '"))) {
        found += 6;
        file = found;

        if ((c = strstr(file, "' "))) {
            *c = '\0';
            return file;
        } else
            goto end;

    } else
        goto end;

end:
    free(file);
    return NULL;
}

/* Extract time and event from Rootcheck log. It doesn't reserve memory. */
int rk_decode_event(char *buffer, rk_event_t *event) {
    char *string;
    char *end;

    if (buffer[0] == '!') {
        string = buffer + 1;
        event->date_last = strtol(string, &end, 10);

        if (event->date_last == LONG_MAX || event->date_last < 0 || *end != '!')
            return -1;

        string = end + 1;
        event->date_first = strtol(string, &end, 10);

        if (event->date_first == LONG_MAX || event->date_first < 0 || *end != ' ')
            return -1;

        event->log = end + 1;
    } else
        event->log = buffer;

    return 0;
}
