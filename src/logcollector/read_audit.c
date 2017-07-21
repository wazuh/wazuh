/* Copyright (C) 2016 Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

#define MAX_CACHE 16
#define MAX_HEADER 64

/* Compile message from cache and send through queue */
static void audit_send_msg(char **cache, int top, const char *file, int drop_it) {
    int i;
    size_t n = 0;
    size_t z;
    char message[OS_MAXSTR];

    for (i = 0; i < top; i++) {
        z = strlen(cache[i]);

        if (n + z + 1 < OS_MAXSTR) {
            if (n > 0)
                message[n++] = ' ';

            strncpy(message + n, cache[i], z);
        }

        n += z;
        free(cache[i]);
    }

    if (!drop_it) {
        message[n] = '\0';

        if (SendMSG(logr_queue, message, file, LOCALFILE_MQ) < 0) {
            merror(QUEUE_SEND);

            if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQPATH);
            }
        }
    }
}

void *read_audit(int pos, int *rc, int drop_it) {
    char *cache[MAX_CACHE];
    char header[MAX_HEADER] = { '\0' };
    int icache = 0;
    char buffer[OS_MAXSTR];
    char *id;
    char *p;
    size_t z;
    long offset = ftell(logff[pos].fp);
    int lines = 0;

    if (offset < 0) {
        merror(FTELL_ERROR, logff[pos].file, errno, strerror(errno));
        return NULL;
    }

    *rc = 0;

    while (fgets(buffer, OS_MAXSTR, logff[pos].fp) && lines < maximum_lines){

        lines++;
        if ((p = strchr(buffer, '\n')))
            *p = '\0';
        else {
            if (strlen(buffer) == OS_MAXSTR - 1) {
                // Message too large, discard line
                while (fgets(buffer, OS_MAXSTR, logff[pos].fp) && !strchr(buffer, '\n'));
            } else {
                mdebug1("Message not complete. Trying again: '%s'", buffer);

                if (fseek(logff[pos].fp, offset, SEEK_SET) < 0) {
                    merror(FSEEK_ERROR, logff[pos].file, errno, strerror(errno));
                    break;
                }
            }

            break;
        }

        // Extract header: "type=\.* msg=audit(\d+.\d+:\d+):"

        if (strncmp(buffer, "type=", 5) || !((id = strstr(buffer + 5, "msg=audit(")) && (p = strstr(id += 10, "): ")))) {
            merror("Discarding audit message because of invalid syntax.");
            break;
        }

        z = p - id;

        if (strncmp(id, header, z)) {
            // Current message belongs to another event: send cached messages
            if (icache > 0)
                audit_send_msg(cache, icache, logff[pos].file, drop_it);

            // Store current event
            *cache = strdup(buffer);
            icache = 1;
            strncpy(header, id, z < MAX_HEADER ? z : MAX_HEADER - 1);
        } else {
            // The header is the same: store
            if (icache == MAX_CACHE)
                merror("Discarding audit message because cache is full.");
            else
                cache[icache++] = strdup(buffer);
        }
    }

    if (icache > 0)
        audit_send_msg(cache, icache, logff[pos].file, drop_it);

    mdebug2("Read %d lines from %s", lines, logff[pos].file);
    return NULL;
}
