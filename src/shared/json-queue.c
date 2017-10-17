/* Copyright (C) 2017 Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

// Initializes queue. Equivalent to initialize every field to 0.
void jqueue_init(file_queue * queue) {
    memset(queue, 0, sizeof(file_queue));
}

/*
 * Open queue with the JSON alerts log file.
 * Returns 0 on success or -1 on error.
 */
int jqueue_open(file_queue * queue) {
    time_t now = time(NULL);
    struct tm tm = *localtime(&now);

    strncpy(queue->file_name, isChroot() ? ALERTSJSON_DAILY : DEFAULTDIR ALERTSJSON_DAILY, MAX_FQUEUE);

    if (queue->fp) {
        fclose(queue->fp);
    }

    if (queue->fp = fopen(queue->file_name, "r"), !queue->fp) {
        merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        return -1;
    }

	/* Position file queue to end of the file */
	if (fseek(queue->fp, 0, SEEK_END) == -1) {
		merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    queue->day = tm.tm_mday;
    return 0;
}

/*
 * Return next JSON object from the queue, or NULL if it is not available.
 * If no more data is available and the day has changed, queue is reloaded.
 */
cJSON * jqueue_next(file_queue * queue) {
    time_t now;
    struct tm tm;
    char buffer[OS_MAXSTR + 1];
    char *end;

    if (!queue->fp && jqueue_open(queue) < 0) {
        return NULL;
    }

    if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
        if (end = strchr(buffer, '\n'), end) {
            *end = '\0';
        }

        return cJSON_Parse(buffer);
    } else {
        now = time(NULL);
        tm = *localtime(&now);

        // If the day has changed, reopen and retry to open

        if (tm.tm_mday != queue->day) {
            if (jqueue_open(queue) < 0) {
                return NULL;
            }

            if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
                if (end = strchr(buffer, '\n'), end) {
                    *end = '\0';
                }

                return cJSON_Parse(buffer);
            } else {
                return NULL;
            }
        } else {
            sleep(1);
            return NULL;
        }
    }
}

// Close queue
void jqueue_close(file_queue * queue) {
    fclose(queue->fp);
    queue->fp = NULL;
}
