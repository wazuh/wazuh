/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
int jqueue_open(file_queue * queue, int tail) {
    strncpy(queue->file_name, isChroot() ? ALERTSJSON_DAILY : DEFAULTDIR ALERTSJSON_DAILY, MAX_FQUEUE);

    if (queue->fp) {
        fclose(queue->fp);
    }

    if (queue->fp = fopen(queue->file_name, "r"), !queue->fp) {
        merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        return -1;
    }

    /* Position file queue to end of the file */
    if (tail && fseek(queue->fp, 0, SEEK_END) == -1) {
        merror(FOPEN_ERROR, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    /* File inode time */
    if (fstat(fileno(queue->fp), &queue->f_status) < 0) {
        merror(FSTAT_ERROR, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    return 0;
}

/*
 * Return next JSON object from the queue, or NULL if it is not available.
 * If no more data is available and the inode has changed, queue is reloaded.
 */
cJSON * jqueue_next(file_queue * queue) {
    struct stat buf;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos;

    if (!queue->fp && jqueue_open(queue, 1) < 0) {
        return NULL;
    }

    clearerr(queue->fp);
    current_pos = w_ftell(queue->fp);

    if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
        return jqueue_parse_json(queue, buffer, current_pos);

    } else {

        if (stat(queue->file_name, &buf) < 0) {
            merror(FSTAT_ERROR, queue->file_name, errno, strerror(errno));
            fclose(queue->fp);
            queue->fp = NULL;
            return NULL;
        }

        // If the inode has changed, reopen and retry to open

        if (buf.st_ino != queue->f_status.st_ino) {
            mdebug2("jqueue_next(): Alert file inode changed. Reloading.");

            if (jqueue_open(queue, 0) < 0) {
                return NULL;
            }

            current_pos = w_ftell(queue->fp);

            if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
                return jqueue_parse_json(queue, buffer, current_pos);

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

/**
 * @brief Validate and parse a JSON object from a buffer
 *
 * @param queue pointer to the file_queue struct
 * @param buffer string with the JSON to be parsed
 * @param current_pos File position located as a backup
 * @return cJSON object with the read JSON, NULL in the JSON is invalid
 */
cJSON * jqueue_parse_json(file_queue * queue, char * buffer, int64_t current_pos) {

    cJSON * object = NULL;
    const char *jsonErrPtr;
    char * end;

    if (end = strchr(buffer, '\n'), end) {
        *end = '\0';
    }

    if ((object = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0), object) && (*jsonErrPtr == '\0')) {
        queue->read_attempts = 0;
        return object;
    }

    // The read JSON is invalid
    if (object) {
        cJSON_Delete(object);
    }

    queue->read_attempts++;
    mdebug2("Invalid JSON alert read from '%s'. Remaining attempts: %d", queue->file_name, MAX_READ_ATTEMPTS - queue->read_attempts);

    if (queue->read_attempts < MAX_READ_ATTEMPTS) {
        if (current_pos >= 0) {
            fseek(queue->fp, current_pos, SEEK_SET);
        }
    } else {
        queue->read_attempts = 0;
        merror("Invalid JSON alert read from '%s'. Skipping it.", queue->file_name);
    }

    return NULL;
}
