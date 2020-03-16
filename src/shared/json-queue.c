/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#ifdef UNIT_TESTING
    #define static
#endif
static void file_sleep(void);
static int Handle_JQueue(file_queue *fileq, int flags) __attribute__((nonnull));

/* To translate between month (int) to month (char) */
static const char *(s_month[]) = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static void file_sleep() {
    struct timeval fp_timeout;

    fp_timeout.tv_sec = FQ_TIMEOUT;
    fp_timeout.tv_usec = 0;

    /* Wait for the select timeout */
    select(0, NULL, NULL, NULL, &fp_timeout);

    return;
}

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
    char *end;
    const char *jsonErrPtr;

    if (!queue->fp && jqueue_open(queue, 1) < 0) {
        return NULL;
    }

    clearerr(queue->fp);

    if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
        if (end = strchr(buffer, '\n'), end) {
            *end = '\0';
        }

        return cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0);
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

            if (fgets(buffer, OS_MAXSTR + 1, queue->fp)) {
                if (end = strchr(buffer, '\n'), end) {
                    *end = '\0';
                }

                return cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0);
            } else {
                return NULL;
            }
        } else {
            sleep(1);
            return NULL;
        }
    }
}

/* Re Handle the file queue */
static int Handle_JQueue(file_queue *fileq, int flags) {
    /* Close if it is open */
    if (!(flags & CRALERT_FP_SET)) {
        if (fileq->fp) {
            fclose(fileq->fp);
            fileq->fp = NULL;
        }

        /*
            We must be able to open the file, fseek and get the
            time of change from it.
        */
        fileq->fp = fopen(fileq->file_name, "r");
        if (!fileq->fp) {
            /* Queue not available */
            merror(FOPEN_ERROR, fileq->file_name, errno, strerror(errno));
            return 0;
        }
    }

    /* Seek to the end of the file */
    if (!(flags & CRALERT_READ_ALL)) {
        if (!fileq->fp) {
            merror(FOPEN_ERROR, fileq->file_name, errno, strerror(errno));
            return 0;
        }

        if (fseek(fileq->fp, 0, SEEK_END) < 0) {
            merror(FSEEK_ERROR, fileq->file_name, errno, strerror(errno));
            fclose(fileq->fp);
            fileq->fp = NULL;
            return -1;
        }
    }

    /* File change time */
    if (fileq->fp) {
        if (fstat(fileno(fileq->fp), &fileq->f_status) < 0) {
            merror(FSTAT_ERROR, fileq->file_name, errno, strerror(errno));
            fclose(fileq->fp);
            fileq->fp = NULL;
            return -1;
        }
    }

    fileq->last_change = fileq->f_status.st_mtime;

    return 1;
}

// Close queue
void jqueue_close(file_queue * queue) {
    fclose(queue->fp);
    queue->fp = NULL;
}

/* Set queue flags */
void jqueue_flags(file_queue *fileq, int flags) {
    fileq->flags = flags;
}

/* Return alert data for the next file in the queue */
alert_data *GetAlertJSONData(file_queue *fileq) {
    alert_data *al_data;
    cJSON *al_json;
    char *groups;
    int i = 0;

    cJSON *json_object;
    cJSON *timestamp;
    cJSON *rule;
    cJSON *syscheck;
    cJSON *location;
    cJSON *srcip;
    cJSON *full_log;

    os_calloc(1, sizeof(alert_data), al_data);

    /* Get message if available */
    al_json = jqueue_next(fileq);

    if (!al_json || !fileq->fp) {
        cJSON_Delete(al_json);
        FreeAlertData(al_data);
        return NULL;
    }

    /* Date */
    timestamp = cJSON_GetObjectItem(al_json, "timestamp");

    if (timestamp) {
        os_strdup(timestamp->valuestring, al_data->date);
    } else {
        merror(MALFORMED_JSON, "timestamp", "alert");
        cJSON_Delete(al_json);
        FreeAlertData(al_data);
        return NULL;
    }

    /* Rule */
    rule = cJSON_GetObjectItem(al_json, "rule");

    if (!rule) {
        merror(MALFORMED_JSON, "rule", "alert");
        cJSON_Delete(al_json);
        FreeAlertData(al_data);
        return NULL;
    }

    // Rule ID
    json_object = cJSON_GetObjectItem(rule, "id");

    if (json_object) {
        al_data->rule = atoi(json_object->valuestring);
    } else {
        merror(MALFORMED_JSON, "id", "alert");
        cJSON_Delete(al_json);
        FreeAlertData(al_data);
        return NULL;
    }

    // Rule description
    json_object = cJSON_GetObjectItem(rule, "description");

    if (json_object) {
        os_strdup(json_object->valuestring, al_data->comment);
    }

    // Groups
    json_object = cJSON_GetObjectItem(rule, "groups");

    if (json_object) {
        /* Groups is an array in the alerts.json file */
        /*
            First, we copy the first item in groups, then the rest,
            in case there is more than one
        */
        os_calloc(1, strlen(cJSON_GetArrayItem(json_object, 0)->valuestring) + 1, groups);
        strcpy(groups, cJSON_GetArrayItem(json_object, 0)->valuestring);

        for (i = 1; i < cJSON_GetArraySize(json_object); i++) {
            os_realloc(groups, strlen(groups) + strlen(cJSON_GetArrayItem(json_object, i)->valuestring) + 2, groups);
            strcat(groups, ",");
            strcat(groups, cJSON_GetArrayItem(json_object, i)->valuestring);
        }

        os_strdup(groups, al_data->group);

        os_free(groups);
    }

    // Level
    json_object = cJSON_GetObjectItem(rule, "level");

    if (json_object) {
        al_data->level = json_object->valueint;
    } else {
        merror(MALFORMED_JSON, "level", "alert");
        cJSON_Delete(al_json);
        FreeAlertData(al_data);
        return NULL;
    }

    /* Syscheck */
    syscheck = cJSON_GetObjectItem(al_json, "syscheck");

    if (syscheck) {
        // Path
        json_object = cJSON_GetObjectItem(syscheck, "path");

        if (json_object) {
            os_strdup(json_object->valuestring, al_data->filename);
        }

        // User
        json_object = cJSON_GetObjectItem(syscheck, "uname_after");

        if (json_object) {
            os_strdup(json_object->valuestring, al_data->user);
        }
    }

    /* Srcip */
    srcip = cJSON_GetObjectItem(al_json, "srcip");

    if (srcip) {
        os_strdup(srcip->valuestring, al_data->srcip);
    }

    /* Location */
    location = cJSON_GetObjectItem(al_json, "location");

    if (location) {
        os_strdup(location->valuestring, al_data->location);
    }

    /* Full log */
    full_log = cJSON_GetObjectItem(al_json, "full_log");

    os_realloc(al_data->log, 2 * sizeof(char *), al_data->log);

    if (full_log) {
        os_strdup(full_log->valuestring, al_data->log[0]);
    }
    else {
        char *full_log_json = cJSON_PrintUnformatted(al_json);

        os_strdup(full_log_json, al_data->log[0]);

        os_free(full_log_json);
    }

    /*
        Because of the format of the full_log field in the json file, the entire log is stored in a single line,
        meanwhile, in the log file, the full log is stored in several lines.
        When freeing memory of an alert we try to free several lines, but in this case there is only one, this is
        why the second element of this array is set to NULL, to prevent a segmentation fault.
    */
    al_data->log[1] = NULL;

    /* Free memory */
    cJSON_Delete(al_json);
    al_json = NULL;

    return al_data;
}

/* Initiates the JSON monitoring */
int Init_JsonQueue(file_queue *fileq, const struct tm *p, int flags) {

    /* Initialize file_queue fields */
    if (!(flags & CRALERT_FP_SET)) {
        fileq->fp = NULL;
    }
    fileq->last_change = 0;
    fileq->flags = 0;

    fileq->day = p->tm_mday;
    fileq->year = p->tm_year + 1900;

    strncpy(fileq->mon, s_month[p->tm_mon], 3);
    memset(fileq->file_name, '\0', MAX_FQUEUE + 1);

    /* Set the supplied flags */
    jqueue_flags(fileq, flags);

    /* Create the logfile name */
    fileq->file_name[0] = '\0';
    fileq->file_name[MAX_FQUEUE] = '\0';

    snprintf(fileq->file_name, MAX_FQUEUE, isChroot() ? ALERTSJSON_DAILY : DEFAULTDIR ALERTSJSON_DAILY);

    if (Handle_JQueue(fileq, fileq->flags) < 0) {
        return -1;
    }

    return 0;
}

/* Read from monitored file in JSON format */
alert_data *Read_JSON_Mon(file_queue *fileq, const struct tm *p, unsigned int timeout) {
    unsigned int i = 0;
    alert_data *al_data;

    /* If the file queue is not available, try to access it */
    if (!fileq->fp) {
        if (Handle_JQueue(fileq, 0) != 1) {
            return NULL;
        }
    }

    if (!fileq->fp) {
        return NULL;
    }

    al_data = GetAlertJSONData(fileq);

    if (al_data) {
        return al_data;
    }

    fileq->day = p->tm_mday;
    fileq->year = p->tm_year + 1900;
    strncpy(fileq->mon, s_month[p->tm_mon], 3);

    if (Handle_JQueue(fileq, 0) != 1) {
        return NULL;
    }

    /* Try up to timeout times to get an event */
    while (i < timeout) {
        al_data = GetAlertJSONData(fileq);

        if (al_data) {
            return al_data;
        }

        i++;
        file_sleep();
    }

    /* Return NULL if timeout expires */
    return NULL;
}
