/* Copyright 2017 Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the json */

#include "shared.h"
#include "logcollector.h"


/* Read json files */
void *read_json(logreader *lf, int *rc, int drop_it) {
    int __ms = 0;
    int i;
    char *p, *jsonParsed;
    char str[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int lines = 0;
    cJSON * obj;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);

    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)) {
            /* Message size > maximum allowed */
            __ms = 1;
        } else {
            /* Message not complete. Return. */
            mdebug1("Message not complete. Trying again: '%s'", str);
            fsetpos(lf->fp, &fp_pos);
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (strlen(str) <= 2) {
            fgetpos(lf->fp, &fp_pos);
            continue;
        }
        /* Windows can have comment on their logs */

        if (str[0] == '#') {
            fgetpos(lf->fp, &fp_pos);
            continue;
        }
#endif

        if (obj = cJSON_Parse(str), obj && cJSON_IsObject(obj)) {
          for (i = 0; lf->labels[i].key; i++) {
              W_JSON_AddField(obj, lf->labels[i].key, lf->labels[i].value);
          }

          jsonParsed = cJSON_PrintUnformatted(obj);
          cJSON_Delete(obj);
        } else {
          cJSON_Delete(obj);
          mdebug1("Line '%s' read from '%s' is not a JSON object.", str, lf->file);
          continue;
        }

        mdebug2("Reading json message: '%s'", jsonParsed);

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSGtoSCK(logr_queue, jsonParsed, lf->file,
                        LOCALFILE_MQ, lf->target_socket, lf->outformat) < 0) {
                merror(QUEUE_SEND);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    merror_exit(QUEUE_FATAL, DEFAULTQPATH);
                }
            }
        }
        free(jsonParsed);
        /* Incorrect message size */
        if (__ms) {
            // strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)
            // truncate str before logging to ossec.log
#define OUTSIZE 4096
            char buf[OUTSIZE + 1];
            buf[OUTSIZE] = '\0';
            snprintf(buf, OUTSIZE, "%s", str);
            merror("Large message size(length=%d): '%s...'", (int)strlen(str), buf);
            while (fgets(str, OS_MAXSTR - 2, lf->fp) != NULL) {
                /* Get the last occurrence of \n */
                if (strrchr(str, '\n') != NULL) {
                    break;
                }
            }
            __ms = 0;
        }
        fgetpos(lf->fp, &fp_pos);
        continue;
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
