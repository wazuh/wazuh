/* Copyright (C) 2015-2019 Wazuh Inc.
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
    int __ms_reported = 0;
    int i;
    char *jsonParsed;
    char str[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int lines = 0;
    cJSON * obj;
    long offset;
    long rbytes;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);

    for (offset = w_ftell(lf->fp); fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines); offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            str[rbytes - 1] = '\0';

            if ((long)strlen(str) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=%ld / total=%ld). Dropping line.", lf->file, (long)strlen(str), rbytes - 1);
                continue;
            }
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (rbytes == OS_MAXSTR - OS_LOG_HEADER - 1) {
            /* Message size > maximum allowed */
            __ms = 1;
        } else if (feof(lf->fp)) {
            /* Message not complete. Return. */
            mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length, str, rbytes > sample_log_length ? "..." : "");
            fsetpos(lf->fp, &fp_pos);
            break;
        }

#ifdef WIN32
        char * p;

        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (rbytes <= 2) {
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
          for (i = 0; lf->labels && lf->labels[i].key; i++) {
              W_JSON_AddField(obj, lf->labels[i].key, lf->labels[i].value);
          }

          jsonParsed = cJSON_PrintUnformatted(obj);
          cJSON_Delete(obj);
        } else {
          cJSON_Delete(obj);
          mdebug1("Line '%.*s'%s read from '%s' is not a JSON object.", sample_log_length, str, rbytes > sample_log_length ? "..." : "", lf->file);
          continue;
        }

        mdebug2("Reading json message: '%.*s'%s", sample_log_length, jsonParsed, strlen(jsonParsed) > (size_t)sample_log_length ? "..." : "");

        /* Send message to queue */
        if (drop_it == 0) {
            w_msg_hash_queues_push(jsonParsed, lf->file, strlen(jsonParsed) + 1, lf->log_target, LOCALFILE_MQ);
        }
        free(jsonParsed);
        /* Incorrect message size */
        if (__ms) {
            // strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)
            // truncate str before logging to ossec.log

            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = %ld): '%.*s'...", lf->file, rbytes, sample_log_length, str);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = %ld): '%.*s'...", lf->file, rbytes, sample_log_length, str);
            }

            for (offset += rbytes; fgets(str, OS_MAXSTR - 2, lf->fp) != NULL; offset += rbytes) {
                rbytes = w_ftell(lf->fp) - offset;

                /* Get the last occurrence of \n */
                if (str[rbytes - 1] == '\n') {
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
