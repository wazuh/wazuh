/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"


/* Read multiline logs */
void *read_multiline(logreader *lf, int *rc, int drop_it) {
    int __ms = 0;
    int __ms_reported = 0;
    int linesgot = 0;
    size_t buffer_size = 0;
    char str[OS_MAX_LOG_SIZE] = {0};
    char buffer[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;
    int size = 0;
    int64_t offset = 0;
    int64_t rbytes = 0;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    for (offset = w_ftell(lf->fp); can_read() && fgets(str, OS_MAX_LOG_SIZE, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines) && offset >= 0; offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;
        linesgot++;

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            if (is_valid_context_file) {
                OS_SHA1_Stream(context, NULL, str);
            }
            str[rbytes - 1] = '\0';

            if ((int64_t)strlen(str) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=" FTELL_TT " / total=" FTELL_TT "). Dropping line.", lf->file, FTELL_INT64 strlen(str), FTELL_INT64 rbytes - 1);
                continue;
            }
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (rbytes == OS_MAX_LOG_SIZE - 1) {
            /* Message size > maximum allowed */
            if (is_valid_context_file) {
                OS_SHA1_Stream(context, NULL, str);
            }
            __ms = 1;
        } else if (feof(lf->fp)) {
            /* Message not complete. Return. */
            mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length, str, rbytes > sample_log_length ? "..." : "");
            if(current_position >= 0) {
                w_fseek(lf->fp, current_position, SEEK_SET);
            }
            break;
        }

#ifdef WIN32
        char * p;

        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif

        /* Add to buffer */
        buffer_size = strlen(buffer);
        if (buffer[0] != '\0' && buffer_size < sizeof(buffer) - 1) {
            buffer[buffer_size] = ' ';
            buffer_size++;
        }

        size = snprintf(buffer + buffer_size, sizeof(buffer) - buffer_size, "%s", str);

        if ((size_t)size >= sizeof(buffer) - buffer_size) {
            __ms = 1;
        }

        if (linesgot < lf->linecount) {
            continue;
        }
        linesgot = 0;

        /* Check ignore and restrict log regex, if configured. */
        if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, buffer)) {
            /* Send message to queue */
            mdebug2("Reading message: '%.*s'%s", sample_log_length, buffer, strlen(buffer) > (size_t)sample_log_length ? "..." : "");
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }

        buffer[0] = '\0';


        /* Incorrect message size */
        if (__ms) {
            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 rbytes, sample_log_length, str);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 rbytes, sample_log_length, str);
            }

            for (offset += rbytes; fgets(str, sizeof(str), lf->fp) != NULL; offset += rbytes) {
                rbytes = w_ftell(lf->fp) - offset;

                /* Flow control */
                if (rbytes <= 0) {
                    break;
                }

                if (is_valid_context_file) {
                    OS_SHA1_Stream(context, NULL, str);
                }

                /* Get the last occurrence of \n */
                if (str[rbytes - 1] == '\n') {
                    break;
                }
            }
            __ms = 0;
        }

        current_position = w_ftell(lf->fp);
    }

    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
