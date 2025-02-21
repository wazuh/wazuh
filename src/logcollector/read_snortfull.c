/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

#define LABEL_PREPROCESSOR_MESSAGE  "[Classification: Preprocessor] [Priority: 3] "

/* Read snort_full files */
void *read_snortfull(logreader *lf, int *rc, int drop_it) {
    int f_msg_size = OS_MAX_LOG_SIZE - 1;
    const char *one = "one";
    const char *two = "two";
    const char *p = NULL;
    char *q;
    char str[OS_MAX_LOG_SIZE] = {0};
    char f_msg[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    while (can_read() && (!maximum_lines || lines < maximum_lines) && fgets(str, sizeof(str), lf->fp)) {

        lines++;

        if (is_valid_context_file) {
            OS_SHA1_Stream(context, NULL, str);
        }

        /* Remove \n at the end of the string */
        if ((q = strrchr(str, '\n')) != NULL) {
            *q = '\0';
        } else {
            goto file_error;
        }

        /* First part of the message */
        if (p == NULL) {
            if (strncmp(str, "[**] [", 6) == 0) {
                snprintf(f_msg, sizeof(f_msg), "%s", str);
                f_msg_size -= strlen(str);
                p = one;
            }
        } else {
            if (p == one) {
                /* Second line has the [Classification: */
                if (strncmp(str, "[Classification: ", 16) == 0) {
                    strncat(f_msg, str, f_msg_size);
                    f_msg_size -= strlen(str);
                    p = two;
                } else if (strncmp(str, "[Priority: ", 10) == 0) {
                    strncat(f_msg, LABEL_PREPROCESSOR_MESSAGE, f_msg_size);
                    f_msg_size -= sizeof(LABEL_PREPROCESSOR_MESSAGE) - 1;
                    p = two;
                }

                /* If it is a preprocessor message, it will not have
                 * the classification.
                 */
                else if ((str[2] == '/') && (str[5] == '-') && (q = strchr(str, ' '))) {
                    strncat(f_msg, LABEL_PREPROCESSOR_MESSAGE, f_msg_size);
                    f_msg_size -= sizeof(LABEL_PREPROCESSOR_MESSAGE) - 1;
                    strncat(f_msg, ++q, f_msg_size - 40);

                    /* Clean for next event */
                    p = NULL;

                    /* Check ignore and restrict log regex, if configured. */
                    if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, str)) {
                        /* Send message to queue */
                        w_msg_hash_queues_push(str, lf->file, strlen(f_msg), lf->log_target, LOCALFILE_MQ);
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAX_LOG_SIZE - 1;
                    str[0] = '\0';
                } else {
                    goto file_error;
                }
            } else if (p == two) {
                /* Third line has the 01/13-15 (date) */
                if ((str[2] == '/') && (str[5] == '-') && (q = strchr(str, ' '))) {
                    strncat(f_msg, ++q, f_msg_size);
                    p = NULL;

                    /* Check ignore and restrict log regex, if configured. */
                    if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, str)) {
                        /* Send message to queue */
                        w_msg_hash_queues_push(str, lf->file, strlen(str) + 1, lf->log_target, LOCALFILE_MQ);
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAX_LOG_SIZE - 1;
                    str[0] = '\0';
                } else {
                    goto file_error;
                }

            }
        }

        continue;

file_error:

        merror("Bad formated snort full file.");
        *rc = -1;
        EVP_MD_CTX_free(context);
        return (NULL);

    }

    current_position = w_ftell(lf->fp);

    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
