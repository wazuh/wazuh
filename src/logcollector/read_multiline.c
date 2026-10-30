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


/**
 * @brief Mark the current position as the start of the next group
 *
 * Keeps a copy of the hash context at that position, so the lines of a group that is not complete
 * when the read stops can be rolled back out of the hash.
 *
 * @param group_context Copy of the hash context at the start of the group. NULL if there is no hash.
 * @param context Current hash context.
 * @param group_pending Set to false: no line of the next group has been hashed yet.
 */
static void multiline_mark_group(EVP_MD_CTX * group_context, EVP_MD_CTX * context, bool * group_pending) {
    if (group_context != NULL) {
        EVP_MD_CTX_copy(group_context, context);
    }
    *group_pending = false;
}

/* Read multiline logs */
void *read_multiline(logreader *lf, int *rc, int drop_it) {
    int __ms_reported = 0;
    int linesgot = 0;
    size_t buffer_size = 0;
    char str[OS_MAX_LOG_SIZE] = {0};
    char buffer[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;
    int size = 0;
    int64_t offset = 0;
    int64_t rbytes = 0;
    int64_t group_length = 0;
    bool group_truncated = false;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    /* Hash context at current_position, the start of the group being collected */
    EVP_MD_CTX *group_context = NULL;
    bool group_pending = false;
    bool rewound = false;

    if (is_valid_context_file) {
        group_context = EVP_MD_CTX_new();
        EVP_MD_CTX_copy(group_context, context);
    }

    for (offset = w_ftell(lf->fp); can_read() && (!maximum_lines || lines < maximum_lines) && offset >= 0 && fgets(str, OS_MAX_LOG_SIZE, lf->fp); offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;
        linesgot++;
        bool line_dropped = false;

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            if (is_valid_context_file) {
                OS_SHA1_Stream_Bytes(context, str, (size_t) rbytes);
            }
            group_pending = true;
            str[rbytes - 1] = '\0';

            if ((int64_t)strlen(str) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=" FTELL_TT " / total=" FTELL_TT "). Dropping line.", lf->file, FTELL_INT64 strlen(str), FTELL_INT64 rbytes - 1);
                /* The line still belongs to its group: it adds no text, but it can complete the group */
                line_dropped = true;
            }
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (rbytes == OS_MAX_LOG_SIZE - 1) {
            /* Message size > maximum allowed */
            if (is_valid_context_file) {
                OS_SHA1_Stream_Bytes(context, str, (size_t) rbytes);
            }
            group_pending = true;

            /* Discard the rest of the line now, so it is not read as the next line of the group */
            char rest[OS_SIZE_1024];
            int64_t rest_offset = offset + rbytes;
            int64_t rest_bytes;

            while (fgets(rest, sizeof(rest), lf->fp) != NULL) {
                rest_bytes = w_ftell(lf->fp) - rest_offset;

                /* Flow control */
                if (rest_bytes <= 0) {
                    break;
                }

                if (is_valid_context_file) {
                    OS_SHA1_Stream_Bytes(context, rest, (size_t) rest_bytes);
                }

                rest_offset += rest_bytes;

                if (rest[rest_bytes - 1] == '\n') {
                    break;
                }
            }

            if (feof(lf->fp)) {
                /* The line is not complete yet: read the group again next time */
                mdebug2("Message not complete from '%s'. Trying again: '%.*s'...", lf->file, sample_log_length, str);
                if (current_position >= 0) {
                    w_fseek(lf->fp, current_position, SEEK_SET);
                }
                rewound = true;
                break;
            }

            rbytes = rest_offset - offset;
            group_truncated = true;
        } else if (feof(lf->fp)) {
            /* Message not complete. Return. */
            mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length, str, rbytes > sample_log_length ? "..." : "");
            if(current_position >= 0) {
                w_fseek(lf->fp, current_position, SEEK_SET);
            }
            rewound = true;
            break;
        }

#ifdef WIN32
        char * p;

        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif

        /* Add to buffer */
        if (!line_dropped) {
            buffer_size = strlen(buffer);
            if (buffer[0] != '\0' && buffer_size < sizeof(buffer) - 1) {
                buffer[buffer_size] = ' ';
                buffer_size++;
            }

            size = snprintf(buffer + buffer_size, sizeof(buffer) - buffer_size, "%s", str);
            group_length += rbytes;

            if ((size_t)size >= sizeof(buffer) - buffer_size) {
                group_truncated = true;
            }
        }

        if (linesgot < lf->linecount) {
            continue;
        }
        linesgot = 0;

        /* A group whose lines were all dropped has nothing to send. Check ignore and restrict log regex, if configured. */
        if (group_length > 0 && drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, buffer)) {
            /* Send message to queue */
            mdebug2("Reading message: '%.*s'%s", sample_log_length, buffer, strlen(buffer) > (size_t)sample_log_length ? "..." : "");
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }

        /* Reported only once the group is complete, as it may be read again while it is not */
        if (group_truncated) {
            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 group_length, sample_log_length, buffer);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = " FTELL_TT "): '%.*s'...", lf->file, FTELL_INT64 group_length, sample_log_length, buffer);
            }
        }

        buffer[0] = '\0';
        group_length = 0;
        group_truncated = false;


        current_position = w_ftell(lf->fp);
        multiline_mark_group(group_context, context, &group_pending);
    }

    /* Lines of a group that is not complete yet were hashed beyond the stored offset */
    if (group_pending) {
        if (maximum_lines && lines >= maximum_lines && !rewound) {
            /* Stopped by the line limit: the stored offset covers the lines already read */
            current_position = w_ftell(lf->fp);
        } else {
            /* Stopped at the end of the file: the group is read again, from its first line, next time */
            if (!rewound && current_position >= 0) {
                w_fseek(lf->fp, current_position, SEEK_SET);
            }
            if (group_context != NULL) {
                EVP_MD_CTX_copy(context, group_context);
            }
        }
    }
    EVP_MD_CTX_free(group_context);

    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
