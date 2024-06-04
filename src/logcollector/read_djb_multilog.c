/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read DJB multilog */

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"


/* To translate between month (int) to month (char) */
static const char *(djb_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                   };
static char djb_host[512 + 1];


/* Initialize multilog */
int init_djbmultilog(logreader *lf) {
    char *djbp_name = NULL;
    char *tmp_str = NULL;

    lf->djb_program_name = NULL;

    /* Initialize hostname */
    memset(djb_host, '\0', 512 + 1);

#ifndef WIN32
    if (gethostname(djb_host, 512 - 1) != 0) {
        strncpy(djb_host, "unknown", 512 - 1);
    } else {
        char *_ltmp;

        /* Remove domain part if available */
        _ltmp = strchr(djb_host, '.');
        if (_ltmp) {
            *_ltmp = '\0';
        }
    }
#else
    strncpy(djb_host, "win32", 512 - 1);
#endif

    /* Multilog must be in the following format: /path/program_name/current */
    tmp_str = strrchr(lf->file, '/');
    if (!tmp_str) {
        return (0);
    }

    /* Must end with /current and must not be in the beginning of the string */
    if ((strcmp(tmp_str, "/current") != 0) || (tmp_str == lf->file)) {
        return (0);
    }

    tmp_str[0] = '\0';

    /* Get final name */
    djbp_name = strrchr(lf->file, '/');
    if (djbp_name == lf->file) {
        tmp_str[0] = '/';
        return (0);
    }

    os_strdup(djbp_name + 1, lf->djb_program_name);
    tmp_str[0] = '/';

    minfo("Using program name '%s' for DJB multilog file: '%s'.",
            lf->djb_program_name, lf->file);

    return (1);
}

void *read_djbmultilog(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAX_LOG_SIZE] = {0};
    char buffer[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;
    *rc = 0;

    /* Must have a valid program name */
    if (!lf->djb_program_name) {
        return (NULL);
    }

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    /* Get new entry */
    while (can_read() && fgets(str, OS_MAX_LOG_SIZE, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        if (is_valid_context_file) {
            OS_SHA1_Stream(context, NULL, str);
        }

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        /* Getting the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need_clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

        /* Multilog messages have the following format:
         * @40000000463246020c2ca16c xx...
         */
        if ((str_len > 26) &&
                (str[0] == '@') &&
                isalnum((int)str[1]) &&
                isalnum((int)str[2]) &&
                isalnum((int)str[3]) &&
                isalnum((int)str[24]) &&
                (str[25] == ' ')) {
            /* Remove spaces and tabs */
            p = str + 26;
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* If message has a valid syslog header, send as is */
            if ((str_len > 44) &&
                    (p[3] == ' ') &&
                    (p[6] == ' ') &&
                    (p[9] == ':') &&
                    (p[12] == ':') &&
                    (p[15] == ' ')) {
                p += 16;
                snprintf(buffer, sizeof(buffer), "%s", p);
            } else {
                /* We will add a proper syslog header */
                time_t djbtime;
                struct tm tm_result = { .tm_sec = 0 };

                djbtime = time(NULL);
                localtime_r(&djbtime, &tm_result);

                /* Syslog time: Apr 27 14:50:32  */
                const int size = snprintf(buffer, sizeof(buffer), "%s %02d %02d:%02d:%02d %s %s: %s",
                         djb_month[tm_result.tm_mon],
                         tm_result.tm_mday,
                         tm_result.tm_hour,
                         tm_result.tm_min,
                         tm_result.tm_sec,
                         djb_host,
                         lf->djb_program_name,
                         p);

                if (size < 0) {
                    merror("Error %d (%s) while reading message: '%s' (length = " FTELL_TT "): '%s'...", errno, strerror(errno), lf->file, FTELL_INT64 size, buffer);
                } else if ((size_t)size >= sizeof(buffer)) {
                    merror("Message size too big on file '%s' (length = " FTELL_TT "): '%s'...", lf->file, FTELL_INT64 size, buffer);
                }
            }
        }

        else {
            mdebug2("Invalid DJB log: '%s'", str);
            continue;
        }

        /* Check ignore and restrict log regex, if configured. */
        if (check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, str)) {
            continue;
        }

        mdebug2("Reading DJB multilog message: '%s'", buffer);

        /* Send message to queue */
        if (drop_it == 0) {
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }
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
