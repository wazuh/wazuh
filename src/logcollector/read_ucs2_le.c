/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the syslog */
#ifdef WIN32

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"


/* Read ucs2 files */
void *read_ucs2_le(logreader *lf, int *rc, int drop_it) {
    int __ms_reported = 0;
    wchar_t str[OS_MAXSTR + 1];
    int lines = 0;
    int64_t offset = 0;
    int64_t rbytes = 0;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    for (offset = w_ftell(lf->fp); can_read() && (!maximum_lines || lines < maximum_lines) && offset >= 0 && fgetws(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp); offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;

        mdebug2("Bytes read from '%s': %lld bytes",lf->file,rbytes);

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }

        /* fgetws() stores one wchar_t per two bytes read, so lengths in str are wide characters */
        size_t wchars = (size_t) rbytes / sizeof(wchar_t);
        bool newline = wchars > 0 && str[wchars - 1] == L'\n';
        bool truncated = !newline && wchars >= OS_MAXSTR - OS_LOG_HEADER - 1;

        /* We may not have gotten a line feed because we reached EOF */
        if (!newline && !truncated && feof(lf->fp)) {
            /* Message not complete. Return. */
            mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length,(char* ) str, rbytes > sample_log_length ? "..." : "");
            w_fseek(lf->fp, current_position, SEEK_SET);
            break;
        }

        /* Every byte the read moves past is part of the stored hash */
        if (is_valid_context_file) {
            OS_SHA1_Stream_Bytes(context, (const char *) str, (size_t) rbytes);
        }

        if (newline) {
            str[wchars - 1] = L'\0';
        } else if (truncated) {
            /* Message size > maximum allowed: send what we got so far */
            str[wchars - 1] = L'\0';

            /* Discard the rest of the line now, before any continue below can skip it */
            wchar_t rest[OS_SIZE_1024];
            int64_t rest_offset = offset + rbytes;
            int64_t rest_bytes;

            while (fgetws(rest, OS_SIZE_1024, lf->fp) != NULL) {
                rest_bytes = w_ftell(lf->fp) - rest_offset;

                /* Flow control */
                if (rest_bytes <= 1) {
                    break;
                }

                if (is_valid_context_file) {
                    OS_SHA1_Stream_Bytes(context, (const char *) rest, (size_t) rest_bytes);
                }

                rest_offset += rest_bytes;

                /* Stop at the end of the line */
                size_t rest_wchars = (size_t) rest_bytes / sizeof(wchar_t);
                if (rest_wchars > 0 && rest[rest_wchars - 1] == L'\n') {
                    break;
                }
            }

            rbytes = rest_offset - offset;

            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = %lld): '%.*s'...", lf->file, rbytes, sample_log_length, (char* ) str);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = %lld): '%.*s'...", lf->file, rbytes, sample_log_length, (char* ) str);
            }
        }

        wchar_t * p;

        if ((p = wcsrchr(str, L'\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (rbytes <= 4) {
            current_position = w_ftell(lf->fp);
            continue;
        }

        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            current_position = w_ftell(lf->fp);
            continue;
        }

        mdebug2("Reading syslog message: '%.*s'%s", sample_log_length, (char * )str, rbytes > sample_log_length ? "..." : "");

        /* Send message to queue */
        if (drop_it == 0) {

            long int utf8_bytes = 0;
            char *utf8_string = NULL;

            if (utf8_bytes = WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)str, -1, NULL, 0, NULL, NULL), utf8_bytes > 0) {
                os_calloc(utf8_bytes + 1, sizeof(char), utf8_string);
                utf8_bytes = WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)str, -1, utf8_string, utf8_bytes, NULL, NULL);
                utf8_string[utf8_bytes] = '\0';
                mdebug2("Line converted to UTF-8 is %ld bytes",utf8_bytes);
            }

            if (!utf8_bytes) {
                mdebug1("Couldn't transform read line to UTF-8: %lu.", GetLastError());
                os_free(utf8_string);
                current_position = w_ftell(lf->fp);
                continue;
            }

            if (!check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, utf8_string)) {
                w_msg_hash_queues_push(utf8_string, lf->file, utf8_bytes, lf->log_target, LOCALFILE_MQ);
            }

            os_free(utf8_string);
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
#endif
