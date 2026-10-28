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

/* Snort already ends the priority line with a space; a second one breaks the snort decoder */
static void append_part(char *f_msg, size_t size, const char *part) {
    size_t len = strlen(f_msg);

    if (len > 0 && len < size - 1 && f_msg[len - 1] != ' ') {
        f_msg[len++] = ' ';
        f_msg[len] = '\0';
    }

    strncat(f_msg, part, size - len - 1);
}

/* MM/DD-hh:mm:ss, or MM/DD/YY-hh:mm:ss with Snort's show_year */
static int is_date_line(const char *str) {
    return str[2] == '/' && (str[5] == '-' || (str[5] == '/' && str[8] == '-'));
}

/* The text of a date line after its date and time, NULL if str is not a date line */
static const char *date_line_text(const char *str) {
    const char *space = is_date_line(str) ? strchr(str, ' ') : NULL;

    return space != NULL ? space + 1 : NULL;
}

/* Queue the alert, unless the ignore and restrict regexes of the localfile drop it, or drop_it is set */
static void send_alert(logreader *lf, const char *message, int drop_it) {
    if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, message)) {
        w_msg_hash_queues_push(message, lf->file, strlen(message) + 1, lf->log_target, LOCALFILE_MQ);
    }
}

static bool is_alert_header(const char *str) {
    return strncmp(str, "[**] [", 6) == 0;
}

/* A line without its line end at the end of the file is still being written */
static bool is_unfinished_line(logreader *lf, const char *str) {
    return strchr(str, '\n') == NULL && feof(lf->fp);
}

typedef enum {
    ALERT_NONE,                 /* Between alerts */
    ALERT_AFTER_HEADER,         /* The header is read: the classification comes next */
    ALERT_AFTER_CLASSIFICATION  /* The classification is read: AppID lines and the date line come next */
} alert_stage_t;

/* The alert being assembled from its lines */
typedef struct {
    alert_stage_t stage;
    char message[OS_MAX_LOG_SIZE];
} alert_t;

typedef enum {
    LINE_ACCEPTED,  /* Part of the alert, or between alerts */
    ALERT_COMPLETE, /* The date line: the message is ready to send */
    LINE_REJECTED   /* Breaks the format */
} line_result_t;

/* First part of the message. Between alerts only a header means something, any other line is skipped */
static line_result_t add_first_line(alert_t *alert, const char *str) {
    if (is_alert_header(str)) {
        snprintf(alert->message, sizeof(alert->message), "%s", str);
        alert->stage = ALERT_AFTER_HEADER;
    }
    return LINE_ACCEPTED;
}

static line_result_t add_second_line(alert_t *alert, const char *str) {
    const char *text;

    /* Second line has the [Classification: */
    if (strncmp(str, "[Classification: ", 16) == 0 || strncmp(str, "[Priority: ", 10) == 0) {
        append_part(alert->message, sizeof(alert->message), str);
        alert->stage = ALERT_AFTER_CLASSIFICATION;
        return LINE_ACCEPTED;
    }

    /* If it is a preprocessor message, it will not have the classification */
    if ((text = date_line_text(str)) != NULL) {
        append_part(alert->message, sizeof(alert->message), LABEL_PREPROCESSOR_MESSAGE);
        append_part(alert->message, sizeof(alert->message), text);
        alert->stage = ALERT_NONE;
        return ALERT_COMPLETE;
    }
    return LINE_REJECTED;
}

static line_result_t add_third_line(alert_t *alert, const char *str) {
    const char *text;

    /* Snort with OpenAppID writes "[AppID: <name>] " before the date line */
    if (strncmp(str, "[AppID: ", 8) == 0) {
        append_part(alert->message, sizeof(alert->message), str);
        return LINE_ACCEPTED;
    }

    /* Third line has the 01/13-15 (date) */
    if ((text = date_line_text(str)) != NULL) {
        append_part(alert->message, sizeof(alert->message), text);
        alert->stage = ALERT_NONE;
        return ALERT_COMPLETE;
    }
    return LINE_REJECTED;
}

static line_result_t add_line(alert_t *alert, const char *str) {
    switch (alert->stage) {
    case ALERT_AFTER_HEADER:
        return add_second_line(alert, str);
    case ALERT_AFTER_CLASSIFICATION:
        return add_third_line(alert, str);
    default:
        return add_first_line(alert, str);
    }
}

/* Remove the line end. Returns false if the line has none */
static bool strip_line_end(char *str) {
    char *end = strrchr(str, '\n');

    if (end == NULL) {
        return false;
    }

    *end = '\0';
    if (end > str && *(end - 1) == '\r') {
        *(end - 1) = '\0';
    }
    return true;
}

/* The line limit does not cut an alert: going back to its header instead would never get past an alert
 * longer than the limit */
static bool line_limit_reached(int lines, const alert_t *alert) {
    return maximum_lines && lines >= maximum_lines && alert->stage == ALERT_NONE;
}

/* Where the alert being assembled starts, to read it again if the read stops before its date line */
typedef struct {
    int64_t position;
    EVP_MD_CTX *context; /* Hash context at position. NULL if the file is not hashed */
} alert_start_t;

static EVP_MD_CTX *copy_context(const EVP_MD_CTX *context) {
    EVP_MD_CTX *copy = EVP_MD_CTX_new();

    if (copy != NULL && EVP_MD_CTX_copy(copy, context) != 1) {
        EVP_MD_CTX_free(copy);
        copy = NULL;
    }
    return copy;
}

/* Called before the header line is hashed, so the copy does not cover it. A NULL context means that the file
 * is not hashed. Returns false, and keeps the previous start, if the hash could not be copied */
static bool mark_alert_start(alert_start_t *start, int64_t position, const EVP_MD_CTX *context) {
    EVP_MD_CTX *saved = NULL;

    if (context != NULL && (saved = copy_context(context)) == NULL) {
        return false;
    }
    EVP_MD_CTX_free(start->context);
    start->context = saved;
    start->position = position;
    return true;
}

/* Take the offset and the hash back to the start of the alert being assembled. The hash is swapped, not
 * copied, so going back cannot fail; start ends up with the hash that was left behind */
static void restore_alert_start(alert_start_t *start, EVP_MD_CTX **context, int64_t *position) {
    *position = start->position;
    if (start->context != NULL) {
        EVP_MD_CTX *left_behind = *context;

        *context = start->context;
        start->context = left_behind;
    }
}

/* Make the next read start at position */
static void retry_from(logreader *lf, int64_t position) {
    mdebug2("Message not complete from '%s'. Trying again.", lf->file);
    if (position >= 0) {
        w_fseek(lf->fp, position, SEEK_SET);
    }
}

/* Read snort_full files */
void *read_snortfull(logreader *lf, int *rc, int drop_it) {
    alert_t alert = { ALERT_NONE, {0} };
    char str[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;
    bool line_left_unread = false;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);
    alert_start_t alert_start = { current_position, NULL };

    while (can_read() && !line_limit_reached(lines, &alert) && fgets(str, sizeof(str), lf->fp)) {

        lines++;

        /* Read it again whole, once the writer finishes it */
        if (is_unfinished_line(lf, str)) {
            line_left_unread = true;
            break;
        }

        if (alert.stage == ALERT_NONE && is_alert_header(str)) {
            if (!mark_alert_start(&alert_start, current_position, is_valid_context_file ? context : NULL)) {
                merror("Could not save the hash state of '%s' at the start of an alert. Trying again later.",
                       lf->file);
                *rc = -1;
                line_left_unread = true;
                break;
            }
        }

        if (is_valid_context_file) {
            w_hash_read_line(lf, context, str, &current_position);
        } else {
            current_position = w_ftell(lf->fp);
        }

        line_result_t result = strip_line_end(str) ? add_line(&alert, str) : LINE_REJECTED;

        if (result == LINE_REJECTED) {
            merror("Bad formated snort full file.");
            *rc = -1;
            EVP_MD_CTX_free(alert_start.context);
            /* The bad line was hashed: store the state so the next read and a restart resume after it */
            if (is_valid_context_file) {
                w_update_file_status(lf->file, current_position, context);
            } else {
                EVP_MD_CTX_free(context);
            }
            return (NULL);
        }

        if (result == ALERT_COMPLETE) {
            send_alert(lf, alert.message, drop_it);
        }
    }

    /* The read stopped before the date line of the alert being assembled */
    if (alert.stage != ALERT_NONE) {
        restore_alert_start(&alert_start, &context, &current_position);
    }

    /* Without an open alert, current_position is the start of the line left unread, which was not hashed */
    if (alert.stage != ALERT_NONE || line_left_unread) {
        retry_from(lf, current_position);
    } else {
        current_position = w_ftell(lf->fp);
    }
    EVP_MD_CTX_free(alert_start.context);

    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
