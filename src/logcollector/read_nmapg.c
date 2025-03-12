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

#define NMAPG_HOST  "Host: "
#define NMAPG_PORT  "Ports:"
#define NMAPG_OPEN  "open/"
#define NMAPG_STAT  "Status:"
#define PORT_PROTO  " %s(%s)"

/* Prototypes */
static char *__go_after(char *x, const char *y);
static char *__get_port(char *str, char *proto, char *port, size_t msize);


/* Get port and protocol */
static char *__get_port(char *str, char *proto, char *port, size_t msize)
{
    int filtered = 0;
    char *p, *q;

    /* Remov whitespace */
    while (*str == ' ') {
        str++;
    }

    /* Get port */
    p = strchr(str, '/');
    if (!p) {
        return (NULL);
    }
    *p = '\0';
    p++;

    /* Get port */
    strncpy(port, str, msize);
    port[msize - 1] = '\0';

    /* Check if the port is open */
    q = __go_after(p, NMAPG_OPEN);
    if (!q) {
        /* Port is not open */
        filtered = 1;
        q = p;

        /* Going to the start of protocol field */
        p = strchr(q, '/');
        if (!p) {
            return (NULL);
        }
        p++;
    } else {
        p = q;
    }

    /* Get protocol */
    str = p;
    p = strchr(str, '/');
    if (!p) {
        return (NULL);
    }
    *p = '\0';
    p++;

    strncpy(proto, str, msize);
    proto[msize - 1] = '\0';

    /* Set proto to null if port is not open */
    if (filtered) {
        proto[0] = '\0';
    }

    /* Remove slashes */
    if (*p == '/') {
        p++;
        q = p;
        p = strchr(p, ',');
        if (p) {
            return (p);
        }

        return (q);
    }

    return (NULL);
}

/* Check if the string matches */
static char *__go_after(char *x, const char *y)
{
    size_t x_s;
    size_t y_s;

    /* X and Y must be not null */
    if (!x || !y) {
        return (NULL);
    }

    x_s = strlen(x);
    y_s = strlen(y);

    if (x_s <= y_s) {
        return (NULL);
    }

    /* String does not match */
    if (strncmp(x, y, y_s) != 0) {
        return (NULL);
    }

    x += y_s;

    return (x);
}

/* Read Nmap grepable files */
void *read_nmapg(logreader *lf, int *rc, int drop_it) {
    int final_msg_s;
    int index = 0;
    int need_clear = 0;

    char str[OS_MAX_LOG_SIZE] = {0};
    char final_msg[OS_MAX_LOG_SIZE] = {0};
    char port[17] = {0};
    char proto[17] = {0};

    char *ip = NULL;
    char *p;
    char *q;

    int lines = 0;
    int bytes_written = 0;

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

        /* If need clear is set, we need to clear the line */
        if (need_clear) {
            if (q = strchr(str, '\n'), q != NULL) {
                need_clear = 0;
            }
            continue;
        }

        /* Remove \n at the end of the string */
        if ((q = strchr(str, '\n')) != NULL) {
            *q = '\0';
        } else {
            need_clear = 1;
        }

        /* Do not get commented lines */
        if ((str[0] == '#') || (str[0] == '\0')) {
            continue;
        }

        /* Get host */
        q = __go_after(str, NMAPG_HOST);
        if (!q) {
            goto file_error;
        }

        /* Get ip/hostname */
        p = strchr(q, ')');
        if (!p) {
            goto file_error;
        }

        /* Setting the valid ip */
        ip = q;

        /* Get the ports */
        q = strchr(p, '\t');
        if (!q) {
            goto file_error;
        }
        q++;

        /* Now fixing p, to have the closing parenthesis */
        p++;
        *p = '\0';

        /* q now should point to the ports */
        p = __go_after(q, NMAPG_PORT);
        if (!p) {
            /* Check if no port is available */
            p = __go_after(q, NMAPG_STAT);
            if (p) {
                continue;
            }

            goto file_error;
        }

        /* Generate final msg */
        bytes_written = snprintf(final_msg, sizeof(final_msg), "Host: %s, open ports:",
                 ip);

        if (bytes_written < 0) {
            final_msg_s = 0;
            merror("Error %d (%s) formatting string from file '%s' (length = " FTELL_TT "): '%s'...", errno, strerror(errno), lf->file, FTELL_INT64 bytes_written, final_msg);
        } else if ((size_t)bytes_written < sizeof(final_msg)) {
            final_msg_s = OS_MAX_LOG_SIZE - strlen(final_msg);
        } else {
            final_msg_s = 0;
            merror("Large message size from file '%s' (length = " FTELL_TT "): '%s'...", lf->file, FTELL_INT64 bytes_written, final_msg);
        }

        /* Get port and protocol */
        do {
            /* Avoid filling the buffer (3*port size) */
            if (final_msg_s < 27) {
                break;
            }

            p = __get_port(p, proto, port, 9);
            if (!p) {
                mdebug1("Bad formated nmap grepable file (port).");
                break;
            }

            /* Port not open */
            if (proto[0] == '\0') {
                continue;
            }

            /* Add ports */
            index = strlen(final_msg);
            index = snprintf((final_msg + index), final_msg_s, PORT_PROTO, port, proto);
            final_msg_s -= index;

        } while (*p == ',' && (p++));

        /* Check ignore and restrict log regex, if configured. */
        if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, final_msg)) {
            /* Send message to queue */
            w_msg_hash_queues_push(final_msg, lf->file, strlen(final_msg) + 1, lf->log_target, HOSTINFO_MQ);
        }

        /* Get next */
        continue;

        /* Handle errors */
file_error:

        merror("Bad formated nmap grepable file.");
        EVP_MD_CTX_free(context);
        *rc = -1;
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
