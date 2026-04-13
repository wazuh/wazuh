/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "shared.h"
#include "logcollector.h"

/* Read datagrams from a UNIX datagram socket */
void *read_socket(logreader *lf, int *rc, int drop_it) {
    int lines = 0;
    char buf[OS_MAXSTR + 1];

    *rc = 0;

    while (can_read() && (!maximum_lines || lines < maximum_lines)) {
        ssize_t rbytes = recv(lf->socket_fd, buf, OS_MAXSTR, 0);

        if (rbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            mdebug1("Error reading from socket '%s': %s", lf->file, strerror(errno));
            *rc = -1;
            break;
        }

        if (rbytes == 0) {
            /* Empty datagram — skip but keep reading queued messages */
            continue;
        }

        buf[rbytes] = '\0';
        size_t msg_len = (size_t)rbytes;

        /* Strip trailing newline if present */
        if (msg_len > 0 && buf[msg_len - 1] == '\n') {
            buf[--msg_len] = '\0';
        }

        if (msg_len == 0) {
            continue;
        }

        if (strlen(buf) != msg_len) {
            mdebug2("Message from socket '%s' contains zero-bytes. Dropping.", lf->file);
            continue;
        }

        if (!w_utf8_valid(buf)) {
            mdebug2("Message from socket '%s' is not valid UTF-8. Dropping.", lf->file);
            continue;
        }

        lines++;

        if ((int)msg_len >= OS_MAXSTR - 1) {
            mwarn("Datagram from socket '%s' may have been truncated (length = %zu): '%.*s'...",
                  lf->file, msg_len, sample_log_length, buf);
        } else {
            mdebug2("Reading socket message: '%.*s'%s", sample_log_length, buf,
                    (int)msg_len > sample_log_length ? "..." : "");
        }

        if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, buf)) {
            w_msg_hash_queues_push(buf, lf->file, msg_len + 1, lf->log_target, LOCALFILE_MQ);
        }
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return NULL;
}

#endif
