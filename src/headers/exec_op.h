/*
 * Subprocess execution library
 * Copyright (C) 2018 Wazuh Inc.
 * May 1, 2018
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EXEC_OP_H
#define EXEC_OP_H

#define W_BIND_STDOUT 1
#define W_BIND_STDERR 2

typedef struct wfd_t {
    FILE * file;
    pid_t pid;
} wfd_t;

// Open a stream from a process without shell (execvp form)
wfd_t * wpopenv(const char * path, char * const * argv, int flags);

// Open a stream from a process without shell (execlp form)
wfd_t * wpopenl(const char * path, int flags, ...);

// Close stream and return exit status
int wpclose(wfd_t * wfd);

#endif // EXEC_OP_H
