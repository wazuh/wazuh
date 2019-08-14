/*
 * Subprocess execution library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 1, 2018
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EXEC_OP_H
#define EXEC_OP_H

#define W_BIND_STDOUT   001
#define W_BIND_STDERR   002
#define W_CHECK_WRITE   004
#define W_APPEND_POOL   010

#ifdef WIN32
#define WEXITSTATUS(x) x
#endif

typedef struct wfd_t {
    FILE * file;
#ifdef WIN32
    PROCESS_INFORMATION pinfo;
#else
    pid_t pid;
#endif
    unsigned int append_pool:1;
} wfd_t;

// Open a stream from a process without shell (execvp form)
wfd_t * wpopenv(const char * path, char * const * argv, int flags);

// Open a stream from a process without shell (execlp form)
wfd_t * wpopenl(const char * path, int flags, ...);

// Close stream and return exit status
int wpclose(wfd_t * wfd);

#endif // EXEC_OP_H
