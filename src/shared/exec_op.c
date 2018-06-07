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

 #ifndef WIN32

#include <shared.h>

// Open a stream from a process without shell (execvp form)
wfd_t * wpopenv(const char * path, char * const * argv, int flags) {
    pid_t pid;
    int pipe_fd[2];
    wfd_t * wfd;
    FILE * fp = NULL;

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        if (pipe(pipe_fd) < 0) {
            return NULL;
        }

        if (fp = fdopen(pipe_fd[0], "r"), !fp) {
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            return NULL;
        }
    }

    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file = fp;

    switch (pid = fork(), pid) {
    case -1:
        // Error
        break;

    case 0:
        // Child code

        if (flags & W_CHECK_WRITE && !access(path, W_OK)) {
            merror("At wpopenv(): file '%s' has write permissions.", path);
            _exit(127);
        }

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            if (flags & W_BIND_STDOUT) {
                dup2(pipe_fd[1], STDOUT_FILENO);
            } else {
                close(STDOUT_FILENO);
            }

            if (flags & W_BIND_STDERR) {
                dup2(pipe_fd[1], STDERR_FILENO);
            } else {
                close(STDERR_FILENO);
            }

            close(pipe_fd[0]);
            close(pipe_fd[1]);
        } else {
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
        }

        close(STDIN_FILENO);

        execvp(path, argv);
        _exit(127);

    default:
        // Parent code

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            close(pipe_fd[1]);
        }
        wfd->pid = pid;
        return wfd;
    }

    // Error

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        fclose(wfd->file);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
    }

    free(wfd);
    return NULL;
}

// Open a stream from a process without shell (execlp form)
wfd_t * wpopenl(const char * path, int flags, ...) {
    int argi;
    char * arg;
    char ** argv;
    va_list args;
    wfd_t * wfd;

    os_malloc(sizeof(char *), argv);
    va_start(args, flags);

    for (argi = 0; arg = va_arg(args, char *), arg; ++argi) {
        argv[argi] = strdup(arg);
        os_realloc(argv, (argi + 2) * sizeof(char *), argv);
    }

    va_end(args);
    argv[argi] = NULL;
    wfd = wpopenv(path, argv, flags);

    while (argi > 0) {
        free(argv[--argi]);
    }

    free(argv);
    return wfd;
}

// Close stream and return exit status
int wpclose(wfd_t * wfd) {
    pid_t pid;
    int wstatus;

    if (wfd->file) {
        fclose(wfd->file);
    }

    while (pid = waitpid(wfd->pid, &wstatus, 0), pid == -1 && errno == EINTR);
    free(wfd);
    return pid == -1 ? -1 : wstatus;
}

#endif
