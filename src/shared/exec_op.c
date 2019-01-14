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

#include <shared.h>
#include <wazuh_modules/wmodules.h>

// Open a stream from a process without shell (execvp form)
wfd_t * wpopenv(const char * path, char * const * argv, int flags) {
    wfd_t * wfd;
    FILE * fp = NULL;

#ifdef WIN32
    int fd;
    LPTSTR lpCommandLine = NULL;
    HANDLE hPipe[2];
    STARTUPINFO sinfo = { .cb = sizeof(STARTUPINFO), .dwFlags = STARTF_USESTDHANDLES };
    PROCESS_INFORMATION pinfo = { 0 };

    // Create pipes

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        if (!CreatePipe(&hPipe[0], &hPipe[1], NULL, 0)) {
            merror("CreatePipe(): %ld", GetLastError());
            return NULL;
        }

        if (!SetHandleInformation(hPipe[1], HANDLE_FLAG_INHERIT, 1)) {
            merror("SetHandleInformation(): %ld", GetLastError());
            CloseHandle(hPipe[0]);
            CloseHandle(hPipe[1]);
            return NULL;
        }

        if (fd = _open_osfhandle((int)hPipe[0], 0), fd < 0) {
            merror("_open_osfhandle(): %ld", GetLastError());
            CloseHandle(hPipe[0]);
            CloseHandle(hPipe[1]);
            return NULL;
        }

        if (fp = _fdopen(fd, "r"), !fp) {
            merror("_fdopen(): %ld", GetLastError());
            _close(fd);
            CloseHandle(hPipe[1]);
            return NULL;
        }

        sinfo.hStdOutput = flags & W_BIND_STDOUT ? hPipe[1] : NULL;
        sinfo.hStdError = flags & W_BIND_STDERR ? hPipe[1] : NULL;
    }

    // Format command string

    if (argv[0]) {
        unsigned i;
        size_t zarg;
        size_t zcommand = strlen(argv[0]) + 3;
        os_malloc(zcommand, lpCommandLine);
        snprintf(lpCommandLine, zcommand, "\"%s\"", argv[0]);

        for (i = 1; argv[i]; ++i) {
            zarg = strlen(argv[i]) + 1;
            os_realloc(lpCommandLine, zcommand + zarg, lpCommandLine);
            snprintf(lpCommandLine + zcommand - 1, zarg + 1, " %s", argv[i]);
            zcommand += zarg;
        }
    }

    mdebug2("path = '%s', command = '%s'", path, lpCommandLine);

    if (!CreateProcess(path, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
        mdebug1("CreateProcess(): %ld", GetLastError());

        if (fp) {
            fclose(fp);
            CloseHandle(hPipe[1]);
        }

        return NULL;
    }

    free(lpCommandLine);
    os_calloc(1, sizeof(wfd_t), wfd);

    if (fp) {
        CloseHandle(hPipe[1]);
        wfd->file = fp;
    }

    if (flags & W_APPEND_POOL) {
        wm_append_handle(pinfo.hProcess);
        wfd->append_pool = 1;
    }

    wfd->pinfo = pinfo;
    return wfd;

#else

    pid_t pid;
    int pipe_fd[2];

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

        int fd = open("/dev/null", O_RDWR, 0);

        if (fd < 0) {
            merror_exit(FOPEN_ERROR, "/dev/null", errno, strerror(errno));
        }

        dup2(fd, STDIN_FILENO);

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            if (flags & W_BIND_STDOUT) {
                dup2(pipe_fd[1], STDOUT_FILENO);
            } else {
                dup2(fd, STDOUT_FILENO);
            }

            if (flags & W_BIND_STDERR) {
                dup2(pipe_fd[1], STDERR_FILENO);
            } else {
                dup2(fd, STDERR_FILENO);
            }

            close(pipe_fd[0]);
            close(pipe_fd[1]);
        } else {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
        }

        close(fd);
        setsid();
        execvp(path, argv);
        _exit(127);

    default:
        // Parent code

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            close(pipe_fd[1]);
        }

        if (flags & W_APPEND_POOL) {
            wm_append_sid(pid);
            wfd->append_pool = 1;
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
#endif // WIN32
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
    int wstatus;

    if (wfd->file) {
        fclose(wfd->file);
    }

#ifdef WIN32
    DWORD exitcode;

    if (wfd->append_pool) {
        wm_remove_handle(wfd->pinfo.hProcess);
    }

    switch (WaitForSingleObject(wfd->pinfo.hProcess, INFINITE)) {
    case WAIT_OBJECT_0:
        GetExitCodeProcess(wfd->pinfo.hProcess, &exitcode);
        wstatus = exitcode;
        break;
    default:
        merror("WaitForSingleObject(): %ld", GetLastError());
        wstatus = -1;
    }

    CloseHandle(wfd->pinfo.hProcess);
    CloseHandle(wfd->pinfo.hThread);
    free(wfd);
    return wstatus;
#else
    pid_t pid;

    if (wfd->append_pool) {
        wm_remove_sid(wfd->pid);
    }

    while (pid = waitpid(wfd->pid, &wstatus, 0), pid == -1 && errno == EINTR);
    free(wfd);
    return pid == -1 ? -1 : wstatus;
#endif
}
