/*
 * Subprocess execution library
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2018
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

// Open a stream from a process without shell (execvp form)
wfd_t * wpopenv(const char * path, char * const * argv, int flags) {
    wfd_t * wfd;
    FILE * fp_in = NULL;
    FILE * fp_out = NULL;

#ifdef WIN32
    if (is_network_path(path)) {
        errno = EACCES;
        mwarn(NETWORK_PATH_EXECUTED, path);
        return (NULL);
    }

    int fd;
    LPTSTR lpCommandLine = NULL;
    HANDLE hPipeIn[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    HANDLE hPipeOut[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    STARTUPINFO sinfo = { .cb = sizeof(STARTUPINFO), .dwFlags = STARTF_USESTDHANDLES };
    PROCESS_INFORMATION pinfo = { 0 };

    // Create pipes

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        if (!CreatePipe(&hPipeOut[0], &hPipeOut[1], NULL, 0)) {
            merror("CreatePipe(): %ld", GetLastError());
            return NULL;
        }

        if (!SetHandleInformation(hPipeOut[1], HANDLE_FLAG_INHERIT, 1)) {
            merror("SetHandleInformation(): %ld", GetLastError());
            CloseHandle(hPipeOut[0]);
            CloseHandle(hPipeOut[1]);
            return NULL;
        }

        if (fd = _open_osfhandle((int)hPipeOut[0], 0), fd < 0) {
            merror("_open_osfhandle(): %ld", GetLastError());
            CloseHandle(hPipeOut[0]);
            CloseHandle(hPipeOut[1]);
            return NULL;
        }

        if (fp_out = _fdopen(fd, "r"), !fp_out) {
            merror("_fdopen(): %ld", GetLastError());
            _close(fd);
            CloseHandle(hPipeOut[1]);
            return NULL;
        }

        sinfo.hStdOutput = flags & W_BIND_STDOUT ? hPipeOut[1] : NULL;
        sinfo.hStdError = flags & W_BIND_STDERR ? hPipeOut[1] : NULL;
    }

    if (flags & W_BIND_STDIN) {
        if (!CreatePipe(&hPipeIn[0], &hPipeIn[1], NULL, 0)) {
            merror("CreatePipe(): %ld", GetLastError());

            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                CloseHandle(hPipeOut[1]);
            }

            return NULL;
        }

        if (!SetHandleInformation(hPipeIn[0], HANDLE_FLAG_INHERIT, 1)) {
            merror("SetHandleInformation(): %ld", GetLastError());
            CloseHandle(hPipeIn[0]);
            CloseHandle(hPipeIn[1]);

            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                CloseHandle(hPipeOut[1]);
            }

            return NULL;
        }

        if (fd = _open_osfhandle((int)hPipeIn[1], 0), fd < 0) {
            merror("_open_osfhandle(): %ld", GetLastError());
            CloseHandle(hPipeIn[0]);
            CloseHandle(hPipeIn[1]);

            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                CloseHandle(hPipeOut[1]);
            }

            return NULL;
        }

        if (fp_in = _fdopen(fd, "w"), !fp_in) {
            merror("_fdopen(): %ld", GetLastError());
            _close(fd);
            CloseHandle(hPipeIn[0]);

            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                CloseHandle(hPipeOut[1]);
            }

            return NULL;
        }

        sinfo.hStdInput = hPipeIn[0];
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

        mdebug2("path = '%s', command = '%s'", path, lpCommandLine);
    }

    if (!CreateProcess(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
        mdebug1("CreateProcess(): %ld", GetLastError());

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            fclose(fp_out);
            CloseHandle(hPipeOut[1]);
        }

        if (flags & W_BIND_STDIN) {
            fclose(fp_in);
            CloseHandle(hPipeIn[0]);
        }

        if (lpCommandLine) {
            free(lpCommandLine);
        }

        return NULL;
    }

    free(lpCommandLine);
    os_calloc(1, sizeof(wfd_t), wfd);

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        CloseHandle(hPipeOut[1]);
        wfd->file_out = fp_out;
    }

    if (flags & W_BIND_STDIN) {
        CloseHandle(hPipeIn[0]);
        wfd->file_in = fp_in;
    }

    wfd->pinfo = pinfo;
    return wfd;

#else

    pid_t pid;
    int pipe_in[2] = { -1, -1 };
    int pipe_out[2] = { -1, -1 };

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        if (pipe(pipe_out) < 0) {
            return NULL;
        }

        fp_out = fdopen(pipe_out[0], "r");

        if (fp_out == NULL) {
            close(pipe_out[0]);
            close(pipe_out[1]);
            return NULL;
        }
    }

    if (flags & W_BIND_STDIN) {
        if (pipe(pipe_in) < 0) {
            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                close(pipe_out[1]);
            }

            return NULL;
        }

        fp_in = fdopen(pipe_in[1], "w");
        if (fp_in == NULL) {
            close(pipe_in[0]);
            close(pipe_in[1]);

            if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                fclose(fp_out);
                close(pipe_out[1]);
            }

            return NULL;
        }
    }

    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_in = fp_in;
    wfd->file_out = fp_out;

    switch (pid = fork(), pid) {
    case -1:
        // Error
        break;

    case 0:
        // Child code

        if (flags & W_CHECK_WRITE && !waccess(path, W_OK)) {
            merror("At wpopenv(): file '%s' has write permissions.", path);
            _exit(127);
        }

        int fd_null = open("/dev/null", O_RDWR, 0);

        if (fd_null < 0) {
            merror_exit(FOPEN_ERROR, "/dev/null", errno, strerror(errno));
        }

        if (flags & W_BIND_STDOUT) {
            dup2(pipe_out[1], STDOUT_FILENO);
        } else {
            dup2(fd_null, STDOUT_FILENO);
        }

        if (flags & W_BIND_STDERR) {
            dup2(pipe_out[1], STDERR_FILENO);
        } else {
            dup2(fd_null, STDERR_FILENO);
        }

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            close(pipe_out[0]); // Used by parent process.
            close(pipe_out[1]); // Already duplicated.
        }

        if (flags & W_BIND_STDIN) {
            dup2(pipe_in[0], STDIN_FILENO);
            close(pipe_in[0]);  // Already duplicated.
            close(pipe_in[1]);  // Used by parent process.
        } else {
            dup2(fd_null, STDIN_FILENO);
        }

        close(fd_null);
        setsid();
        execvp(path, argv);
        _exit(127);

    default:
        // Parent code

        if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
            close(pipe_out[1]);
        }

        if (flags & W_BIND_STDIN) {
            close(pipe_in[0]);
        }

        wfd->pid = pid;
        return wfd;
    }

    // Error

    if (flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
        fclose(fp_out);
        close(pipe_out[1]);
    }

    if (flags & W_BIND_STDIN) {
        fclose(fp_in);
        close(pipe_in[0]);
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

    if (wfd->file_in) {
        fclose(wfd->file_in);
    }

    if (wfd->file_out) {
        fclose(wfd->file_out);
    }

#ifdef WIN32
    DWORD exitcode;

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

    while (pid = waitpid(wfd->pid, &wstatus, 0), pid == -1 && errno == EINTR);
    free(wfd);
    return pid == -1 ? -1 : wstatus;
#endif
}
