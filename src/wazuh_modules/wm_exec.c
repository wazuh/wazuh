/*
 * Wazuh Module Manager
 * Copyright (C) 2016 Wazuh Inc.
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

// Data structure to share with the reader thread

typedef struct ThreadInfo {
#ifdef WIN32
    CHAR *output;
    HANDLE pipe;
#else
    pthread_mutex_t mutex;
    pthread_cond_t finished;
    int pipe;
    char *output;
#endif
} ThreadInfo;

#ifdef WIN32

// Windows version -------------------------------------------------------------

static DWORD WINAPI Reader(LPVOID args);    // Reading thread's start point

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *status, int secs) {
    HANDLE hThread = NULL;
    DWORD dwCreationFlags;
    STARTUPINFO sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
    ThreadInfo tinfo = { 0 };
    int retval = 0;

    sinfo.cb = sizeof(STARTUPINFO);

    if (output) {
        sinfo.dwFlags = STARTF_USESTDHANDLES;

        // Create stdout pipe and make it inheritable

        if (!CreatePipe(&tinfo.pipe, &sinfo.hStdOutput, NULL, 0)) {
            merror("CreatePipe()");
            return -1;
        }

        sinfo.hStdError = sinfo.hStdOutput;

        if (!SetHandleInformation(sinfo.hStdOutput, HANDLE_FLAG_INHERIT, 1)) {
            merror("SetHandleInformation()");
            return -1;
        }
    }

    // Create child process and close inherited pipes

    dwCreationFlags = wm_task_nice < -10 ? HIGH_PRIORITY_CLASS :
                      wm_task_nice < 0 ? ABOVE_NORMAL_PRIORITY_CLASS :
                      wm_task_nice == 0 ? NORMAL_PRIORITY_CLASS :
                      wm_task_nice < 10 ? BELOW_NORMAL_PRIORITY_CLASS :
                      IDLE_PRIORITY_CLASS;

    if (!CreateProcess(NULL, command, NULL, NULL, TRUE, dwCreationFlags, NULL, NULL, &sinfo, &pinfo)) {
        merror("CreateProcess(): %ld", GetLastError());
        return -1;
    }

    if (output) {
        CloseHandle(sinfo.hStdOutput);

        // Create reading thread

        hThread = CreateThread(NULL, 0, Reader, &tinfo, 0, NULL);

        if (!hThread) {
            merror("CreateThread(): %ld", GetLastError());
            return -1;
        }
    }

    switch (WaitForSingleObject(pinfo.hProcess, secs * 1000)) {
    case 0:
        if (status) {
            DWORD exitcode;
            GetExitCodeProcess(pinfo.hProcess, &exitcode);
            *status = exitcode;
        }

        break;

    case WAIT_TIMEOUT:
        TerminateProcess(pinfo.hProcess, 1);
        retval = WM_ERROR_TIMEOUT;
        break;

    default:
        merror("WaitForSingleObject()");
        TerminateProcess(pinfo.hProcess, 1);
        retval = -1;
    }

    if (output) {
        // Output

        if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) {
            TerminateThread(hThread, 1);
            WaitForSingleObject(hThread, INFINITE);
        }

        if (retval >= 0)
            *output = tinfo.output ? tinfo.output : strdup("");
        else
            free(tinfo.output);

        CloseHandle(hThread);
        CloseHandle(tinfo.pipe);
    }

    // Cleanup

    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);

    return retval;
}

// Reading thread's start point

DWORD WINAPI Reader(LPVOID args) {
    ThreadInfo *tinfo = (ThreadInfo *)args;
    CHAR buffer[WM_BUFFER_MAX + 1];
    DWORD length = 0;
    DWORD nbytes;

    while (ReadFile(tinfo->pipe, buffer, 1024, &nbytes, NULL), nbytes > 0) {
        int nextsize = length + nbytes;

        if (nextsize <= WM_STRING_MAX) {
            tinfo->output = (char*)realloc(tinfo->output, nextsize + 1);
            memcpy(tinfo->output + length, buffer, nbytes);
            length = nextsize;
            tinfo->output[length] = '\0';
        } else {
            mwarn("String limit reached.");
            break;
        }
    }

    return 0;
}

#else

// Unix version ----------------------------------------------------------------

#include <unistd.h>
#define EXECVE_ERROR 0xFF

#ifndef _GNU_SOURCE
extern char ** environ;
#endif

static void* reader(void *args);   // Reading thread's start point

static volatile pid_t wm_children[WM_POOL_SIZE] = { 0 };                // Child process pool
static pthread_mutex_t wm_children_mutex = PTHREAD_MUTEX_INITIALIZER;   // Mutex for child process pool

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *exitcode, int secs)
{
    char **argv;
    pid_t pid;
    int pipe_fd[2];
    ThreadInfo tinfo = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL };
    pthread_t thread;
    struct timespec timeout = { 0, 0 };
    int retval = -1;
    int status;

    // Create pipe for child's stdout

    if (output && pipe(pipe_fd) < 0) {
        merror("At wm_exec(): pipe(): %s", strerror(errno));
        return -1;
    }

    // Fork

    switch (pid = fork()) {
    case -1:

        // Error

        merror("fork()");
        return -1;

    case 0:

        // Child

        argv = wm_strtok(command);

        if (output) {
            close(pipe_fd[0]);
            dup2(pipe_fd[1], STDOUT_FILENO);
            dup2(pipe_fd[1], STDERR_FILENO);
            close(pipe_fd[1]);
        } else {
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
        }

        close(STDIN_FILENO);

        setsid();
        if (nice(wm_task_nice)) {}

        if (execve(argv[0], argv, environ) < 0)
            exit(EXECVE_ERROR);

        break;

    default:

        // Parent

        wm_append_sid(pid);

        if (output) {
            close(pipe_fd[1]);
            tinfo.pipe = pipe_fd[0];

            // Launch thread

            pthread_mutex_lock(&tinfo.mutex);

            if (pthread_create(&thread, NULL, reader, &tinfo)) {
                merror("Couldn't create reading thread.");
                pthread_mutex_unlock(&tinfo.mutex);
                return -1;
            }

            gettime(&timeout);
            timeout.tv_sec += secs;

            // Wait for reading termination

            switch (secs ? pthread_cond_timedwait(&tinfo.finished, &tinfo.mutex, &timeout) : pthread_cond_wait(&tinfo.finished, &tinfo.mutex)) {
            case 0:
                retval = 0;
                break;

            case ETIMEDOUT:
                retval = WM_ERROR_TIMEOUT;
                kill(-pid, SIGTERM);
                pthread_cancel(thread);
                break;

            default:
                kill(-pid, SIGTERM);
                pthread_cancel(thread);
            }

            // Wait for thread

            pthread_mutex_unlock(&tinfo.mutex);
            pthread_join(thread, NULL);

            // Cleanup

            pthread_mutex_destroy(&tinfo.mutex);
            pthread_cond_destroy(&tinfo.finished);
        } else {
            retval = 0;
        }

        // Wait for child process

        switch (waitpid(pid, &status, 0)) {
        case -1:
            merror("waitpid()");
            retval = -1;
            break;

        default:
            if (WEXITSTATUS(status) == EXECVE_ERROR) {
                merror("Invalid command: '%s': (%d) %s", command, errno, strerror(errno));
                retval = -1;
            } else if (exitcode)
                *exitcode = WEXITSTATUS(status);
        }

        wm_remove_sid(pid);

        if (output) {
            // Setup output

            if (retval >= 0) {
                *output = tinfo.output ? tinfo.output : strdup("");
            } else {
                free(tinfo.output);
            }
        }
    }

    return retval;
}

// Reading thread's start point

void* reader(void *args) {
    ThreadInfo *tinfo = (ThreadInfo *)args;
    char buffer[WM_BUFFER_MAX + 1];
    int length = 0;
    int nbytes;

    while ((nbytes = read(tinfo->pipe, buffer, WM_BUFFER_MAX)) > 0) {
        int nextsize = length + nbytes;

        if (nextsize <= WM_STRING_MAX) {
            tinfo->output = (char*)realloc(tinfo->output, nextsize + 1);
            memcpy(tinfo->output + length, buffer, nbytes);
            length = nextsize;
        } else {
            mwarn("String limit reached.");
            break;
        }
    }

    if (tinfo->output)
        tinfo->output[length] = '\0';

    pthread_mutex_lock(&tinfo->mutex);
    pthread_cond_signal(&tinfo->finished);
    pthread_mutex_unlock(&tinfo->mutex);

    close(tinfo->pipe);
    return NULL;
}

// Add process group to pool

void wm_append_sid(pid_t sid) {
    int i;

    pthread_mutex_lock(&wm_children_mutex);

    for (i = 0; i < WM_POOL_SIZE; i++) {
        if (!wm_children[i]) {
            wm_children[i] = sid;
            break;
        }
    }

    pthread_mutex_unlock(&wm_children_mutex);

    if (i == WM_POOL_SIZE)
        merror("Child process pool is full. Couldn't register sid %d.", (int)sid);
}

// Remove process group from pool

void wm_remove_sid(pid_t sid) {
    int i;

    pthread_mutex_lock(&wm_children_mutex);

    for (i = 0; i < WM_POOL_SIZE; i++) {
        if (wm_children[i] == sid) {
            wm_children[i] = 0;
            break;
        }
    }

    if (i == WM_POOL_SIZE)
        merror("Child process %d not found.", (int)sid);

    pthread_mutex_unlock(&wm_children_mutex);
}

// Terminate every child process group. Doesn't wait for them!

void wm_kill_children() {
    // This function may be called from a signal handler

    int i;
    int timeout;
    pid_t sid;

    for (i = 0; i < WM_POOL_SIZE; i++) {
        sid = wm_children[i];

        if (sid) {
            if (wm_kill_timeout) {
                timeout = wm_kill_timeout;

                // Fork a process to kill the child

                switch (fork()) {
                case -1:
                    merror("wm_kill_children(): Couldn't fork: (%d) %s.", errno, strerror(errno));
                    break;

                case 0: // Child
                    kill(-sid, SIGTERM);

                    do {
                        sleep(1);

                        // Poll process, waitpid() does not work here

                        switch (kill(-sid, 0)) {
                        case -1:
                            switch (errno) {
                            case ESRCH:
                                exit(EXIT_SUCCESS);

                            default:
                                merror("wm_kill_children(): Couldn't wait PID %d: (%d) %s.", sid, errno, strerror(errno));
                                exit(EXIT_FAILURE);
                            }

                        default:
                            timeout--;
                        }
                    } while (timeout);

                    // If time is gone, kill process

                    mdebug1("Killing process group %d", sid);

                    kill(-sid, SIGKILL);
                    exit(EXIT_SUCCESS);

                default: // Parent
                    wm_children[i] = 0;
                }
            } else {
                // Kill immediately
                kill(-sid, SIGKILL);
            }
        }
    }
}

#endif // WIN32
