/*
 * Wazuh Module Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 25, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#if defined(WAZUH_UNIT_TESTING) && defined(WIN32)
#include "../../unit_tests/wrappers/windows/processthreadsapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/handleapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/libc/kernel32_wrappers.h"
#endif

static pthread_mutex_t wm_children_mutex;   // Mutex for child process pool

// Data structure to share with the reader thread

typedef struct ThreadInfo {
#ifdef WIN32
    CHAR * output;
    HANDLE pipe;
#else
    pthread_mutex_t mutex;
    pthread_cond_t finished;
    int pipe;
    char * output;
#endif
} ThreadInfo;

STATIC OSList * wm_children_list = NULL;    // Child process list

// Clean node data
static void wm_children_node_clean(pid_t *p_sid) {
    os_free(p_sid);
}

// Initialize children pool

void wm_children_pool_init() {
    w_mutex_init(&wm_children_mutex, NULL);
    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, (void (*)(void *))wm_children_node_clean);
}

#ifdef WIN32

// Windows version -------------------------------------------------------------

static DWORD WINAPI Reader(LPVOID args);    // Reading thread's start point

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *status, int secs, const char * add_path) {
    HANDLE hThread = NULL;
    DWORD dwCreationFlags;
    STARTUPINFO sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
    ThreadInfo tinfo = { 0 };
    int retval = 0;
    int winerror = 0;

    // Add environment variable if exists

    if (add_path != NULL) {

        char * new_path;
        os_calloc(OS_SIZE_6144, sizeof(char), new_path);
        char * env_path = getenv("PATH");

        if (!env_path) {
            snprintf(new_path, OS_SIZE_6144 - 1, "PATH=%s", add_path);
        } else if (strlen(env_path) >= OS_SIZE_6144) {
            merror("at wm_exec(): PATH environment variable too large.");
            retval = -1;
        } else {
            snprintf(new_path, OS_SIZE_6144 - 1, "PATH=%s;%s", add_path, env_path);
        }

        // Using '_putenv' instead of '_putenv_s' for compatibility with Windows XP.
        if (_putenv(new_path) < 0) {
            merror("at wm_exec(): Unable to set new 'PATH' environment variable (%s).", strerror(errno));
            retval = -1;
        }

        char * new_env = getenv("PATH");
        if (new_env != NULL) {
            mdebug1("New 'PATH' environment variable set: '%s'", new_env);
        }
        os_free(new_path);
    }

    sinfo.cb = sizeof(STARTUPINFO);

    if (output) {
        sinfo.dwFlags = STARTF_USESTDHANDLES;

        // Create stdout pipe and make it inheritable

        if (!CreatePipe(&tinfo.pipe, &sinfo.hStdOutput, NULL, 0)) {
            winerror = GetLastError();
            merror("at wm_exec(): CreatePipe(%d): %s", winerror, win_strerror(winerror));
            return -1;
        }

        sinfo.hStdError = sinfo.hStdOutput;

        if (!SetHandleInformation(sinfo.hStdOutput, HANDLE_FLAG_INHERIT, 1)) {
            winerror = GetLastError();
            merror("at wm_exec(): SetHandleInformation(%d): %s", winerror, win_strerror(winerror));
            return -1;
        }
    }

    // Create child process and close inherited pipes

    dwCreationFlags = wm_task_nice < -10 ? HIGH_PRIORITY_CLASS :
                      wm_task_nice < 0 ? ABOVE_NORMAL_PRIORITY_CLASS :
                      wm_task_nice == 0 ? NORMAL_PRIORITY_CLASS :
                      wm_task_nice < 10 ? BELOW_NORMAL_PRIORITY_CLASS :
                      IDLE_PRIORITY_CLASS;

    size_t size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, command, -1, NULL, 0);
    wchar_t *wcommand;
    os_calloc(size, sizeof(wchar_t), wcommand);

    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, command, -1, wcommand, size);
    mdebug2("UTF-8 command: %ls", wcommand);

    if (!CreateProcessW(NULL, wcommand, NULL, NULL, TRUE, dwCreationFlags, NULL, NULL, &sinfo, &pinfo)) {
        winerror = GetLastError();
        merror("at wm_exec(): CreateProcess(%d): %s", winerror, win_strerror(winerror));
        os_free(wcommand);
        return -1;
    }

    os_free(wcommand);

    if (output) {
        CloseHandle(sinfo.hStdOutput);

        // Create reading thread

        hThread = w_create_thread(NULL, 0, Reader, &tinfo, 0, NULL);
    }

    switch (WaitForSingleObject(pinfo.hProcess, secs ? (unsigned)(secs * 1000) : INFINITE)) {
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
        winerror = GetLastError();
        merror("at wm_exec(): WaitForSingleObject(%d): %s", winerror, win_strerror(winerror));
        TerminateProcess(pinfo.hProcess, 1);
        retval = -1;
    }

    if (output) {
        // Output

        if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) {
            TerminateThread(hThread, 1);
            WaitForSingleObject(hThread, INFINITE);
        }

        if (retval >= 0) {
            *output = tinfo.output ? tinfo.output : strdup("");
        } else {
            free(tinfo.output);
        }

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
    ThreadInfo * tinfo = (ThreadInfo *)args;
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

// Add process to pool

void wm_append_handle(HANDLE hProcess) {
    HANDLE * p_hProcess = NULL;

    w_mutex_lock(&wm_children_mutex);
    if (wm_children_list != NULL) {
        os_calloc(1, sizeof(HANDLE), p_hProcess);
        *p_hProcess = hProcess;

        void * retval = OSList_AddData(wm_children_list, (void *)p_hProcess);

        if (retval == NULL) {
            merror("Child process handle %p could not be registered in the children list.", hProcess);
            os_free(p_hProcess);
        }
    }
    w_mutex_unlock(&wm_children_mutex);
}

// Remove process from pool

void wm_remove_handle(HANDLE hProcess) {
    OSListNode * node_it = NULL;
    HANDLE * p_hProcess = NULL;

    w_mutex_lock(&wm_children_mutex);
    if (wm_children_list != NULL) {
        OSList_foreach(node_it, wm_children_list) {
            p_hProcess = (HANDLE *)node_it->data;
            if (p_hProcess && *p_hProcess == hProcess) {
                OSList_DeleteThisNode(wm_children_list, node_it);
                os_free(p_hProcess);
                w_mutex_unlock(&wm_children_mutex);
                return;
            }
        }
        mwarn("Child process handle %p could not be removed because it was not found in the children list.", hProcess);
    }
    w_mutex_unlock(&wm_children_mutex);
}

// Terminate every child process group. Doesn't wait for them!

void wm_kill_children() {
    // This function may be called from a signal handler

    HANDLE * p_hProcess = NULL;
    OSListNode * node_it = NULL;

    w_mutex_lock(&wm_children_mutex);
    OSList_foreach(node_it, wm_children_list) {
        if (node_it->data) {
            p_hProcess = (HANDLE *)node_it->data;
            TerminateProcess(*p_hProcess, ERROR_PROC_NOT_FOUND);
        }
    }

    // Release dynamic children's list
    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;

    w_mutex_unlock(&wm_children_mutex);
}

#else

// Unix version ----------------------------------------------------------------

#include <unistd.h>

#ifndef _GNU_SOURCE
extern char ** environ;
#endif

static void* reader(void *args);   // Reading thread's start point

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path)
{
    char ** argv;
    pid_t pid;
    int pipe_fd[2];
    ThreadInfo tinfo = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL };
    pthread_t thread;
    struct timespec timeout = { 0, 0 };
    int retval = -1;
    int status;

    if (exitcode) {
        *exitcode = 0;
    }

    // Create pipe for child's stdout

    if (output) {
        if (pipe(pipe_fd) < 0) {
            merror("At wm_exec(): pipe(): %s", strerror(errno));
            return -1;
        }
        w_descriptor_cloexec(pipe_fd[0]);
    }

    // Fork

    switch (pid = fork()) {
    case -1:

        // Error

        merror("Cannot run a subprocess: %s (%d)", strerror(errno), errno);

        if (output) {
            close(pipe_fd[0]);
            close(pipe_fd[1]);
        }

        return -1;

    case 0:

        // Child

        // Add environment variable if exists

        if (add_path != NULL) {

            char * new_path = NULL;
            os_calloc(OS_SIZE_6144, sizeof(char), new_path);
            char *env_path = getenv("PATH");

            if (!env_path) {
                snprintf(new_path, OS_SIZE_6144 - 1, "%s", add_path);
            } else if (strlen(env_path) >= OS_SIZE_6144) {
                merror("at wm_exec(): PATH environment variable too large.");
            } else {
                const int bytes_written = snprintf(new_path, OS_SIZE_6144, "%s:%s", add_path, env_path);

                if (bytes_written >= OS_SIZE_6144) {
                    merror("at wm_exec(): New environment variable too large.");
                }
                else if (bytes_written < 0) {
                    merror("at wm_exec(): New environment variable error: %d (%s).", errno, strerror(errno));
                }
            }

            if (setenv("PATH", new_path, 1) < 0) {
                merror("at wm_exec(): Unable to set new 'PATH' environment variable (%s).", strerror(errno));
            }

            char * new_env = getenv("PATH");
            if (new_env != NULL) {
                mdebug1("New 'PATH' environment variable set: '%s'", new_env);
            }
            os_free(new_path);
        }

        argv = w_strtok(command);

        int fd = open("/dev/null", O_RDWR, 0);

        if (fd < 0) {
            merror_exit(FOPEN_ERROR, "/dev/null", errno, strerror(errno));
        }

        dup2(fd, STDIN_FILENO);

        if (output) {
            close(pipe_fd[0]);
            dup2(pipe_fd[1], STDOUT_FILENO);
            dup2(pipe_fd[1], STDERR_FILENO);
            close(pipe_fd[1]);
        } else {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
        }

        close(fd);

        setsid();
        if (nice(wm_task_nice)) {}
        execvp(argv[0], argv);
        _exit(EXECVE_ERROR);

        break;

    default:

        // Parent

        wm_append_sid(pid);

        if (output) {
            close(pipe_fd[1]);
            tinfo.pipe = pipe_fd[0];

            // Launch thread

            w_mutex_lock(&tinfo.mutex);

            if (pthread_create(&thread, NULL, reader, &tinfo)) {
                merror("Couldn't create reading thread.");
                w_mutex_unlock(&tinfo.mutex);

                if (output) {
                    close(pipe_fd[0]);
                    close(pipe_fd[1]);
                }

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
                break;

            default:
                kill(-pid, SIGTERM);
            }
            // Wait for thread

            w_mutex_unlock(&tinfo.mutex);
            pthread_join(thread, NULL);

            // Cleanup

            w_mutex_destroy(&tinfo.mutex);
            w_cond_destroy(&tinfo.finished);

            // Wait for child process

            switch (waitpid(pid, &status, 0)) {
            case -1:
                merror("waitpid()");
                retval = -1;
                break;

            default:
                if (WEXITSTATUS(status) == EXECVE_ERROR) {
                    mdebug1("Invalid command: '%s': (%d) %s", command, errno, strerror(errno));
                    retval = -1;
                }

                if (exitcode)
                    *exitcode = WEXITSTATUS(status);
            }

        } else if (secs) {
            // Kill and timeout
            sleep(1);
            secs--;
            do {
                if (waitpid(pid,&status,WNOHANG) == 0) { // Command yet not finished
                    retval = -1;
                    switch (kill(pid, 0)) {
                    case -1:
                        switch(errno) {
                        case ESRCH:
                            merror("At wm_exec(): No such process. Couldn't wait PID %d: (%d) %s.", pid, errno, strerror(errno));
                            retval = -2;
                            break;

                        default:
                            merror("At wm_exec(): Couldn't wait PID %d: (%d) %s.", pid, errno, strerror(errno));
                            retval = -3;
                        }
                        break;

                    default:
                        if (secs > 0) {
                            sleep(1);
                            secs--;
                        } else if (!secs) {
                            secs--;
                            continue;
                        }
                    }

                    if (retval == -2 || retval == -3) {
                        break;
                    }

                } else { // Command finished
                    if (WEXITSTATUS(status) == EXECVE_ERROR) {
                        mdebug1("Invalid command: '%s': (%d) %s", command, errno, strerror(errno));
                        retval = -1;
                    } else {
                        retval = 0;
                    }

                    if (exitcode) {
                        *exitcode = WEXITSTATUS(status);
                    }

                    break;
                }
            } while(secs >= 0);

            if(retval != 0) {
                kill(pid,SIGTERM);
                retval = WM_ERROR_TIMEOUT;

                // Wait for child process

                switch (waitpid(pid, &status, 0)) {
                case -1:
                    merror("waitpid(): %s (%d)", strerror(errno), errno);
                    retval = -1;
                    break;

                default:
                    if (WEXITSTATUS(status) == EXECVE_ERROR) {
                        mdebug1("Invalid command: '%s': (%d) %s", command, errno, strerror(errno));
                        retval = -1;
                    }

                    if (exitcode)
                        *exitcode = WEXITSTATUS(status);
                }
            }
        } else {
            switch (waitpid(pid, &status, 0)) {
            case -1:
                merror("waitpid()");
                retval = -1;
                break;

            default:
                if (WEXITSTATUS(status) == EXECVE_ERROR) {
                    mdebug1("Invalid command: '%s': (%d) %s", command, errno, strerror(errno));
                    retval = -1;
                } else {
                    retval = 0;
                }

                if (exitcode) {
                    *exitcode = WEXITSTATUS(status);
                }
            }
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
    ThreadInfo * tinfo = (ThreadInfo *)args;
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

    if (tinfo->output) {
        tinfo->output[length] = '\0';
    }

    w_mutex_lock(&tinfo->mutex);
    w_cond_signal(&tinfo->finished);
    w_mutex_unlock(&tinfo->mutex);

    close(tinfo->pipe);
    return NULL;
}

// Add process group to pool

void wm_append_sid(pid_t sid) {
    pid_t * p_sid = NULL;

    w_mutex_lock(&wm_children_mutex);
    if (wm_children_list != NULL) {
        os_calloc(1, sizeof(pid_t), p_sid);
        *p_sid = sid;

        void * retval = OSList_AddData(wm_children_list, (void *)p_sid);

        if (retval == NULL) {
            merror("Child process ID %d could not be registered in the children list.", sid);
            os_free(p_sid);
        }
    }
    w_mutex_unlock(&wm_children_mutex);
}

// Remove process group from pool

void wm_remove_sid(pid_t sid) {

    OSListNode * node_it = NULL;
    pid_t * p_sid = NULL;

    w_mutex_lock(&wm_children_mutex);
    if (wm_children_list != NULL) {
        OSList_foreach(node_it, wm_children_list) {
            p_sid = (pid_t *)node_it->data;
            if (p_sid && *p_sid == sid) {
                OSList_DeleteThisNode(wm_children_list, node_it);
                os_free(p_sid);
                w_mutex_unlock(&wm_children_mutex);
                return;
            }
        }
        mwarn("Child process ID %d could not be removed because it was not found in the children list.", sid);
    }
    w_mutex_unlock(&wm_children_mutex);
}

// Terminate every child process group. Doesn't wait for them!

void wm_kill_children() {
    // This function may be called from a signal handler

    int timeout;
    pid_t sid;
    pid_t * p_sid = NULL;
    OSListNode * node_it = NULL;

    w_mutex_lock(&wm_children_mutex);
    OSList_foreach(node_it, wm_children_list) {
        p_sid = (pid_t *)node_it->data;
        if (p_sid) {
            sid = *p_sid;
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
                    break;

                }
            } else {
                // Kill immediately
                kill(-sid, SIGKILL);
            }
        }
    }

    // Release dynamic children's list
    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;

    w_mutex_unlock(&wm_children_mutex);
}

#endif // WIN32
