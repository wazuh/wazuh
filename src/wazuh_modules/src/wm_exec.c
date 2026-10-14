/*
 * Wazuh Module Manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// pipe2(), on Linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
    bool done;      // The reader has stopped reading; guarded by mutex
    bool abandon;   // The caller gave up waiting for end of file; guarded by mutex
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
            CloseHandle(tinfo.pipe);
            CloseHandle(sinfo.hStdOutput);
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

    if (!wCreateProcessW(NULL, wcommand, NULL, NULL, TRUE, dwCreationFlags, NULL, NULL, &sinfo, &pinfo)) {
        winerror = GetLastError();
        mwarn("Cannot run '%s': %s (%d)", command, win_strerror(winerror), winerror);
        os_free(wcommand);
        if (output) {
            CloseHandle(tinfo.pipe);
            CloseHandle(sinfo.hStdOutput);
        }
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
#include <poll.h>

#ifndef _GNU_SOURCE
extern char ** environ;
#endif

static void* reader(void *args);   // Reading thread's start point

// How often the reader checks whether the caller has given up on it, in milliseconds
#define WM_EXEC_READER_POLL_MS 1000

/**
 * @brief Wait for the reader thread to stop reading. The caller holds tinfo->mutex.
 * @param tinfo Data shared with the reader thread.
 * @param deadline Absolute time to give up at, or NULL to wait with no limit.
 * @return 0 once the reader is done, ETIMEDOUT if the deadline passed first, or the error
 *         pthread_cond_(timed)wait() reported.
 */
static int wm_exec_wait_reader(ThreadInfo * tinfo, const struct timespec * deadline) {
    while (!tinfo->done) {
        const int rc = deadline ? pthread_cond_timedwait(&tinfo->finished, &tinfo->mutex, deadline)
                                : pthread_cond_wait(&tinfo->finished, &tinfo->mutex);

        if (rc != 0) {
            return tinfo->done ? 0 : rc;
        }
    }

    return 0;
}

/**
 * @brief Stop a command whose output is still being read. The caller holds tinfo->mutex.
 *
 * SIGTERM goes to the whole process group first, so the command can exit cleanly. A group
 * that is still holding the pipe after wazuh_modules.kill_timeout seconds gets SIGKILL. If the
 * pipe stays open even then, a process that left the group holds it, and the reader is told
 * to stop instead of waiting for an end of file that may never come.
 *
 * @param pid Process ID of the command, which leads its own process group.
 * @param tinfo Data shared with the reader thread.
 */
static void wm_exec_stop_reading_command(pid_t pid, ThreadInfo * tinfo) {
    struct timespec deadline;

    kill(-pid, SIGTERM);

    gettime(&deadline);
    deadline.tv_sec += wm_kill_timeout;

    if (wm_exec_wait_reader(tinfo, &deadline) == 0) {
        return;
    }

    mdebug1("Process group %d did not stop %d seconds after SIGTERM. Killing it.", pid, wm_kill_timeout);
    kill(-pid, SIGKILL);

    gettime(&deadline);
    deadline.tv_sec += 1;

    if (wm_exec_wait_reader(tinfo, &deadline) != 0) {
        mdebug1("The output pipe of process %d is still open after it was killed. Abandoning it.", pid);
        tinfo->abandon = true;
    }
}

/**
 * @brief Stop a command run without output capture and reap it.
 *
 * Same escalation as wm_exec_stop_reading_command(): SIGTERM to the process group, then
 * SIGKILL if the command has not exited after wazuh_modules.kill_timeout seconds.
 *
 * @param pid Process ID of the command, which leads its own process group.
 * @param status Filled in with the exit status of the command.
 * @return pid once reaped, or -1 if waitpid() failed.
 */
static pid_t wm_exec_stop_command(pid_t pid, int * status) {
    kill(-pid, SIGTERM);

    for (int waited = 0; waited < wm_kill_timeout; waited++) {
        const pid_t reaped = waitpid(pid, status, WNOHANG);

        if (reaped != 0) {
            return reaped;
        }

        sleep(1);
    }

    const pid_t reaped = waitpid(pid, status, WNOHANG);

    if (reaped != 0) {
        return reaped;
    }

    mdebug1("Process group %d did not stop %d seconds after SIGTERM. Killing it.", pid, wm_kill_timeout);
    kill(-pid, SIGKILL);

    return waitpid(pid, status, 0);
}

/**
 * @brief Wait for a command to exit, up to a deadline.
 *
 * @param pid Process ID of the command.
 * @param status Filled in with the exit status of the command once reaped.
 * @param deadline Absolute time, as gettime() reports it, to give up at.
 * @return pid once reaped, 0 if it is still running at the deadline, or -1 if waitpid() failed.
 */
static pid_t wm_exec_wait_child(pid_t pid, int * status, const struct timespec * deadline) {
    static const struct timespec step = { 0, 100000000 }; // 100 ms
    struct timespec now;

    for (;;) {
        const pid_t reaped = waitpid(pid, status, WNOHANG);

        if (reaped != 0) {
            return reaped;
        }

        gettime(&now);

        if (now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) {
            return 0;
        }

        nanosleep(&step, NULL);
    }
}

/**
 * @brief Translate a raw waitpid() status into the exit code callers see
 * @param status Raw status as filled in by waitpid()
 * @return The process' own exit code if it exited normally, or 128 + the
 *         signal number if it was killed by one (the same convention shells
 *         use) -- WEXITSTATUS() alone is unspecified on a signalled process
 *         and reads as 0 on Linux, silently reporting a crash as success.
 */
STATIC int wm_exec_exit_code(int status) {
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status);
}

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path)
{
    return wm_exec_env(command, output, exitcode, secs, add_path, NULL);
}

// Execute command with timeout of secs and extra environment variables

int wm_exec_env(char *command, char **output, int *exitcode, int secs, const char * add_path, char * const * env)
{
    char ** argv;
    pid_t pid;
    int pipe_fd[2];
    ThreadInfo tinfo = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, false, false };
    pthread_t thread;
    struct timespec timeout = { 0, 0 };
    int retval = -1;
    int status;

    if (exitcode) {
        *exitcode = 0;
    }

    // Create pipe for child's stdout

    if (output) {
        // Both ends close on exec: a command another thread launches meanwhile must not inherit
        // the write end, or this command's reader would not see end of file until that one exits
        // too. The child still gets a usable stdout and stderr, since dup2() clears the flag on
        // the copies. pipe2() sets the flag atomically; where it is missing, a fork in another
        // thread between pipe() and the fcntl() calls can still leak the ends.
#ifdef __linux__
        if (pipe2(pipe_fd, O_CLOEXEC) < 0) {
            merror("At wm_exec(): pipe2(): %s", strerror(errno));
            return -1;
        }
#else
        if (pipe(pipe_fd) < 0) {
            merror("At wm_exec(): pipe(): %s", strerror(errno));
            return -1;
        }
        w_descriptor_cloexec(pipe_fd[0]);
        w_descriptor_cloexec(pipe_fd[1]);
#endif
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

        // Only this child's copy of the environment changes, and exec replaces it right away
        for (char * const * var = env; var && *var; var++) {
            if (putenv(*var) != 0) {
                merror("at wm_exec(): Unable to set an environment variable (%s).", strerror(errno));
            }
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

                // The write end was already closed above. Nobody will read the command's
                // output, so do not leave it running nor unreaped. The child may not have
                // made its own process group yet, so signal it directly as well.
                close(pipe_fd[0]);
                kill(-pid, SIGKILL);
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                wm_remove_sid(pid);

                return -1;
            }

            gettime(&timeout);
            timeout.tv_sec += secs;

            // Wait for reading termination

            switch (wm_exec_wait_reader(&tinfo, secs ? &timeout : NULL)) {
            case 0:
                retval = 0;
                break;

            case ETIMEDOUT:
                retval = WM_ERROR_TIMEOUT;
                wm_exec_stop_reading_command(pid, &tinfo);
                break;

            default:
                wm_exec_stop_reading_command(pid, &tinfo);
            }
            // Wait for thread

            w_mutex_unlock(&tinfo.mutex);
            pthread_join(thread, NULL);

            // Cleanup

            w_mutex_destroy(&tinfo.mutex);
            w_cond_destroy(&tinfo.finished);

            // Wait for child process. End of file on the pipe does not mean the command is gone:
            // it may have sent its output elsewhere and kept running, or ignored SIGTERM while
            // the processes holding the pipe died. Bound the wait by what is left of the timeout.

            pid_t reaped = waitpid(pid, &status, WNOHANG);

            if (reaped == 0 && secs) {
                if (reaped = wm_exec_wait_child(pid, &status, &timeout), reaped == 0) {
                    retval = WM_ERROR_TIMEOUT;
                    reaped = wm_exec_stop_command(pid, &status);
                }
            } else if (reaped == 0) {
                reaped = waitpid(pid, &status, 0);
            }

            switch (reaped) {
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
                    *exitcode = wm_exec_exit_code(status);
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
                        *exitcode = wm_exec_exit_code(status);
                    }

                    break;
                }
            } while(secs >= 0);

            if(retval != 0) {
                retval = WM_ERROR_TIMEOUT;

                // Stop the whole process group and wait for the child process

                switch (wm_exec_stop_command(pid, &status)) {
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
                        *exitcode = wm_exec_exit_code(status);
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
                    *exitcode = wm_exec_exit_code(status);
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

    for (;;) {
        struct pollfd pfd = { .fd = tinfo->pipe, .events = POLLIN };
        bool abandon;

        // Checked on every pass, not only when the pipe is idle: a process that left the
        // command's group may keep writing, and the caller has killed the command by then.
        w_mutex_lock(&tinfo->mutex);
        abandon = tinfo->abandon;
        w_mutex_unlock(&tinfo->mutex);

        if (abandon) {
            break;
        }

        const int ready = poll(&pfd, 1, WM_EXEC_READER_POLL_MS);

        if (ready == 0 || (ready < 0 && errno == EINTR)) {
            continue;
        }

        if (ready < 0 || (nbytes = read(tinfo->pipe, buffer, WM_BUFFER_MAX)) <= 0) {
            break;
        }

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
    tinfo->done = true;
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
