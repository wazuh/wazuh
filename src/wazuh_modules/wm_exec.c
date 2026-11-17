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

// pipe2()
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
#include "../../unit_tests/wrappers/windows/fileapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/libc/kernel32_wrappers.h"

// Local to this file: other users of these headers keep the real calls
#define ReadFile wrap_ReadFile
#define PeekNamedPipe wrap_PeekNamedPipe
#endif

static pthread_mutex_t wm_children_mutex;   // Mutex for child process pool

// Data structure to share with the reader thread

typedef struct ThreadInfo {
#ifdef WIN32
    CHAR * output;
    size_t length;
    size_t capacity;
    HANDLE pipe;            // Read end, owned by the state: closed when the last owner releases it
    volatile LONG stop;
    volatile LONG refs;     // Owners left: the reader and wm_exec()
    volatile LONG failure;  // WM_READER_* outcome, written by the reader before it exits
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

// Reader shutdown timings
#define WM_READER_JOIN_MS 1000
#define WM_READER_STOP_MS 1000

// How often the reader looks for new output and for a stop request
#define WM_EXEC_POLL_MS 20

// Consecutive empty polls that only yield the CPU before the reader starts sleeping
#define WM_EXEC_SPIN_POLLS 8

// Pipe buffer size requested from the system: a quota hint, not memory committed up front
#define WM_EXEC_PIPE_SIZE (1024 * 1024)

// Size of the buffer used to read and drop output that cannot be kept
#define WM_EXEC_DISCARD_SIZE 4096

// Reader outcomes: the output kept so far is still returned
#define WM_READER_OK 0
#define WM_READER_LIMIT 1
#define WM_READER_NOMEM 2

static DWORD WINAPI Reader(LPVOID args);    // Reading thread's start point

static void wm_reader_release(ThreadInfo * rinfo) {
    if (InterlockedDecrement(&rinfo->refs) == 0) {
        free(rinfo->output);
        CloseHandle(rinfo->pipe);
        free(rinfo);
    }
}

// Tells the reader to exit at its next poll, even if the pipe is still held open
STATIC void wm_reader_request_stop(ThreadInfo * rinfo) {
    InterlockedExchange(&rinfo->stop, 1);
}

static void wm_log_reader_wait_failure(void) {
    int winerror = GetLastError();

    merror("at wm_exec(): WaitForSingleObject(reader)(%d): %s", winerror, win_strerror(winerror));
}

// Returns false if the reader did not exit: it is then left to release the state when it does.

static bool wm_stop_reader(HANDLE hThread, ThreadInfo * rinfo) {
    DWORD result = WaitForSingleObject(hThread, WM_READER_JOIN_MS);

    if (result == WAIT_OBJECT_0) {
        return true;
    }

    wm_reader_request_stop(rinfo);

    if (result == WAIT_FAILED) {
        wm_log_reader_wait_failure();
        return false;
    }

    result = WaitForSingleObject(hThread, WM_READER_STOP_MS);

    switch (result) {
    case WAIT_OBJECT_0:
        // The pipe was still open after the command ended or was terminated: the output may be incomplete
        mdebug1("at wm_exec(): Stopped reading the command output before its end.");
        return true;

    case WAIT_TIMEOUT:
        return false;

    default:
        wm_log_reader_wait_failure();
        return false;
    }
}

// Falls back to the child alone when it is not in a job

static void wm_terminate_process(HANDLE hJob, HANDLE hProcess) {
    if (hJob == NULL || !TerminateJobObject(hJob, 1)) {
        TerminateProcess(hProcess, 1);
    }
}

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *status, int secs, const char * add_path) {
    HANDLE hThread = NULL;
    HANDLE hJob = NULL;
    HANDLE hPipe = NULL;
    ThreadInfo * rinfo = NULL;
    DWORD dwCreationFlags;
    STARTUPINFO sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
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

        if (!CreatePipe(&hPipe, &sinfo.hStdOutput, NULL, WM_EXEC_PIPE_SIZE)) {
            winerror = GetLastError();
            merror("at wm_exec(): CreatePipe(%d): %s", winerror, win_strerror(winerror));
            return -1;
        }

        sinfo.hStdError = sinfo.hStdOutput;

        if (!SetHandleInformation(sinfo.hStdOutput, HANDLE_FLAG_INHERIT, 1)) {
            winerror = GetLastError();
            merror("at wm_exec(): SetHandleInformation(%d): %s", winerror, win_strerror(winerror));
            CloseHandle(hPipe);
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

    // Start suspended so the process joins its job before it can spawn children
    dwCreationFlags |= CREATE_SUSPENDED;

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
            CloseHandle(hPipe);
            CloseHandle(sinfo.hStdOutput);
        }
        return -1;
    }

    os_free(wcommand);

    // Close our copy of the write end at once, so no later child can inherit it

    if (output) {
        CloseHandle(sinfo.hStdOutput);
    }

    // Job creation is best effort: on failure only the direct child is terminated on timeout
    hJob = CreateJobObjectW(NULL, NULL);

    if (hJob == NULL) {
        winerror = GetLastError();
        mdebug1("at wm_exec(): CreateJobObject(%d): %s", winerror, win_strerror(winerror));
    } else {
        JOBOBJECT_BASIC_LIMIT_INFORMATION limits = { 0 };

        // Lets a descendant that asks for it leave the job; without it the process runs outside any job
        limits.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;

        if (!SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &limits, sizeof(limits))) {
            winerror = GetLastError();
            mdebug1("at wm_exec(): SetInformationJobObject(%d): %s", winerror, win_strerror(winerror));
            CloseHandle(hJob);
            hJob = NULL;
        } else if (!AssignProcessToJobObject(hJob, pinfo.hProcess)) {
            winerror = GetLastError();
            mdebug1("at wm_exec(): AssignProcessToJobObject(%d): %s", winerror, win_strerror(winerror));
            CloseHandle(hJob);
            hJob = NULL;
        }
    }

    if (ResumeThread(pinfo.hThread) == (DWORD)-1) {
        winerror = GetLastError();
        merror("at wm_exec(): ResumeThread(%d): %s", winerror, win_strerror(winerror));
        wm_terminate_process(hJob, pinfo.hProcess);

        if (hJob != NULL) {
            CloseHandle(hJob);
        }

        if (output) {
            CloseHandle(hPipe);
        }

        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
        return -1;
    }

    if (output) {
        // The reader may outlive this function, so it owns its data

        os_calloc(1, sizeof(ThreadInfo), rinfo);
        rinfo->pipe = hPipe;
        rinfo->refs = 2;

        // Create reading thread

        hThread = w_create_thread(NULL, 0, Reader, rinfo, 0, NULL);
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
        wm_terminate_process(hJob, pinfo.hProcess);
        retval = WM_ERROR_TIMEOUT;
        break;

    default:
        winerror = GetLastError();
        merror("at wm_exec(): WaitForSingleObject(%d): %s", winerror, win_strerror(winerror));
        wm_terminate_process(hJob, pinfo.hProcess);
        retval = -1;
    }

    if (output) {
        // Output

        if (wm_stop_reader(hThread, rinfo)) {
            if (rinfo->failure == WM_READER_LIMIT) {
                mwarn("String limit reached.");
            } else if (rinfo->failure == WM_READER_NOMEM) {
                merror("at wm_exec(): Cannot allocate memory for the command output.");
            }

            if (retval >= 0) {
                if (rinfo->output) {
                    // Best effort: a failed shrink keeps the original buffer
                    char * shrunk = (char *)realloc(rinfo->output, rinfo->length + 1);
                    *output = shrunk ? shrunk : rinfo->output;
                    rinfo->output = NULL;
                } else {
                    *output = strdup("");
                }
            }
        } else {
            // The reader frees the state when it exits; nothing it may still use is touched here
            mwarn("at wm_exec(): Could not collect the command output.");
            if (retval >= 0) {
                *output = NULL;
            }

            // A timeout that fired is still reported as one
            if (retval == 0) {
                retval = -1;
            }
        }

        wm_reader_release(rinfo);
        CloseHandle(hThread);
    }

    // Cleanup

    if (hJob != NULL) {
        CloseHandle(hJob);
    }

    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);

    return retval;
}

// Makes room in the output buffer for up to avail more bytes, within the size limit.
// Returns how many bytes can be read into the buffer, or 0 with the outcome set if none can.

static size_t wm_reader_reserve(ThreadInfo * tinfo, size_t avail) {
    size_t room = WM_STRING_MAX - tinfo->length;
    size_t nextsize;

    if (room == 0) {
        tinfo->failure = WM_READER_LIMIT;
        return 0;
    }

    if (avail < room) {
        room = avail;
    }

    nextsize = tinfo->length + room;

    if (nextsize + 1 > tinfo->capacity) {
        size_t newcap = tinfo->capacity ? tinfo->capacity : WM_BUFFER_MAX * 4;

        while (newcap < nextsize + 1) {
            newcap *= 2;
        }

        if (newcap > WM_STRING_MAX + 1) {
            newcap = WM_STRING_MAX + 1;
        }

        char * newbuf = (char *)realloc(tinfo->output, newcap);

        if (newbuf == NULL) {
            tinfo->failure = WM_READER_NOMEM;
            return 0;
        }

        tinfo->output = newbuf;
        tinfo->capacity = newcap;
    }

    return room;
}

// Waits for more output: yields for a few empty polls in a row, then sleeps
// so a quiet command costs little while a busy one is read without delay

static void wm_reader_idle(unsigned * empty_polls) {
    if (*empty_polls < WM_EXEC_SPIN_POLLS) {
        (*empty_polls)++;
        Sleep(0);
    } else {
        Sleep(WM_EXEC_POLL_MS);
    }
}

// Reading thread's start point

DWORD WINAPI Reader(LPVOID args) {
    ThreadInfo * tinfo = (ThreadInfo *)args;
    CHAR discard[WM_EXEC_DISCARD_SIZE];
    DWORD avail;
    DWORD nbytes;
    unsigned empty_polls = 0;

    // Reads only when the pipe has data, so it never blocks and sees stop. A failed peek means the data ended.
    // No logging: wm_exec() reports the outcome.

    while (!tinfo->stop && PeekNamedPipe(tinfo->pipe, NULL, 0, NULL, &avail, NULL)) {
        CHAR * dest = discard;
        size_t room = sizeof(discard);

        if (avail == 0) {
            wm_reader_idle(&empty_polls);
            continue;
        }

        // Once the output cannot be kept, keep draining so the command does not block on a full pipe
        if (tinfo->failure == WM_READER_OK) {
            size_t space = wm_reader_reserve(tinfo, avail);

            if (space > 0) {
                dest = tinfo->output + tinfo->length;
                room = space;
            }
        }

        if (!ReadFile(tinfo->pipe, dest, avail < room ? avail : (DWORD)room, &nbytes, NULL)) {
            break;
        }

        if (nbytes == 0) {
            wm_reader_idle(&empty_polls);
            continue;
        }

        empty_polls = 0;

        if (dest != discard) {
            tinfo->length += nbytes;
            tinfo->output[tinfo->length] = '\0';
        }
    }

    wm_reader_release(tinfo);

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

static void* reader(void *args);   // Reading thread's start point

// How often the reader checks whether the caller has given up on it, in milliseconds
#define WM_EXEC_READER_POLL_MS 1000

// Shortest and longest step between checks for a command to exit, in milliseconds. A command
// that just closed its output is usually still exiting, and becomes reapable within the first
// short step; the steps double from there so a long wait does not spin.
#define WM_EXEC_REAP_STEP_MIN_MS 1
#define WM_EXEC_REAP_STEP_MAX_MS 100

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
    long step_ms = WM_EXEC_REAP_STEP_MIN_MS;
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

        const struct timespec step = { step_ms / 1000, (step_ms % 1000) * 1000000 };
        nanosleep(&step, NULL);

        step_ms = (step_ms * 2 < WM_EXEC_REAP_STEP_MAX_MS) ? step_ms * 2 : WM_EXEC_REAP_STEP_MAX_MS;
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
        // the copies. pipe2() sets the flag atomically; without it (not Linux, or glibc < 2.9), a fork
        // in another thread between pipe() and the fcntl() calls can still leak the ends.
#if defined(__linux__) && !(defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 9)
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
                // A command just stopped by the timeout closes its output before it can be reaped
                if (retval == WM_ERROR_TIMEOUT) {
                    gettime(&timeout);
                    timeout.tv_sec += 1;
                }

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
