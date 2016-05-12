/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 25, 2016
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
    HANDLE thread;
    STARTUPINFO sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
    ThreadInfo tinfo = { 0 };
    int retval = 0;

    sinfo.cb = sizeof(STARTUPINFO);
    sinfo.dwFlags = STARTF_USESTDHANDLES;

    // Create stdout pipe and make it inheritable

    if (!CreatePipe(&tinfo.pipe, &sinfo.hStdOutput, NULL, 0)) {
        merror("%s: ERROR: CreatePipe()", ARGV0);
        return -1;
    }

    sinfo.hStdError = sinfo.hStdOutput;

    if (!SetHandleInformation(sinfo.hStdOutput, HANDLE_FLAG_INHERIT, 1)) {
        merror("%s: ERROR: SetHandleInformation()", ARGV0);
        return -1;
    }

    // Create child process and close inherited pipes

    if (!CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
        merror("%s: ERROR: CreateProcess(): %ld", ARGV0, GetLastError());
        return -1;
    }

    CloseHandle(sinfo.hStdOutput);

    // Create reading thread

    thread = CreateThread(NULL, 0, Reader, &tinfo, 0, NULL);

    if (!thread) {
        merror("%s: ERROR: CreateThread(): %ld", ARGV0, GetLastError());
        return -1;
    }

    // Get output

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
        merror("%s: ERROR: WaitForSingleObject()", ARGV0);
        TerminateProcess(pinfo.hProcess, 1);
        retval = -1;
    }

    // Output

    WaitForSingleObject(thread, INFINITE);

    if (retval >= 0)
        *output = tinfo.output ? tinfo.output : strdup("");
    else
        free(tinfo.output);

    // Cleanup

    CloseHandle(thread);
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

    while (ReadFile(tinfo->pipe, buffer, 1024, &nbytes, NULL)) {
        if (nbytes > 0) {
            int nextsize = length + nbytes;

            if (nextsize <= WM_STRING_MAX) {
                tinfo->output = (char*)realloc(tinfo->output, nextsize + 1);
                memcpy(tinfo->output + length, buffer, nbytes);
                length = nextsize;
            } else {
                merror("%s: WARN: String limit reached.", ARGV0);
                break;
            }
        }
        else
            break;
    }

    if (tinfo->output)
        tinfo->output[length] = '\0';

    CloseHandle(tinfo->pipe);
    return 0;
}

#else

// Unix version ----------------------------------------------------------------

#define EXECVE_ERROR 0xFF

void* reader(void *args);   // Reading thread's start point

// Work-around for OS X

static inline void get_time(struct timespec *ts) {
#ifdef __MACH__
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

// Execute command with timeout of secs

int wm_exec(char *command, char **output, int *exitcode, int secs)
{
    static char* const envp[] = { NULL };
    char **argv = wm_strsplit(command);
    pid_t pid;
    int pipe_fd[2];
    ThreadInfo tinfo = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL };
    pthread_t thread;
    struct timespec timeout = { 0, 0 };
    int retval = 0;
    int status;

    // Create pipe for child's stdout

    if (pipe(pipe_fd) < 0)
        return -1;

    // Fork

    switch (pid = fork()) {
    case -1:

        // Error

        merror("%s: ERROR: fork()", ARGV0);
        return -1;

    case 0:

        // Child

        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);

        if (execve(argv[0], argv, envp) < 0)
            exit(EXECVE_ERROR);

        // Child won't return

    default:

        // Parent

        close(pipe_fd[1]);
        tinfo.pipe = pipe_fd[0];

        // Launch thread

        pthread_mutex_lock(&tinfo.mutex);

        if (pthread_create(&thread, NULL, reader, &tinfo)) {
            merror("%s: ERROR: Couldn't create reading thread.", ARGV0);
            return -1;
        }

        get_time(&timeout);
        timeout.tv_sec += secs;

        // Wait for reading termination

        switch (pthread_cond_timedwait(&tinfo.finished, &tinfo.mutex, &timeout)) {
        case 0:
            break;

        case ETIMEDOUT:
            kill(pid, SIGKILL);
            retval = WM_ERROR_TIMEOUT;
            break;

        default:
            merror("%s: ERROR: pthread_cond_timedwait()", ARGV0);
            kill(pid, SIGKILL);
            retval = -1;
        }

        // Wait for thread

        pthread_mutex_unlock(&tinfo.mutex);
        pthread_join(thread, NULL);

        // Wait for child process

        switch (waitpid(pid, &status, WNOHANG)) {
        case -1:
            merror("%s: ERROR: waitpid()", ARGV0);
            retval = -1;
            break;

        case 0:
            merror("%s: WARN: Subprocess was killed.", ARGV0);
            kill(pid, SIGKILL);
            break;

        default:
            if (WEXITSTATUS(status) == EXECVE_ERROR)
                retval = -1;
            else if (exitcode)
                *exitcode = WEXITSTATUS(status);
        }

        // Setup output

        if (retval >= 0)
            *output = tinfo.output ? tinfo.output : strdup("");
        else
            free(tinfo.output);

        // Cleanup

        pthread_mutex_destroy(&tinfo.mutex);
        pthread_cond_destroy(&tinfo.finished);
        free(argv);

        return retval;
    }
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
            merror("%s: WARN: String limit reached.", ARGV0);
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

#endif // WIN32
