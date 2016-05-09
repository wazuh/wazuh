/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 25, 2016
 */

#include "wmodules.h"

static volatile int flag_timeout = -1;  // Flag: child process expired its runtime

// Check whether the last execution timed out

int wm_exec_timeout() {
    return flag_timeout;
}

#ifdef WIN32

// Windows version -------------------------------------------------------------

typedef struct ThreadArgs {
    CHAR *output;
    HANDLE pipe;
} ThreadArgs;

// Reading thread's start point
static DWORD WINAPI Reader(LPVOID args);

// Join string array to single whitespace-separated string
static LPSTR JoinArgs(char* const *argv);

// Execute command with timeout of secs

char* wm_exec(char* const *argv, int *status, int secs) {
    HANDLE thread;
    STARTUPINFO sinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
    LPSTR command = JoinArgs(argv);
    ThreadArgs threadargs = { 0 };
    DWORD exitcode;

    sinfo.cb = sizeof(STARTUPINFO);
    sinfo.dwFlags = STARTF_USESTDHANDLES;

    // Create stdout pipe and make it inheritable

    if (!CreatePipe(&threadargs.pipe, &sinfo.hStdOutput, NULL, 0)) {
        merror("%s: ERROR: CreatePipe()", ARGV0);
        return NULL;
    }

    sinfo.hStdError = sinfo.hStdOutput;

    if (!SetHandleInformation(sinfo.hStdOutput, HANDLE_FLAG_INHERIT, 1)) {
        merror("%s: ERROR: SetHandleInformation()", ARGV0);
        return NULL;
    }

    // Create child process and close inherited pipes

    if (!CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
        merror("%s: ERROR: CreateProcess(): %ld", ARGV0, GetLastError());
        return NULL;
    }

    CloseHandle(sinfo.hStdOutput);

    // Create reading thread

    thread = CreateThread(NULL, 0, Reader, &threadargs, 0, NULL);

    if (!thread) {
        merror("%s: ERROR: CreateThread(): %ld", ARGV0, GetLastError());
        return NULL;
    }

    // Get output

    switch (WaitForSingleObject(pinfo.hProcess, secs * 1000)) {
    case 0:
        WaitForSingleObject(thread, INFINITE);

        if (!threadargs.output)
            threadargs.output = strdup("");

        break;
    case WAIT_TIMEOUT:
        TerminateProcess(pinfo.hProcess, 1);
        WaitForSingleObject(pinfo.hProcess, INFINITE);
        WaitForSingleObject(thread, INFINITE);

        if (threadargs.output) {
            free(threadargs.output);
            threadargs.output = NULL;
        }
        break;
    default:
        merror("%s: ERROR: WaitForSingleObject()", ARGV0);
        TerminateProcess(pinfo.hProcess, 1);
        WaitForSingleObject(thread, INFINITE);

        if (!threadargs.output)
            threadargs.output = strdup("");
    }

    // Get status and cleanup

    GetExitCodeProcess(pinfo.hProcess, &exitcode);
    *status = exitcode;

    CloseHandle(threadargs.pipe);
    CloseHandle(thread);
    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);

    free(command);

    return threadargs.output;
}

// Reading thread's start point

DWORD WINAPI Reader(LPVOID args) {
    ThreadArgs *thread = (ThreadArgs *)args;
    CHAR buffer[WM_BUFFER_MAX + 1];
    DWORD length = 0;
    DWORD nbytes;

    while (ReadFile(thread->pipe, buffer, 1024, &nbytes, NULL)) {
        if (nbytes > 0) {
            int nextsize = length + nbytes;

            if (nbytes > WM_STRING_MAX) {
                merror("%s: WARN: String limit reached.", ARGV0);
                thread->output[length] = '\0';
                return 1;
            }

            thread->output = (char*)realloc(thread->output, nextsize + 1);
            memcpy(thread->output + length, buffer, nbytes);
            length = nextsize;
        } else
            break;
    }

    thread->output[length] = '\0';
    return 0;
}

// Join string array to single whitespace-separated string

LPSTR JoinArgs(char* const *argv) {
    int i;
    char *output = NULL;

    for (i = 0; argv[i]; i++)
        wm_strcat(&output, argv[i], ' ');

    return output;
}

#else

// Unix version ----------------------------------------------------------------

static void start_timer(int secs);      // Start timer and reset timeout flag
static void stop_timer();               // Stop timer
static void timer_handler(int signum);  // Handler for SIGALRM

static timer_t timerid;                 // Timer identifier

// Execute command with timeout of secs

char* wm_exec(char* const *argv, int *status, int secs)
{
    static char * const envp[] = { NULL };
    char buffer[WM_BUFFER_MAX + 1];
    char *output = NULL;
    pid_t pid;
    int length = 0;
    int nbytes;
    int pipe_fd[2];

    // Create pipe for child's stdout

    if (pipe(pipe_fd) < 0)
        return NULL;

    // Fork

    pid = fork();

    switch (pid) {
    case -1:

        // Error
        return NULL;

    case 0:

        // Child

        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);

        if (execve(argv[0], argv, envp) < 0)
            return NULL;

        // Child won't return

    default:

        // Parent

        close(pipe_fd[1]);
        start_timer(secs);

        while (!flag_timeout && (nbytes = read(pipe_fd[0], buffer, WM_BUFFER_MAX)) > 0) {
            int nextsize = length + nbytes;

            if (nextsize > WM_STRING_MAX) {
                merror("%s: WARN: String limit reached.", ARGV0);
                break;
            }

            os_realloc(output, nextsize + 1, output);
            memcpy(output + length, buffer, nbytes);
            length = nextsize;
        }

        stop_timer();
        kill(pid, SIGKILL);

        if (flag_timeout) {
            if (output) {
                free(output);
                output = NULL;
            }
        } else {
            if (output)
                output[length] = '\0';
            else
                output = strdup("");
        }

        waitpid(pid, status, 0);
        *status = WEXITSTATUS(*status);
        close(pipe_fd[0]);

        return output;
    }
}

// Start timer and reset timeout flag

void start_timer(int secs) {
    struct itimerspec value = { .it_interval = { 0, 0 }, .it_value = { secs, 0 } };

    // If this is the first time, create timer

    if (flag_timeout == -1) {
        const struct sigaction action = { .sa_handler = timer_handler };
        struct sigevent event = { .sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGALRM };

        sigaction(SIGALRM, &action, NULL);
        timer_create(CLOCK_MONOTONIC, &event, &timerid);
    }

    flag_timeout = 0;
    timer_settime(timerid, 0, &value, NULL);
}

// Stop timer

void stop_timer() {
    struct itimerspec value = { .it_interval = { 0, 0 }, .it_value = { 0, 0 } };
    timer_settime(timerid, 0, &value, NULL);
}

// Handler for SIGALRM

void timer_handler(int signum)
{
    if (signum == SIGALRM) {
        flag_timeout = 1;
    }
}

#endif // WIN32
