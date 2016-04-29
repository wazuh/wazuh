/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 25, 2016
 */

#include "wmodules.h"

static void start_timer(int secs);      // Start timer and reset timeout flag
static void stop_timer();               // Stop timer
static void timer_handler(int signum);  // Handler for SIGALRM

static timer_t timerid;                 // Timer identifier
static volatile int flag_timeout = -1;  // Flag: child process expired its runtime

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

// Check whether the last execution timed out

int wm_exec_timeout() {
    return flag_timeout;
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
