/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"

#ifndef WIN32
#include <sys/resource.h>
#include <sys/wait.h>
#endif

// Remove static qualifier from tests
#ifdef WAZUH_UNIT_TESTING
#define static
#endif

// Limits of the diff/fc child
#define FIM_DIFF_CHILD_TIMEOUT      10                  // Seconds of wall clock time
#define FIM_DIFF_CHILD_MAX_MEMORY   (512 * 1024 * 1024) // Bytes of address space
#define FIM_DIFF_CHILD_MAX_OUTPUT   OS_MAXSTR           // Bytes written to the output file (more than gen_diff_str() reads)

// Time limit used by fim_diff_exec(); a variable so that the tests can shorten it
static unsigned int fim_diff_exec_timeout = FIM_DIFF_CHILD_TIMEOUT;

#ifndef WIN32

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

// Candidate locations of diff; no PATH lookup
static const char *fim_diff_exec_bins[] = { "/usr/bin/diff", "/bin/diff", NULL };

// Signals the daemon handles, blocked across fork() and reset in the child
static const int fim_diff_exec_fork_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2 };

#ifdef WAZUH_UNIT_TESTING
// Coverage builds turn a direct execve() call into a wrapper that first writes the profile files, which the
// memory and file size limits make fail. A call through a pointer is left as it is.
static int (* volatile fim_diff_execve)(const char *, char * const [], char * const []) = execve;
#else
#define fim_diff_execve execve
#endif

/**
 * @brief Opens a file for the child and marks it close-on-exec in the parent
 *
 * @param path File to open
 * @param flags open() flags
 *
 * @return File descriptor, or -1 on error
 */
static int fim_diff_exec_open(const char *path, int flags) {
    int fd = open(path, flags | O_CLOEXEC, 0600);

    // O_CLOEXEC is 0 on some platforms (see defs.h)
#if O_CLOEXEC == 0
    if (fd >= 0) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
#endif

    return fd;
}

/**
 * @brief Checks whether diff reported that it ran out of memory
 *
 * @param err_file File with the stderr of the child
 *
 * @return true if the child failed to allocate memory
 */
static bool fim_diff_exec_out_of_memory(const char *err_file) {
    char buffer[OS_SIZE_256] = {0};
    bool oom = false;
    FILE *fp = wfopen(err_file, "r");

    if (fp != NULL) {
        size_t n = fread(buffer, 1, sizeof(buffer) - 1, fp);
        buffer[n] = '\0';
        oom = strstr(buffer, "memory exhausted") != NULL || strstr(buffer, "out of memory") != NULL ||
              strstr(buffer, "Cannot allocate memory") != NULL;
        fclose(fp);
    }

    return oom;
}

// LCOV_EXCL_START
/**
 * @brief Child side: applies the limits, redirects the output and runs diff
 *
 * Only async-signal-safe calls are made here, since the parent is multithreaded.
 */
static void fim_diff_exec_child(const char *bin, char * const argv[], char * const envp[], int null_fd, int out_fd, int err_fd) {
    static const int reset_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGUSR1, SIGUSR2, SIGXCPU, SIGXFSZ };
    struct sigaction sa;
    sigset_t mask;
    struct rlimit rl;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0; i < sizeof(reset_signals) / sizeof(reset_signals[0]); i++) {
        sigaction(reset_signals[i], &sa, NULL);
    }

    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);

    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);

    rl.rlim_cur = fim_diff_exec_timeout;
    rl.rlim_max = fim_diff_exec_timeout + 2;
    setrlimit(RLIMIT_CPU, &rl);

    rl.rlim_cur = rl.rlim_max = FIM_DIFF_CHILD_MAX_OUTPUT;
    setrlimit(RLIMIT_FSIZE, &rl);

    // macOS enforces neither limit, so only time and output are bounded there
#if !defined(__MACH__)
    rl.rlim_cur = rl.rlim_max = FIM_DIFF_CHILD_MAX_MEMORY;
#if defined(RLIMIT_AS) && !defined(AIX)
    setrlimit(RLIMIT_AS, &rl);
#elif defined(RLIMIT_DATA)
    setrlimit(RLIMIT_DATA, &rl);
#endif
#endif

    if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(out_fd, STDOUT_FILENO) < 0 || dup2(err_fd, STDERR_FILENO) < 0) {
        _exit(127);
    }

    fim_diff_execve(bin, argv, envp);
    _exit(127);
}
// LCOV_EXCL_STOP

fim_diff_exec_rc fim_diff_exec(const char *old_file, const char *new_file, const char *out_file) {
    char err_file[PATH_MAX];
    const char *bin = NULL;
    int null_fd = -1;
    int out_fd = -1;
    int err_fd = -1;
    int status = 0;
    bool timed_out = false;
    pid_t pid;
    fim_diff_exec_rc rc = FIM_DIFF_EXEC_ERROR;

    for (int i = 0; fim_diff_exec_bins[i] != NULL; i++) {
        if (access(fim_diff_exec_bins[i], X_OK) == 0) {
            bin = fim_diff_exec_bins[i];
            break;
        }
    }

    if (bin == NULL) {
        merror(FIM_DIFF_CMD_NOT_FOUND);
        return FIM_DIFF_EXEC_ERROR;
    }

    if (snprintf(err_file, sizeof(err_file), "%s-err", out_file) >= (int)sizeof(err_file)) {
        return FIM_DIFF_EXEC_ERROR;
    }

    // The scratch folder is private to this call, so the output files must not exist yet
    null_fd = fim_diff_exec_open("/dev/null", O_RDWR);
    out_fd = fim_diff_exec_open(out_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW);
    err_fd = fim_diff_exec_open(err_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW);

    if (null_fd < 0 || out_fd < 0 || err_fd < 0) {
        merror(FOPEN_ERROR, out_fd < 0 ? out_file : err_file, errno, strerror(errno));
        goto end;
    }

    // Built before fork(): the child must not allocate
    char * const argv[] = { (char *)"diff", (char *)old_file, (char *)new_file, NULL };
    char * const envp[] = { (char *)"LC_ALL=C", (char *)"PATH=/usr/bin:/bin", NULL };

    // The daemon's handlers must not run in the child before it resets them
    sigset_t blocked;
    sigset_t previous;
    sigemptyset(&blocked);
    for (size_t i = 0; i < sizeof(fim_diff_exec_fork_signals) / sizeof(fim_diff_exec_fork_signals[0]); i++) {
        sigaddset(&blocked, fim_diff_exec_fork_signals[i]);
    }
    pthread_sigmask(SIG_BLOCK, &blocked, &previous);

    pid = fork();

    if (pid == 0) {
        fim_diff_exec_child(bin, argv, envp, null_fd, out_fd, err_fd); // LCOV_EXCL_LINE
    }

    int fork_errno = errno;
    pthread_sigmask(SIG_SETMASK, &previous, NULL);

    if (pid < 0) {
        merror(FORK_ERROR, fork_errno, strerror(fork_errno));
        goto end;
    }

    close(null_fd);
    close(out_fd);
    close(err_fd);
    null_fd = out_fd = err_fd = -1;

    time_t deadline = w_get_monotonic_time() + fim_diff_exec_timeout;
    unsigned long delay = 1;

    while (true) {
        pid_t ret = waitpid(pid, &status, WNOHANG);

        if (ret == pid) {
            break;
        }

        if (ret < 0 && errno != EINTR) {
            int err = errno;
            merror("waitpid() failed for the diff process: %s (%d)", strerror(err), err);
            // With ECHILD the pid is no longer our child and may belong to another process
            if (err != ECHILD) {
                kill(pid, SIGKILL);
            }
            goto end;
        }

        if (w_get_monotonic_time() >= deadline) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
            timed_out = true;
            break;
        }

        w_time_delay(delay);
        delay = delay < 50 ? delay * 2 : 50;
    }

    if (timed_out) {
        rc = FIM_DIFF_EXEC_TIMEOUT;
    } else if (WIFEXITED(status)) {
        switch (WEXITSTATUS(status)) {
        case 0:
            rc = FIM_DIFF_EXEC_SAME;
            break;
        case 1:
            rc = FIM_DIFF_EXEC_DIFF;
            break;
        case 127:
            // The child could not run diff
            mdebug2(FIM_DIFF_CHILD_EXIT, 127, 0);
            rc = FIM_DIFF_EXEC_ERROR;
            break;
        default:
            mdebug2(FIM_DIFF_CHILD_EXIT, WEXITSTATUS(status), 0);
            rc = fim_diff_exec_out_of_memory(err_file) ? FIM_DIFF_EXEC_MEMORY : FIM_DIFF_EXEC_FAILED;
        }
    } else if (WIFSIGNALED(status)) {
        if (WTERMSIG(status) != SIGXFSZ) {
            mdebug2(FIM_DIFF_CHILD_EXIT, -1, WTERMSIG(status));
        }

        switch (WTERMSIG(status)) {
        case SIGXFSZ:
            // The output reached its size limit: what was written is the head of the diff
            rc = FIM_DIFF_EXEC_DIFF;
            break;
        case SIGXCPU:
        case SIGKILL:
            rc = FIM_DIFF_EXEC_TIMEOUT;
            break;
        case SIGSEGV:
        case SIGBUS:
        case SIGABRT:
            rc = FIM_DIFF_EXEC_MEMORY;
            break;
        default:
            rc = FIM_DIFF_EXEC_FAILED;
        }
    }

end:
    if (null_fd >= 0) {
        close(null_fd);
    }
    if (out_fd >= 0) {
        close(out_fd);
    }
    if (err_fd >= 0) {
        close(err_fd);
    }
    unlink(err_file);

    return rc;
}

#else // WIN32

// Only one child is created at a time, so that no other output handle is inheritable meanwhile
static pthread_mutex_t fim_diff_exec_spawn_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Creates a job object that limits the memory of each process and kills them when it is closed
 *
 * @return Job handle, or NULL on error
 */
static HANDLE fim_diff_exec_job(void) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job = CreateJobObjectA(NULL, NULL);

    if (job == NULL) {
        return NULL;
    }

    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                              JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                              JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.ProcessMemoryLimit = FIM_DIFF_CHILD_MAX_MEMORY;

    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }

    return job;
}

fim_diff_exec_rc fim_diff_exec(const char *old_file, const char *new_file, const char *out_file) {
    char system_dir[MAX_PATH];
    char *cmdline = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE out = INVALID_HANDLE_VALUE;
    HANDLE nul = INVALID_HANDLE_VALUE;
    HANDLE job = NULL;
    DWORD exit_code = (DWORD)-1;
    bool timed_out = false;
    bool truncated = false;
    BOOL created;
    fim_diff_exec_rc rc = FIM_DIFF_EXEC_ERROR;

    UINT len = GetSystemDirectoryA(system_dir, sizeof(system_dir));

    if (len == 0 || len >= sizeof(system_dir)) {
        merror(FIM_DIFF_CMD_NOT_FOUND);
        return FIM_DIFF_EXEC_ERROR;
    }

    size_t size = strlen(system_dir) + strlen(old_file) + strlen(new_file) + 32;
    os_malloc(size, cmdline);
    snprintf(cmdline, size, "\"%s\\fc.exe\" /n \"%s\" \"%s\"", system_dir, old_file, new_file);

    out = CreateFileA(out_file, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);

    if (out == INVALID_HANDLE_VALUE || nul == INVALID_HANDLE_VALUE) {
        merror(FOPEN_ERROR, out_file, (int)GetLastError(), win_strerror(GetLastError()));
        goto end;
    }

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = out;
    si.hStdError = nul;

    job = fim_diff_exec_job();

    w_mutex_lock(&fim_diff_exec_spawn_mutex);
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(nul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    created = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(nul, HANDLE_FLAG_INHERIT, 0);
    w_mutex_unlock(&fim_diff_exec_spawn_mutex);

    if (!created) {
        merror(FIM_DIFF_CMD_START_ERROR, (int)GetLastError(), win_strerror(GetLastError()));
        goto end;
    }

    // A job cannot be nested on old Windows versions: then only the time and output limits apply
    if (job != NULL && !AssignProcessToJobObject(job, pi.hProcess)) {
        mdebug2(FIM_DIFF_NO_JOB, (int)GetLastError());
        CloseHandle(job);
        job = NULL;
    }

    ResumeThread(pi.hThread);

    DWORD start = GetTickCount();

    while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
        LARGE_INTEGER written;

        if (GetFileSizeEx(out, &written) && written.QuadPart >= FIM_DIFF_CHILD_MAX_OUTPUT) {
            truncated = true;
        } else if (GetTickCount() - start >= fim_diff_exec_timeout * 1000) {
            timed_out = true;
        } else {
            continue;
        }

        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        break;
    }

    GetExitCodeProcess(pi.hProcess, &exit_code);

    if (timed_out) {
        rc = FIM_DIFF_EXEC_TIMEOUT;
    } else if (truncated) {
        rc = FIM_DIFF_EXEC_DIFF;
    } else if (exit_code == 0) {
        rc = FIM_DIFF_EXEC_SAME;
    } else if (exit_code == 1) {
        rc = FIM_DIFF_EXEC_DIFF;
    } else {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;

        mdebug2(FIM_DIFF_CHILD_EXIT, (int)exit_code, 0);
        rc = FIM_DIFF_EXEC_FAILED;

        if (job != NULL && QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info), NULL) &&
            info.PeakProcessMemoryUsed >= FIM_DIFF_CHILD_MAX_MEMORY / 10 * 9) {
            rc = FIM_DIFF_EXEC_MEMORY;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

end:
    if (job != NULL) {
        CloseHandle(job);
    }
    if (out != INVALID_HANDLE_VALUE) {
        CloseHandle(out);
    }
    if (nul != INVALID_HANDLE_VALUE) {
        CloseHandle(nul);
    }
    os_free(cmdline);

    return rc;
}

#endif // WIN32
