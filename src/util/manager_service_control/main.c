/*
 * Wazuh manager service control executable
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the Free Software Foundation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROGRAM_NAME "wazuh-manager-service-control"
#define CONTROL_NAME "wazuh-manager-control"
#define SYSTEMCTL_PATH "/usr/bin/systemctl"
#define SYSTEMD_DIRECTORY "/run/systemd/system"
#define MANAGER_SERVICE "wazuh-manager.service"
#define REQUEST_UNIT "wazuh-manager-service-control@"
#define STATUS_FD 3
#define ACTIVE_WAIT_SECONDS 60

typedef enum
{
    SERVICE_ACTIVE,
    SERVICE_TRANSITIONAL,
    SERVICE_INACTIVE,
    SERVICE_QUERY_FAILED
} service_state_t;

typedef enum
{
    STEP_WAIT,
    STEP_SYSTEMCTL,
    STEP_START,
    STEP_CONTROL,
    STEP_IGNORE
} request_step_t;

static void fail(const char *message)
{
    dprintf(STDERR_FILENO, "%s: %s\n", PROGRAM_NAME, message);
    _exit(EXIT_FAILURE);
}

static void print_help(void)
{
    dprintf(STDOUT_FILENO,
            "Usage: %s {restart|reload}\n"
            "       %s -h\n"
            "\n"
            "Commands:\n"
            "  restart  Restart the Wazuh manager service\n"
            "  reload   Reload the Wazuh manager while keeping agent connections active\n"
            "\n"
            "Options:\n"
            "  -h       Show this help\n",
            PROGRAM_NAME,
            PROGRAM_NAME);
}

static bool valid_action(const char *action)
{
    return strcmp(action, "restart") == 0 || strcmp(action, "reload") == 0;
}

static bool authorized_caller(uid_t allowed_uid, uid_t caller_uid, uid_t effective_uid)
{
    return allowed_uid != (uid_t)-1 && (caller_uid == 0 || caller_uid == allowed_uid) && effective_uid == 0;
}

/* A root caller (the systemd request unit) needs no set-user-ID bit; any other caller only gets root through it. */
static bool require_setuid(uid_t caller_uid)
{
    return caller_uid != 0;
}

static uid_t manager_uid(void)
{
    const long initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = initial_size > 0 ? (size_t)initial_size : 1024;
    char *buffer = NULL;
    struct passwd pwd = {0};
    struct passwd *result = NULL;
    int error;

    do {
        char *new_buffer = realloc(buffer, size);
        if (new_buffer == NULL) {
            free(buffer);
            fail("cannot allocate user lookup buffer");
        }

        buffer = new_buffer;
        error = getpwnam_r(WAZUH_RUNTIME_USER, &pwd, buffer, size, &result);
        size *= 2;
    } while (error == ERANGE && size <= 65536);

    const uid_t uid = result != NULL ? result->pw_uid : (uid_t)-1;
    free(buffer);
    return uid;
}

static bool path_is_safe(const struct stat *info, mode_t type, bool require_setuid)
{
    return (info->st_mode & S_IFMT) == type && info->st_uid == 0 && (info->st_mode & 0022) == 0 &&
           (!require_setuid || (info->st_mode & S_ISUID) != 0);
}

static void validate_path(const char *path, mode_t type, bool require_setuid)
{
    struct stat info;

    if (stat(path, &info) != 0) {
        fail("required privileged path is unavailable");
    }

    if (!path_is_safe(&info, type, false)) {
        fail("unsafe privileged path ownership or permissions");
    }

    if (require_setuid && !path_is_safe(&info, type, true)) {
        fail("service control is not installed set-user-ID");
    }
}

static bool derive_install_paths(const char *executable_path,
                                 char *bin_path,
                                 char *home_path,
                                 char *control_path,
                                 char *process_list_path)
{
    const char *separator = strrchr(executable_path, '/');
    if (separator == NULL || separator == executable_path || strcmp(separator + 1, PROGRAM_NAME) != 0) {
        return false;
    }

    const size_t bin_length = (size_t)(separator - executable_path);
    if (bin_length >= PATH_MAX) {
        return false;
    }
    memcpy(bin_path, executable_path, bin_length);
    bin_path[bin_length] = '\0';

    separator = strrchr(bin_path, '/');
    if (separator == NULL || separator == bin_path) {
        return false;
    }
    const size_t home_length = (size_t)(separator - bin_path);
    memcpy(home_path, bin_path, home_length);
    home_path[home_length] = '\0';

    if (snprintf(control_path, PATH_MAX, "%s/bin/%s", home_path, CONTROL_NAME) >= PATH_MAX) {
        return false;
    }

    if (snprintf(process_list_path, PATH_MAX, "%s/bin/.process_list", home_path) >= PATH_MAX) {
        return false;
    }

    return true;
}

static void resolve_install_paths(char *executable_path,
                                  char *bin_path,
                                  char *home_path,
                                  char *control_path,
                                  char *process_list_path)
{
    const ssize_t length = readlink("/proc/self/exe", executable_path, PATH_MAX - 1);
    if (length <= 0 || length >= PATH_MAX - 1) {
        fail("cannot resolve service control path");
    }
    executable_path[length] = '\0';

    if (!derive_install_paths(executable_path, bin_path, home_path, control_path, process_list_path)) {
        fail("unexpected service control path");
    }
}

static bool systemd_running(void)
{
    if (access(SYSTEMD_DIRECTORY, F_OK) != 0) {
        return false;
    }

    FILE *stream = fopen("/proc/1/comm", "r");
    if (stream == NULL) {
        return false;
    }

    char name[32] = {0};
    const bool read = fgets(name, sizeof(name), stream) != NULL;
    fclose(stream);
    name[strcspn(name, "\n")] = '\0';
    return read && strcmp(name, "systemd") == 0;
}

/* Whether a line of a /proc/self/cgroup stream (one per hierarchy on cgroup v1, one on v2) names the unit. */
static bool cgroup_names(FILE *stream, const char *unit)
{
    char line[PATH_MAX];
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strstr(line, unit) != NULL) {
            return true;
        }
    }
    return false;
}

static bool in_request_unit(void)
{
    FILE *stream = fopen("/proc/self/cgroup", "r");
    if (stream == NULL) {
        return false;
    }

    const bool found = cgroup_names(stream, REQUEST_UNIT);
    fclose(stream);
    return found;
}

/*
 * Whether a manager daemon runs: a <home>/var/run/wazuh-manager-*.pid names a live process that executes from
 * inside <home>. The executable check keeps a stale pid file whose pid was reused from counting.
 */
static bool manager_running(const char *home_path)
{
    char run_path[PATH_MAX];
    if (snprintf(run_path, sizeof(run_path), "%s/var/run", home_path) >= (int)sizeof(run_path)) {
        return false;
    }

    DIR *directory = opendir(run_path);
    if (directory == NULL) {
        return false;
    }

    const size_t home_length = strlen(home_path);
    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(directory)) != NULL) {
        const char *name = entry->d_name;
        const size_t length = strlen(name);
        if (strncmp(name, "wazuh-manager-", strlen("wazuh-manager-")) != 0 || length < strlen(".pid") ||
            strcmp(name + length - strlen(".pid"), ".pid") != 0) {
            continue;
        }

        char pid_path[PATH_MAX];
        if (snprintf(pid_path, sizeof(pid_path), "%s/%s", run_path, name) >= (int)sizeof(pid_path)) {
            continue;
        }

        /* var/run is writable by the service account: a link is not followed, a FIFO does not block. */
        const int fd = open(pid_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        struct stat info;
        char line[32] = {0};
        const ssize_t read_length =
            fstat(fd, &info) == 0 && S_ISREG(info.st_mode) ? read(fd, line, sizeof(line) - 1) : -1;
        close(fd);
        if (read_length <= 0) {
            continue;
        }
        line[strcspn(line, "\n")] = '\0';

        char *end = NULL;
        errno = 0;
        const long pid = strtol(line, &end, 10);
        if (pid <= 0 || pid > INT_MAX || errno != 0 || end == line || *end != '\0' || kill((pid_t)pid, 0) != 0) {
            continue;
        }

        char link_path[64];
        char executable[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", pid);
        const ssize_t executable_length = readlink(link_path, executable, sizeof(executable) - 1);
        if (executable_length <= 0) {
            continue;
        }
        executable[executable_length] = '\0';
        found = strncmp(executable, home_path, home_length) == 0 && executable[home_length] == '/';
    }

    closedir(directory);
    return found;
}

/*
 * The step a restart or reload takes in the manager unit's state. Outside the request unit (set-user-ID path, no
 * systemd) an inactive manager is reloaded by running the control script directly, which starts its daemons in
 * the caller's cgroup. The request unit never does that: its cgroup is the oneshot's, whose processes systemd
 * kills when it ends. There, an inactive unit with manager daemons running (started by hand, outside the unit) is
 * restarted, or for a reload started, through systemd, whose start takes those daemons over; with no manager
 * daemon running the request is ignored, so a stale one never starts a stopped manager.
 */
static request_step_t request_step(const char *action, service_state_t state, bool request_unit, bool running)
{
    const bool reload = strcmp(action, "reload") == 0;

    if (!request_unit && !reload) {
        return STEP_SYSTEMCTL;
    }

    switch (state) {
        case SERVICE_ACTIVE:
            return STEP_SYSTEMCTL;
        case SERVICE_INACTIVE:
            if (!request_unit) {
                return STEP_CONTROL;
            }
            if (!running) {
                return STEP_IGNORE;
            }
            return reload ? STEP_START : STEP_SYSTEMCTL;
        default:
            return STEP_WAIT;
    }
}

static void become_root(void)
{
    if (setgroups(0, NULL) != 0 || setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
        fail("cannot restore root identity");
    }

    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
        fail("cannot verify root identity");
    }
}

/*
 * In the request unit `unknown` counts as inactive: systemd before 230 prints it for a unit that exists but is not
 * loaded, and the manager unit of this installation exists. Elsewhere it stays a failed query.
 */
static service_state_t parse_service_state(const char *state, bool request_unit)
{
    if (strcmp(state, "active") == 0) {
        return SERVICE_ACTIVE;
    }

    if (strcmp(state, "activating") == 0 || strcmp(state, "reloading") == 0 || strcmp(state, "deactivating") == 0) {
        return SERVICE_TRANSITIONAL;
    }

    if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0 ||
        (request_unit && strcmp(state, "unknown") == 0)) {
        return SERVICE_INACTIVE;
    }

    return SERVICE_QUERY_FAILED;
}

static service_state_t service_state(bool request_unit)
{
    int output_pipe[2];
    if (pipe(output_pipe) != 0) {
        return SERVICE_QUERY_FAILED;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return SERVICE_QUERY_FAILED;
    }

    if (pid == 0) {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0) {
            _exit(EXIT_FAILURE);
        }
        close(output_pipe[1]);

        become_root();
        char *const arguments[] = {"systemctl", "is-active", MANAGER_SERVICE, NULL};
        execv(SYSTEMCTL_PATH, arguments);
        _exit(EXIT_FAILURE);
    }

    close(output_pipe[1]);
    char state[32] = {0};
    const ssize_t length = read(output_pipe[0], state, sizeof(state) - 1);
    close(output_pipe[0]);

    int status;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited != pid || length <= 0) {
        return SERVICE_QUERY_FAILED;
    }

    state[strcspn(state, "\r\n")] = '\0';
    return parse_service_state(state, request_unit);
}

static void ensure_standard_descriptors(void)
{
    for (int descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; ++descriptor) {
        if (fcntl(descriptor, F_GETFD) >= 0 || errno != EBADF) {
            continue;
        }

        const int opened = open("/dev/null", O_RDWR);
        if (opened != descriptor) {
            if (opened >= 0) {
                close(opened);
            }
            _exit(EXIT_FAILURE);
        }
    }
}

static void close_inherited_descriptors(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        const long maximum = sysconf(_SC_OPEN_MAX);
        for (int descriptor = STATUS_FD + 1; descriptor < maximum; ++descriptor) {
            close(descriptor);
        }
        return;
    }

    const int directory_fd = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        const long descriptor = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && end != NULL && *end == '\0' && descriptor > STATUS_FD && descriptor != directory_fd) {
            close((int)descriptor);
        }
    }

    closedir(directory);
}

static void notify_accepted(void)
{
    const char accepted = '1';
    if (write(STATUS_FD, &accepted, sizeof(accepted)) < 0 && errno != EBADF) {
        fail("cannot report accepted action");
    }
    close(STATUS_FD);
}

static void execute_control(const char *control_path, const char *action)
{
    become_root();
    umask(0022);
    char *const arguments[] = {(char *)control_path, (char *)action, NULL};
    execv(control_path, arguments);
    fail("cannot execute manager control");
}

static bool check_passed(int status)
{
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * Runs `wazuh-manager-control check` (the checks a start runs, nothing started or stopped) as root, with the
 * sanitized environment, and waits for it. The unit's ExecStop stops every daemon before its ExecStart checks
 * anything, so a configuration or credential the start would refuse must be refused here, while the manager is
 * still running. Its output goes to this program's standard error; its refusal is also in the manager log.
 */
static bool run_check(const char *control_path)
{
    const pid_t pid = fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
            _exit(EXIT_FAILURE);
        }
        become_root();
        umask(0022);
        char *const arguments[] = {(char *)control_path, "check", NULL};
        execv(control_path, arguments);
        _exit(EXIT_FAILURE);
    }

    int status;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    return waited == pid && check_passed(status);
}

/* The refusal names the action that was asked for: a refused reload did not restart anything either. */
static const char *check_failed_message(const char *action)
{
    return strcmp(action, "reload") == 0
               ? "the manager configuration or credentials check failed; the manager was not reloaded"
               : "the manager configuration or credentials check failed; the manager was not restarted";
}

/* Runs `systemctl <verb>` on the manager unit once the check passes; a refusal names the requested action. */
static void execute_systemctl(const char *control_path, const char *verb, const char *action)
{
    if (!run_check(control_path)) {
        fail(check_failed_message(action));
    }

    become_root();
    char *const arguments[] = {"systemctl", (char *)verb, MANAGER_SERVICE, NULL};
    execv(SYSTEMCTL_PATH, arguments);
    fail("cannot execute systemctl");
}

int main(int argc, char **argv)
{
    ensure_standard_descriptors();

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        print_help();
        return EXIT_SUCCESS;
    }

    if (argc != 2 || !valid_action(argv[1])) {
        fail("expected restart, reload, or -h");
    }

    const uid_t allowed_uid = manager_uid();
    const uid_t caller_uid = getuid();
    if (!authorized_caller(allowed_uid, caller_uid, geteuid())) {
        fail("unauthorized caller");
    }

    char executable_path[PATH_MAX];
    char bin_path[PATH_MAX];
    char home_path[PATH_MAX];
    char control_path[PATH_MAX];
    char process_list_path[PATH_MAX];
    resolve_install_paths(executable_path, bin_path, home_path, control_path, process_list_path);

    validate_path(executable_path, S_IFREG, require_setuid(caller_uid));
    validate_path(home_path, S_IFDIR, false);
    validate_path(bin_path, S_IFDIR, false);
    validate_path(control_path, S_IFREG, false);
    struct stat process_list_info;
    if (stat(process_list_path, &process_list_info) == 0) {
        validate_path(process_list_path, S_IFREG, false);
    } else if (errno != ENOENT) {
        fail("cannot inspect process list");
    }

    const bool use_systemd = systemd_running();
    if (use_systemd) {
        validate_path(SYSTEMCTL_PATH, S_IFREG, false);
    }

    if (clearenv() != 0 || setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0 || setenv("LANG", "C", 1) != 0) {
        fail("cannot sanitize environment");
    }

    umask(0077);
    close_inherited_descriptors();
    notify_accepted();

    if (use_systemd) {
        const bool request_unit = in_request_unit();
        for (int attempt = 0; attempt < ACTIVE_WAIT_SECONDS; ++attempt) {
            const service_state_t state = service_state(request_unit);
            const bool running = request_unit && state == SERVICE_INACTIVE && manager_running(home_path);
            switch (request_step(argv[1], state, request_unit, running)) {
                case STEP_SYSTEMCTL:
                    execute_systemctl(control_path, argv[1], argv[1]);
                    break;
                case STEP_START:
                    dprintf(STDERR_FILENO,
                            "%s: the manager runs outside %s; starting the unit, which restarts every daemon inside "
                            "it\n",
                            PROGRAM_NAME,
                            MANAGER_SERVICE);
                    execute_systemctl(control_path, "start", argv[1]);
                    break;
                case STEP_CONTROL:
                    execute_control(control_path, argv[1]);
                    break;
                case STEP_IGNORE:
                    dprintf(STDERR_FILENO,
                            "%s: the manager is not running; %s request ignored\n",
                            PROGRAM_NAME,
                            argv[1]);
                    return EXIT_SUCCESS;
                case STEP_WAIT:
                    break;
            }
            sleep(1);
        }
        fail("cannot determine a safe manager service state");
    }

    execute_control(control_path, argv[1]);
    return EXIT_FAILURE;
}
