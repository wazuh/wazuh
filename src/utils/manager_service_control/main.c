/*
 * Wazuh manager service control executable
 * Copyright (C) 2015, Wazuh Inc.
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
#define STATUS_FD 3
#define ACTIVE_WAIT_SECONDS 60

typedef enum
{
    SERVICE_ACTIVE,
    SERVICE_TRANSITIONAL,
    SERVICE_INACTIVE,
    SERVICE_QUERY_FAILED
} service_state_t;

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

static void become_root(void)
{
    if (setgroups(0, NULL) != 0 || setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
        fail("cannot restore root identity");
    }

    if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
        fail("cannot verify root identity");
    }
}

static service_state_t parse_service_state(const char *state)
{
    if (strcmp(state, "active") == 0) {
        return SERVICE_ACTIVE;
    }

    if (strcmp(state, "activating") == 0 || strcmp(state, "reloading") == 0 || strcmp(state, "deactivating") == 0) {
        return SERVICE_TRANSITIONAL;
    }

    if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0) {
        return SERVICE_INACTIVE;
    }

    return SERVICE_QUERY_FAILED;
}

static service_state_t service_state(void)
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
    return parse_service_state(state);
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

static void execute_systemctl(const char *action)
{
    become_root();
    char *const arguments[] = {"systemctl", (char *)action, MANAGER_SERVICE, NULL};
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

    validate_path(executable_path, S_IFREG, true);
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
        if (strcmp(argv[1], "reload") == 0) {
            for (int attempt = 0; attempt < ACTIVE_WAIT_SECONDS; ++attempt) {
                const service_state_t state = service_state();
                if (state == SERVICE_ACTIVE) {
                    execute_systemctl(argv[1]);
                }
                if (state == SERVICE_INACTIVE) {
                    execute_control(control_path, argv[1]);
                }
                sleep(1);
            }
            fail("cannot determine a safe manager service state");
        }
        execute_systemctl(argv[1]);
    }

    execute_control(control_path, argv[1]);
    return EXIT_FAILURE;
}
