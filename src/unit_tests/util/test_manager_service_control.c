/*
 * Wazuh manager service control - Unit Tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the Free Software Foundation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>

#undef fail
#define main wazuh_manager_service_control_main
#include "../../util/manager_service_control/main.c"
#undef main

static void test_help_option_succeeds(void **state)
{
    (void)state;
    char *argv[] = {"wazuh-manager-service-control", "-h", NULL};

    assert_int_equal(wazuh_manager_service_control_main(2, argv), EXIT_SUCCESS);
}

static void test_actions_are_strictly_allowlisted(void **state)
{
    (void)state;
    assert_true(valid_action("restart"));
    assert_true(valid_action("reload"));
    assert_false(valid_action("status"));
    assert_false(valid_action("restart extra"));
    assert_false(valid_action(""));
}

static void test_caller_requires_allowed_real_uid_and_root_effective_uid(void **state)
{
    (void)state;
    const uid_t manager = 1000;

    assert_true(authorized_caller(manager, manager, 0));
    assert_true(authorized_caller(manager, 0, 0));
    assert_false(authorized_caller(manager, 1001, 0));
    assert_false(authorized_caller(manager, manager, manager));
    assert_false(authorized_caller((uid_t)-1, manager, 0));
}

static void test_setuid_required_only_for_non_root_callers(void **state)
{
    (void)state;
    assert_false(require_setuid(0));
    assert_true(require_setuid(1000));
    assert_true(require_setuid(1001));
}

static void test_privileged_path_policy(void **state)
{
    (void)state;
    struct stat info = {.st_mode = S_IFREG | 04750, .st_uid = 0};

    assert_true(path_is_safe(&info, S_IFREG, true));

    info.st_mode = S_IFREG | 0750;
    assert_false(path_is_safe(&info, S_IFREG, true));
    assert_true(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFREG | 0770;
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFREG | 0752;
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_mode = S_IFDIR | 0750;
    assert_true(path_is_safe(&info, S_IFDIR, false));
    assert_false(path_is_safe(&info, S_IFREG, false));

    info.st_uid = 1000;
    assert_false(path_is_safe(&info, S_IFDIR, false));
}

static void test_service_states(void **state)
{
    (void)state;
    for (int request_unit = 0; request_unit <= 1; ++request_unit) {
        assert_int_equal(parse_service_state("active", request_unit), SERVICE_ACTIVE);
        assert_int_equal(parse_service_state("activating", request_unit), SERVICE_TRANSITIONAL);
        assert_int_equal(parse_service_state("reloading", request_unit), SERVICE_TRANSITIONAL);
        assert_int_equal(parse_service_state("deactivating", request_unit), SERVICE_TRANSITIONAL);
        assert_int_equal(parse_service_state("inactive", request_unit), SERVICE_INACTIVE);
        assert_int_equal(parse_service_state("failed", request_unit), SERVICE_INACTIVE);
        assert_int_equal(parse_service_state("", request_unit), SERVICE_QUERY_FAILED);
        assert_int_equal(parse_service_state("garbage", request_unit), SERVICE_QUERY_FAILED);
    }
}

/* systemd before 230 prints `unknown` for an unloaded unit: inactive in the request unit only. */
static void test_unknown_state_is_inactive_only_in_request_unit(void **state)
{
    (void)state;
    assert_int_equal(parse_service_state("unknown", false), SERVICE_QUERY_FAILED);
    assert_int_equal(parse_service_state("unknown", true), SERVICE_INACTIVE);
}

static void test_request_unit_is_found_in_any_cgroup_line(void **state)
{
    (void)state;
    char v2[] = "0::/system.slice/system-wazuh\\x2dmanager\\x2dservice\\x2dcontrol.slice/"
                "wazuh-manager-service-control@reload.service\n";
    char v1[] = "11:cpuset:/\n"
                "1:name=systemd:/system.slice/wazuh-manager-service-control@restart.service\n";
    char manager[] = "0::/system.slice/wazuh-manager.service\n";
    FILE *stream;

    stream = fmemopen(v2, strlen(v2), "r");
    assert_true(cgroup_names(stream, REQUEST_UNIT));
    fclose(stream);

    stream = fmemopen(v1, strlen(v1), "r");
    assert_true(cgroup_names(stream, REQUEST_UNIT));
    fclose(stream);

    stream = fmemopen(manager, strlen(manager), "r");
    assert_false(cgroup_names(stream, REQUEST_UNIT));
    fclose(stream);
}

/* Every action x state x request unit x running combination. The request unit never runs the control script. */
static void test_request_step_table(void **state)
{
    (void)state;
    const struct
    {
        const char *action;
        service_state_t state;
        bool request_unit;
        bool running;
        request_step_t expected;
    } cases[] = {
        /* Outside the request unit: a restart always goes to systemctl, whatever the state. */
        {"restart", SERVICE_ACTIVE, false, false, STEP_SYSTEMCTL},
        {"restart", SERVICE_ACTIVE, false, true, STEP_SYSTEMCTL},
        {"restart", SERVICE_INACTIVE, false, false, STEP_SYSTEMCTL},
        {"restart", SERVICE_INACTIVE, false, true, STEP_SYSTEMCTL},
        {"restart", SERVICE_TRANSITIONAL, false, false, STEP_SYSTEMCTL},
        {"restart", SERVICE_TRANSITIONAL, false, true, STEP_SYSTEMCTL},
        {"restart", SERVICE_QUERY_FAILED, false, false, STEP_SYSTEMCTL},
        {"restart", SERVICE_QUERY_FAILED, false, true, STEP_SYSTEMCTL},
        /* Outside the request unit: a reload of an inactive manager runs the control script. */
        {"reload", SERVICE_ACTIVE, false, false, STEP_SYSTEMCTL},
        {"reload", SERVICE_ACTIVE, false, true, STEP_SYSTEMCTL},
        {"reload", SERVICE_INACTIVE, false, false, STEP_CONTROL},
        {"reload", SERVICE_INACTIVE, false, true, STEP_CONTROL},
        {"reload", SERVICE_TRANSITIONAL, false, false, STEP_WAIT},
        {"reload", SERVICE_TRANSITIONAL, false, true, STEP_WAIT},
        {"reload", SERVICE_QUERY_FAILED, false, false, STEP_WAIT},
        {"reload", SERVICE_QUERY_FAILED, false, true, STEP_WAIT},
        /* In the request unit, a restart. */
        {"restart", SERVICE_ACTIVE, true, false, STEP_SYSTEMCTL},
        {"restart", SERVICE_ACTIVE, true, true, STEP_SYSTEMCTL},
        {"restart", SERVICE_INACTIVE, true, false, STEP_IGNORE},
        {"restart", SERVICE_INACTIVE, true, true, STEP_SYSTEMCTL},
        {"restart", SERVICE_TRANSITIONAL, true, false, STEP_WAIT},
        {"restart", SERVICE_TRANSITIONAL, true, true, STEP_WAIT},
        {"restart", SERVICE_QUERY_FAILED, true, false, STEP_WAIT},
        {"restart", SERVICE_QUERY_FAILED, true, true, STEP_WAIT},
        /* In the request unit, a reload: an inactive unit with daemons outside it is started. */
        {"reload", SERVICE_ACTIVE, true, false, STEP_SYSTEMCTL},
        {"reload", SERVICE_ACTIVE, true, true, STEP_SYSTEMCTL},
        {"reload", SERVICE_INACTIVE, true, false, STEP_IGNORE},
        {"reload", SERVICE_INACTIVE, true, true, STEP_START},
        {"reload", SERVICE_TRANSITIONAL, true, false, STEP_WAIT},
        {"reload", SERVICE_TRANSITIONAL, true, true, STEP_WAIT},
        {"reload", SERVICE_QUERY_FAILED, true, false, STEP_WAIT},
        {"reload", SERVICE_QUERY_FAILED, true, true, STEP_WAIT},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        assert_int_equal(request_step(cases[i].action, cases[i].state, cases[i].request_unit, cases[i].running),
                         cases[i].expected);
    }
}

/* Creates <home>/bin and an empty <home>/var/run. */
static void make_tree(const char *home)
{
    char path[PATH_MAX];
    assert_int_equal(mkdir(home, 0700), 0);
    snprintf(path, sizeof(path), "%s/var", home);
    assert_int_equal(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/var/run", home);
    assert_int_equal(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/bin", home);
    assert_int_equal(mkdir(path, 0700), 0);
}

/* A temporary installation home, <resolved temporary directory>/manager, holding a tree. */
static void make_home(char *home)
{
    char template[] = "/tmp/test_manager_service_control.XXXXXX";
    char base[PATH_MAX];
    assert_non_null(mkdtemp(template));
    assert_non_null(realpath(template, base));
    assert_true(snprintf(home, PATH_MAX, "%s/manager", base) < PATH_MAX);
    make_tree(home);
}

static void write_file(const char *home, const char *relative, const char *content)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", home, relative);
    FILE *stream = fopen(path, "w");
    assert_non_null(stream);
    fputs(content, stream);
    fclose(stream);
}

static void write_pid_file(const char *home, const char *name, pid_t pid)
{
    char relative[PATH_MAX];
    char content[32];
    snprintf(relative, sizeof(relative), "var/run/%s", name);
    snprintf(content, sizeof(content), "%d\n", (int)pid);
    write_file(home, relative, content);
}

/* Removes the temporary directory that holds the home. */
static void remove_home(const char *home)
{
    char base[PATH_MAX];
    char command[PATH_MAX + 16];
    snprintf(base, sizeof(base), "%s", home);
    *strrchr(base, '/') = '\0';
    snprintf(command, sizeof(command), "rm -rf '%s'", base);
    assert_int_equal(system(command), 0);
}

/* Starts <home>/bin/sleep, a copy of the system's, and waits until its executable is the copy. */
static pid_t start_sleep_in_home(const char *home)
{
    char command[3 * PATH_MAX];
    char copy[PATH_MAX];
    snprintf(copy, sizeof(copy), "%s/bin/sleep", home);
    snprintf(command, sizeof(command), "cp \"$(command -v sleep)\" '%s'", copy);
    assert_int_equal(system(command), 0);

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0) {
        char *const arguments[] = {copy, "30", NULL};
        execv(copy, arguments);
        _exit(EXIT_FAILURE);
    }

    char link_path[64];
    char executable[PATH_MAX] = {0};
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int)pid);
    for (int attempt = 0; attempt < 200 && strcmp(executable, copy) != 0; ++attempt) {
        usleep(10000);
        const ssize_t length = readlink(link_path, executable, sizeof(executable) - 1);
        executable[length > 0 ? length : 0] = '\0';
    }
    assert_string_equal(executable, copy);
    return pid;
}

static void stop_child(pid_t pid)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static void test_manager_running_without_pid_files(void **state)
{
    (void)state;
    char home[PATH_MAX];
    make_home(home);

    assert_false(manager_running(home));

    char run_path[PATH_MAX];
    assert_true(snprintf(run_path, sizeof(run_path), "%s/var/run", home) < (int)sizeof(run_path));
    assert_int_equal(rmdir(run_path), 0);
    assert_false(manager_running(home));

    remove_home(home);
}

/* A live process whose executable is outside the home (this test) is not a manager daemon. */
static void test_manager_running_requires_executable_inside_home(void **state)
{
    (void)state;
    char home[PATH_MAX];
    make_home(home);

    write_pid_file(home, "wazuh-manager-remoted-1.pid", getpid());
    assert_false(manager_running(home));

    remove_home(home);
}

static void test_manager_running_ignores_dead_pid(void **state)
{
    (void)state;
    char home[PATH_MAX];
    make_home(home);

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0) {
        _exit(EXIT_SUCCESS);
    }
    waitpid(pid, NULL, 0);
    write_pid_file(home, "wazuh-manager-remoted-1.pid", pid);
    assert_false(manager_running(home));

    remove_home(home);
}

static void test_manager_running_ignores_garbage_and_other_files(void **state)
{
    (void)state;
    char home[PATH_MAX];
    make_home(home);
    const pid_t pid = start_sleep_in_home(home);

    char content[32];
    snprintf(content, sizeof(content), "%dx\n", (int)pid);
    write_file(home, "var/run/wazuh-manager-db-1.pid", content);
    write_file(home, "var/run/wazuh-manager-analysisd-1.pid", "not a pid\n");
    write_file(home, "var/run/wazuh-manager-authd-1.pid", "");
    write_file(home, "var/run/wazuh-manager-apid-1.pid", "-1\n");
    write_pid_file(home, "other-daemon-1.pid", pid);
    write_pid_file(home, "wazuh-manager-remoted.lock", pid);
    write_file(home, "var/run/wazuh-manager-db-2.pid", "4294967295\n");
    /* A live pid without an executable to read: kthreadd. */
    write_pid_file(home, "wazuh-manager-clusterd-2.pid", 2);
    /* A link is not followed, even to a valid pid file, and a FIFO is not read (it would block). */
    char path[PATH_MAX];
    char target[PATH_MAX];
    write_pid_file(home, "valid", pid);
    assert_true(snprintf(target, sizeof(target), "%s/var/run/valid", home) < (int)sizeof(target));
    assert_true(snprintf(path, sizeof(path), "%s/var/run/wazuh-manager-modulesd-1.pid", home) < (int)sizeof(path));
    assert_int_equal(symlink(target, path), 0);
    assert_true(snprintf(path, sizeof(path), "%s/var/run/wazuh-manager-authd-2.pid", home) < (int)sizeof(path));
    assert_int_equal(mkfifo(path, 0600), 0);
    assert_false(manager_running(home));

    stop_child(pid);
    remove_home(home);
}

static void test_manager_running_finds_a_daemon_of_this_installation(void **state)
{
    (void)state;
    char home[PATH_MAX];
    make_home(home);
    const pid_t pid = start_sleep_in_home(home);

    write_pid_file(home, "wazuh-manager-remoted-1.pid", pid);
    assert_true(manager_running(home));

    /* A home whose path is a prefix of this one's (<base>/manage) does not match. */
    char prefix[PATH_MAX];
    snprintf(prefix, sizeof(prefix), "%.*s", (int)(strlen(home) - 1), home);
    make_tree(prefix);
    write_pid_file(prefix, "wazuh-manager-remoted-1.pid", pid);
    assert_false(manager_running(prefix));

    stop_child(pid);
    assert_false(manager_running(home));

    remove_home(home);
}

static void test_install_paths_are_derived_independently(void **state)
{
    (void)state;
    char bin_path[PATH_MAX];
    char home_path[PATH_MAX];
    char control_path[PATH_MAX];
    char process_list_path[PATH_MAX];

    assert_true(derive_install_paths("/var/wazuh-manager/bin/wazuh-manager-service-control",
                                     bin_path,
                                     home_path,
                                     control_path,
                                     process_list_path));
    assert_string_equal(bin_path, "/var/wazuh-manager/bin");
    assert_string_equal(home_path, "/var/wazuh-manager");
    assert_string_not_equal(bin_path, home_path);
    assert_string_equal(control_path, "/var/wazuh-manager/bin/wazuh-manager-control");
    assert_string_equal(process_list_path, "/var/wazuh-manager/bin/.process_list");

    assert_false(derive_install_paths("/var/wazuh-manager/bin/unexpected-control",
                                      bin_path,
                                      home_path,
                                      control_path,
                                      process_list_path));
}

static void test_check_verdict_requires_a_clean_exit(void **state)
{
    (void)state;
    assert_true(check_passed(0));          /* exited 0 */
    assert_false(check_passed(1 << 8));    /* exited 1: the check refused */
    assert_false(check_passed(20 << 8));
    assert_false(check_passed(SIGKILL));   /* killed: no verdict */
    assert_false(check_passed(SIGSEGV));
}

static void test_check_refusal_names_the_requested_action(void **state)
{
    (void)state;
    assert_string_equal(check_failed_message("restart"),
                        "the manager configuration or credentials check failed; the manager was not restarted");
    assert_string_equal(check_failed_message("reload"),
                        "the manager configuration or credentials check failed; the manager was not reloaded");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_help_option_succeeds),
        cmocka_unit_test(test_actions_are_strictly_allowlisted),
        cmocka_unit_test(test_caller_requires_allowed_real_uid_and_root_effective_uid),
        cmocka_unit_test(test_setuid_required_only_for_non_root_callers),
        cmocka_unit_test(test_privileged_path_policy),
        cmocka_unit_test(test_service_states),
        cmocka_unit_test(test_request_unit_is_found_in_any_cgroup_line),
        cmocka_unit_test(test_unknown_state_is_inactive_only_in_request_unit),
        cmocka_unit_test(test_request_step_table),
        cmocka_unit_test(test_manager_running_without_pid_files),
        cmocka_unit_test(test_manager_running_requires_executable_inside_home),
        cmocka_unit_test(test_manager_running_ignores_dead_pid),
        cmocka_unit_test(test_manager_running_ignores_garbage_and_other_files),
        cmocka_unit_test(test_manager_running_finds_a_daemon_of_this_installation),
        cmocka_unit_test(test_install_paths_are_derived_independently),
        cmocka_unit_test(test_check_verdict_requires_a_clean_exit),
        cmocka_unit_test(test_check_refusal_names_the_requested_action),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
