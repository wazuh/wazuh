/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/syscall.h>

#include "shared.h"
#include "rootcheck.h"

rkconfig rootcheck;

/* When a task shows up in a /proc listing or in the ps output */
#define ALWAYS      0
#define FIRST_ONLY  1   /* Exits during the sweep */
#define LATER_ONLY  2   /* Starts during the sweep */
#define NEVER       3

typedef struct {
    int pid;
    int tgid;       /* Differs from pid for a thread */
    int kill;       /* Answers kill(pid, 0) */
    int gsid;       /* Answers getsid() */
    int gpid;       /* Answers getpgid() */
    int listed;
    int reachable;  /* /proc/<pid> can be opened */
    int in_ps;
} fake_task_t;

#define PROC(pid)           {pid, pid, 1, 1, 1, ALWAYS, 1, ALWAYS}
#define THREAD(tid, tgid)   {tid, tgid, 1, 1, 1, NEVER, 1, NEVER}
#define HIDDEN(pid)         {pid, pid, 1, 1, 1, NEVER, 1, NEVER}

static const fake_task_t *fake_tasks;
static int fake_tasks_count;
static int ps_status;               /* Returned by pclose() */
static int ps_empty;                /* ps prints no PIDs */
static int proc_listings;           /* /proc listings read to the end */
static int ps_runs;                 /* ps snapshots taken */
static int listing_pos;
static int fake_dir;                /* Its address is the DIR * of every opened directory */
static struct dirent fake_entry;
static char ps_buf[OS_SIZE_65536];

static const char *const proc_extras[] = {".", "..", "self", "sys"};
#define PROC_EXTRAS (int)(sizeof(proc_extras) / sizeof(proc_extras[0]))

static const fake_task_t *find_task(int pid)
{
    for (int i = 0; i < fake_tasks_count; i++) {
        if (fake_tasks[i].pid == pid) {
            return &fake_tasks[i];
        }
    }
    return NULL;
}

static int present(int when, int done)
{
    switch (when) {
    case ALWAYS:
        return 1;
    case FIRST_ONLY:
        return done == 0;
    case LATER_ONLY:
        return done > 0;
    default:
        return 0;
    }
}

int __wrap_kill(pid_t pid, __attribute__((unused)) int sig)
{
    const fake_task_t *task = find_task(pid);

    if (task && task->kill) {
        return 0;
    }
    errno = ESRCH;
    return -1;
}

pid_t __wrap_getsid(pid_t pid)
{
    const fake_task_t *task = find_task(pid);

    if (task && task->gsid) {
        return pid;
    }
    errno = ESRCH;
    return -1;
}

pid_t __wrap_getpgid(pid_t pid)
{
    const fake_task_t *task = find_task(pid);

    if (task && task->gpid) {
        return pid;
    }
    errno = ESRCH;
    return -1;
}

/* Not a PID used by any table */
pid_t __wrap_getpid(void)
{
    return 2;
}

/* tgkill(tgid, tid, 0): succeeds only when tid exists in thread group tgid */
long __wrap_syscall(long number, ...)
{
    const fake_task_t *task;
    va_list args;
    int tgid;
    int tid;

    assert_int_equal(number, SYS_tgkill);

    va_start(args, number);
    tgid = va_arg(args, int);
    tid = va_arg(args, int);
    va_end(args);

    task = find_task(tid);
    if (!task || !task->kill || task->tgid != tgid) {
        errno = ESRCH;
        return -1;
    }

    return 0;
}

/* The task of a "/proc/<pid><suffix>" path, if it exists and is reachable */
static const fake_task_t *reachable_task(const char *path, const char *suffix)
{
    const fake_task_t *task;
    char *end;
    long pid;

    if (strncmp(path, "/proc/", 6) != 0) {
        return NULL;
    }

    pid = strtol(path + 6, &end, 10);
    if (end == path + 6 || strcmp(end, suffix) != 0) {
        return NULL;
    }

    task = find_task((int)pid);
    return (task && task->reachable) ? task : NULL;
}

DIR *__wrap_wopendir(const char *name)
{
    if (strcmp(name, "/proc") == 0) {
        listing_pos = 0;
        return (DIR *)&fake_dir;
    }

    if (reachable_task(name, "")) {
        return (DIR *)&fake_dir;
    }

    errno = ENOENT;
    return NULL;
}

/* Lists a few non-numeric entries, then every process (never a thread) */
struct dirent *__wrap_readdir(__attribute__((unused)) DIR *dirp)
{
    while (listing_pos < PROC_EXTRAS + fake_tasks_count) {
        int pos = listing_pos++;

        if (pos < PROC_EXTRAS) {
            snprintf(fake_entry.d_name, sizeof(fake_entry.d_name), "%s", proc_extras[pos]);
            return &fake_entry;
        }

        const fake_task_t *task = &fake_tasks[pos - PROC_EXTRAS];
        if (task->tgid == task->pid && present(task->listed, proc_listings)) {
            snprintf(fake_entry.d_name, sizeof(fake_entry.d_name), "%d", task->pid);
            return &fake_entry;
        }
    }

    proc_listings++;
    return NULL;
}

int __wrap_closedir(__attribute__((unused)) DIR *dirp)
{
    return 0;
}

int __wrap_w_stat(const char *pathname, struct stat *buf)
{
    if (reachable_task(pathname, "")) {
        memset(buf, 0, sizeof(*buf));
        return 0;
    }

    errno = ENOENT;
    return -1;
}

/* Only ps exists outside /proc */
int __wrap_waccess(const char *path, __attribute__((unused)) int mode)
{
    if (strcmp(path, "/bin/ps") == 0) {
        return 0;
    }
    errno = ENOENT;
    return -1;
}

/* Reached by is_file() for paths that are not directories: none exist here */
FILE *__wrap_wfopen(__attribute__((unused)) const char *path, __attribute__((unused)) const char *mode)
{
    errno = ENOENT;
    return NULL;
}

FILE *__wrap_popen(const char *command, __attribute__((unused)) const char *type)
{
    size_t len = 0;

    assert_string_equal(command, "/bin/ps -e -o pid= 2>/dev/null");

    ps_buf[0] = '\n';
    for (int i = 0; i < fake_tasks_count; i++) {
        const fake_task_t *task = &fake_tasks[i];

        if (!ps_empty && task->tgid == task->pid && present(task->in_ps, ps_runs)) {
            len += snprintf(ps_buf + len, sizeof(ps_buf) - len, "%7d\n", task->pid);
        }
    }
    ps_runs++;

    return fmemopen(ps_buf, len ? len : 1, "r");
}

int __wrap_pclose(FILE *stream)
{
    fclose(stream);
    return ps_status;
}

/* The Linux scan must never run ps once per PID */
int __wrap_system(const char *command)
{
    fail_msg("check_rc_pids() invoked a shell: system(\"%s\")", command);
    return -1;
}

int __wrap_notify_rk(int rk_type, const char *msg)
{
    check_expected(rk_type);
    check_expected(msg);
    return mock_type(int);
}

static void expect_notify_rk(int rk_type, const char *msg)
{
    expect_value(__wrap_notify_rk, rk_type, rk_type);
    expect_string(__wrap_notify_rk, msg, msg);
    will_return(__wrap_notify_rk, 0);
}

/* expect_string() keeps the pointer, so formatted messages must outlive the call */
static char expected_msgs[32][OS_SIZE_1024];
static int expected_msgs_used;

static void expect_no_hidden(int processes)
{
    char *msg = expected_msgs[expected_msgs_used++];

    snprintf(msg, OS_SIZE_1024, "No hidden process by Kernel-level rootkits.\n"
             "      /bin/ps is not trojaned. Analyzed %d processes.", processes);
    expect_notify_rk(ALERT_OK, msg);
}

static void expect_hidden_from_proc(int pid)
{
    char *msg = expected_msgs[expected_msgs_used++];

    snprintf(msg, OS_SIZE_1024, "Process '%d' hidden from /proc. Possible kernel level rootkit.", pid);
    expect_notify_rk(ALERT_ROOTKIT_FOUND, msg);
}

static void set_fake_tasks(const fake_task_t *tasks, int count)
{
    fake_tasks = tasks;
    fake_tasks_count = count;
}

static int never_thread(__attribute__((unused)) int pid)
{
    return 0;
}

static int always_thread(__attribute__((unused)) int pid)
{
    return 1;
}

static int setup(void **state)
{
    (void)state;
    memset(&rootcheck, 0, sizeof(rkconfig));
    set_fake_tasks(NULL, 0);
    ps_status = 0;
    ps_empty = 0;
    proc_listings = 0;
    ps_runs = 0;
    listing_pos = 0;
    expected_msgs_used = 0;
    return 0;
}

/* ===================================================================
 * check_rc_pid_report(): the alert rules shared by every platform
 * =================================================================== */

static void test_report_exited_process(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {.kill0 = 1, .gsid0 = 1, .gpid0 = 1, .ps0 = 1};

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 0);
}

static void test_report_hidden_from_kill(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 0, .gsid0 = 1, .gpid0 = 1, .ps0 = 1,
        .kill1 = 0, .gsid1 = 1, .gpid1 = 1,
        .proc_stat = 1, .proc_read = 1, .proc_opendir = 1,
    };

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '42' hidden from kill (0) or getsid (1). Possible kernel-level rootkit.");

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 1);
}

static void test_report_defunct_process_ignored(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 1, .gsid0 = 0, .gpid0 = 0, .ps0 = 1,
        .kill1 = 1, .gsid1 = 0, .gpid1 = 0,
        .proc_stat = 1, .proc_read = 1, .proc_opendir = 1,
    };

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 0);
}

static void test_report_hidden_from_getpgid(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 1, .gsid0 = 1, .gpid0 = 1, .ps0 = 1,
        .kill1 = 1, .gsid1 = 1, .gpid1 = 0,
        .proc_stat = 1, .proc_read = 1, .proc_opendir = 1,
    };

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '42' hidden from kill (1), getsid (1) or getpgid. Possible kernel-level rootkit.");

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 1);
}

static void test_report_hidden_from_proc(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 1, .gsid0 = 1, .gpid0 = 1, .ps0 = 1,
        .kill1 = 1, .gsid1 = 1, .gpid1 = 1,
        .proc_stat = 1, .proc_read = 0, .proc_opendir = 1,
    };

    expect_hidden_from_proc(42);

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 1);
}

static void test_report_thread_not_hidden_from_proc(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 1, .gsid0 = 1, .gpid0 = 1, .ps0 = 1,
        .kill1 = 1, .gsid1 = 1, .gpid1 = 1,
        .proc_stat = 1, .proc_read = 0, .proc_opendir = 1,
    };

    assert_int_equal(check_rc_pid_report(42, &probes, always_thread), 0);
}

static void test_report_hidden_from_ps(void **state)
{
    (void)state;
    rc_pid_probes_t probes = {
        .kill0 = 1, .gsid0 = 1, .gpid0 = 1, .ps0 = 0,
        .kill1 = 1, .gsid1 = 1, .gpid1 = 1,
        .proc_stat = 1, .proc_read = 1, .proc_opendir = 1,
    };

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '42' hidden from ps. Possible trojaned version installed.");

    assert_int_equal(check_rc_pid_report(42, &probes, never_thread), 1);
}

/* ===================================================================
 * check_rc_pids() on Linux
 *
 * Every scan covers PIDs 1 to 4194303, above the old 32768 limit.
 * =================================================================== */

static void test_scan_threads_and_high_pids_not_reported(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1), PROC(500), THREAD(501, 500), THREAD(502, 500),
        PROC(40000), THREAD(40001, 40000), PROC(69999),
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_no_hidden(4);

    check_rc_pids();
}

static void test_scan_hidden_above_32768(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = { PROC(1), HIDDEN(50000) };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_hidden_from_proc(50000);

    check_rc_pids();
}

static void test_scan_process_started_during_sweep(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {600, 600, 1, 1, 1, LATER_ONLY, 1, LATER_ONLY},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_no_hidden(2);

    check_rc_pids();
}

static void test_scan_process_exited_during_sweep(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {700, 700, 0, 0, 0, FIRST_ONLY, 0, FIRST_ONLY},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_no_hidden(2);

    check_rc_pids();
}

/* tgkill() fails for it too, but it is not taken for a thread because kill()
 * does not reach it */
static void test_scan_hidden_from_kill_not_a_thread(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {60000, 60000, 0, 1, 1, NEVER, 1, NEVER},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '60000' hidden from kill (0) or getsid (1). Possible kernel-level rootkit.");

    check_rc_pids();
}

static void test_scan_covers_full_pid_range(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = { PROC(1), HIDDEN(30000), HIDDEN(4194303) };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_hidden_from_proc(30000);
    expect_hidden_from_proc(4194303);

    check_rc_pids();
}

static void test_scan_hidden_from_ps(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {800, 800, 1, 1, 1, ALWAYS, 1, NEVER},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '800' hidden from ps. Possible trojaned version installed.");

    check_rc_pids();
}

static void test_scan_ps_lists_nothing(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {800, 800, 1, 1, 1, ALWAYS, 1, NEVER},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));
    ps_empty = 1;

    expect_no_hidden(2);

    check_rc_pids();
}

static void test_scan_ps_exit_status_ignored(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {800, 800, 1, 1, 1, ALWAYS, 1, NEVER},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));
    ps_status = 1;

    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Process '800' hidden from ps. Possible trojaned version installed.");

    check_rc_pids();
}

static void test_scan_hidden_from_system_calls(void **state)
{
    (void)state;
    static const fake_task_t tasks[] = {
        PROC(1),
        {900, 900, 0, 0, 0, NEVER, 1, NEVER},
    };
    set_fake_tasks(tasks, sizeof(tasks) / sizeof(tasks[0]));

    expect_hidden_from_proc(900);

    check_rc_pids();
}

static void test_scan_excessive_hidden(void **state)
{
    (void)state;
    static fake_task_t tasks[18];
    tasks[0] = (fake_task_t)PROC(1);
    for (int i = 1; i < 18; i++) {
        tasks[i] = (fake_task_t)HIDDEN(51000 + i);
    }
    set_fake_tasks(tasks, 18);

    for (int i = 1; i <= 16; i++) {
        expect_hidden_from_proc(51000 + i);
    }
    expect_notify_rk(ALERT_SYSTEM_CRIT, "Excessive number of hidden processes. It maybe a false-positive or something really bad is going on.");

    check_rc_pids();
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_report_exited_process, setup),
        cmocka_unit_test_setup(test_report_hidden_from_kill, setup),
        cmocka_unit_test_setup(test_report_defunct_process_ignored, setup),
        cmocka_unit_test_setup(test_report_hidden_from_getpgid, setup),
        cmocka_unit_test_setup(test_report_hidden_from_proc, setup),
        cmocka_unit_test_setup(test_report_thread_not_hidden_from_proc, setup),
        cmocka_unit_test_setup(test_report_hidden_from_ps, setup),
        cmocka_unit_test_setup(test_scan_threads_and_high_pids_not_reported, setup),
        cmocka_unit_test_setup(test_scan_hidden_above_32768, setup),
        cmocka_unit_test_setup(test_scan_process_started_during_sweep, setup),
        cmocka_unit_test_setup(test_scan_process_exited_during_sweep, setup),
        cmocka_unit_test_setup(test_scan_hidden_from_kill_not_a_thread, setup),
        cmocka_unit_test_setup(test_scan_covers_full_pid_range, setup),
        cmocka_unit_test_setup(test_scan_hidden_from_ps, setup),
        cmocka_unit_test_setup(test_scan_ps_lists_nothing, setup),
        cmocka_unit_test_setup(test_scan_ps_exit_status_ignored, setup),
        cmocka_unit_test_setup(test_scan_hidden_from_system_calls, setup),
        cmocka_unit_test_setup(test_scan_excessive_hidden, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
