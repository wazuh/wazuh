/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include "shared.h"
#include "rootcheck.h"
#ifdef __linux__
#include <sys/syscall.h>
#endif

/* Prototypes */
static int  proc_read(int pid);
static int  proc_opendir(int pid);
static int  proc_stat(int pid);
static void loop_all_pids(const char *ps, pid_t max_pid, int *_errors, int *_total);

/* Global variables */
static int noproc;


/* If /proc is mounted, check to see if the pid is present */
static int proc_read(int pid)
{
    char dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(dir, OS_SIZE_1024, "%d", pid);
    if (isfile_ondir(dir, "/proc")) {
        return (1);
    }
    return (0);
}

/* If /proc is mounted, check to see if the pid is present */
static int proc_opendir(int pid)
{
    char    dir[OS_SIZE_1024 + 1];
    DIR     *dp = NULL;

    if (noproc) {
        return (0);
    }

    dp  = wopendir("/proc");
    if (!dp) {
        return 0;
    }
    closedir(dp);

    snprintf(dir, OS_SIZE_1024, "/proc/%d", pid);
    dp  = wopendir(dir);
    if (!dp) {
        return 0;
    }
    closedir(dp);

    return (1);
}

/* If /proc is mounted, check to see if the pid is present there */
static int proc_stat(int pid)
{
    char proc_dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(proc_dir, OS_SIZE_1024, "%s/%d", "/proc", pid);

    if (is_file(proc_dir)) {
        return (1);
    }

    return (0);
}

static void report_excessive_hidden(void)
{
    char op_msg[OS_SIZE_1024 + 1];
    snprintf(op_msg, OS_SIZE_1024, "Excessive number of hidden processes"
             ". It maybe a false-positive or "
             "something really bad is going on.");
    notify_rk(ALERT_SYSTEM_CRIT, op_msg);
}

int check_rc_pid_report(pid_t pid, const rc_pid_probes_t *probes, int (*is_thread)(int pid))
{
    /* If it matches, process was terminated in the meantime, so move on */
    if (!probes->gsid1 && !probes->kill1 && !probes->gpid1 && !probes->proc_stat &&
            !probes->proc_read && !probes->proc_opendir) {
        return (0);
    }

#ifdef AIX
    /* Ignore AIX wait and sched programs */
    if (probes->gsid0 == probes->gsid1 &&
            probes->kill0 == probes->kill1 &&
            probes->gpid0 == probes->gpid1 &&
            probes->ps0 == 1 &&
            probes->gsid0 == 1 &&
            probes->kill0 == 0) {
        /* The wait and sched programs do not respond to kill 0.
         * So if everything else finds it, including ps, getpid, getsid,
         * but not kill, we can safely ignore on AIX.
         * A malicious program would specially try to hide from ps.
         */
        return (0);
    }
#endif

    if (probes->gsid0 == probes->gsid1 &&
            probes->kill0 == probes->kill1 &&
            probes->gsid0 != probes->kill0) {
        /* If kill worked, but getsid and getpgid did not, it may
         * be a defunct process -- ignore.
         */
        if (! (probes->kill0 == 1 && probes->gsid0 == 0 && probes->gpid0 == 0 && probes->gsid1 == 0) ) {
            char op_msg[OS_SIZE_1024 + 1];

            snprintf(op_msg, OS_SIZE_1024, "Process '%d' hidden from "
                     "kill (%d) or getsid (%d). Possible kernel-level"
                     " rootkit.", (int)pid, probes->kill0, probes->gsid0);
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            return (1);
        }
    } else if (probes->kill1 != probes->gsid1 ||
               probes->gpid1 != probes->kill1 ||
               probes->gpid1 != probes->gsid1) {
        /* See defunct process comment above */
        if (! (probes->kill1 == 1 && probes->gsid1 == 0 && probes->gpid0 == 0) ) {
            char op_msg[OS_SIZE_1024 + 1];

            snprintf(op_msg, OS_SIZE_1024, "Process '%d' hidden from "
                     "kill (%d), getsid (%d) or getpgid. Possible "
                     "kernel-level rootkit.", (int)pid, probes->kill1, probes->gsid1);
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            return (1);
        }
    } else if (probes->proc_read != probes->proc_stat  ||
               probes->proc_read != probes->proc_opendir ||
               probes->proc_stat != probes->kill1) {
        /* Check if the pid is a thread (not showing in /proc */
        if (!noproc && !is_thread((int)pid)) {
            char op_msg[OS_SIZE_1024 + 1];

            snprintf(op_msg, OS_SIZE_1024, "Process '%d' hidden from "
                     "/proc. Possible kernel level rootkit.", (int)pid);
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            return (1);
        }
    } else if (probes->gsid1 && probes->kill1 && !probes->ps0) {
        /* checking if the pid is a thread (not showing on ps */
        if (!is_thread((int)pid)) {
            char op_msg[OS_SIZE_1024 + 1];

            snprintf(op_msg, OS_SIZE_1024, "Process '%d' hidden from "
                     "ps. Possible trojaned version installed.",
                     (int)pid);
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            return (1);
        }
    }

    return (0);
}

/* Check all the available PIDs for hidden stuff */
static void loop_all_pids(const char *ps, pid_t max_pid, int *_errors, int *_total)
{
    int _kill0 = 0;
    int _kill1 = 0;
    int _gsid0 = 0;
    int _gsid1 = 0;
    int _gpid0 = 0;
    int _gpid1 = 0;
    int _ps0 = -1;
    int _proc_stat  = 0;
    int _proc_read  = 0;
    int _proc_opendir = 0;

    pid_t i = 1;
    pid_t my_pid;

    char command[OS_SIZE_1024 + 64];

    my_pid = getpid();

    for (;; i++) {
        if ((i <= 0) || (i > max_pid)) {
            break;
        }

        (*_total)++;

        _kill0 = 0;
        _kill1 = 0;
        _gsid0 = 0;
        _gsid1 = 0;
        _gpid0 = 0;
        _gpid1 = 0;
        _ps0 = -1;

        /* kill test */
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) {
            _kill0 = 1;
        }

        /* getsid test */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {
            _gsid0 = 1;
        }

        /* getpgid test */
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {
            _gpid0 = 1;
        }

        /* /proc test */
        _proc_stat = proc_stat(i);
        _proc_read = proc_read(i);
        _proc_opendir = proc_opendir(i);

        /* If PID does not exist, move on */
        if (!_kill0     && !_gsid0     && !_gpid0 &&
                !_proc_stat && !_proc_read && !_proc_opendir) {
            continue;
        }

        /* Ignore our own pid */
        if (i == my_pid) {
            continue;
        }

        /* Check the number of errors */
        if ((*_errors) > 15) {
            report_excessive_hidden();
            return;
        }

        /* Check if the process appears in ps(1) output */
        if (*ps) {
            snprintf(command, sizeof(command), "%s -p %d > /dev/null 2>&1", ps, (int)i);
            _ps0 = 0;
            if (system(command) == 0) {
                _ps0 = 1;
            }
        }

        /* If we are run in the context of OSSEC-HIDS, sleep here (no rush) */
#ifdef OSSECHIDS
#ifdef WIN32
        Sleep(rootcheck.tsleep);
#else
        struct timeval timeout = {0, rootcheck.tsleep * 1000};
        select(0, NULL, NULL, NULL, &timeout);
#endif
#endif

        /* Everything fine, move on */
        if (_ps0 && _kill0 && _gsid0 && _gpid0 && _proc_stat && _proc_read) {
            continue;
        }

        /*
         * If our kill or getsid system call got the PID but ps(1) did not,
         * find out if the PID is deleted (not used anymore)
         */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {
            _gsid1 = 1;
        }
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) {
            _kill1 = 1;
        }
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {
            _gpid1 = 1;
        }

        _proc_stat = proc_stat(i);
        _proc_read = proc_read(i);
        _proc_opendir = proc_opendir(i);

        rc_pid_probes_t probes = {
            .kill0 = _kill0, .gsid0 = _gsid0, .gpid0 = _gpid0, .ps0 = _ps0,
            .kill1 = _kill1, .gsid1 = _gsid1, .gpid1 = _gpid1,
            .proc_stat = _proc_stat, .proc_read = _proc_read, .proc_opendir = _proc_opendir,
        };

        if (check_rc_pid_report(i, &probes, check_rc_readproc)) {
            (*_errors)++;
        }
    }
}

#ifdef __linux__
/* Highest PID a 64-bit kernel can assign. pid_max is not used as the bound:
 * lowering it leaves running processes above the new value */
#define RC_PID_LIMIT 4194303

#define RC_BIT_SET(map, n) ((map)[(n) >> 3] |= (unsigned char)(1 << ((n) & 7)))
#define RC_BIT_GET(map, n) (((map)[(n) >> 3] >> ((n) & 7)) & 1)

typedef struct {
    pid_t pid;
    rc_pid_probes_t probes;
} rc_pid_candidate_t;

/* Mark the numeric entries of /proc. Returns -1 if /proc cannot be read */
static int rc_read_proc_list(unsigned char *map, size_t map_size, pid_t max_pid)
{
    DIR *dp = wopendir("/proc");
    struct dirent *entry;

    if (!dp) {
        return (-1);
    }

    memset(map, 0, map_size);

    while ((entry = readdir(dp)) != NULL) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);

        if (*end == '\0' && pid > 0 && pid <= max_pid) {
            RC_BIT_SET(map, pid);
        }
    }

    closedir(dp);
    return (0);
}

/* Mark the PIDs listed by ps. Returns 0 if it listed none */
static int rc_read_ps_list(const char *ps, unsigned char *map, size_t map_size, pid_t max_pid)
{
    char command[OS_SIZE_1024 + 64];
    char line[OS_SIZE_128];
    int found = 0;
    FILE *fp;

    snprintf(command, sizeof(command), "%s -e -o pid= 2>/dev/null", ps);

    fp = popen(command, "r");
    if (!fp) {
        return (0);
    }

    memset(map, 0, map_size);

    while (fgets(line, sizeof(line), fp)) {
        long pid = strtol(line, NULL, 10);

        if (pid > 0 && pid <= max_pid) {
            RC_BIT_SET(map, pid);
            found = 1;
        }
    }

    /* The exit status is not trusted: a tampered ps could fail on purpose to
     * turn the comparison off */
    pclose(fp);

    if (!found) {
        mtdebug1(ARGV0, "No process list from '%s'. Skipping the ps comparison.", ps);
    }

    return (found);
}

/* Whether pid is a thread other than its process's main thread: kill() reaches
 * it, but tgkill() does not take it as the leader of its own thread group */
static int rc_is_thread(int pid)
{
    if (kill(pid, 0) == -1 && errno == ESRCH) {
        return (0);
    }

    return (syscall(SYS_tgkill, pid, pid, 0) == -1 && errno == ESRCH);
}

/* Probe every PID the kernel can assign, comparing each one against a single
 * snapshot of /proc and ps. Returns -1 if /proc cannot be read */
static int scan_all_pids_linux(const char *ps, int *_errors, int *_total)
{
    pid_t max_pid = RC_PID_LIMIT;
    size_t map_size = ((size_t)max_pid >> 3) + 1;
    unsigned char *listed = NULL;
    unsigned char *ps_seen = NULL;
    rc_pid_candidate_t *candidates = NULL;
    size_t ncandidates = 0;
    size_t capacity = 0;
    size_t c;
    int ps_usable = 0;
    int ret = 0;
    pid_t my_pid = getpid();
    pid_t i;

    os_calloc(map_size, sizeof(unsigned char), listed);
    os_calloc(map_size, sizeof(unsigned char), ps_seen);

    if (rc_read_proc_list(listed, map_size, max_pid) < 0) {
        ret = -1;
        goto end;
    }

    if (*ps) {
        ps_usable = rc_read_ps_list(ps, ps_seen, map_size, max_pid);
    }

    for (i = 1; i <= max_pid; i++) {
        rc_pid_probes_t probes = { .ps0 = -1 };
        int listed_pid = RC_BIT_GET(listed, i);

        probes.kill0 = !((kill(i, 0) == -1) && (errno == ESRCH));
        probes.gsid0 = !((getsid(i) == -1) && (errno == ESRCH));
        probes.gpid0 = !((getpgid(i) == -1) && (errno == ESRCH));

        /* Only IDs the system calls do not see are looked up in /proc: a
         * missing entry leaves nothing cached, a thread's entry would */
        if (!probes.kill0 && !probes.gsid0 && !probes.gpid0 && !listed_pid && !proc_stat(i)) {
            continue;
        }

        if (i == my_pid) {
            continue;
        }

        /* Threads answer the system calls but are never listed in /proc */
        if (!listed_pid && rc_is_thread(i)) {
            continue;
        }

        (*_total)++;

        if (ps_usable) {
            probes.ps0 = RC_BIT_GET(ps_seen, i);
        }

        if (listed_pid && probes.kill0 && probes.gsid0 && probes.gpid0 && probes.ps0 && proc_stat(i)) {
            continue;
        }

        if (ncandidates == capacity) {
            capacity = capacity ? capacity * 2 : 16;
            os_realloc(candidates, capacity * sizeof(rc_pid_candidate_t), candidates);
        }

        candidates[ncandidates].pid = i;
        candidates[ncandidates].probes = probes;
        ncandidates++;
    }

    /* Re-check with ps output read once more and fresh probes per PID, so a
     * process that started or exited during the sweep is not reported */
    if (ncandidates > 0 && ps_usable) {
        ps_usable = rc_read_ps_list(ps, ps_seen, map_size, max_pid);
    }

    for (c = 0; c < ncandidates; c++) {
        pid_t pid = candidates[c].pid;
        rc_pid_probes_t *probes = &candidates[c].probes;

        if ((*_errors) > 15) {
            report_excessive_hidden();
            break;
        }

        probes->kill1 = !((kill(pid, 0) == -1) && (errno == ESRCH));
        probes->gsid1 = !((getsid(pid) == -1) && (errno == ESRCH));
        probes->gpid1 = !((getpgid(pid) == -1) && (errno == ESRCH));
        probes->proc_stat = proc_stat(pid);
        probes->proc_read = proc_read(pid);
        probes->proc_opendir = proc_opendir(pid);
        probes->ps0 = ps_usable ? RC_BIT_GET(ps_seen, pid) : -1;

        if (check_rc_pid_report(pid, probes, rc_is_thread)) {
            (*_errors)++;
        }
    }

end:
    os_free(candidates);
    os_free(listed);
    os_free(ps_seen);
    return (ret);
}
#endif

/* Scan the whole filesystem looking for possible issues */
void check_rc_pids()
{
    int _total = 0;
    int _errors = 0;

    char ps[OS_SIZE_1024 + 1];

    char proc_0[] = "/proc";
    char proc_1[] = "/proc/1";

    pid_t max_pid = MAX_PID;
    noproc = 1;

    /* Checking where ps is */
    memset(ps, '\0', OS_SIZE_1024 + 1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if (!is_file(ps)) {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if (!is_file(ps)) {
            ps[0] = '\0';
        }
    }

    /* Proc is mounted */
    if (is_file(proc_0) && is_file(proc_1)) {
        noproc = 0;
    }

#ifdef __linux__
    if (noproc || scan_all_pids_linux(ps, &_errors, &_total) < 0) {
        loop_all_pids(ps, max_pid, &_errors, &_total);
    }
#else
    loop_all_pids(ps, max_pid, &_errors, &_total);
#endif

    if (_errors == 0) {
        char op_msg[OS_SIZE_2048];
        snprintf(op_msg, OS_SIZE_2048, "No hidden process by Kernel-level "
                 "rootkits.\n      %s is not trojaned. "
                 "Analyzed %d processes.", ps, _total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

#else
void check_rc_pids()
{
    return;
}
#endif
