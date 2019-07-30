/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* SCHED_BATCH is Linux specific and is only picked up with _GNU_SOURCE */
#ifdef __linux__
#include <sched.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "rootcheck/rootcheck.h"

/* Prototypes */
//static void send_sk_db(int first_scan);
void * fim_run_realtime(__attribute__((unused)) void * args);
void * fim_run_integrity(__attribute__((unused)) void * args);


#ifdef WIN32
static void fim_realtime_windows ();
#elif defined INOTIFY_ENABLED
static void fim_realtime_linux ();
static void *symlink_checker_thread(__attribute__((unused)) void * data);
static void update_link_monitoring(int pos, char *old_path, char *new_path);
static void unlink_files(OSHashNode **row, OSHashNode **node, void *data);
static void send_silent_del(char *path);
#endif


/* Send a message related to syscheck change/addition */
int send_syscheck_msg(const char *msg)
{
    if (SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQPATH);
        }

        /* Try to send it again */
        SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ);
    }
    mdebug1(FIM_CHECKSUM_MSG, msg);
    return (0);
}


/* Send a message related to rootcheck change/addition */
int send_rootcheck_msg(const char *msg)
{
    if (SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQPATH);
        }

        /* Try to send it again */
        SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ);
    }
    return (0);
}


/* Periodically run the integrity checker */
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    time_t curr_time = 0;
    time_t prev_time_sk = 0;
    char curr_hour[12];
    struct tm *p;
    //int first_start = 1;

#ifndef WIN32
    /* Launch rootcheck thread */
    w_create_thread(w_rootcheck_thread, &syscheck);
#else
    if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)w_rootcheck_thread,
                    &syscheck,
                    0,
                    NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif

    /* SCHED_BATCH forces the kernel to assume this is a cpu intensive
     * process and gives it a lower priority. This keeps ossec-syscheckd
     * from reducing the interactivity of an ssh session when checksumming
     * large files. This is available in kernel flavors >= 2.6.16.
     */
#ifdef SCHED_BATCH
    struct sched_param pri;
    int status;

    pri.sched_priority = 15;
    status = sched_setscheduler(0, SCHED_BATCH, &pri);

    mdebug1(FIM_SCHED_BATCH, status);
#endif

    minfo(FIM_DAEMON_STARTED);

    /* Some time to settle */
    memset(curr_hour, '\0', 12);
    sleep(syscheck.tsleep * 3);

    /* If the scan time/day is set, reset the syscheck.time/rootcheck.time */
    if (syscheck.scan_time || syscheck.scan_day) {
        /* At least once a week */
        syscheck.time = 604800;
    }

    if (!syscheck.disabled) {
        minfo(FIM_FREQUENCY_TIME, syscheck.time);
        fim_scan();
    }

#ifndef WIN32
    /* Launch Real-time thread */
    w_create_thread(fim_run_realtime, &syscheck);
#else
    if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)fim_run_realtime,
                    &syscheck,
                    0,
                    NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif

#ifdef WIN_WHODATA
    HANDLE t_hdle;
    long unsigned int t_id;
    //  Scan
    if (syscheck.wdata.whodata_setup && !run_whodata_scan()) {
        if (t_hdle = CreateThread(NULL, 0, state_checker, NULL, 0, &t_id), !t_hdle) {
            merror(FIM_ERROR_CHECK_THREAD);
        }

    }
#endif

#ifdef ENABLE_AUDIT
        audit_set_db_consistency();
#endif

    /* Before entering in daemon mode itself */
    prev_time_sk = time(0);

    /* If the scan_time or scan_day is set, we need to handle the
     * current day/time on the loop.
     */
    if (syscheck.scan_time || syscheck.scan_day) {
        curr_time = time(0);
        p = localtime(&curr_time);

        /* Assign hour/min/sec values */
        snprintf(curr_hour, 9, "%02d:%02d:%02d",
                 p->tm_hour,
                 p->tm_min,
                 p->tm_sec);

        curr_day = p->tm_mday;

        if (syscheck.scan_time && syscheck.scan_day) {
            if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                    (OS_IsonDay(p->tm_wday, syscheck.scan_day))) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_time) {
            if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_day) {
            if (OS_IsonDay(p->tm_wday, syscheck.scan_day)) {
                day_scanned = 1;
            }
        }
    }

    /* Check every SYSCHECK_WAIT */
    while (1) {
        int run_now = 0;
        curr_time = time(0);

        /* Check if syscheck should be restarted */
        run_now = os_check_restart_syscheck();

        /* Check if a day_time or scan_time is set */
        if (syscheck.scan_time || syscheck.scan_day) {
            p = localtime(&curr_time);

            /* Day changed */
            if (curr_day != p->tm_mday) {
                day_scanned = 0;
                curr_day = p->tm_mday;
            }

            /* Check for the time of the scan */
            if (!day_scanned && syscheck.scan_time && syscheck.scan_day) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                        (OS_IsonDay(p->tm_wday, syscheck.scan_day))) {
                    day_scanned = 1;
                    run_now = 1;
                }
            } else if (!day_scanned && syscheck.scan_time) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            } else if (!day_scanned && syscheck.scan_day) {
                /* Check for the day of the scan */
                if (OS_IsonDay(p->tm_wday, syscheck.scan_day)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            }
        }

        /* If time elapsed is higher than the syscheck time, run syscheck time */
        if (((curr_time - prev_time_sk) > syscheck.time) || run_now) {
            fim_scheduled_scan();
            prev_time_sk = time(0);
        }
        sleep(SYSCHECK_WAIT);
    }
}


// Starting Real-time thread
void * fim_run_realtime(__attribute__((unused)) void * args) {

    while (1) {
        log_realtime_status(1);
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
#ifdef INOTIFY_ENABLED
            fim_realtime_linux ();
#elif defined WIN32
            fim_realtime_windows ();
#endif
        } else {
            pthread_exit(NULL);
        }
    }
}


// Realtime in Windows
#ifdef WIN32
void fim_realtime_windows () {
    if (WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE) == WAIT_FAILED) {
        merror(FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
        sleep(SYSCHECK_WAIT);
    } else {
        sleep(syscheck.tsleep);
    }

}
#endif


// Realtime in Linux OS with INOTIFY
#ifdef INOTIFY_ENABLED
void fim_realtime_linux () {
    struct timeval selecttime;
    fd_set rfds;
    int run_now = 0;

    selecttime.tv_sec = SYSCHECK_WAIT;
    selecttime.tv_usec = 0;

    /* zero-out the fd_set */
    FD_ZERO (&rfds);
    FD_SET(syscheck.realtime->fd, &rfds);

    run_now = select(syscheck.realtime->fd + 1,
                    &rfds,
                    NULL,
                    NULL,
                    &selecttime);

    if (run_now < 0) {
        merror(FIM_ERROR_SELECT);
    } else if (run_now == 0) {
        /* Timeout */
    } else if (FD_ISSET (syscheck.realtime->fd, &rfds)) {
        realtime_process();
    }
}
#endif


void log_realtime_status(int next) {
    /*
     * 0: stop (initial)
     * 1: run
     * 2: pause
     */

    static int status = 0;

    switch (status) {
    case 0:
        if (next == 1) {
            minfo(FIM_REALTIME_STARTED);
            status = next;
        }
        break;
    case 1:
        if (next == 2) {
            minfo(FIM_REALTIME_PAUSED);
            status = next;
        }
        break;
    case 2:
        if (next == 1) {
            minfo(FIM_REALTIME_RESUMED);
            status = next;
        }
    }
}

void symlink_checker_init() {
#ifndef WIN32
    w_create_thread(symlink_checker_thread, NULL);
#endif
}

#ifndef WIN32
static void *symlink_checker_thread(__attribute__((unused)) void * data) {
    int checker_sleep = getDefine_Int("syscheck", "symlink_scan_interval", 1, 2592000);
    int i;
    char *real_path;
    char *conv_link;

    syscheck.sym_checker_interval = checker_sleep;
    mdebug1(FIM_LINKCHECK_START, checker_sleep);

    while (1) {
        sleep(checker_sleep);
        mdebug1(FIM_LINKCHECK_START, checker_sleep);

        for (i = 0; syscheck.dir[i]; i++) {
            if (syscheck.converted_links[i]) {
                if (real_path = realpath(syscheck.dir[i], NULL), !real_path) {
                    continue;
                }

                conv_link = NULL;

                //if (strcmp(real_path, conv_link)) {
                    minfo(FIM_LINKCHECK_CHANGED, syscheck.dir[i], conv_link, real_path);
                    update_link_monitoring(i, conv_link, real_path);
                //} else {
                //    mdebug1(FIM_LINKCHECK_NOCHANGE, syscheck.dir[i]);
                //}

                //free(conv_link);
                free(real_path);
            }
        }

        mdebug1(FIM_LINKCHECK_FINALIZE);
    }

    return NULL;
}


static void update_link_monitoring(int pos, char *old_path, char *new_path) {
    w_rwlock_wrlock((pthread_rwlock_t *)&syscheck.fp->mutex);
    free(syscheck.converted_links[pos]);
    os_strdup(new_path, syscheck.converted_links[pos]);
    w_rwlock_unlock((pthread_rwlock_t *)&syscheck.fp->mutex);

    // Scan for new files
    //read_dir(new_path, NULL, pos, NULL, syscheck.recursion_level[pos], 0, '+');

    // Remove unlink files
    OSHash_It_ex(syscheck.fp, 2, (void *) old_path, unlink_files);
}


static void unlink_files(OSHashNode **row, OSHashNode **node, void *data) {
    char *dir = (char *) data;

    if (!strncmp(dir, (*node)->key, strlen(dir))) {
        syscheck_node *s_node = (syscheck_node *) (*node)->data;
        OSHashNode *r_node = *node;

        mdebug2(FIM_LINKCHECK_FILE, (*node)->key, dir);

        send_silent_del((*node)->key);

        if ((*node)->next) {
            (*node)->next->prev = (*node)->prev;
        }

        if ((*node)->prev) {
            (*node)->prev->next = (*node)->next;
        }

        *node = (*node)->next;

        // If the node is the first and last node of the row
        if (*row == r_node) {
            *row = r_node->next;
        }

        free(r_node->key);
        free(r_node);
        free(s_node->checksum);
        free(s_node);
    }
}

static void send_silent_del(char *path) {
    char del_msg[OS_SIZE_6144 + 1];

    snprintf(del_msg, OS_SIZE_6144, "-1!:::::::::::::+ %s", path);
    send_syscheck_msg(del_msg);
}


// Starting Real-time thread
void * fim_run_integrity(__attribute__((unused)) void * args) {

    while (1) {
        sleep(600);
    }
}

#endif
