/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


// SCHED_BATCH is Linux specific and is only picked up with _GNU_SOURCE
#ifdef __linux__
#include <sched.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "rootcheck/rootcheck.h"

// Prototypes
void * fim_run_realtime(__attribute__((unused)) void * args);
int fim_whodata_initialize();

#ifdef WIN32
static void set_priority_windows_thread();
#elif defined INOTIFY_ENABLED
static void *symlink_checker_thread(__attribute__((unused)) void * data);
static void fim_link_update(int pos, char *new_path);
static void fim_link_check_delete(int pos);
static void fim_link_delete_range(int pos);
static void fim_link_silent_scan(char *path, int pos);
static void fim_link_reload_broken_link(char *path, int index);
#endif

// Send a message
static void fim_send_msg(char mq, const char * location, const char * msg) {
    if (SendMSG(syscheck.queue, msg, location, mq) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQPATH);
        }

        // Try to send it again
        SendMSG(syscheck.queue, msg, location, mq);
    }
}

// Send a data synchronization control message
void fim_send_sync_msg(const char * msg) {
    mdebug2(FIM_DBSYNC_SEND, msg);
    fim_send_msg(DBSYNC_MQ, SYSCHECK, msg);
    struct timespec timeout = { syscheck.send_delay / 1000000, syscheck.send_delay % 1000000 * 1000 };
    nanosleep(&timeout, NULL);
}

// Send a message related to syscheck change/addition
void send_syscheck_msg(const char *msg)
{
#ifndef WIN32
    mdebug2(FIM_SEND, msg);
#endif
    fim_send_msg(SYSCHECK_MQ, SYSCHECK, msg);
    struct timespec timeout = { syscheck.send_delay / 1000000, syscheck.send_delay % 1000000 * 1000 };
    nanosleep(&timeout, NULL);
}

// Send a scan info event
void fim_send_scan_info(fim_scan_event event) {
    cJSON * json = fim_scan_info_json(event, time(NULL));
    char * plain = cJSON_PrintUnformatted(json);

    send_syscheck_msg(plain);

    free(plain);
    cJSON_Delete(json);
}

// Send a message related to logs
int send_log_msg(const char * msg)
{
    fim_send_msg(LOCALFILE_MQ, SYSCHECK, msg);
    return (0);
}


// Periodically run the integrity checker
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    time_t curr_time = 0;
    time_t prev_time_sk = 0;
    char curr_hour[12];
    struct tm *p;

    // Some time to settle
    memset(curr_hour, '\0', 12);
    sleep(syscheck.tsleep);
    minfo(FIM_DAEMON_STARTED);

    // A higher nice value means a low priority.
#ifndef WIN32
    mdebug1(FIM_PROCESS_PRIORITY, syscheck.process_priority);

    if (nice(syscheck.process_priority) == -1) {
        merror(NICE_ERROR, strerror(errno), errno);
    }
#endif

#ifndef WIN32
    // Launch rootcheck thread
    w_create_thread(w_rootcheck_thread, &syscheck);
#else
    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)w_rootcheck_thread,
            &syscheck, 0, NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif

    // If the scan time/day is set, reset the syscheck.time/rootcheck.time
    if (syscheck.scan_time || syscheck.scan_day) {
        // At least once a week
        syscheck.time = 604800;
    }

    // Deleting content local/diff directory
    char *diff_dir;

    os_calloc(PATH_MAX, sizeof(char), diff_dir);
    snprintf(diff_dir, PATH_MAX, "%s/local/", DIFF_DIR_PATH);

    cldir_ex(diff_dir);

    if (syscheck.disabled) {
        return;
    }

    // Create File integrity monitoring base-line
    minfo(FIM_FREQUENCY_TIME, syscheck.time);
    fim_scan();
#ifndef WIN32
    // Launch Real-time thread
    w_create_thread(fim_run_realtime, &syscheck);

    // Launch inventory synchronization thread, if enabled
    if (syscheck.enable_inventory) {
        w_create_thread(fim_run_integrity, &syscheck);
    }

    // Launch symbolic links checker thread
    w_create_thread(symlink_checker_thread, NULL);

#else
    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fim_run_integrity,
            &syscheck, 0, NULL) == NULL) {
        merror(THREAD_ERROR);
    }
    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fim_run_realtime,
            &syscheck, 0, NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif

    // Launch Whodata real-time thread
    fim_whodata_initialize();

    // Before entering in daemon mode itself
    prev_time_sk = time(0);

    // If the scan_time or scan_day is set, we need to handle the current day/time on the loop.
    if (syscheck.scan_time || syscheck.scan_day) {
        curr_time = time(0);
        p = localtime(&curr_time);

        // Assign hour/min/sec values
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

    // Check every SYSCHECK_WAIT
    while (1) {
        int run_now = 0;
        curr_time = time(0);

        // Check if syscheck should be restarted
        run_now = os_check_restart_syscheck();

        // Check if a day_time or scan_time is set
        if (syscheck.scan_time || syscheck.scan_day) {
            p = localtime(&curr_time);

            // Day changed
            if (curr_day != p->tm_mday) {
                day_scanned = 0;
                curr_day = p->tm_mday;
            }

            // Check for the time of the scan
            if (!day_scanned && syscheck.scan_time && syscheck.scan_day) {
                // Assign hour/min/sec values
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                        (OS_IsonDay(p->tm_wday, syscheck.scan_day))) {
                    day_scanned = 1;
                    run_now = 1;
                }
            } else if (!day_scanned && syscheck.scan_time) {
                // Assign hour/min/sec values
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            } else if (!day_scanned && syscheck.scan_day) {
                // Check for the day of the scan
                if (OS_IsonDay(p->tm_wday, syscheck.scan_day)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            }
        }

        // If time elapsed is higher than the syscheck time, run syscheck time
        if (((curr_time - prev_time_sk) > syscheck.time) || run_now) {
            fim_scan();
            prev_time_sk = time(0);
        }
        sleep(SYSCHECK_WAIT);
    }
}


// Starting Real-time thread
void * fim_run_realtime(__attribute__((unused)) void * args) {

#if defined INOTIFY_ENABLED || defined WIN32

#ifdef WIN32
    set_priority_windows_thread();

    // Directories in Windows configured with real-time add recursive watches
    int i = 0;
    while (syscheck.dir[i]) {
        if (syscheck.opts[i] & REALTIME_ACTIVE) {
            realtime_adddir(syscheck.dir[i], 0);
        }
        i++;
    }
#endif

    while (1) {
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            log_realtime_status(1);

#ifdef INOTIFY_ENABLED
            struct timeval selecttime;
            fd_set rfds;
            int run_now = 0;

            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            // zero-out the fd_set
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
                // Timeout
            } else if (FD_ISSET (syscheck.realtime->fd, &rfds)) {
                realtime_process();
            }

#elif defined WIN32
            if (WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE) == WAIT_FAILED) {
                merror(FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
            }
#endif
        } else {
            sleep(SYSCHECK_WAIT);
        }
    }

#else
    mwarn(FIM_WARN_REALTIME_UNSUPPORTED);
    pthread_exit(NULL);
#endif

}


#ifdef WIN32
void set_priority_windows_thread() {
    DWORD dwCreationFlags = syscheck.process_priority <= -10 ? THREAD_PRIORITY_HIGHEST :
                      syscheck.process_priority <= -5 ? THREAD_PRIORITY_ABOVE_NORMAL :
                      syscheck.process_priority <= 0 ? THREAD_PRIORITY_NORMAL :
                      syscheck.process_priority <= 5 ? THREAD_PRIORITY_BELOW_NORMAL :
                      syscheck.process_priority <= 10 ? THREAD_PRIORITY_LOWEST :
                      THREAD_PRIORITY_IDLE;

    mdebug1(FIM_PROCESS_PRIORITY, syscheck.process_priority);

    if(!SetThreadPriority(GetCurrentThread(), dwCreationFlags)) {
        int dwError = GetLastError();
        merror("Can't set thread priority: %d", dwError);
    }
}
#endif


int fim_whodata_initialize() {
#if defined INOTIFY_ENABLED || defined WIN32

#ifdef WIN32
    set_priority_windows_thread();
#endif

    for (int i = 0; syscheck.dir[i]; i++) {
        if (syscheck.opts[i] & WHODATA_ACTIVE) {
            realtime_adddir(syscheck.dir[i], i + 1);
        }
    }

#ifdef WIN_WHODATA
    HANDLE t_hdle;
    long unsigned int t_id;
    if (syscheck.wdata.whodata_setup && !run_whodata_scan()) {
        if (t_hdle = CreateThread(NULL, 0, state_checker, NULL, 0, &t_id), !t_hdle) {
            merror(FIM_ERROR_CHECK_THREAD);
            return -1;
        }
    }
#elif ENABLE_AUDIT
    audit_set_db_consistency();
#endif

#else
    mwarn(FIM_WARN_WHODATA_UNSUPPORTED);
#endif

    return 0;
}

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


#ifdef INOTIFY_ENABLED
static void *symlink_checker_thread(__attribute__((unused)) void * data) {
    char *real_path;
    int i;

    syscheck.sym_checker_interval = getDefine_Int("syscheck", "symlink_scan_interval", 1, 2592000);
    mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

    while (1) {
        sleep(syscheck.sym_checker_interval);
        mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

        w_mutex_lock(&syscheck.fim_scan_mutex);
        for (i = 0; syscheck.dir[i]; i++) {
            if (!syscheck.symbolic_links[i]) {
                continue;
            }

            real_path = realpath(syscheck.symbolic_links[i], NULL);

            if (*syscheck.dir[i]) {
                if (real_path) {
                    // Check if link has changed
                    if (strcmp(real_path, syscheck.dir[i])) {
                        minfo(FIM_LINKCHECK_CHANGED, syscheck.dir[i], syscheck.symbolic_links[i], real_path);
                        fim_link_update(i, real_path);
                    } else {
                        mdebug1(FIM_LINKCHECK_NOCHANGE, syscheck.dir[i]);
                    }
                } else {
                    // Broken link
                    char path[PATH_MAX];

                    snprintf(path, PATH_MAX, "%s", syscheck.dir[i]);
                    fim_link_check_delete(i);

                    int config = fim_configuration_directory(path, "file");

                    if (config >= 0) {
                        fim_link_silent_scan(path, config);
                    }
                }
            } else {
                // Check real_path to reload broken link.
                if (real_path) {
                    fim_link_reload_broken_link(real_path, i);
                }
            }
            os_free(real_path);
        }
        w_mutex_unlock(&syscheck.fim_scan_mutex);
        mdebug1(FIM_LINKCHECK_FINALIZE);
    }

    return NULL;
}


static void fim_link_update(int pos, char *new_path) {
    if (*syscheck.dir[pos]) {
        fim_link_check_delete(pos);
    }

    os_free(syscheck.dir[pos]);
    os_calloc(strlen(new_path) + 1, sizeof(char), syscheck.dir[pos]);
    snprintf(syscheck.dir[pos], strlen(new_path) + 1, "%s", new_path);

    //Add new entries without alert.
    fim_link_silent_scan(new_path, pos);
}


static void fim_link_check_delete(int pos) {
    struct stat statbuf;

    if (w_stat(syscheck.symbolic_links[pos], &statbuf) < 0) {
        if(errno == ENOENT) {
            fim_link_delete_range(pos);
            *syscheck.dir[pos] = '\0';
            return;
        }
        mdebug1(FIM_STAT_FAILED, syscheck.symbolic_links[pos], errno, strerror(errno));
    }
}

static void fim_link_delete_range(int pos) {
    char **paths;
    char first_entry[PATH_MAX];
    char last_entry[PATH_MAX];
    int i;

    snprintf(first_entry, PATH_MAX, "%s/", syscheck.dir[pos]);
    snprintf(last_entry, PATH_MAX, "%s0", syscheck.dir[pos]);

    paths = rbtree_range(syscheck.fim_entry, first_entry, last_entry);

    // If link pointing to a file
    fim_delete(syscheck.dir[pos]);

    for(i = 0; paths[i] != NULL; i++) {
        int config = fim_configuration_directory(paths[i], "file");
        if (config == pos) {
            minfo("deleting file '%s'", paths[i]);
            fim_delete (paths[i]);
        }
    }
    os_free(paths);
}

static void fim_link_silent_scan(char *path, int pos) {
    struct fim_element *item;

    os_calloc(1, sizeof(fim_element), item);
    item->index = pos;
    item->mode = FIM_SCHEDULED;

#ifndef WIN32
    if (syscheck.opts[pos] & REALTIME_ACTIVE) {
        realtime_adddir(path, 0);
    }
#endif

    fim_checker(path, item, NULL, 0);
    os_free(item);
}

static void fim_link_reload_broken_link(char *path, int index) {
    int element;
    int found = 0;

    for (element = 0; syscheck.dir[element]; element++) {
        if (strcmp(path, syscheck.dir[element]) == 0) {
            // If a configuration directory exsists dont reload
            mwarn("Directory '%s' already monitoried, ignoring link '%s'",
                  syscheck.dir[element], syscheck.symbolic_links[index]);
            found = 1;
        }
    }
    // Reload broken link
    if (!found) {
        fim_link_update(index, path);
    }
}
#endif
