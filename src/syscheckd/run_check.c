/* Copyright (C) 2015-2020, Wazuh Inc.
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

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "rootcheck/rootcheck.h"
#include "fim_db.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "unit_tests/wrappers/windows/processthreadsapi_wrappers.h"
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

// Prototypes
#ifdef WIN32
DWORD WINAPI fim_run_realtime(__attribute__((unused)) void * args);
#else
void * fim_run_realtime(__attribute__((unused)) void * args);
#endif

int fim_whodata_initialize();
#ifdef WIN32
STATIC void set_priority_windows_thread();
#ifdef WIN_WHODATA
STATIC void set_whodata_mode_changes();
#endif
#else
static void *symlink_checker_thread(__attribute__((unused)) void * data);
STATIC void fim_link_update(int pos, char *new_path);
STATIC void fim_link_check_delete(int pos);
STATIC void fim_link_delete_range(int pos);
STATIC void fim_link_silent_scan(char *path, int pos);
STATIC void fim_link_reload_broken_link(char *path, int index);
STATIC void fim_delete_realtime_watches(int pos);
#endif

// Send a message
STATIC void fim_send_msg(char mq, const char * location, const char * msg) {
    if (SendMSG(syscheck.queue, msg, location, mq) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
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

    if (syscheck.sync_max_eps == 0) {
        return;
    }

    static long n_msg_sent = 0;

    if (++n_msg_sent == syscheck.sync_max_eps) {
        sleep(1);
        n_msg_sent = 0;
    }
}


// Send a message related to syscheck change/addition
void send_syscheck_msg(const char *msg)
{
    mdebug2(FIM_SEND, msg);
    fim_send_msg(SYSCHECK_MQ, SYSCHECK, msg);

    if (syscheck.max_eps == 0) {
        return;
    }

    static unsigned n_msg_sent = 0;

    if (++n_msg_sent == syscheck.max_eps) {
        sleep(1);
        n_msg_sent = 0;
    }
}

// Send a scan info event
void fim_send_scan_info(fim_scan_event event) {
    cJSON * json = fim_scan_info_json(event, time(NULL));
    char * plain = cJSON_PrintUnformatted(json);

    send_syscheck_msg(plain);

    free(plain);
    cJSON_Delete(json);
}


// LCOV_EXCL_START
// Send a message related to logs
int send_log_msg(const char * msg)
{
    fim_send_msg(LOCALFILE_MQ, SYSCHECK, msg);
    return (0);
}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
// Periodically run the integrity checker
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    time_t curr_time = 0;
    time_t prev_time_sk = 0;
    char curr_hour[12];
    struct tm tm_result = { .tm_sec = 0 };

    // Some time to settle
    memset(curr_hour, '\0', 12);

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
    if (CreateThread(NULL, 0, w_rootcheck_thread, &syscheck, 0, NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif

    // If the scan time/day is set, reset the syscheck.time/rootcheck.time
    if (syscheck.scan_time || syscheck.scan_day) {
        // At least once a week
        syscheck.time = 604800;
    }

    // Deleting content local/diff directory
    char diff_dir[PATH_MAX];

    snprintf(diff_dir, PATH_MAX, "%s/local/", DIFF_DIR_PATH);

    if (cldir_ex(diff_dir) == -1 && errno != ENOENT) {
        merror("Unable to clear directory '%s': %s (%d)", diff_dir, strerror(errno), errno);
    }

    if (syscheck.disabled) {
        return;
    }

    minfo(FIM_DAEMON_STARTED);

    // Create File integrity monitoring base-line
    minfo(FIM_FREQUENCY_TIME, syscheck.time);
    fim_scan();
#ifndef WIN32
    // Launch Real-time thread
    w_create_thread(fim_run_realtime, &syscheck);

    // Launch inventory synchronization thread, if enabled
    if (syscheck.enable_synchronization) {
        w_create_thread(fim_run_integrity, &syscheck);
    }

    // Launch symbolic links checker thread
    w_create_thread(symlink_checker_thread, NULL);

#else
    if (syscheck.enable_synchronization) {
        if (CreateThread(NULL, 0, fim_run_integrity, &syscheck, 0, NULL) == NULL) {
            merror(THREAD_ERROR);
        }
    }

    if (CreateThread(NULL, 0, fim_run_realtime, &syscheck, 0, NULL) == NULL) {

        merror(THREAD_ERROR);
    }
#endif

    // Launch Whodata real-time thread
    if(syscheck.enable_whodata) {
        fim_whodata_initialize();
    }

    // Before entering in daemon mode itself
    prev_time_sk = time(0);

    // If the scan_time or scan_day is set, we need to handle the current day/time on the loop.
    if (syscheck.scan_time || syscheck.scan_day) {
        curr_time = time(0);
        localtime_r(&curr_time, &tm_result);

        // Assign hour/min/sec values
        snprintf(curr_hour, 9, "%02d:%02d:%02d",
                 tm_result.tm_hour,
                 tm_result.tm_min,
                 tm_result.tm_sec);

        curr_day = tm_result.tm_mday;

        if (syscheck.scan_time && syscheck.scan_day) {
            if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                    (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day))) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_time) {
            if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_day) {
            if (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day)) {
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
            localtime_r(&curr_time, &tm_result);

            // Day changed
            if (curr_day != tm_result.tm_mday) {
                day_scanned = 0;
                curr_day = tm_result.tm_mday;
            }

            // Check for the time of the scan
            if (!day_scanned && syscheck.scan_time && syscheck.scan_day) {
                // Assign hour/min/sec values
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         tm_result.tm_hour, tm_result.tm_min, tm_result.tm_sec);

                if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                        (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day))) {
                    day_scanned = 1;
                    run_now = 1;
                }
            } else if (!day_scanned && syscheck.scan_time) {
                // Assign hour/min/sec values
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         tm_result.tm_hour, tm_result.tm_min, tm_result.tm_sec);

                if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            } else if (!day_scanned && syscheck.scan_day) {
                // Check for the day of the scan
                if (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day)) {
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
// LCOV_EXCL_STOP


// LCOV_EXCL_START
// Starting Real-time thread
#ifdef WIN32
DWORD WINAPI fim_run_realtime(__attribute__((unused)) void * args) {
#else
void * fim_run_realtime(__attribute__((unused)) void * args) {
#endif

#if defined INOTIFY_ENABLED || defined WIN32

static int _base_line = 0;

#ifdef WIN32
    set_priority_windows_thread();
#endif

    while (1) {
#ifdef WIN32
        // Directories in Windows configured with real-time add recursive watches
        for (int i = 0; syscheck.dir[i]; i++) {
            if (syscheck.opts[i] & REALTIME_ACTIVE) {
                realtime_adddir(syscheck.dir[i], 0, 0);
            }
        }
#endif

        if (_base_line == 0) {
            _base_line = 1;

            if (syscheck.realtime != NULL) {
                if (syscheck.realtime->queue_overflow) {
                    realtime_sanitize_watch_map();
                    syscheck.realtime->queue_overflow = false;
                }
                mdebug2(FIM_NUM_WATCHES, syscheck.realtime->dirtb->elements);
            }
        }

#ifdef WIN_WHODATA
        if (syscheck.realtime_change) {
            set_whodata_mode_changes();
        }
#endif
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
    for (int i = 0; syscheck.dir[i]; i++) {
        if (syscheck.opts[i] & REALTIME_ACTIVE) {
            mwarn(FIM_WARN_REALTIME_UNSUPPORTED);
            break;
        }
    }

    pthread_exit(NULL);
#endif

}
// LCOV_EXCL_STOP


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
    int retval = 0;

#if defined ENABLE_AUDIT || defined WIN32

#ifdef WIN32
    set_priority_windows_thread();
#endif

    for (int i = 0; syscheck.dir[i]; i++) {

        if (syscheck.opts[i] & WHODATA_ACTIVE) {

#ifdef WIN_WHODATA // Whodata on Windows
            if(realtime_adddir(syscheck.dir[i], i + 1, 0) == -2) {
                syscheck.wdata.dirs_status[i].status &= ~WD_CHECK_WHODATA;
                syscheck.opts[i] &= ~WHODATA_ACTIVE;
                syscheck.wdata.dirs_status[i].status |= WD_CHECK_REALTIME;
                syscheck.realtime_change = 1;
            }
#else // Whodata on Linux
            realtime_adddir(fim_get_real_path(i), i + 1, (syscheck.opts[i] & CHECK_FOLLOW) ? 1 : 0);
#endif

        }
    }

#ifdef WIN_WHODATA
    HANDLE t_hdle;
    long unsigned int t_id;

    /* If the initialization of the Whodata engine fails,
    Wazuh must monitor files/directories in Realtime mode. */
    if (!run_whodata_scan()) {
        if (t_hdle = CreateThread(NULL, 0, state_checker, NULL, 0, &t_id), !t_hdle) {
            merror(FIM_ERROR_CHECK_THREAD);
            retval = -1;
        }
    } else {
        merror(FIM_ERROR_WHODATA_INIT);

        // In case SACLs and policies have been set, restore them.
        audit_restore();

        // Add proper flags for the realtime thread monitors the directories/files.
        for (int i = 0; syscheck.dir[i]; i++) {
            syscheck.wdata.dirs_status[i].status &= ~WD_CHECK_WHODATA;
            syscheck.opts[i] &= ~WHODATA_ACTIVE;
            syscheck.wdata.dirs_status[i].status |= WD_CHECK_REALTIME;
            syscheck.realtime_change = 1;
        }

        retval = -1;
    }

#elif ENABLE_AUDIT
    audit_set_db_consistency();

#endif

#else
    if (syscheck.enable_whodata) {
        mwarn(FIM_WARN_WHODATA_UNSUPPORTED);
    }
#endif

    return retval;
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


#ifndef WIN32
// LCOV_EXCL_START
static void *symlink_checker_thread(__attribute__((unused)) void * data) {
    char *real_path;
    int i;

    mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

    while (1) {
        sleep(syscheck.sym_checker_interval);
        mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

        w_mutex_lock(&syscheck.fim_scan_mutex);
        for (i = 0; syscheck.dir[i]; i++) {
            if (!syscheck.symbolic_links[i] || !(CHECK_FOLLOW & syscheck.opts[i])) {
                continue;
            }

            real_path = realpath(syscheck.dir[i], NULL);

            if (*syscheck.symbolic_links[i]) {
                if (real_path) {
                    // Check if link has changed
                    if (strcmp(real_path, syscheck.symbolic_links[i])) {
                        minfo(FIM_LINKCHECK_CHANGED, syscheck.dir[i], syscheck.symbolic_links[i], real_path);
                        fim_link_update(i, real_path);
                    } else {
                        mdebug1(FIM_LINKCHECK_NOCHANGE, syscheck.symbolic_links[i]);
                    }
                } else {
                    // Broken link
                    char path[PATH_MAX];

                    snprintf(path, PATH_MAX, "%s", syscheck.symbolic_links[i]);
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
// LCOV_EXCL_STOP

STATIC void fim_link_update(int pos, char *new_path) {
    int i;

    if (*syscheck.dir[pos]) {
        fim_link_delete_range(pos);
    }

    // Check if the updated path of the link is already in the configuration
    for (i = 0; syscheck.dir[i] != NULL; i++) {
        if (strcmp(new_path, syscheck.dir[i]) == 0) {
            mdebug1(FIM_LINK_ALREADY_ADDED, syscheck.dir[i]);
            *syscheck.symbolic_links[pos] = '\0';
            return;
        }
    }

    os_free(syscheck.symbolic_links[pos]);
    os_strdup(new_path, syscheck.symbolic_links[pos]);

    // Add new entries without alert.
    fim_link_silent_scan(new_path, pos);
}

STATIC void fim_link_check_delete(int pos) {
    struct stat statbuf;

    if (w_stat(syscheck.symbolic_links[pos], &statbuf) < 0) {
        if (errno == ENOENT) {
            *syscheck.symbolic_links[pos] = '\0';
            return;
        }

        mdebug1(FIM_STAT_FAILED, syscheck.symbolic_links[pos], errno, strerror(errno));
    } else {
        fim_link_delete_range(pos);

        if (syscheck.realtime && syscheck.realtime->dirtb) {
            fim_delete_realtime_watches(pos);
        }

        *syscheck.symbolic_links[pos] = '\0';
    }
}

STATIC void fim_delete_realtime_watches(__attribute__((unused)) int pos) {
#ifdef INOTIFY_ENABLED
    OSHashNode *hash_node;
    char *data;
    W_Vector * watch_to_delete = W_Vector_init(1024);
    unsigned int inode_it = 0;
    int deletion_it = 0;
    int dir_conf;
    int watch_conf;

    assert(watch_to_delete != NULL);
    dir_conf = fim_configuration_directory(syscheck.symbolic_links[pos], "file");

    if (dir_conf > -1) {
        w_mutex_lock(&syscheck.fim_realtime_mutex);
        hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it);
        while(hash_node) {
            data = hash_node->data;
            if (data) {
                watch_conf = fim_configuration_directory(data, "file");

                if (dir_conf == watch_conf) {
                    W_Vector_insert(watch_to_delete, hash_node->key);
                    deletion_it++;
                }
            }
            hash_node = OSHash_Next(syscheck.realtime->dirtb, &inode_it, hash_node);
        }

        deletion_it--;
        while(deletion_it >= 0) {
            const char * wd_str = W_Vector_get(watch_to_delete, deletion_it);
            assert(wd_str != NULL);

            inotify_rm_watch(syscheck.realtime->fd, atol(wd_str));
            free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd_str));
            deletion_it--;
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);
    }

    W_Vector_free(watch_to_delete);
#endif
    return;
}

STATIC void fim_link_delete_range(int pos) {
    char first_entry[PATH_MAX] = {0};
    char last_entry[PATH_MAX]  = {0};
    fim_tmp_file * file = NULL;

    snprintf(first_entry, PATH_MAX, "%s/", syscheck.symbolic_links[pos]);
    snprintf(last_entry, PATH_MAX, "%s0", syscheck.symbolic_links[pos]);

    w_mutex_lock(&syscheck.fim_entry_mutex);

    if (fim_db_get_path_range(syscheck.database, first_entry, last_entry, &file, syscheck.database_store) != FIMDB_OK) {
        merror(FIM_DB_ERROR_RM_RANGE, first_entry, last_entry);
    }

    w_mutex_unlock(&syscheck.fim_entry_mutex);

    if (file && file->elements) {
        fim_event_mode mode = FIM_MODE(syscheck.opts[pos]);

        if (fim_db_delete_range(syscheck.database, file,
                                &syscheck.fim_entry_mutex, syscheck.database_store, mode) != FIMDB_OK) {
            merror(FIM_DB_ERROR_RM_RANGE, first_entry, last_entry);
        }
    }
}

STATIC void fim_link_silent_scan(char *path, int pos) {
    struct fim_element *item;

    os_calloc(1, sizeof(fim_element), item);
    item->index = pos;
    item->mode = FIM_SCHEDULED;

    if (syscheck.opts[pos] & REALTIME_ACTIVE) {
        realtime_adddir(path, 0, 1);    // This is acting always on links, so `followsl` will always be `1`
    }

    fim_checker(path, item, NULL, 0);
    os_free(item);
}

STATIC void fim_link_reload_broken_link(char *path, int index) {
    int element;
    int found = 0;

    for (element = 0; syscheck.dir[element]; element++) {
        if (strcmp(path, syscheck.dir[element]) == 0) {
            // If a configuration directory exists don't reload
            mdebug1(FIM_LINK_ALREADY_ADDED, syscheck.dir[element]);
            found = 1;
        }
    }

    // Reload broken link
    if (!found) {
        os_free(syscheck.symbolic_links[index]);
        os_strdup(path, syscheck.symbolic_links[index]);

        // Add new entries without alert.
        fim_link_silent_scan(path, index);
    }
}

#endif
#ifdef WIN_WHODATA
void set_whodata_mode_changes() {
    if (!syscheck.realtime) {
        realtime_start();
    }

    syscheck.realtime_change = 0;

    int i;
    for (i = 0; syscheck.dir[i]; i++) {
        if (syscheck.wdata.dirs_status[i].status & WD_CHECK_REALTIME) {
            // At this point the directories in whodata mode that have been deconfigured are added to realtime
            syscheck.wdata.dirs_status[i].status &= ~WD_CHECK_REALTIME;
            syscheck.opts[i] |= REALTIME_ACTIVE;
            if (realtime_adddir(syscheck.dir[i], 0, 0) != 1) {
                merror(FIM_ERROR_REALTIME_ADDDIR_FAILED, syscheck.dir[i]);
            } else {
                mdebug1(FIM_REALTIME_MONITORING, syscheck.dir[i]);
            }
        }
    }
}
#endif
