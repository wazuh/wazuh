/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "db/fim_db_files.h"

#ifdef WAZUH_UNIT_TESTING
unsigned int files_read = 0;
time_t last_time = 0;

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
STATIC void fim_link_update(const char *new_path, directory_t *configuration);
STATIC void fim_link_check_delete(directory_t *configuration);
STATIC void fim_link_delete_range(directory_t *configuration);
STATIC void fim_link_silent_scan(const char *path, directory_t *configuration);
STATIC void fim_link_reload_broken_link(char *path, directory_t *configuration);
#endif

// Send a message
STATIC void fim_send_msg(char mq, const char * location, const char * msg) {
    if (SendMSG(syscheck.queue, msg, location, mq) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
        }

        // Try to send it again
        SendMSG(syscheck.queue, msg, location, mq);
    }
}

// Send a data synchronization control message
void fim_send_sync_msg(const char *location, const char * msg) {
    mdebug2(FIM_DBSYNC_SEND, msg);
    fim_send_msg(DBSYNC_MQ, location, msg);

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
void send_syscheck_msg(const cJSON *_msg) {
    char *msg = cJSON_PrintUnformatted(_msg);

    mdebug2(FIM_SEND, msg);
    fim_send_msg(SYSCHECK_MQ, SYSCHECK, msg);

    os_free(msg);

    if (syscheck.max_eps == 0) {
        return;
    }

    static atomic_int_t n_msg_sent = ATOMIC_INT_INITIALIZER(0);

    if (atomic_int_inc(&n_msg_sent) >= syscheck.max_eps) {
        sleep(1);
        atomic_int_set(&n_msg_sent, 0);
    }
}

// Send a scan info event
void fim_send_scan_info(fim_scan_event event) {
    cJSON * json = fim_scan_info_json(event, time(NULL));

    send_syscheck_msg(json);

    cJSON_Delete(json);
}

void check_max_fps() {
#ifndef WAZUH_UNIT_TESTING
    static unsigned int files_read = 0;
    static time_t last_time = 0;
#endif
    static pthread_mutex_t fps_mutex = PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    struct timespec wait_time = {0, 0};

    if (syscheck.max_files_per_second == 0) {
        return;
    }
    w_mutex_lock(&fps_mutex);
    gettime(&wait_time);

    if (wait_time.tv_sec != last_time) {
        files_read = 0;
        last_time = wait_time.tv_sec;
    }

    if (files_read < syscheck.max_files_per_second) {
        files_read++;
        w_mutex_unlock(&fps_mutex);
        return;
    }
    mdebug2(FIM_REACHED_MAX_FPS);
    wait_time.tv_sec += 1;

    // Wait for one second or until the thread is unlocked using w_cond_broadcast
    int rt = pthread_cond_timedwait(&cond, &fps_mutex, &wait_time);
    if (rt == ETIMEDOUT) {
        // In case that the mutex is unlocked due to a timeout, free all blocked threads.
        files_read = 0;
        w_cond_broadcast(&cond);
    } else if (rt != 0) {
        mdebug2("pthread_cond_timedwait failed: %s", strerror(rt));
    }
    w_mutex_unlock(&fps_mutex);
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
#else
    set_priority_windows_thread();
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

    snprintf(diff_dir, PATH_MAX, "%s/local/", DIFF_DIR);

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
            prev_time_sk = fim_scan();
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
    int nfds = -1;

#ifdef WIN32
    directory_t *dir_it;
    OSListNode *node_it;

    set_priority_windows_thread();
#endif

    while (1) {
#ifdef WIN32
        // Directories in Windows configured with real-time add recursive watches
        w_rwlock_wrlock(&syscheck.directories_lock);
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
                realtime_adddir(dir_it->path, dir_it);
            }
        }
        w_rwlock_unlock(&syscheck.directories_lock);
#endif

        w_mutex_lock(&syscheck.fim_realtime_mutex);
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
        w_mutex_unlock(&syscheck.fim_realtime_mutex);

#ifdef WIN_WHODATA
        if (syscheck.realtime_change) {
            set_whodata_mode_changes();
        }
#endif
        w_mutex_lock(&syscheck.fim_realtime_mutex);
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            nfds = syscheck.realtime->fd;
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);

        if (nfds >= 0) {
            log_realtime_status(1);
#ifdef INOTIFY_ENABLED
            struct timeval selecttime;
            fd_set rfds;
            int run_now = 0;

            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            // zero-out the fd_set
            FD_ZERO (&rfds);
            FD_SET(nfds, &rfds);
            run_now = select(nfds + 1,
                            &rfds,
                            NULL,
                            NULL,
                            &selecttime);


            if (run_now < 0) {
                merror(FIM_ERROR_SELECT);
            } else if (run_now == 0) {
                // Timeout
            } else if (FD_ISSET (nfds, &rfds)) {
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
    directory_t *dir_it;
    OSListNode *node_it;
    w_rwlock_rdlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            mwarn(FIM_WARN_REALTIME_UNSUPPORTED);
            break;
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

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

#ifdef WIN_WHODATA
int fim_whodata_initialize() {
    int retval = 0;
    long unsigned int t_id;
    HANDLE t_hdle;
    directory_t *dir_it;
    OSListNode *node_it;

    w_rwlock_wrlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if ((dir_it->options & WHODATA_ACTIVE) == 0) {
            continue;
        }

        if (realtime_adddir(dir_it->path, dir_it) == -2) {
            dir_it->dirs_status.status &= ~WD_CHECK_WHODATA;
            dir_it->dirs_status.status |= WD_CHECK_REALTIME;
            dir_it->options &= ~WHODATA_ACTIVE;
            syscheck.realtime_change = 1;
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    if (syscheck.wdata.fd == NULL) {
        OSList_foreach(node_it, syscheck.wildcards) {
            dir_it = node_it->data;
            if (FIM_MODE(dir_it->options) == FIM_WHODATA) {
                whodata_audit_start();
                break;
            }
        }
    }

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

        w_rwlock_wrlock(&syscheck.directories_lock);
        // Add proper flags for the realtime thread monitors the directories/files.
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            dir_it->dirs_status.status &= ~WD_CHECK_WHODATA;
            dir_it->dirs_status.status |= WD_CHECK_REALTIME;
            dir_it->options &= ~WHODATA_ACTIVE;
            syscheck.realtime_change = 1;
        }

        retval = -1;
        w_rwlock_unlock(&syscheck.directories_lock);
    }

    return retval;
}

#elif defined ENABLE_AUDIT
int fim_whodata_initialize() {
    audit_set_db_consistency();

    return 0;
}

#else
int fim_whodata_initialize() {
    if (syscheck.enable_whodata) {
        mwarn(FIM_WARN_WHODATA_UNSUPPORTED);
    }
    return -1;
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


#ifndef WIN32
// LCOV_EXCL_START
static void *symlink_checker_thread(__attribute__((unused)) void * data) {
    char *real_path;
    directory_t *dir_it;
    OSListNode *node_it;

    mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

    while (1) {
        sleep(syscheck.sym_checker_interval);
        mdebug1(FIM_LINKCHECK_START, syscheck.sym_checker_interval);

        w_mutex_lock(&syscheck.fim_scan_mutex);
        w_rwlock_rdlock(&syscheck.directories_lock);

        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if ((dir_it->options & CHECK_FOLLOW) == 0) {
                continue;
            }

            real_path = realpath(dir_it->path, NULL);

            if (dir_it->symbolic_links) {
                if (real_path) {
                    // Check if link has changed
                    if (strcmp(real_path, dir_it->symbolic_links)) {
                        minfo(FIM_LINKCHECK_CHANGED, dir_it->path, dir_it->symbolic_links, real_path);
                        fim_link_update(real_path, dir_it);
                    } else {
                        mdebug1(FIM_LINKCHECK_NOCHANGE, dir_it->symbolic_links);
                    }
                } else {
                    // Broken link
                    char path[PATH_MAX];

                    snprintf(path, PATH_MAX, "%s", dir_it->symbolic_links);
                    fim_link_check_delete(dir_it);

                    directory_t *config = fim_configuration_directory(path);

                    if (config != NULL) {
                        fim_link_silent_scan(path, config);
                    }
                }
            } else {
                // Check real_path to reload broken link.
                if (real_path && strcmp(real_path, dir_it->path) != 0) {
                    fim_link_reload_broken_link(real_path, dir_it);
                }
            }

            os_free(real_path);
        }

        w_rwlock_unlock(&syscheck.directories_lock);
        w_mutex_unlock(&syscheck.fim_scan_mutex);
        mdebug1(FIM_LINKCHECK_FINALIZE);
    }

    return NULL;
}
// LCOV_EXCL_STOP

STATIC void fim_link_update(const char *new_path, directory_t *configuration) {
    int in_configuration = false;
    int is_new_link = true;
    directory_t *dir_it;
    OSListNode *node_it;

    // Check if the previously pointed folder is in the configuration
    // and delete its database entries if it isn't
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it == configuration) {
            // This is the link being changed
            continue;
        }

        if (strcmp(configuration->symbolic_links, dir_it->symbolic_links ? dir_it->symbolic_links : dir_it->path) == 0) {
            in_configuration = true;
            break;
        }
    }

    if (in_configuration == false) {
#ifdef ENABLE_AUDIT
        // Remove the audit rule for the previous link only if the path is not configured in other entry.
        if (configuration->options & WHODATA_ACTIVE) {
            remove_audit_rule_syscheck(configuration->symbolic_links);
        }
#endif
        fim_link_delete_range(configuration);
    }

    // Check if the updated path of the link is already in the configuration
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it == configuration) {
            if (strcmp(new_path, dir_it->path) == 0) {
                // We were monitoring a link, now we are monitoring the actual directory
#ifdef ENABLE_AUDIT
                if (dir_it->options & WHODATA_ACTIVE) {
                    add_whodata_directory(dir_it->path);
                }
#endif
                is_new_link = false;
                break;
            }
        } else if (strcmp(new_path, dir_it->symbolic_links ? dir_it->symbolic_links : dir_it->path) == 0) {
            mdebug1(FIM_LINK_ALREADY_ADDED, dir_it->path);
            is_new_link = false;
            break;
        }
    }

    w_mutex_lock(&syscheck.fim_symlink_mutex);
    os_free(configuration->symbolic_links);

    if (is_new_link) {
        os_strdup(new_path, configuration->symbolic_links);
    }

    w_mutex_unlock(&syscheck.fim_symlink_mutex);
    if (is_new_link) {
        // Add new entries without alert.
        fim_link_silent_scan(new_path, configuration);
    }
}

STATIC void fim_link_check_delete(directory_t *configuration) {
    struct stat statbuf;

    if (w_stat(configuration->symbolic_links, &statbuf) < 0) {
        if (errno == ENOENT) {
#ifdef ENABLE_AUDIT
            if (configuration->options & WHODATA_ACTIVE) {
                remove_audit_rule_syscheck(configuration->symbolic_links);
            }
#endif
            w_mutex_lock(&syscheck.fim_symlink_mutex);
            os_free(configuration->symbolic_links);
            w_mutex_unlock(&syscheck.fim_symlink_mutex);
            return;
        }

        mdebug1(FIM_STAT_FAILED, configuration->symbolic_links, errno, strerror(errno));
    } else {
        fim_link_delete_range(configuration);

        w_mutex_lock(&syscheck.fim_realtime_mutex);
        if (syscheck.realtime && syscheck.realtime->dirtb) {
            fim_delete_realtime_watches(configuration);
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);

#ifdef ENABLE_AUDIT
        if (configuration->options & WHODATA_ACTIVE) {
            remove_audit_rule_syscheck(configuration->symbolic_links);
        }
#endif
        w_mutex_lock(&syscheck.fim_symlink_mutex);
        os_free(configuration->symbolic_links);
        w_mutex_unlock(&syscheck.fim_symlink_mutex);
    }
}

void fim_delete_realtime_watches(__attribute__((unused)) const directory_t *configuration) {
#ifdef INOTIFY_ENABLED
    OSHashNode *hash_node;
    char *data;
    W_Vector * watch_to_delete = W_Vector_init(1024);
    unsigned int inode_it = 0;
    int deletion_it = 0;
    directory_t *dir_conf;
    directory_t *watch_conf;

    assert(watch_to_delete != NULL);
    assert(configuration != NULL);

    dir_conf = fim_configuration_directory(configuration->symbolic_links);

    if (dir_conf == NULL) {
        W_Vector_free(watch_to_delete);
        return;
    }

    for (hash_node = OSHash_Begin(syscheck.realtime->dirtb, &inode_it); hash_node;
         hash_node = OSHash_Next(syscheck.realtime->dirtb, &inode_it, hash_node)) {
        data = hash_node->data;
        if (data == NULL) {
            continue;
        }
        watch_conf = fim_configuration_directory(data);

        if (dir_conf == watch_conf) {
            W_Vector_insert(watch_to_delete, hash_node->key);
            deletion_it++;
        }
    }

    deletion_it--;
    while(deletion_it >= 0) {
        const char * wd_str = W_Vector_get(watch_to_delete, deletion_it);
        assert(wd_str != NULL);

        inotify_rm_watch(syscheck.realtime->fd, atol(wd_str));
        free(OSHash_Delete_ex(syscheck.realtime->dirtb, wd_str));
        deletion_it--;
    }

    W_Vector_free(watch_to_delete);
#endif
    return;
}

STATIC void fim_link_delete_range(directory_t *configuration) {
    fim_tmp_file * file = NULL;
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .report_event = false, .w_evt = NULL, .type = FIM_DELETE };
    char pattern[PATH_MAX] = {0};

    // Create the sqlite LIKE pattern.
    snprintf(pattern, PATH_MAX, "%s%c%%", configuration->symbolic_links, PATH_SEP);

    if (fim_db_get_path_from_pattern(syscheck.database, pattern, &file, syscheck.database_store) != FIMDB_OK) {
        merror(FIM_DB_ERROR_RM_PATTERN, pattern);
    }

    if (file && file->elements) {
        if (fim_db_delete_range(syscheck.database, file, &syscheck.fim_entry_mutex, syscheck.database_store,
                                &evt_data, configuration) != FIMDB_OK) {
            merror(FIM_DB_ERROR_RM_PATTERN, pattern);
        }
    }
}

STATIC void fim_link_silent_scan(const char *path, directory_t *configuration) {
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = false };

    fim_checker(path, &evt_data, configuration);

    realtime_adddir(path, configuration);
#ifdef ENABLE_AUDIT
    if (configuration->options & WHODATA_ACTIVE) {
        // Just in case, we need to remove the configured directory if it was previously monitored
        remove_audit_rule_syscheck(configuration->path);
    }
#endif
}

STATIC void fim_link_reload_broken_link(char *path, directory_t *configuration) {
    directory_t *dir_it;
    OSListNode *node_it;

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (strcmp(path, dir_it->path) == 0) {
            // If a configuration directory exists don't reload
            mdebug1(FIM_LINK_ALREADY_ADDED, dir_it->path);
            return;
        }
    }

    // Reload broken link
    w_mutex_lock(&syscheck.fim_symlink_mutex);
    os_free(configuration->symbolic_links);
    os_strdup(path, configuration->symbolic_links);
    w_mutex_unlock(&syscheck.fim_symlink_mutex);

    // Add new entries without alert.
    fim_link_silent_scan(path, configuration);
}

#endif
#ifdef WIN_WHODATA
void set_whodata_mode_changes() {
    directory_t *dir_it;
    OSListNode *node_it;

    if (syscheck.realtime == NULL) {
        realtime_start();
    }

    syscheck.realtime_change = 0;

    w_rwlock_rdlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->dirs_status.status & WD_CHECK_REALTIME) {
            // At this point the directories in whodata mode that have been deconfigured are added to realtime
            dir_it->dirs_status.status &= ~WD_CHECK_REALTIME;
            dir_it->options |= REALTIME_ACTIVE;
            if (realtime_adddir(dir_it->path, dir_it) != 1) {
                merror(FIM_ERROR_REALTIME_ADDDIR_FAILED, dir_it->path);
            } else {
                mdebug1(FIM_REALTIME_MONITORING, dir_it->path);
            }
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);
}
#endif
