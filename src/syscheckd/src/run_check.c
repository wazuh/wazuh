/* Copyright (C) 2015, Wazuh Inc.
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
#include "../os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "../rootcheck/rootcheck.h"
#include "file/file.h"
#include "ebpf/include/ebpf_whodata.h"

#ifdef WAZUH_UNIT_TESTING
unsigned int files_read = 0;
time_t last_time = 0;
void audit_set_db_consistency(void);
#ifdef WIN32

#include "../../unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/processthreadsapi_wrappers.h"
#include "../../unit_tests/wrappers/windows/synchapi_wrappers.h"
#define localtime_r(x, y)
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

// Prototypes
#ifdef WIN32
DWORD WINAPI fim_run_realtime(__attribute__((unused)) void * args);
DWORD WINAPI fim_run_integrity(__attribute__((unused)) void * args);
#else
void * fim_run_realtime(__attribute__((unused)) void * args);
void * fim_run_integrity(__attribute__((unused)) void * args);
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
STATIC void fim_link_silent_scan(const char *path, directory_t *configuration);
STATIC void fim_link_reload_broken_link(char *path, directory_t *configuration);
#endif

bool is_fim_shutdown = false;

bool fim_shutdown_process_on() {
    bool ret = is_fim_shutdown;
    return ret;
}

// Send a message
STATIC void fim_send_msg(char mq, const char * location, const char * msg) {
    if (fim_shutdown_process_on()) {
        return;
    }

    if (SendMSGPredicated(syscheck.queue, msg, location, mq, fim_shutdown_process_on) < 0) {
        merror(QUEUE_SEND);

        if ((syscheck.queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
            merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
        }

        // Try to send it again
        SendMSGPredicated(syscheck.queue, msg, location, mq, fim_shutdown_process_on);
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

// Persist a syscheck message
void persist_syscheck_msg(const cJSON* _msg) {
    if (syscheck.enable_synchronization) {
        char* msg = cJSON_PrintUnformatted(_msg);

        mdebug2(FIM_PERSIST, msg);

        // TODO: Use real value for id/index
        asp_persist_diff(syscheck.sync_handle, "idfim", 1, "fim index", msg);

        os_free(msg);
    } else {
        mdebug2("FIM synchronization is disabled");
    }
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
    while (files_read >= syscheck.max_files_per_second) {
        int rt = pthread_cond_timedwait(&cond, &fps_mutex, &wait_time);
        if (rt == ETIMEDOUT) {
            files_read = 0;
            w_cond_broadcast(&cond);
            break;
        } else if (rt != 0) {
            mdebug2("pthread_cond_timedwait failed: %s", strerror(rt));
            break;
        }
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

    // Deleting content of FIM diff directory
    char diff_file_dir[PATH_MAX];
    char diff_registry_dir[PATH_MAX];
    char diff_local_dir[PATH_MAX];


    // The contents of the report_changes diff directory must be deleted whenever the agent is started.
    // Directory used for files.
    snprintf(diff_file_dir, PATH_MAX, "%s/file/", DIFF_DIR);
    if (cldir_ex(diff_file_dir) == -1 && errno != ENOENT) {
        merror("Unable to clear directory '%s': %s (%d)", diff_file_dir, strerror(errno), errno);
    }
    // Directory used for registries.
    snprintf(diff_registry_dir, PATH_MAX, "%s/registry/", DIFF_DIR);
    if (cldir_ex(diff_registry_dir) == -1 && errno != ENOENT) {
        merror("Unable to clear directory '%s': %s (%d)", diff_registry_dir, strerror(errno), errno);
    }
    // Old directory used by report_changes, may be leftover from an old installation
    snprintf(diff_local_dir, PATH_MAX, "%s/local/", DIFF_DIR);
    if (cldir_ex(diff_local_dir) == -1 && errno != ENOENT) {
        merror("Unable to clear directory '%s': %s (%d)", diff_local_dir, strerror(errno), errno);
    }

    if (syscheck.disabled) {
        return;
    }

    minfo(FIM_DAEMON_STARTED);

    if (syscheck.file_limit_enabled) {
        mdebug2(FIM_FILE_LIMIT_VALUE, syscheck.file_entry_limit);
    } else {
        mdebug2(FIM_LIMIT_UNLIMITED, "file");
    }

#ifdef WIN32
    if (syscheck.registry_limit_enabled) {
        mdebug2(FIM_REGISTRY_LIMIT_VALUE, syscheck.db_entry_registry_limit);
    } else {
        mdebug2(FIM_LIMIT_UNLIMITED, "registry");
    }
#endif

    // Create File integrity monitoring base-line
    minfo(FIM_FREQUENCY_TIME, syscheck.time);
    fim_scan();

#ifndef WIN32
    // Launch Real-time thread
    w_create_thread(fim_run_realtime, &syscheck);

    // Launch symbolic links checker thread
    w_create_thread(symlink_checker_thread, NULL);

    if (syscheck.enable_synchronization) {
        // Launch inventory synchronization thread
        w_create_thread(fim_run_integrity, NULL);
    } else {
        mdebug1("FIM inventory synchronization is disabled");
    }
#else
    if (CreateThread(NULL, 0, fim_run_realtime, &syscheck, 0, NULL) == NULL) {

        merror(THREAD_ERROR);
    }

    if (syscheck.enable_synchronization) {
        if (CreateThread(NULL, 0, fim_run_integrity, NULL, 0, NULL) == NULL) {
            merror(THREAD_ERROR);
        }
    } else {
        mdebug1("FIM inventory synchronization is disabled");
    }
#endif

    // Launch Whodata audit real-time thread
    if (syscheck.enable_whodata && syscheck.whodata_provider == AUDIT_PROVIDER) {
        fim_whodata_initialize();
    }

    // Launch Whodata ebpf real-time thread
    if (syscheck.enable_whodata && syscheck.whodata_provider == EBPF_PROVIDER) {
#ifdef __linux__
#ifdef ENABLE_AUDIT
        w_create_thread(ebpf_whodata, NULL);
#else
        merror(FIM_ERROR_EBPF_NOT_SUPPORTED);
#endif
#endif
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

// Starting Real-time thread
#if defined WIN32
DWORD WINAPI fim_run_realtime(__attribute__((unused)) void * args) {
    directory_t *dir_it;
    OSListNode *node_it;
    int watches;

    SafeWow64DisableWow64FsRedirection(NULL); //Disable virtual redirection to 64bits folder due this is a x86 process
    set_priority_windows_thread();
    // Directories in Windows configured with real-time add recursive watches
    w_rwlock_wrlock(&syscheck.directories_lock);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            realtime_adddir(dir_it->path, dir_it);
        }
    }
    w_rwlock_unlock(&syscheck.directories_lock);

    watches = get_realtime_watches();
    if (watches != 0) {
        mdebug2(FIM_NUM_WATCHES, watches);
    }

    while (FOREVER()) {

#ifdef WIN_WHODATA
        if (syscheck.realtime_change) {
            set_whodata_mode_changes();
        }
#endif
        if (get_realtime_watches() > 0) {
            log_realtime_status(1);

            if (WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE) == WAIT_FAILED) {
                merror(FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
            }
        } else {
            sleep(SYSCHECK_WAIT);
        }

        // Directories in Windows configured with real-time add recursive watches
        w_rwlock_wrlock(&syscheck.directories_lock);
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
                realtime_adddir(dir_it->path, dir_it);
            }
        }
        w_rwlock_unlock(&syscheck.directories_lock);
    }
    return 0;
}

#elif defined INOTIFY_ENABLED
void *fim_run_realtime(__attribute__((unused)) void * args) {
    int nfds = -1;

    fim_realtime_print_watches();

    while (FOREVER()) {
        w_mutex_lock(&syscheck.fim_realtime_mutex);
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            nfds = syscheck.realtime->fd;
        }
        w_mutex_unlock(&syscheck.fim_realtime_mutex);

        if (nfds >= 0) {
            log_realtime_status(1);
            struct timeval selecttime;
            fd_set rfds;
            int run_now = 0;

            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            // zero-out the fd_set
            FD_ZERO (&rfds);
            FD_SET(nfds, &rfds);
            run_now = select(nfds + 1, &rfds, NULL, NULL, &selecttime);

            if (run_now < 0) {
                merror(FIM_ERROR_SELECT);
            } else if (run_now == 0) {
                // Timeout
            } else if (FD_ISSET (nfds, &rfds)) {
                realtime_process();
            }

        } else {
            sleep(SYSCHECK_WAIT);
        }
    }
    return NULL;
}

#else
void * fim_run_realtime(__attribute__((unused)) void * args) {
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
    return NULL;
}
#endif

#ifdef WIN32
DWORD WINAPI fim_run_integrity(__attribute__((unused)) void * args) {
#else
void * fim_run_integrity(__attribute__((unused)) void * args) {
#endif
    while (FOREVER()) {
        mdebug1("Running inventory synchronization.");

        asp_sync_module(syscheck.sync_handle, 0, syscheck.sync_response_timeout, 3, syscheck.sync_max_eps);

        mdebug1("Inventory synchronization finished, waiting for %d seconds before next run.", syscheck.sync_interval);
        sleep(syscheck.sync_interval);
    }

#ifdef WIN32
    return 0;
#else
    return NULL;
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
    mwarn(FIM_WARN_WHODATA_UNSUPPORTED);
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
                        mdebug2(FIM_LINKCHECK_CHANGED, dir_it->path, dir_it->symbolic_links, real_path);
                        fim_link_update(real_path, dir_it);
                    } else {
                        mdebug2(FIM_LINKCHECK_NOCHANGE, dir_it->symbolic_links);
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
        if ((configuration->options & WHODATA_ACTIVE) && syscheck.whodata_provider == AUDIT_PROVIDER) {
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
                if ((dir_it->options & WHODATA_ACTIVE) && syscheck.whodata_provider == AUDIT_PROVIDER) {
                    add_whodata_directory(dir_it->path);
                }
#endif
                is_new_link = false;
                break;
            }
        } else if (strcmp(new_path, dir_it->symbolic_links ? dir_it->symbolic_links : dir_it->path) == 0) {
            mdebug2(FIM_LINK_ALREADY_ADDED, dir_it->path);
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

    if (w_lstat(configuration->symbolic_links, &statbuf) < 0) {
        if (errno == ENOENT) {
#ifdef ENABLE_AUDIT
            if ((configuration->options & WHODATA_ACTIVE) && syscheck.whodata_provider == AUDIT_PROVIDER) {
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

        fim_realtime_delete_watches(configuration);

#ifdef ENABLE_AUDIT
        if ((configuration->options & WHODATA_ACTIVE) && syscheck.whodata_provider == AUDIT_PROVIDER) {
            remove_audit_rule_syscheck(configuration->symbolic_links);
        }
#endif
        w_mutex_lock(&syscheck.fim_symlink_mutex);
        os_free(configuration->symbolic_links);
        w_mutex_unlock(&syscheck.fim_symlink_mutex);
    }
}

STATIC void fim_link_silent_scan(const char *path, directory_t *configuration) {
    event_data_t evt_data = { .mode = FIM_SCHEDULED, .w_evt = NULL, .report_event = false };

    fim_checker(path, &evt_data, configuration, NULL, NULL);

    realtime_adddir(path, configuration);
#ifdef ENABLE_AUDIT
    if ((configuration->options & WHODATA_ACTIVE) && syscheck.whodata_provider == AUDIT_PROVIDER) {
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
            mdebug2(FIM_LINK_ALREADY_ADDED, dir_it->path);
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
