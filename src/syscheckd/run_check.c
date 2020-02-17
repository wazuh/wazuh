/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "rootcheck/rootcheck.h"
#include "syscheck_op.h"

/* Prototypes */
static void send_sk_db(int first_scan);
#ifndef WIN32
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

/* Send syscheck db to the server */
static void send_sk_db(int first_start)
{
#ifdef WIN_WHODATA
    long unsigned int t_id;
#endif

    if (!syscheck.dir[0]) {
        return;
    }

    log_realtime_status(2);
    minfo(FIM_FREQUENCY_STARTED);

    /* Send first start scan control message */
    if(first_start) {
        send_syscheck_msg(HC_FIM_DB_SFS);
        sleep(syscheck.tsleep * 5);
        create_db();
        minfo(FIM_FREQUENCY_ENDED);
    } else {
        send_syscheck_msg(HC_FIM_DB_SS);
        sleep(syscheck.tsleep * 5);
        run_dbcheck();
        minfo(FIM_FREQUENCY_ENDED);
    }
    sleep(syscheck.tsleep * 5);
#ifdef WIN32
    /* Check for registry changes on Windows */
    minfo(FIM_WINREGISTRY_START);
    os_winreg_check();
    sleep(syscheck.tsleep * 5);
    minfo(FIM_WINREGISTRY_ENDED);
#endif

    /* Send end scan control message */
    if(first_start) {
        send_syscheck_msg(HC_FIM_DB_EFS);

        // Running whodata-audit
#ifdef ENABLE_AUDIT
        audit_set_db_consistency();
#endif

        // Running whodata-windows
#ifdef WIN_WHODATA
    if (syscheck.wdata.whodata_setup && !run_whodata_scan()) {
        minfo(FIM_WHODATA_START);
        w_create_thread(NULL, 0, state_checker, NULL, 0, &t_id);
    }
#endif

    } else {
        send_syscheck_msg(HC_FIM_DB_ES);
    }
}

/* Periodically run the integrity checker */
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    time_t curr_time = 0;
    time_t prev_time_sk = 0;
    char curr_hour[12];
    struct tm tm_result = { .tm_sec = 0 };
    int first_start = 1;

#ifndef WIN32
    /* Launch rootcheck thread */
    w_create_thread(w_rootcheck_thread,&syscheck);
#else
    w_create_thread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)w_rootcheck_thread,
                    &syscheck,
                    0,
                    NULL);
#endif

#ifdef INOTIFY_ENABLED
    /* To be used by select */
    struct timeval selecttime;
    fd_set rfds;
#endif

    /* SCHED_BATCH forces the kernel to assume this is a cpu intensive
     * process and gives it a lower priority. This keeps ossec-syscheckd
     * from reducing the interactivity of an ssh session when checksumming
     * large files. This is available in kernel flavors >= 2.6.16.
     */
#ifdef SCHED_BATCH
    struct sched_param pri;
    int status;

    pri.sched_priority = 0;
    status = sched_setscheduler(0, SCHED_BATCH, &pri);

    mdebug1(FIM_SCHED_BATCH, status);
#endif

#ifdef DEBUG
    minfo(FIM_DAEMON_STARTED);
#endif

    /* Some time to settle */
    memset(curr_hour, '\0', 12);
    sleep(syscheck.tsleep * 10);

    /* If the scan time/day is set, reset the
     * syscheck.time/rootcheck.time
     */
    if (syscheck.scan_time || syscheck.scan_day) {
        /* At least once a week */
        syscheck.time = 604800;
    }
    /* Printing syscheck properties */

    if (!syscheck.disabled) {
        minfo(FIM_FREQUENCY_TIME, syscheck.time);
        /* Will create the db to store syscheck data */
        if (syscheck.scan_on_start) {
            send_sk_db(first_start);
            first_start = 0;
        }
    }

    /* Before entering in daemon mode itself */
    prev_time_sk = time(0);
    sleep(syscheck.tsleep * 10);

    /* If the scan_time or scan_day is set, we need to handle the
     * current day/time on the loop.
     */
    if (syscheck.scan_time || syscheck.scan_day) {
        curr_time = time(0);
        localtime_r(&curr_time, &tm_result);

        /* Assign hour/min/sec values */
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

    /* Check every SYSCHECK_WAIT */
    while (1) {
        int run_now = 0;
        curr_time = time(0);

        /* Check if syscheck should be restarted */
        run_now = os_check_restart_syscheck();

        /* Check if a day_time or scan_time is set */
        if (syscheck.scan_time || syscheck.scan_day) {
            localtime_r(&curr_time, &tm_result);

            /* Day changed */
            if (curr_day != tm_result.tm_mday) {
                day_scanned = 0;
                curr_day = tm_result.tm_mday;
            }

            /* Check for the time of the scan */
            if (!day_scanned && syscheck.scan_time && syscheck.scan_day) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         tm_result.tm_hour, tm_result.tm_min, tm_result.tm_sec);

                if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                        (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day))) {
                    day_scanned = 1;
                    run_now = 1;
                }
            } else if (!day_scanned && syscheck.scan_time) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         tm_result.tm_hour, tm_result.tm_min, tm_result.tm_sec);

                if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            } else if (!day_scanned && syscheck.scan_day) {
                /* Check for the day of the scan */
                if (OS_IsonDay(tm_result.tm_wday, syscheck.scan_day)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            }
        }


        /* If time elapsed is higher than the syscheck time, run syscheck time */
        if (((curr_time - prev_time_sk) > syscheck.time) || run_now) {
            if (syscheck.scan_on_start == 0) {
                send_sk_db(first_start);
                first_start = 0;
                syscheck.scan_on_start = 1;
            } else {
                send_sk_db(first_start);
            }
            prev_time_sk = time(0);
        }

#ifdef INOTIFY_ENABLED
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            /* zero-out the fd_set */
            FD_ZERO (&rfds);
            FD_SET(syscheck.realtime->fd, &rfds);
            log_realtime_status(1);

            run_now = select(syscheck.realtime->fd + 1, &rfds,
                             NULL, NULL, &selecttime);
            if (run_now < 0) {
                merror(FIM_ERROR_SELECT);
                sleep(SYSCHECK_WAIT);
            } else if (run_now == 0) {
                /* Timeout */
            } else if (FD_ISSET (syscheck.realtime->fd, &rfds)) {
                realtime_process();
            }
        } else {
            sleep(SYSCHECK_WAIT);
        }
#elif defined(WIN32)
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            log_realtime_status(1);
            if (WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE) == WAIT_FAILED) {
                merror(FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
                sleep(SYSCHECK_WAIT);
            } else {
                sleep(syscheck.tsleep);
            }
        } else {
            sleep(SYSCHECK_WAIT);
        }
#else
        sleep(SYSCHECK_WAIT);
#endif
    }
}

/* Read file information and return a pointer to the checksum */
int c_read_file(const char *file_name, const char *linked_file, const char *oldsum, char *newsum, int dir_position, whodata_evt *evt)
{
    int size = 0, perm = 0, owner = 0, group = 0, md5sum = 0, sha1sum = 0, sha256sum = 0, mtime = 0, inode = 0;
    struct stat statbuf;
    os_md5 mf_sum;
    os_sha1 sf_sum;
    os_sha256 sf256_sum;
    syscheck_node *s_node;
    char str_size[50], str_mtime[50], str_inode[50];
#ifdef WIN32
    unsigned int attributes = 0;
    char *sid = NULL;
    char *str_perm = NULL;
    char *user;
#else
    char *w_inode = NULL;
    char str_owner[50], str_group[50], str_perm[50];
#endif

    /* Clean sums */
    strncpy(mf_sum,  "", 1);
    strncpy(sf_sum,  "", 1);
    strncpy(sf256_sum, "", 1);

    /* Stat the file */
#ifdef WIN32
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        char alert_msg[OS_SIZE_6144 + OS_SIZE_2048];
        char wd_sum[OS_SIZE_6144 + 1];

#ifdef WIN_WHODATA
        // If this flag is enable, the remove event will be notified at another point
        if (evt && evt->ignore_remove_event) {
            mdebug2(FIM_WHODATA_FILENOEXIST, file_name);
            return -1;
        }
#endif

        alert_msg[sizeof(alert_msg) - 1] = '\0';

        // Extract the whodata sum here to not include it in the hash table
        if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
            merror(FIM_ERROR_WHODATA_SUM_MAX, file_name);
        }

        //Alert for deleted file
        snprintf(alert_msg, sizeof(alert_msg), "-1!%s:%s:%s: %s", wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", linked_file ? linked_file : "", file_name);
        send_syscheck_msg(alert_msg);

#ifndef WIN32
        if(evt && evt->inode) {
            w_inode = OSHash_Delete_ex(syscheck.inode_hash, evt->inode);
        }
        else {
            if (s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, file_name), s_node) {
                char *inode_str;
                char *checksum_inode;

                os_strdup(s_node->checksum, checksum_inode);
                if(inode_str = get_attr_from_checksum(checksum_inode, SK_INODE), !inode_str || *inode_str == '\0') {
                    OSHashNode *s_inode;
                    unsigned int i;

                    for (s_inode = OSHash_Begin(syscheck.inode_hash, &i); s_inode; s_inode = OSHash_Next(syscheck.inode_hash, &i, s_inode)) {
                        if(s_inode && s_inode->data){
                            if(!strcmp(s_inode->data, file_name)) {
                                inode_str = s_inode->key;
                                break;
                            }
                        }
                    }
                }
                if(inode_str){
                    w_inode = OSHash_Delete_ex(syscheck.inode_hash, inode_str);
                }
                os_free(checksum_inode);
            }
        }
#endif
        // Delete from hash table
        if (s_node = OSHash_Delete_ex(syscheck.fp, file_name), s_node) {
            os_free(s_node->checksum);
            os_free(s_node);
        }
#ifndef WIN32
        os_free(w_inode);
#endif

        struct timeval timeout = {0, syscheck.rt_delay * 1000};
        select(0, NULL, NULL, NULL, &timeout);

        return (-1);
    }

    /* Get the old sum values */

    /* size */
    if (oldsum[0] == '+') {
        size = 1;
    }

    /* perm */
    if (oldsum[1] == '+') {
        perm = 1;
    }

    /* owner */
    if (oldsum[2] == '+') {
        owner = 1;
    }

    /* group */
    if (oldsum[3] == '+') {
        group = 1;
    }

    /* md5 sum */
    if (oldsum[4] == '+') {
        md5sum = 1;
    }

    /* sha1 sum */
    if (oldsum[5] == '+') {
        sha1sum = 1;
    }

    /* Modification time */
    if (oldsum[6] == '+') {
        mtime = 1;
    }

    /* Inode */
    if (oldsum[7] == '+') {
        inode = 1;
    }

    /* sha256 sum */
    if (oldsum[8] == '+') {
        sha256sum = 1;
    }

    /* Attributes*/
#ifdef WIN32
    if (oldsum[9] == '+') {
        attributes = w_get_file_attrs(file_name);
    }
#endif

    /* Report changes */
    if (oldsum[SK_DB_REPORT_CHANG] == '-') {
        delete_target_file(file_name);
    }

    /* Generate new checksum */
    newsum[0] = '\0';
    if (S_ISREG(statbuf.st_mode)) {
        if (sha1sum || md5sum || sha256sum) {
            /* Generate checksums of the file */
            if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY, syscheck.file_max_size) < 0) {
                return -1;
            }
        }
    }

#ifndef WIN32

    if (size == 0){
        *str_size = '\0';
    } else {
        sprintf(str_size, "%ld", (long)statbuf.st_size);
    }

    if (perm == 0){
        *str_perm = '\0';
    } else {
        sprintf(str_perm, "%ld", (long)statbuf.st_mode);
    }

    if (owner == 0){
        *str_owner = '\0';
    } else {
        sprintf(str_owner, "%ld", (long)statbuf.st_uid);
    }

    if (group == 0){
        *str_group = '\0';
    } else {
        sprintf(str_group, "%ld", (long)statbuf.st_gid);
    }

    if (mtime == 0){
        *str_mtime = '\0';
    } else {
        sprintf(str_mtime, "%ld", (long)statbuf.st_mtime);
    }

    if (inode == 0){
        *str_inode = '\0';
    } else {
        sprintf(str_inode, "%ld", (long)statbuf.st_ino);
    }

    char *user_name = get_user(file_name, statbuf.st_uid, NULL);
    char *group_name = get_group(statbuf.st_gid);
    snprintf(newsum, OS_SIZE_4096, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%u",
        str_size,
        str_perm,
        str_owner,
        str_group,
        md5sum   == 0 ? "" : mf_sum,
        sha1sum  == 0 ? "" : sf_sum,
        owner == 0 ? "" : user_name,
        group == 0 ? "" : group_name,
        str_mtime,
        inode == 0 ? "" : str_inode,
        sha256sum  == 0 ? "" : sf256_sum,
        0);

    os_free(user_name);
    os_free(group_name);
#else
    user = get_user(file_name, statbuf.st_uid, &sid);

    if (size == 0){
        *str_size = '\0';
    } else {
        sprintf(str_size, "%ld", (long)statbuf.st_size);
    }

    if (perm == 1) {
        int error;
        char perm_unescaped[OS_SIZE_6144 + 1];
        if (error = w_get_file_permissions(file_name, perm_unescaped, OS_SIZE_6144), error) {
            merror(FIM_ERROR_EXTRACT_PERM, file_name, error);
        } else {
            str_perm = escape_perm_sum(perm_unescaped);
        }
    }

    if (mtime == 0){
        *str_mtime = '\0';
    } else {
        sprintf(str_mtime, "%ld", (long)statbuf.st_mtime);
    }

    if (inode == 0){
        *str_inode = '\0';
    } else {
        sprintf(str_inode, "%ld", (long)statbuf.st_ino);
    }

    snprintf(newsum, OS_SIZE_4096, "%s:%s:%s::%s:%s:%s:%s:%s:%s:%s:%u",
        str_size,
        (str_perm) ? str_perm : "",
        (owner == 0) && sid ? "" : sid,
        md5sum   == 0 ? "" : mf_sum,
        sha1sum  == 0 ? "" : sf_sum,
        owner == 0 ? "" : user,
        group == 0 ? "" : get_group(statbuf.st_gid),
        str_mtime,
        inode == 0 ? "" : str_inode,
        sha256sum  == 0 ? "" : sf256_sum,
        attributes);

        os_free(user);
        if (sid) {
            LocalFree(sid);
        }
        free(str_perm);
#endif

    return (0);
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

                conv_link = get_converted_link_path(i);

                if (strcmp(real_path, conv_link)) {
                    minfo(FIM_LINKCHECK_CHANGED, syscheck.dir[i], conv_link, real_path);
                    update_link_monitoring(i, conv_link, real_path);
                } else {
                    mdebug1(FIM_LINKCHECK_NOCHANGE, syscheck.dir[i]);
                }

                free(conv_link);
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
    read_dir(new_path, NULL, pos, NULL, syscheck.recursion_level[pos], 0, '+');

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
#endif
