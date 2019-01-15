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
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "rootcheck/rootcheck.h"
#include "syscheck_op.h"

/* Prototypes */
static void send_sk_db(int first_scan);



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
    if (!syscheck.dir[0]) {
        return;
    }

    log_realtime_status(2);
    minfo("Starting syscheck scan.");

    /* Send first start scan control message */
    if(first_start) {
        send_syscheck_msg(HC_FIM_DB_SFS);
        sleep(syscheck.tsleep * 5);
        create_db();
    } else {
        send_syscheck_msg(HC_FIM_DB_SS);
        sleep(syscheck.tsleep * 5);
        run_dbcheck();
    }
    sleep(syscheck.tsleep * 5);
#ifdef WIN32
    /* Check for registry changes on Windows */
    os_winreg_check();
    sleep(syscheck.tsleep * 5);
#endif

    /* Send end scan control message */
    if(first_start) {
        send_syscheck_msg(HC_FIM_DB_EFS);
#ifdef ENABLE_AUDIT
        audit_set_db_consistency();
#endif
    } else {
        send_syscheck_msg(HC_FIM_DB_ES);
    }
    minfo("Ending syscheck scan. Database completed.");
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
    int first_start = 1;

#ifndef WIN32
    /* Launch rootcheck thread */
    w_create_thread(w_rootcheck_thread,&syscheck);
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

    mdebug1("Setting SCHED_BATCH returned: %d", status);
#endif

#ifdef DEBUG
    minfo("Starting daemon...");
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
        rootcheck.time = 604800;
    }
    /* Printing syscheck properties */

    if (!syscheck.disabled) {
        minfo("Syscheck scan frequency: %d seconds", syscheck.time);
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
                merror("Select failed (for realtime fim).");
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
                merror("WaitForSingleObjectEx failed (for realtime fim).");
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
int c_read_file(const char *file_name, const char *oldsum, char *newsum, whodata_evt * evt)
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
    char *w_inode;
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
    struct stat statbuf_lnk;

    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        char alert_msg[OS_SIZE_6144 + 1];
        char wd_sum[OS_SIZE_6144 + 1];

        alert_msg[sizeof(alert_msg) - 1] = '\0';

        // Extract the whodata sum here to not include it in the hash table
        if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
            merror("The whodata sum for '%s' file could not be included in the alert as it is too large.", file_name);
        }

        /* Find tag position for the evaluated file name */
        int pos = find_dir_pos(file_name, 1, 0, 0);

        //Alert for deleted file
        snprintf(alert_msg, sizeof(alert_msg), "-1!%s:%s %s", wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", file_name);
        send_syscheck_msg(alert_msg);


#ifndef WIN32
        if(evt && evt->inode) {
            if (w_inode = OSHash_Delete_ex(syscheck.inode_hash, evt->inode), w_inode) {
                free(w_inode);
            }
        }
        else {
            if (s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, file_name), s_node) {
                char *inode_str;
                char *checksum_inode;

                os_strdup(s_node->checksum, checksum_inode);
                inode_str = get_attr_from_checksum(checksum_inode, SK_INODE);
                
                if (w_inode = OSHash_Delete_ex(syscheck.inode_hash, inode_str), w_inode) {
                    free(w_inode);
                }
                os_free(checksum_inode);
            }
        }
#endif
        // Delete from hash table
        if (s_node = OSHash_Delete_ex(syscheck.fp, file_name), s_node) {
            free(s_node->checksum);
            free(s_node);
        }

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
    newsum[OS_MAXSTR] = '\0';
    if (S_ISREG(statbuf.st_mode))
    {
        if (sha1sum || md5sum || sha256sum) {
            /* Generate checksums of the file */
            if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0) {
                strncpy(sf_sum, "n/a", 4);
                strncpy(mf_sum, "n/a", 4);
                strncpy(sf256_sum, "n/a", 4);
            }
        }
    }

#ifndef WIN32
    /* If it is a link, check if the actual file is valid */
    else if (S_ISLNK(statbuf.st_mode)) {
        if (stat(file_name, &statbuf_lnk) == 0) {
            if (S_ISREG(statbuf_lnk.st_mode)) {
                if (sha1sum || md5sum || sha256sum) {
                    /* Generate checksums of the file */
                    if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0) {
                        strncpy(sf_sum, "n/a", 4);
                        strncpy(mf_sum, "n/a", 4);
                        strncpy(sf256_sum, "n/a", 4);
                    }
                }
            }
        }
    }

    if (size == 0){
        *str_size = '\0';
    } else {
        sprintf(str_size, "%ld", (long)statbuf.st_size);
    }

    if (perm == 0){
        *str_perm = '\0';
    } else {
        if (S_ISLNK(statbuf.st_mode)) {
            sprintf(str_perm,"%ld",(long)statbuf_lnk.st_mode);
        } else {
            sprintf(str_perm, "%ld", (long)statbuf.st_mode);
        }
    }

    if (owner == 0){
        *str_owner = '\0';
    } else {
        if (S_ISLNK(statbuf.st_mode)) {
            sprintf(str_owner,"%ld",(long)statbuf_lnk.st_uid);
        } else {
            sprintf(str_owner, "%ld", (long)statbuf.st_uid);
        }
    }

    if (group == 0){
        *str_group = '\0';
    } else {
        if (S_ISLNK(statbuf.st_mode)) {
            sprintf(str_group,"%ld",(long)statbuf_lnk.st_gid);
        } else {
            sprintf(str_group, "%ld", (long)statbuf.st_gid);
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

    snprintf(newsum, OS_MAXSTR, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%u",
        str_size,
        str_perm,
        str_owner,
        str_group,
        md5sum   == 0 ? "" : mf_sum,
        sha1sum  == 0 ? "" : sf_sum,
        owner == 0 ? "" : get_user(file_name, S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_uid : statbuf.st_uid, NULL),
        group == 0 ? "" : get_group(S_ISLNK(statbuf.st_mode) ? statbuf_lnk.st_gid : statbuf.st_gid),
        str_mtime,
        str_inode,
        sha256sum  == 0 ? "" : sf256_sum,
        0);
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
            merror("It was not possible to extract the permissions of '%s'. Error: %d.", file_name, error);
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

    snprintf(newsum, OS_MAXSTR, "%s:%s:%s::%s:%s:%s:%s:%s:%s:%s:%u",
        str_size,
        (str_perm) ? str_perm : "",
        (owner == 0) && sid ? "" : sid,
        md5sum   == 0 ? "" : mf_sum,
        sha1sum  == 0 ? "" : sf_sum,
        owner == 0 ? "" : user,
        group == 0 ? "" : get_group(statbuf.st_gid),
        str_mtime,
        str_inode,
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
            minfo("Starting syscheck real-time monitoring.");
            status = next;
        }
        break;
    case 1:
        if (next == 2) {
            minfo("Pausing syscheck real-time monitoring.");
            status = next;
        }
        break;
    case 2:
        if (next == 1) {
            minfo("Resuming syscheck real-time monitoring.");
            status = next;
        }
    }
}
