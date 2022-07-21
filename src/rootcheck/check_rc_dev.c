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

/* Prototypes */
static int read_dev_file(const char *file_name);
static int read_dev_dir(const char *dir_name);

/* Global variables */
static int _dev_errors;
static int _dev_total;


static int read_dev_file(const char *file_name)
{
    struct stat statbuf;

    if (lstat(file_name, &statbuf) < 0) {
        return (-1);
    }

    /* Process directories recursively */
    if (S_ISDIR(statbuf.st_mode)) {
        mtdebug2(ARGV0, "Reading dir: %s\n", file_name);
        return (read_dev_dir(file_name));
    }

    else if (S_ISREG(statbuf.st_mode)) {
        char op_msg[OS_SIZE_1024 + 1];
        const char op_msg_fmt[] = "File '%*s' present on /dev. Possible hidden file.";

        const int size = snprintf(NULL, 0, op_msg_fmt, (int)strlen(file_name), file_name);

        if (size >= 0) {
            if ((size_t)size < sizeof(op_msg)) {
                snprintf(op_msg, sizeof(op_msg), op_msg_fmt, (int)strlen(file_name), file_name);
            } else {
                const unsigned int surplus = size - sizeof(op_msg) + 1;
                snprintf(op_msg, sizeof(op_msg), op_msg_fmt, (int)(strlen(file_name) - surplus), file_name);
            }

            notify_rk(ALERT_SYSTEM_CRIT, op_msg);
        } else {
            mtdebug2(ARGV0, "Error %d (%s) with snprintf with file %s\n", errno, strerror(errno), file_name);
        }
        _dev_errors++;
    }

    return (0);
}

static int read_dev_dir(const char *dir_name)
{
    int i;
    DIR *dp;
    struct dirent *entry = NULL;
    char f_name[PATH_MAX + 2];
    char f_dir[PATH_MAX + 2];

    /* When will these people learn that /dev is not
     * meant to store log files or other kind of texts?
     */
    const char *(ignore_dev[]) = {"MAKEDEV", "README.MAKEDEV",
                                  "MAKEDEV.README", ".udevdb",
                                  ".udev.tdb", ".initramfs-tools",
                                  "MAKEDEV.local", ".udev", ".initramfs",
                                  "oprofile", "fd", "cgroup",
#ifdef SOLARIS
                                  ".devfsadm_dev.lock",
                                  ".devlink_db_lock",
                                  ".devlink_db",
                                  ".devfsadm_daemon.lock",
                                  ".devfsadm_deamon.lock",
                                  ".devfsadm_synch_door",
                                  ".zone_reg_door",
#endif
                                  NULL
                                 };

    /* Full path ignore */
    const char *(ignore_dev_full_path[]) = {"shm/sysconfig",
                                            "bus/usb/.usbfs",
                                            "shm",
                                            "gpmctl",
                                            NULL
                                           };

    if (dir_name == NULL || strlen(dir_name) > PATH_MAX) {
        mterror(ARGV0, "Invalid directory given.");
        return (-1);
    }

    /* Open directory */
    dp = opendir(dir_name);
    if (!dp) {
        return (-1);
    }

    /* Iterate over all files in the directory */
    while ((entry = readdir(dp)) != NULL) {
        /* Ignore . and ..  */
        if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        _dev_total++;

        /* Do not look for the ignored files */
        for (i = 0; ignore_dev[i] != NULL; i++) {
            if (strcmp(ignore_dev[i], entry->d_name) == 0) {
                break;
            }
        }
        if (ignore_dev[i] != NULL) {
            continue;
        }

        *f_name = '\0';
        snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);

        /* Do not look for the full ignored files */
        for (i = 0; ignore_dev_full_path[i] != NULL; i++) {
            snprintf(f_dir, PATH_MAX + 1, "%s/%s", dir_name, ignore_dev_full_path[i]);
            if (strcmp(f_dir, f_name) == 0) {
                break;
            }
        }

        /* Check against the full path */
        if (ignore_dev_full_path[i] != NULL) {
            continue;
        }

        /* Do not look for the user ignored paths and files */
        if (check_ignore(f_name)) {
            continue;
        }

        /* Found a non-ignored entry in the directory, so process it */
        read_dev_file(f_name);
    }

    closedir(dp);
    return (0);
}

void check_rc_dev(const char *basedir)
{
    char file_path[OS_SIZE_1024 + 1];

    _dev_total = 0, _dev_errors = 0;
    mtdebug1(ARGV0, "Starting on check_rc_dev");

    snprintf(file_path, OS_SIZE_1024, "%s/dev", basedir);

    read_dev_dir(file_path);
    if (_dev_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No problem detected on the /dev "
                 "directory. Analyzed %d files",
                 _dev_total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

#else

/* Not relevant on Windows */
void check_rc_dev(__attribute__((unused)) char *basedir)
{
    return;
}

#endif /* WIN32 */
