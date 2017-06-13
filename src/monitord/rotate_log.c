/* Copyright (C) 2017 Wazuh Inc.
 * June 12, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

#ifdef WIN32
#define mkdir(x, y) _mkdir(x)
#define unlink(x) _unlink(x)
#endif

static const char * MONTHS[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};

static void remove_old_logs(const char *base_dir, int keep_log_days);
static void remove_old_logs_y(const char * base_dir, int year, time_t threshold);
static void remove_old_logs_m(const char * base_dir, int year, int month, time_t threshold);

void w_rotate_log(const struct tm *p, int compress, int keep_log_days) {
    char old_path[PATH_MAX];
    char base_dir[PATH_MAX];
    char year_dir[PATH_MAX];
    char month_dir[PATH_MAX];
    char new_path[PATH_MAX];

    debug1("%s: DEBUG: Rotating file ossec.log", __local_name);

#ifdef WIN32
    // ossec.log
    snprintf(old_path, PATH_MAX, "%s", LOGFILE);
    // logs
    strcpy(base_dir, "logs");
#else
    // /var/ossec/logs/ossec.log
    snprintf(old_path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec
    snprintf(base_dir, PATH_MAX, "%s/logs/ossec", isChroot() ? "" : DEFAULTDIR);
#endif

    snprintf(year_dir, PATH_MAX, "%s/%d", base_dir, p->tm_year + 1900);
    snprintf(month_dir, PATH_MAX, "%s/%s", year_dir, MONTHS[p->tm_mon]);
    snprintf(new_path, PATH_MAX, "%s/ossec-%02d.log", month_dir, p->tm_mday);

    // Create folders

    if (IsDir(year_dir) < 0 && mkdir(year_dir, 0770) < 0) {
        ErrorExit(MKDIR_ERROR, __local_name, year_dir, errno, strerror(errno));
    }

    if (IsDir(month_dir) < 0 && mkdir(month_dir, 0770) < 0) {
        ErrorExit(MKDIR_ERROR, __local_name, month_dir, errno, strerror(errno));
    }

    if (rename(old_path, new_path) == 0) {
        if (compress) {
            OS_CompressLog(new_path);
        }
    } else {
        merror("%s: ERROR: Couldn't rename '%s' to '%s'", __local_name, old_path, new_path);
    }

    // Remove old compressed files
    remove_old_logs(base_dir, keep_log_days);
}

void remove_old_logs(const char *base_dir, int keep_log_days) {
    time_t threshold = time(NULL) - (keep_log_days + 1) * 86400;
    char path[PATH_MAX];
    int year;
    DIR *dir;
    struct dirent *dirent;

    if (dir = opendir(base_dir), !dir) {
        merror("%s: ERROR: Couldn't open directory '%s' to delete old logs: %s", __local_name, base_dir, strerror(errno));
        return;
    }

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        if (sscanf(dirent->d_name, "%d", &year) > 0) {
            snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
            remove_old_logs_y(path, year, threshold);
        }
    }

    closedir(dir);
}

void remove_old_logs_y(const char * base_dir, int year, time_t threshold) {
    char path[PATH_MAX];
    int month;
    DIR *dir;
    struct dirent *dirent;

    if (dir = opendir(base_dir), !dir) {
        merror("%s: ERROR: Couldn't open directory '%s' to delete old logs: %s", __local_name, base_dir, strerror(errno));
        return;
    }

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        // Find month

        for (month = 0; month < 12; month++) {
            if (strcmp(dirent->d_name, MONTHS[month]) == 0) {
                break;
            }
        }

        snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);

        if (month < 12) {
            remove_old_logs_m(path, year, month, threshold);
        } else {
            merror("%s: WARN: Unexpected folder '%s'", __local_name, path);
        }
    }

    closedir(dir);
}

void remove_old_logs_m(const char * base_dir, int year, int month, time_t threshold) {
    char path[PATH_MAX];
    DIR *dir;
    int day;
    struct dirent *dirent;
    time_t now = time(NULL);
    struct tm *p = localtime(&now);

    p->tm_year = year - 1900;
    p->tm_mon = month;
    p->tm_hour = 0;
    p->tm_min = 0;
    p->tm_sec = 0;

    if (dir = opendir(base_dir), !dir) {
        merror("%s: ERROR: Couldn't open directory '%s' to delete old logs: %s", __local_name, base_dir, strerror(errno));
        return;
    }

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        if (sscanf(dirent->d_name, "ossec-%02d.log", &day) > 0) {
            p->tm_mday = day;

            if (mktime(p) < threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                debug2("%s: Removing old log '%s'", __local_name, path);
                unlink(path);
            }
        }
    }

    closedir(dir);
}
