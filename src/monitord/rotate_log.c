/* Copyright (C) 2015-2019, Wazuh Inc.
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
#define localtime_r(x, y) localtime_s(y, x)
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

void w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations) {
    char old_path[PATH_MAX];
    char old_path_json[PATH_MAX];
    char base_dir[PATH_MAX];
    char year_dir[PATH_MAX];
    char month_dir[PATH_MAX];
    char new_path[PATH_MAX];
    char new_path_json[PATH_MAX];
    char compressed_path[PATH_MAX];
    char rename_path[PATH_MAX];
    char old_rename_path[PATH_MAX];
    struct tm tm;
    time_t now;
    int counter = 0;

    if (new_day)
        minfo("Running daily rotation of log files.");
    else {
        if (rotate_json)
            minfo("Rotating 'ossec.json' file: Maximum size reached.");
        else
            minfo("Rotating 'ossec.log' file: Maximum size reached.");
    }

    if (new_day)
        now = time(NULL) - 86400;
    else
        now = time(NULL);

    localtime_r(&now, &tm);

#ifdef WIN32
    // ossec.log
    snprintf(old_path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(old_path_json, PATH_MAX, "%s", LOGJSONFILE);
    // logs
    strcpy(base_dir, "logs");
#else
    // /var/ossec/logs/ossec.log
    snprintf(old_path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec.json
    snprintf(old_path_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);
    // /var/ossec/logs/ossec
    snprintf(base_dir, PATH_MAX, "%s/logs/ossec", isChroot() ? "" : DEFAULTDIR);
#endif

    snprintf(year_dir, PATH_MAX, "%s/%d", base_dir, tm.tm_year + 1900);
    snprintf(month_dir, PATH_MAX, "%s/%s", year_dir, MONTHS[tm.tm_mon]);
    snprintf(new_path, PATH_MAX, "%s/ossec-%02d.log", month_dir, tm.tm_mday);
    snprintf(new_path_json, PATH_MAX, "%s/ossec-%02d.json", month_dir, tm.tm_mday);
    snprintf(compressed_path, PATH_MAX, "%s.gz", new_path);

    // Create folders

    if (IsDir(year_dir) < 0 && mkdir(year_dir, 0770) < 0) {
        merror_exit(MKDIR_ERROR, year_dir, errno, strerror(errno));
    }

    if (IsDir(month_dir) < 0 && mkdir(month_dir, 0770) < 0) {
        merror_exit(MKDIR_ERROR, month_dir, errno, strerror(errno));
    }

    if (new_day || (!new_day && !rotate_json)) {

        /* Count rotated log files of the current day */
        while(!IsFile(compressed_path)){
            counter++;
            snprintf(new_path, PATH_MAX, "%s/ossec-%02d-%03d.log", month_dir, tm.tm_mday, counter);
            snprintf(compressed_path, PATH_MAX, "%s.gz", new_path);
        }

        /* Rotate compressed logs if needed */
        if (counter == daily_rotations) {
            if (daily_rotations == 1 && counter == 1) {
                snprintf(new_path, PATH_MAX, "%s/ossec-%02d.log", month_dir, tm.tm_mday);
            } else {
                snprintf(rename_path, PATH_MAX, "%s/ossec-%02d.log.gz", month_dir, tm.tm_mday);
                snprintf(old_rename_path, PATH_MAX, "%s/ossec-%02d-001.log.gz", month_dir, tm.tm_mday);
                counter = 1;
                while (counter < daily_rotations) {
                    if (rename_ex(old_rename_path, rename_path) != 0) {
                        merror("Couldn't rename compressed log '%s' to '%s': '%s'", old_rename_path, rename_path, strerror(errno));
                        return;
                    }
                    counter++;
                    snprintf(rename_path, PATH_MAX, "%s", old_rename_path);
                    snprintf(old_rename_path, PATH_MAX, "%s/ossec-%02d-%03d.log.gz", month_dir, tm.tm_mday, counter);
                }
                snprintf(new_path, PATH_MAX, "%s/ossec-%02d-%03d.log", month_dir, tm.tm_mday, counter - 1);
            }
        }

        if (!IsFile(old_path)) {
            if (rename_ex(old_path, new_path) == 0) {
                if (compress) {
                    OS_CompressLog(new_path);
                }
            } else {
                merror("Couldn't rename '%s' to '%s': %s", old_path, new_path, strerror(errno));
            }
        }

    }

    if (new_day || (!new_day && rotate_json)) {

        snprintf(compressed_path, PATH_MAX, "%s.gz", new_path_json);

        /* Count rotated log files of the current day */
        while(!IsFile(compressed_path)) {
            counter++;
            snprintf(new_path_json, PATH_MAX, "%s/ossec-%02d-%03d.json", month_dir, tm.tm_mday, counter);
            snprintf(compressed_path, PATH_MAX, "%s.gz", new_path_json);
        }

        /* Rotate compressed logs if needed */
        if (counter == daily_rotations) {
            if (daily_rotations == 1 && counter == 1) {
                snprintf(new_path_json, PATH_MAX, "%s/ossec-%02d.json", month_dir, tm.tm_mday);
            } else {
                snprintf(rename_path, PATH_MAX, "%s/ossec-%02d.json.gz", month_dir, tm.tm_mday);
                snprintf(old_rename_path, PATH_MAX, "%s/ossec-%02d-001.json.gz", month_dir, tm.tm_mday);
                counter = 1;
                while (counter < daily_rotations) {
                    if (rename_ex(old_rename_path, rename_path) != 0) {
                        merror("Couldn't rename compressed log '%s' to '%s': '%s'", old_rename_path, rename_path, strerror(errno));
                        return;
                    }
                    counter++;
                    snprintf(rename_path, PATH_MAX, "%s", old_rename_path);
                    snprintf(old_rename_path, PATH_MAX, "%s/ossec-%02d-%03d.json.gz", month_dir, tm.tm_mday, counter);
                }
                snprintf(new_path_json, PATH_MAX, "%s/ossec-%02d-%03d.json", month_dir, tm.tm_mday, counter - 1);
            }
        }

        if (!IsFile(old_path_json)) {
            if (rename_ex(old_path_json, new_path_json) == 0) {
                if (compress) {
                    OS_CompressLog(new_path_json);
                }
            } else {
                merror("Couldn't rename '%s' to '%s': %s", old_path_json, new_path_json, strerror(errno));
            }
        }
    }

    minfo("Starting new log after rotation.");

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
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
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
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
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
            mwarn("Unexpected folder '%s'", path);
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
    struct tm tm;
    int counter;

    localtime_r(&now, &tm);

    tm.tm_year = year - 1900;
    tm.tm_mon = month;
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;

    if (dir = opendir(base_dir), !dir) {
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
        return;
    }

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        if (sscanf(dirent->d_name, "ossec-%02d.log", &day) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }

        if (sscanf(dirent->d_name, "ossec-%02d-%03d.log", &day, &counter) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }

        if (sscanf(dirent->d_name, "ossec-%02d.json", &day) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }

        if (sscanf(dirent->d_name, "ossec-%02d-%03d.json", &day, &counter) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }

    }

    closedir(dir);
}
