/* Copyright (C) 2015-2021, Wazuh Inc.
 * June 12, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

/*TODO: Put this in a common place as is used across many files and two executables*/
#ifdef WIN32
#define mkdir(x, y) _mkdir(x)
#define unlink(x) _unlink(x)
#define localtime_r(x, y) localtime_s(y, x)
static const int USE_UNIX_PATH = 0;
#else
static const int USE_UNIX_PATH = 1;
#endif

#define UNIX_BASE_PATH "logs/wazuh"
#define WIN_BASE_PATH "logs"

static const char LOG_EXT[] = "log";
static const char JSON_EXT[] = "json";

static void remove_old_logs_m(const char * base_dir, int year, int month, time_t threshold) {
    struct tm tm = { .tm_sec = 0 };
    time_t now = time(NULL);
    localtime_r(&now, &tm);

    tm.tm_year = year - 1900;
    tm.tm_mon = month;
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;

    DIR *dir;
    char path[PATH_MAX];
    if (dir = opendir(base_dir), !dir) {
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
        return;
    }

    struct dirent *dirent = NULL;
    while (dirent = readdir(dir), dirent) {
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0'
                    || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        int day = 0;
        int counter = 0;
        if (sscanf(dirent->d_name, "ossec-%02d.log", &day) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }
        else if (sscanf(dirent->d_name, "ossec-%02d-%03d.log", &day, &counter) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }
        else if (sscanf(dirent->d_name, "ossec-%02d.json", &day) > 0) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                mdebug2("Removing old log '%s'", path);
                unlink(path);
            }
        }
        else if (sscanf(dirent->d_name, "ossec-%02d-%03d.json", &day, &counter) > 0) {
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

static void remove_old_logs_y(const char * base_dir, int year, time_t threshold) {

    DIR *dir;
    if (dir = opendir(base_dir), !dir) {
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
        return;
    }

    struct dirent *dirent = NULL;
    while (dirent = readdir(dir), dirent) {
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0'
                    || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        int month;
        for (month = 0; month < 12; month++) {
            if (strcmp(dirent->d_name, get_short_month_name(month)) == 0) {
                break;
            }
        }

        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);

        if (month < 12) {
            remove_old_logs_m(path, year, month, threshold);
        } else {
            mwarn("Unexpected folder '%s'", path);
        }
    }

    closedir(dir);
}

void remove_old_logs(int keep_log_days) {
    time_t threshold = time(NULL) - (keep_log_days + 1) * DAY_IN_SECONDS;

    //TODO assert that we are in the install directory or this will fail to get the logs
    char base_dir[PATH_MAX];
    snprintf(base_dir, PATH_MAX, USE_UNIX_PATH ? UNIX_BASE_PATH : WIN_BASE_PATH);

    DIR *dir;
    struct dirent *dirent = NULL;
    if (dir = opendir(base_dir), !dir) {
        merror("Couldn't open directory '%s' to delete old logs: %s", base_dir, strerror(errno));
        return;
    }

    while (dirent = readdir(dir), dirent) {
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0'
                    || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        int year = 0;
        if (sscanf(dirent->d_name, "%d", &year) > 0) {
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
            remove_old_logs_y(path, year, threshold);
        }
    }

    closedir(dir);
}

void w_rotate_log(const rotate_log_config_t* config) {
    const char* ext = config->log_extension & LE_LOG ? LOG_EXT : JSON_EXT;

    char base_dir[PATH_MAX];
    snprintf(base_dir, PATH_MAX, USE_UNIX_PATH ? UNIX_BASE_PATH : WIN_BASE_PATH);

    struct tm tm = { .tm_sec = 0 };
    localtime_r(&config->log_creation_time, &tm);

    char year_dir[PATH_MAX];
    char month_dir[PATH_MAX];
    os_snprintf(year_dir, PATH_MAX, "%s/%d", base_dir, tm.tm_year + 1900);
    os_snprintf(month_dir, PATH_MAX, "%s/%s", year_dir, get_short_month_name(tm.tm_mon));

    if (IsDir(year_dir) < 0 && mkdir(year_dir, 0770) < 0) {
        merror_exit(MKDIR_ERROR, year_dir, errno, strerror(errno));
    }

    if (IsDir(month_dir) < 0 && mkdir(month_dir, 0770) < 0) {
        merror_exit(MKDIR_ERROR, month_dir, errno, strerror(errno));
    }

    char rotated_log_path[PATH_MAX];
    char compressed_path[PATH_MAX];

    int rotated_log_count = 0;
    do{
            os_snprintf(rotated_log_path, PATH_MAX
                    , rotated_log_count == 0
                    ? "%s/ossec-%02d"
                    : "%s/ossec-%02d-%03d"
                    , month_dir
                    , tm.tm_mday
                    , rotated_log_count);

        os_snprintf(compressed_path, PATH_MAX, "%s.%s.gz", rotated_log_path, ext);

        if(IsFile(compressed_path) != 0) {
            break;
        }

        rotated_log_count++;
    }while(1);

    const int daily_rotations = config->configured_daily_rotations;
    if (rotated_log_count == daily_rotations) {
        if(daily_rotations != 1) {
            char previous_rotated_log[PATH_MAX];
            char rotated_log[PATH_MAX];

            os_snprintf(previous_rotated_log, PATH_MAX, "%s/ossec-%02d.%s.gz", month_dir, tm.tm_mday, ext);

            for(int i = 1; i < daily_rotations; ++i)
            {
                os_snprintf(rotated_log, PATH_MAX, "%s/ossec-%02d-%03d.%s.gz", month_dir, tm.tm_mday, i, ext);
                if (rename_ex(rotated_log, previous_rotated_log) != 0) {
                    merror("Couldn't rename compressed log '%s' to '%s': '%s'", rotated_log, previous_rotated_log, strerror(errno));
                    //TODO we don't keep trying or recover from a failed rotation
                    return;
                }
                //TODO assert that both have the same capacity
                strcpy(previous_rotated_log, rotated_log);
            }
        }

        os_snprintf(rotated_log_path, PATH_MAX, daily_rotations == 1
                ? "%s/ossec-%02d"
                : "%s/ossec-%02d-%03d"
                , month_dir
                , tm.tm_mday
                , rotated_log_count - 1);
    }

    char current_log_path[PATH_MAX];
    os_snprintf(current_log_path, PATH_MAX, "%s", config->log_extension & LE_JSON ? LOGJSONFILE : LOGFILE);
    os_snprintf(rotated_log_path, PATH_MAX, "%s.%s", rotated_log_path, ext);

    if (IsFile(current_log_path) == 0) {
        if (rename_ex(current_log_path, rotated_log_path) == 0) {
            if (config->compress) {
                OS_CompressLog(rotated_log_path);
            }
        }
        else {
            merror("Couldn't rename '%s' to '%s': %s", current_log_path, rotated_log_path, strerror(errno));
        }
    }

    minfo("Starting new log after rotation.");
}
