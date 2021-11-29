/* Copyright (C) 2015-2019, Wazuh Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

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

static rotation_node *get_rotation_node_list(char *dir_name, rotation_node **last_node, int *count, char *tag, char *ext);
static rotation_node *get_sorted_year(DIR *dir);
static rotation_node *get_sorted_file(DIR *dir, char *dir_base, rotation_node **last_node, int *count, char *tag, char *ext);

rotation_list *get_rotation_list(char *tag, char *ext) {
    int i;
    char month_path[PATH_MAX];
    char logs_path[PATH_MAX];
    char *TAG;

    rotation_list *rot_list;
    rotation_node *year_it;
    rotation_node *file_it;
    rotation_node *year_list;

    if(!strncmp(tag, "logs", strlen(tag))) {
        TAG = OSSECLOG;
    } else if(!strncmp(tag, "alerts", strlen(tag))) {
        TAG = ALERTS;
    } else {
        TAG = EVENTS;
    }

    snprintf(logs_path, PATH_MAX, "%s", TAG);
    year_list = get_rotation_node_list(logs_path, NULL, NULL, NULL, NULL);
    os_calloc(1, sizeof(rotation_list), rot_list);

    year_it = year_list;
    while (year_it) {
        rotation_node *r_year = year_it;

        for (i = 0; i < 12; i++) {
            DIR *dir;
            os_snprintf(month_path, PATH_MAX, "%s/%d/%s", logs_path, year_it->first_value, MONTHS[i]);
            if (dir = opendir(month_path), dir) {
                rotation_node *last_file_node = NULL;
                int count = 0;

                closedir(dir);
                file_it = get_rotation_node_list(month_path, &last_file_node, &count, tag, ext);
                if(file_it) {
                    if (rot_list->first) {
                        file_it->prev = rot_list->last;
                        if (rot_list->last) {
                            rot_list->last->next = file_it;
                        }
                    } else {
                        rot_list->first = file_it;
                    }

                    rot_list->last = last_file_node;
                    rot_list->count += count;
                    if(!last_file_node) {
                        rot_list->last = rot_list->first;
                    }
                }
            }
        }

        year_it = year_it->next;
        free(r_year);
    }


    return rot_list;
}


rotation_node *get_rotation_node_list(char *dir_name, rotation_node **last_node, int *count, char *tag, char *ext) {
    DIR *dir;
    rotation_node *list = NULL;

    if (dir = opendir(dir_name), !dir) {
        return NULL;
    }

    list = !last_node ? get_sorted_year(dir) : get_sorted_file(dir, dir_name, last_node, count, tag, ext);

    closedir(dir);

    return list;
}

rotation_node *get_sorted_year(DIR *dir) {
    struct dirent *entry;
    rotation_node *list = NULL;
    rotation_node *node;
    rotation_node *node_it;

    while (entry = readdir(dir), entry) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        os_calloc(1, sizeof(rotation_node), node);
        node->first_value = strtol(entry->d_name, NULL, 10);

        if (list) {
            rotation_node *higher = NULL;
            node_it = list;

            while (1) {
                if (node_it->first_value > node->first_value) {
                    higher = node_it;
                    break;
                }

                if (node_it->next) {
                   node_it = node_it->next;
                } else {
                    break;
                }
            }

            if (higher) {
                node->next = higher;
                if (higher->prev) {
                    higher->prev->next = node;
                }
                node->prev = higher->prev;
                higher->prev = node;

                if (list == higher) {
                    list = node;
                }
            } else {
                node->prev = node_it;
                node_it->next = node;
            }
        } else {
            list = node;
        }

    }

    return list;
}

rotation_node *get_sorted_file(DIR *dir, char *dir_base, rotation_node **last_node, int *count, char *tag, char *ext) {
    struct dirent *entry;
    rotation_node *list = NULL;
    rotation_node *node;
    rotation_node *node_it;
    char pattern[PATH_MAX];
    size_t size;

    snprintf(pattern, PATH_MAX, "ossec-%s-%%d-%%d.", tag);

    while (entry = readdir(dir), entry) {
        int first = 0;
        int second = 0;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        if (!strstr(entry->d_name, ext)) {
            continue;
        }

        if (!sscanf(entry->d_name, pattern, &first, &second)) {
            continue;
        }

        os_calloc(1, sizeof(rotation_node), node);
        node->first_value = first;
        node->second_value = second;
        size = strlen(entry->d_name) + strlen(dir_base) + 3;
        os_calloc(size, sizeof(char), node->string_value);
        snprintf(node->string_value, size, "%s/%s", dir_base, entry->d_name);
        ++(*count);

        if (list) {
            rotation_node *higher = NULL;
            node_it = list;

            while (1) {
                if (node_it->first_value > node->first_value ||
                    (node_it->first_value == node->first_value && node_it->second_value > node->second_value)) {
                    higher = node_it;
                    break;
                }

                if (node_it->next) {
                   node_it = node_it->next;
                } else {
                    break;
                }
            }

            if (higher) {
                node->next = higher;
                if (higher->prev) {
                    higher->prev->next = node;
                }
                node->prev = higher->prev;
                higher->prev = node;

                if (list == higher) {
                    list = node;
                }

                if(!*last_node) {
                    *last_node = higher;
                }

            } else {
                node->prev = node_it;
                node_it->next = node;
                *last_node = node;
            }
        } else {
            list = node;
        }
    }

    return list;
}

void purge_rotation_list(rotation_list *list, int keep_files) {
    rotation_node *node;
    int i;

    if (!list || list->count <= keep_files || keep_files == -1) {
        return;
    }

    list->count = keep_files;

    for (node = list->last, i = 0; node && i < keep_files; node = node->prev, i++);

    while (node) {
        rotation_node *r_node = node;

        if (unlink(node->string_value) == -1) {
            mdebug1("Unable to delete '%s' due to '%s'", node->string_value, strerror(errno));
        } else {
            mdebug2("Removing the rotated file '%s'.", node->string_value);
        }

        if (node->prev) {
            node->prev->next = node->next;
        } else {
            list->first = node->next;
        }
        if (node->next) {
            node->next->prev = node->prev;
        }

        node = node->prev;
        free(r_node->string_value);
        free(r_node);
    }
}

void delete_node(rotation_list *list, char *path) {
    rotation_node *node;

    if (!list) {
        return;
    }

    node = list->last;

    while (node) {
        if (!strcmp(path, node->string_value)) {

            if (node->prev) {
                node->prev->next = node->next;
            } else {
                list->first = node->next;
            }

            if (node->next) {
                node->next->prev = node->prev;
            } else {
                list->last = node->prev;
            }

            list->count--;

            os_free(node->string_value);
            os_free(node);

            break;
        }

        node = node->prev;
    }

}

void add_new_rotation_node(rotation_list *list, char *value, int keep_files) {
    rotation_node *new_node;
    rotation_node *r_node;
    int first_value = 0;
    int second_value = 0;
    char TAG[OS_FLSIZE];
    char pattern[PATH_MAX];
    char *file_basename;

    file_basename = strrchr(value, PATH_SEP_ROT);

    if(!list) {
        return;
    }

    if(list->last && !strncmp(list->last->string_value, value, strlen(list->last->string_value))) {
        return;
    }

    if(file_basename && strstr(file_basename,"logs")) {
        strcpy(TAG, "logs");
    } else if(file_basename && strstr(file_basename,"alerts")){
        strcpy(TAG, "alerts");
    } else if(file_basename && strstr(file_basename,"archive")){
        strcpy(TAG, "archive");
    }

    snprintf(pattern, PATH_MAX, "%cossec-%s-%%d-%%d.", PATH_SEP_ROT, TAG);
    file_basename = strrchr(value, PATH_SEP_ROT);

    os_calloc(1, sizeof(rotation_node), new_node);
    os_strdup(value, new_node->string_value);

    if (file_basename && !sscanf(file_basename, pattern, &first_value, &second_value)) {
        second_value = 0;
    }

    new_node->first_value = first_value;
    new_node->second_value = second_value;

    new_node->prev = list->last;
    if(list->last) {
        list->last->next = new_node;
    }
    list->last = new_node;
    list->count++;
    if(!list->first) {
        list->first = list->last;
    }

    if(list->count > keep_files && keep_files != -1) {
        if(unlink(list->first->string_value) == -1) {
            char compressed_log[OS_FLSIZE+3];
            snprintf(compressed_log, OS_FLSIZE+3, "%s.gz", list->first->string_value);
            if(unlink(compressed_log) == -1) {
                mdebug1("Unable to delete '%s' due to '%s'", compressed_log, strerror(errno));
            } else {
                mdebug2("Removing the rotated file '%s'.", compressed_log);
            }
        } else {
            mdebug2("Removing the rotated file '%s'.", list->first->string_value);
        }
        /* Delete sign file */
        char sign_log[OS_FLSIZE+3];
        snprintf(sign_log, OS_FLSIZE+3, "%s.sum", list->first->string_value);
        if (unlink(sign_log) == -1) {
            mdebug1("Unable to delete '%s' due to '%s'", sign_log, strerror(errno));
        } else {
            mdebug2("Removing the sign file '%s'.", sign_log);
        }
        r_node = list->first;
        list->first = list->first->next;
        if (list->first) {
            list->first->prev = NULL;
        }
        free(r_node->string_value);
        free(r_node);
        list->count--;
    }
}

void remove_old_logs(const char *base_dir, int maxage, const char * type, rotation_list *list_log, rotation_list *list_json) {
    time_t threshold = time(NULL) - (maxage + 1) * 86400;
    char path[PATH_MAX];
    int year;
    DIR *dir;
    struct dirent *dirent = NULL;

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
            remove_old_logs_y(path, year, threshold, type, list_log, list_json);
        }
    }

    closedir(dir);
}

void remove_old_logs_y(const char * base_dir, int year, time_t threshold, const char * type, rotation_list *list_log, rotation_list *list_json) {
    char path[PATH_MAX];
    int month;
    DIR *dir;
    struct dirent *dirent = NULL;

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
            remove_old_logs_m(path, year, month, threshold, type, list_log, list_json);
        } else {
            mwarn("Unexpected folder '%s'", path);
        }
    }

    closedir(dir);
}

void remove_old_logs_m(const char * base_dir, int year, int month, time_t threshold, const char * type, rotation_list *list_log, rotation_list *list_json) {
    char path[PATH_MAX];
    char ext[9];
    DIR *dir;
    struct dirent *dirent = NULL;
    time_t now = time(NULL);
    struct tm tm = { .tm_sec = 0 };
    int counter, day;

    char match_log_simple[PATH_MAX], match_log[PATH_MAX];

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

    snprintf(match_log_simple, PATH_MAX - 1, "ossec-%s-%%02d.%%s", type);
    snprintf(match_log, PATH_MAX - 1, "ossec-%s-%%02d-%%03d.%%s", type);

    while (dirent = readdir(dir), dirent) {
        // Skip "." and ".."
        if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
            continue;
        }

        if (sscanf(dirent->d_name, match_log_simple, &day, ext) == 2) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                if (!strcmp(ext, "log") || !strcmp(ext, "log.gz") || !strcmp(ext, "log.sum")) {
                    snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                    mdebug2("Removing old log '%s'", path);
                    unlink(path);
                    delete_node(list_log, path);
                } else if (!strcmp(ext, "json") || !strcmp(ext, "json.gz") || !strcmp(ext, "json.sum")) {
                    snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                    mdebug2("Removing old log '%s'", path);
                    unlink(path);
                    delete_node(list_json, path);
                }
            }
        }

        if (sscanf(dirent->d_name, match_log, &day, &counter, ext) == 3) {
            tm.tm_mday = day;

            if (mktime(&tm) <= threshold) {
                if (!strcmp(ext, "log") || !strcmp(ext, "log.gz") || !strcmp(ext, "log.sum")) {
                    snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                    mdebug2("Removing old log '%s'", path);
                    unlink(path);
                    delete_node(list_log, path);
                } else if (!strcmp(ext, "json") || !strcmp(ext, "json.gz") || !strcmp(ext, "json.sum")) {
                    snprintf(path, PATH_MAX, "%s/%s", base_dir, dirent->d_name);
                    mdebug2("Removing old log '%s'", path);
                    unlink(path);
                    delete_node(list_json, path);
                }
            }
        }
    }

    closedir(dir);
}

time_t calc_next_rotation(time_t tm, const char units, int interval)
{
    int counter;  /* Number of intervals to rotate in a day */
    int i = 1;
    struct tm rot  = { .tm_sec = 0 };
    time_t ret = tm;
    int seconds, n_minutes;
    localtime_r(&ret, &rot);

    switch (units) {
        case 'w':
            /* Seconds left to the next rotation day depending if its this week or the next */
            seconds = (interval > rot.tm_wday) ? (interval-rot.tm_wday) * SECONDS_PER_DAY : (((7-(rot.tm_wday-interval)) * SECONDS_PER_DAY) + 3600);
            ret = tm + seconds;
            localtime_r(&ret, &rot);
            rot.tm_hour = 0;
            rot.tm_min = 0;
        break;
        case 'h':
            counter = 24 / interval;
            while (rot.tm_hour >= i*interval && i < counter) {
                i++;
            }
            /* The next rotation is tomorrow */
            if (i == counter) {
                ret += SECONDS_PER_DAY;
                localtime_r(&ret, &rot);
                rot.tm_hour = 0;
            /* The next rotation is today */
            } else {
                rot.tm_hour = i*interval;
            }
            rot.tm_min = 0;
        break;
        case 'm':
            counter = 24*60 / interval;
            n_minutes = (rot.tm_hour*60 + rot.tm_min) / interval;
            /* The next rotation is tomorrow */
            if (n_minutes == counter-1) {
                ret += SECONDS_PER_DAY;
                localtime_r(&ret, &rot);
                rot.tm_hour = 0;
                rot.tm_min = 0;
            /* The next rotation is today */
            } else {
                /* The next rotation will be in the next n_minutes iteration */
                rot.tm_hour = 0;
                rot.tm_min = 0;
                rot.tm_sec = 0;
                ret = mktime(&rot);
                ret += interval * 60 * (n_minutes + 1);
                localtime_r(&ret, &rot);
            }
        break;
    }

    rot.tm_sec = 0;
    ret = mktime(&rot);

    mdebug2("Next scheduled rotation: %d/%d/%d %d:%d:%d", rot.tm_mday, rot.tm_mon+1,
            rot.tm_year+1900, rot.tm_hour, rot.tm_min, rot.tm_sec);

    return ret;
}
