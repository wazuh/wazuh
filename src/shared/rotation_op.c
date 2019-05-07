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
    } if(!strncmp(tag, "archives", strlen(tag))) {
        TAG = EVENTS;
    }
#ifndef WIN32
    snprintf(logs_path, PATH_MAX, "%s%s", !isChroot() ? DEFAULTDIR : "", TAG);
#else
    snprintf(logs_path, PATH_MAX, "%s", TAG);
#endif
    year_list = get_rotation_node_list(logs_path, NULL, NULL, NULL, NULL);
    rot_list = calloc(1, sizeof(rotation_list));

    year_it = year_list;
    while (year_it) {
        rotation_node *r_year = year_it;

        for (i = 0; i < 12; i++) {
            DIR *dir;
            snprintf(month_path, PATH_MAX, "%s/%d/%s", logs_path, year_it->first_value, MONTHS[i]);
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

        node = calloc(1, sizeof(rotation_node));
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

        node = calloc(1, sizeof(rotation_node));
        node->first_value = first;
        node->second_value = second;
        size = strlen(entry->d_name) + strlen(dir_base) + 3;
        node->string_value = calloc(size, sizeof(char));
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

    if (list->count <= keep_files || keep_files == -1) {
        return;
    }

    list->count = keep_files;

    for (node = list->last, i = 0; node && i < keep_files; node = node->prev, i++);

    while (node) {
        rotation_node *r_node = node;

        if(unlink(node->string_value) == -1) {
            mdebug1("Unable to delete '%s' due to '%s'", node->string_value, strerror(errno));
        } else {
            mdebug2("Removing the rotated file '%s'.", node->string_value);
        }

        if (node->prev) {
            node->prev->next = node->next;
        } else {
            list->first = node->next;
        }
        if(node->next) {
            node->next->prev = node->prev;
        }

        node = node->prev;
        free(r_node->string_value);
        free(r_node);
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
        r_node = list->first;
        if(list->first){
            list->first = list->first->next;
            list->first->prev = NULL;
        }
        free(r_node->string_value);
        free(r_node);
        list->count--;
    }
}






