/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

void write_debug_file (const char *ar_name, const char *msg) {
    char path[PATH_MAX];
    char *timestamp = w_get_timestamp(time(NULL));

    snprintf(path, PATH_MAX, "%s", LOG_FILE);

    FILE *ar_log_file = fopen(path, "a");

    if (ar_log_file) {
        fprintf(ar_log_file, "%s %s: %s\n", timestamp, ar_name, msg);
        fclose(ar_log_file);
    }

    os_free(timestamp);
}

cJSON* get_json_from_input (const char *input) {
    cJSON *input_json = NULL;
    cJSON *origin_json = NULL;
    cJSON *version_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *extra_args = NULL;
    cJSON *alert_json = NULL;
    const char *json_err;

    // Parsing input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        return NULL;
    }

    // Detect version
    if (version_json = cJSON_GetObjectItem(input_json, "version"), !version_json || (version_json->type != cJSON_Number)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(input_json, "origin"), !origin_json || (origin_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect command
    if (command_json = cJSON_GetObjectItem(input_json, "command"), !command_json || (command_json->type != cJSON_String)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input_json, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect extra_args
    if (extra_args = cJSON_GetObjectItem(parameters_json, "extra_args"), !extra_args || (extra_args->type != cJSON_Array)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect program
    if (alert_json = cJSON_GetObjectItem(parameters_json, "program"), !alert_json || (alert_json->type != cJSON_String)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    return input_json;
}

char* get_command (cJSON *input) {
    // Detect command
    cJSON *command_json = cJSON_GetObjectItem(input, "command");
    if (command_json && (command_json->type == cJSON_String)) {
        return command_json->valuestring;
    }

    return NULL;
}

char* get_username_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *username_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect username
    username_json = cJSON_GetObjectItem(data_json, "dstuser");
    if (username_json && (username_json->type == cJSON_String)) {
        return username_json->valuestring;
    }

    return NULL;
}

char* get_extra_args_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *extra_args_json = NULL;
    char args[COMMANDSIZE];
    char *extra_args = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect extra_args
    if (extra_args_json = cJSON_GetObjectItem(parameters_json, "extra_args"), !extra_args_json || (extra_args_json->type != cJSON_Array)) {
        return NULL;
    }

    memset(args, '\0', COMMANDSIZE);
    for (int i = 0; i < cJSON_GetArraySize(extra_args_json); i++) {
        cJSON *subitem = cJSON_GetArrayItem(extra_args_json, i);
        if (subitem && (subitem->type == cJSON_String)) {
            if (strlen(args) + strlen(subitem->valuestring) + 2 > COMMANDSIZE) {
                break;
            }
            if (args[0] != '\0') {
                strcat(args, " ");
            }
            strcat(args, subitem->valuestring);
        }
    }

    if (args[0] != '\0') {
        os_strdup(args, extra_args);
    }

    return extra_args;
}

cJSON* get_alert_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        return NULL;
    }

    return alert_json;
}

char* get_srcip_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *srcip_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect srcip
    srcip_json = cJSON_GetObjectItem(data_json, "srcip");
    if (srcip_json && (srcip_json->type == cJSON_String)) {
        return srcip_json->valuestring;
    }

    return NULL;
}

#ifndef WIN32

int lock (const char *lock_path, const char *lock_pid_path, const char *log_path, const char *proc_name) {
    char log_msg[LOGSIZE];
    int i=0;
    int max_iteration = 50;
    int saved_pid = -1;
    int read;

    // Providing a lock.
    while (true) {
        FILE *pid_file;
        int current_pid = -1;

        if (mkdir(lock_path, S_IRWXG) == 0) {
            // Lock acquired (setting the pid)
            pid_t pid = getpid();
            if (pid_file = fopen(lock_pid_path, "w"), !pid_file) {
                write_debug_file(log_path, "Cannot write pid file");
                return OS_INVALID;
            } else {
                fprintf(pid_file, "%d", (int)pid);
                fclose(pid_file);
                return OS_SUCCESS;
            }
        }

        // Getting currently/saved PID locking the file
        if (pid_file = fopen(lock_pid_path, "r"), !pid_file) {
            write_debug_file(log_path, "Cannot read pid file");
        } else {
            read = fscanf(pid_file, "%d", &current_pid);
            fclose(pid_file);

            if (read == 1) {
                if (saved_pid == -1) {
                    saved_pid = current_pid;
                }

                if (current_pid == saved_pid) {
                    i++;
                }

            } else {
                write_debug_file(log_path, "Cannot read pid file");
            }
        }

        sleep(i);

        i++;

        // So i increments 2 by 2 if the pid does not change.
        // If the pid keeps changing, we will increments one
        // by one and fail after MAX_ITERACTION
        if (i >= max_iteration) {
            bool kill = false;
            wfd_t *wfd = NULL;
            char *command_ex_1[4] = {"pgrep", "-f", (char *)proc_name, NULL};
            if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDOUT), wfd) {
                char output_buf[BUFFERSIZE];
                while (fgets(output_buf, BUFFERSIZE, wfd->file_out)) {
                    int pid = atoi(output_buf);
                    if (pid == current_pid) {
                        wfd_t *wfd2 = NULL;
                        char pid_str[10];
                        memset(pid_str, '\0', 10);
                        snprintf(pid_str, 9, "%d", pid);
                        char *command_ex_2[4] = {"kill", "-9", pid_str, NULL};
                        if (wfd2 = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDOUT), wfd2) {
                            wpclose(wfd2);
                            memset(log_msg, '\0', LOGSIZE);
                            snprintf(log_msg, LOGSIZE -1, "Killed process %d holding lock.", pid);
                            write_debug_file(log_path, log_msg);
                            kill = true;
                            unlock(lock_path, log_path);
                            i = 0;
                            saved_pid = -1;
                        }
                        break;
                    }
                }
                wpclose(wfd);
            } else {
                write_debug_file(log_path, "Unable to run pgrep");
            }

            if (!kill) {
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE -1, "Unable to kill process %d holding lock.", current_pid);
                write_debug_file(log_path, log_msg);

                // Unlocking
                unlock(lock_path, log_path);

                // Try take lock again
                if (mkdir(lock_path, S_IRWXG) == 0) {
                    // Lock acquired (setting the pid)
                    pid_t pid = getpid();
                    pid_file = fopen(lock_pid_path, "w");
                    fprintf(pid_file, "%d", (int)pid);
                    fclose(pid_file);

                    return OS_SUCCESS;
                }

                return OS_INVALID;
            }
        }
    }

}

void unlock (const char *lock_path, const char *log_path) {
    if (rmdir_ex(lock_path) < 0) {
        write_debug_file(log_path, "Unable to remove lock folder");
    }
}

int get_ip_version (char *ip) {
    struct addrinfo hint, *res = NULL;
    int ret;

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(ip, NULL, &hint, &res);
    if (ret) {
        freeaddrinfo(res);
        return OS_INVALID;
    }
    if (res->ai_family == AF_INET) {
        freeaddrinfo(res);
        return 4;
    } else if (res->ai_family == AF_INET6) {
        freeaddrinfo(res);
        return 6;
    }

    freeaddrinfo(res);
    return OS_INVALID;
}

#endif
