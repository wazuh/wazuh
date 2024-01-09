/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

/**
 * Build JSON message with keys to be sent to execd
 * @param ar_name Name of active response
 * @param keys Array of keys
 * @return char * with the JSON message in string format
 */
static char* build_json_keys_message(const char *ar_name, char **keys);

/**
 * Get srcip from win eventdata
 * @param data Input
 * @return cJSON * with the ipAddress or NULL on fail
 * */
static cJSON* get_srcip_from_win_eventdata(const cJSON *data);


void write_debug_file(const char *ar_name, const char *msg) {
    char *timestamp = w_get_timestamp(time(NULL));

    FILE *ar_log_file = wfopen(LOG_FILE, "a");

    if (ar_log_file) {
        fprintf(ar_log_file, "%s %s: %s\n", timestamp, ar_name, msg);
        fclose(ar_log_file);
    }

    os_free(timestamp);
}

int setup_and_check_message(char **argv, cJSON **message) {
    int ret = OS_INVALID;
    char input[OS_MAXSTR];
    cJSON *input_json = NULL;

#ifndef WIN32
    char *home_path = w_homedir(argv[0]);

    /* Trim absolute path to get Wazuh's installation directory */
    home_path = w_strtok_r_str_delim("/active-response", &home_path);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
    os_free(home_path);
#endif

    write_debug_file(argv[0], "Starting");

    memset(input, '\0', OS_MAXSTR);
    if (fgets(input, OS_MAXSTR, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    const char *action = get_command_from_json(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("add", action)) {
        ret = ADD_COMMAND;
    } else if (!strcmp("delete", action)) {
        ret = DELETE_COMMAND;
    } else {
        write_debug_file(argv[0], "Invalid value of 'command'");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (message) {
        *message = input_json;
    }

    return ret;
}

int send_keys_and_check_message(char **argv, char **keys) {
    int ret = OS_INVALID;
    char *keys_msg;
    char input[OS_MAXSTR];
    cJSON *input_json = NULL;

    // Build and send message with keys
    keys_msg = build_json_keys_message(basename_ex(argv[0]), keys);

    write_debug_file(argv[0], keys_msg);

    fprintf(stdout, "%s\n", keys_msg);
    fflush(stdout);

    os_free(keys_msg);

    // Read the response of previous message
    memset(input, '\0', OS_MAXSTR);
    if (fgets(input, OS_MAXSTR, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    const char *action = get_command_from_json(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("continue", action)) {
        ret = CONTINUE_COMMAND;
    } else if (!strcmp("abort", action)) {
        ret = ABORT_COMMAND;
    } else {
        ret = OS_INVALID;
        write_debug_file(argv[0], "Invalid value of 'command'");
    }

    cJSON_Delete(input_json);

    return ret;
}

cJSON* get_json_from_input(const char *input) {
    cJSON *input_json = NULL;
    cJSON *version_json = NULL;
    cJSON *origin_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    const char *json_err;

    // Parsing input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        return NULL;
    }

    // Detect version
    version_json = cJSON_GetObjectItem(input_json, "version");
    if (!cJSON_IsNumber(version_json)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect origin
    origin_json = cJSON_GetObjectItem(input_json, "origin");
    if (!cJSON_IsObject(origin_json)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect command
    command_json = cJSON_GetObjectItem(input_json, "command");
    if (!cJSON_IsString(command_json)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input_json, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    return input_json;
}

const char* get_command_from_json(const cJSON *input) {
    cJSON *command_json = NULL;

    // Detect command
    command_json = cJSON_GetObjectItem(input, "command");
    if (cJSON_IsString(command_json)) {
        return command_json->valuestring;
    }

    return NULL;
}

const cJSON* get_alert_from_json(const cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        return NULL;
    }

    // Detect alert
    alert_json = cJSON_GetObjectItem(parameters_json, "alert");
    if (!cJSON_IsObject(alert_json)) {
        return NULL;
    }

    return alert_json;
}

const char* get_srcip_from_json(const cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *srcip_json = NULL;

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        return NULL;
    }

    // Detect alert
    alert_json = cJSON_GetObjectItem(parameters_json, "alert");
    if (!cJSON_IsObject(alert_json)) {
        return NULL;
    }

    // Detect data
    data_json = cJSON_GetObjectItem(alert_json, "data");
    if (!cJSON_IsObject(data_json)) {
        return NULL;
    }

    // Detect srcip from win.eventdata
    srcip_json = get_srcip_from_win_eventdata(data_json);
    if (cJSON_IsString(srcip_json)) {
        return srcip_json->valuestring;
    }
    // Detect srcip from data
    srcip_json = cJSON_GetObjectItem(data_json, "srcip");
    if (cJSON_IsString(srcip_json)) {
        return srcip_json->valuestring;
    }

    return NULL;
}

static cJSON* get_srcip_from_win_eventdata(const cJSON *data) {
    cJSON *win_json = NULL;
    cJSON *eventdata_json = NULL;
    cJSON *ipAddress_json = NULL;

    // Detect win
    win_json = cJSON_GetObjectItem(data, "win");
    if (!cJSON_IsObject(win_json)) {
        return NULL;
    }

    // Detect eventdata
    eventdata_json = cJSON_GetObjectItem(win_json, "eventdata");
    if (!cJSON_IsObject(eventdata_json)) {
        return NULL;
    }

    // Detect ipAddress
    ipAddress_json = cJSON_GetObjectItem(eventdata_json, "ipAddress");
    if (cJSON_IsString(ipAddress_json)) {
        return ipAddress_json;
    }

    // Detect destinationIp
    ipAddress_json = cJSON_GetObjectItem(eventdata_json, "destinationIp");
    if (cJSON_IsString(ipAddress_json)) {
        return ipAddress_json;
    }

    return NULL;
}

const char* get_username_from_json(const cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *username_json = NULL;

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        return NULL;
    }

    // Detect alert
    alert_json = cJSON_GetObjectItem(parameters_json, "alert");
    if (!cJSON_IsObject(alert_json)) {
        return NULL;
    }

    // Detect data
    data_json = cJSON_GetObjectItem(alert_json, "data");
    if (!cJSON_IsObject(data_json)) {
        return NULL;
    }

    // Detect username
    username_json = cJSON_GetObjectItem(data_json, "dstuser");
    if (cJSON_IsString(username_json)) {
        return username_json->valuestring;
    }

    return NULL;
}

char* get_extra_args_from_json(const cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *extra_args_json = NULL;
    char args[COMMANDSIZE_4096];
    char *extra_args = NULL;

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        return NULL;
    }

    // Detect extra_args
    extra_args_json = cJSON_GetObjectItem(parameters_json, "extra_args");
    if (!cJSON_IsArray(extra_args_json)) {
        return NULL;
    }

    memset(args, '\0', COMMANDSIZE_4096);
    for (int i = 0; i < cJSON_GetArraySize(extra_args_json); i++) {
        cJSON *subitem = cJSON_GetArrayItem(extra_args_json, i);
        if (cJSON_IsString(subitem)) {
            if (strlen(args) + strlen(subitem->valuestring) + 2 > COMMANDSIZE_4096) {
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

char* get_keys_from_json(const cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *keys_json = NULL;
    char args[COMMANDSIZE_4096];
    char *keys = NULL;

    // Detect parameters
    parameters_json = cJSON_GetObjectItem(input, "parameters");
    if (!cJSON_IsObject(parameters_json)) {
        return NULL;
    }

    // Detect keys
    keys_json = cJSON_GetObjectItem(parameters_json, "keys");
    if (!cJSON_IsArray(keys_json)) {
        return NULL;
    }

    memset(args, '\0', COMMANDSIZE_4096);
    for (int i = 0; i < cJSON_GetArraySize(keys_json); i++) {
        cJSON *subitem = cJSON_GetArrayItem(keys_json, i);
        if (cJSON_IsString(subitem)) {
            if (strlen(args) + strlen(subitem->valuestring) + 2 > COMMANDSIZE_4096) {
                break;
            }
            strcat(args, "-");
            strcat(args, subitem->valuestring);
        }
    }

    if (args[0] != '\0') {
        os_strdup(args, keys);
    }

    return keys;
}

static char* build_json_keys_message(const char *ar_name, char **keys) {
    cJSON *_object = NULL;
    cJSON *_array = NULL;
    char *msg = NULL;
    int keys_size;

    cJSON *message = cJSON_CreateObject();

    cJSON_AddNumberToObject(message, "version", VERSION);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "origin", _object);

    cJSON_AddStringToObject(_object, "name", ar_name ? ar_name : "");
    cJSON_AddStringToObject(_object, "module", AR_MODULE_NAME);

    cJSON_AddStringToObject(message, "command", CHECK_KEYS_ENTRY);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "parameters", _object);

    _array = cJSON_CreateArray();
    cJSON_AddItemToObject(_object, "keys", _array);

    for (keys_size = 0; (keys != NULL) && (keys[keys_size] != NULL); keys_size++) {
        cJSON_AddItemToArray(_array, cJSON_CreateString(keys[keys_size]));
    }

    msg = cJSON_PrintUnformatted(message);

    cJSON_Delete(message);

    return msg;
}

void splitStrFromCharDelimiter(const char * output_buf, const char delimiter, char * strBefore, char * strAfter){
    const char *pos = NULL;

    if (output_buf != NULL) {
        pos = strchr(output_buf, delimiter);

        if (pos != NULL) {
            if (strBefore != NULL) {
                strncpy(strBefore, output_buf, pos - output_buf);
            }
            if (strAfter != NULL) {
                strncpy(strAfter, pos + 1, strlen(pos));
            }
        }
    }
}

int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2) {
    int retVal = 0;
    const char *pos = NULL;

    if (str_pattern_1 != NULL) {
        pos = strstr(output_buf, str_pattern_1);
    }

    if (pos != NULL) {
        char state[OS_MAXSTR];
        char buffer[OS_MAXSTR];

        if (str_pattern_2 != NULL) {
            snprintf(buffer, OS_MAXSTR -1, "%%*s %%%lds", strlen(str_pattern_2));
            if (sscanf(pos, buffer /*"%*s %7s"*/, state) == 1) {
                if (strcmp(state, str_pattern_2) == 0) {
                    retVal = 1;
                } else {
                    retVal = 0;
                }
            }
        } else {
            retVal = 1;
        }
    }

    return retVal;
}

#ifndef WIN32

int lock(const char *lock_path, const char *lock_pid_path, const char *log_path, const char *proc_name) {
    char log_msg[OS_MAXSTR];
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
            if (pid_file = wfopen(lock_pid_path, "w"), !pid_file) {
                write_debug_file(log_path, "Cannot write pid file");
                return OS_INVALID;
            } else {
                fprintf(pid_file, "%d", (int)pid);
                fclose(pid_file);
                return OS_SUCCESS;
            }
        }

        // Getting currently/saved PID locking the file
        if (pid_file = wfopen(lock_pid_path, "r"), !pid_file) {
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
            char *pgrep_path = NULL;

            if (get_binary_path("pgrep", &pgrep_path) < 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", pgrep_path);
                write_debug_file(log_path, log_msg);
            }
            char *command_ex_1[4] = { pgrep_path, "-f", (char *)proc_name, NULL };

            wfd_t *wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDOUT);
            if (!wfd) {
                write_debug_file(log_path, "Unable to run pgrep");
            } else {
                char output_buf[OS_MAXSTR];
                while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
                    int pid = atoi(output_buf);
                    if (pid == current_pid) {
                        char pid_str[10];
                        char *kill_path = NULL;
                        memset(pid_str, '\0', 10);
                        snprintf(pid_str, 9, "%d", pid);

                        if (get_binary_path("kill", &kill_path) < 0) {
                            memset(log_msg, '\0', OS_MAXSTR);
                            snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", kill_path);
                            write_debug_file(log_path, log_msg);
                        }
                        char *command_ex_2[4] = { kill_path, "-9", pid_str, NULL };

                        wfd_t *wfd2 = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDOUT);
                        if (!wfd2) {
                            write_debug_file(log_path, "Unable to run kill");
                        } else {
                            wpclose(wfd2);
                            memset(log_msg, '\0', OS_MAXSTR);
                            snprintf(log_msg, OS_MAXSTR -1, "Killed process %d holding lock.", pid);
                            write_debug_file(log_path, log_msg);
                            kill = true;
                            unlock(lock_path, log_path);
                            i = 0;
                            saved_pid = -1;
                        }
                        os_free(kill_path);
                        break;
                    }
                }
                wpclose(wfd);
            }

            os_free(pgrep_path);

            if (!kill) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Unable to kill process %d holding lock.", current_pid);
                write_debug_file(log_path, log_msg);

                // Unlocking
                unlock(lock_path, log_path);

                // Try take lock again
                if (mkdir(lock_path, S_IRWXG) == 0) {
                    // Lock acquired (setting the pid)
                    pid_t pid = getpid();
                    pid_file = wfopen(lock_pid_path, "w");
                    fprintf(pid_file, "%d", (int)pid);
                    fclose(pid_file);

                    return OS_SUCCESS;
                }

                return OS_INVALID;
            }
        }
    }

}

void unlock(const char *lock_path, const char *log_path) {
    if (rmdir_ex(lock_path) < 0) {
        write_debug_file(log_path, "Unable to remove lock folder");
    }
}

int get_ip_version(const char *ip) {
    struct addrinfo hint, *res = NULL;
    int ret;

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = AF_UNSPEC;
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
