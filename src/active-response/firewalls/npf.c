/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

#define NPFCTL "/sbin/npfctl"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char log_msg[LOGSIZE];
    static char *srcip;
    static char *action;
    static cJSON *input_json = NULL;
    char *home_path = w_homedir(argv[0]);

    /* Trim absolute path to get Wazuh's installation directory */
    home_path = w_strtok_r_str_delim("/active-response", &home_path);
    
    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }
    os_free(home_path);

    write_debug_file(argv[0], "Starting");

    memset(input, '\0', BUFFERSIZE);
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file(argv[0], "Invalid value of 'command'");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Get srcip
    srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (access(NPFCTL, F_OK) < 0) {
        write_debug_file(argv[0], "The NPFCTL is not accessible");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    wfd_t *wfd1 = NULL;
    char *cmd[3] = {NPFCTL, "show", NULL};
    if (wfd1 = wpopenv(NPFCTL, cmd, W_BIND_STDOUT), wfd1) {
        char output_buf[BUFFERSIZE];
        int flag = false;
        while (fgets(output_buf, BUFFERSIZE, wfd1->file)) {
            const char *pos = strstr(output_buf, "filtering:");
            if (pos != NULL) {
                char state[15];
                if (pos && sscanf(pos, "%*s %9s", state) == 1) {
                    if (strcmp(state, "active") != 0) {
                        memset(log_msg, '\0', LOGSIZE);
                        snprintf(log_msg, LOGSIZE -1, "The filter property is inactive");
                        write_debug_file(argv[0], log_msg);
                        cJSON_Delete(input_json);
                        wpclose(wfd1);
                        return OS_INVALID;
                    }
                    flag = true;
                    break;
                } else {
                    memset(log_msg, '\0', LOGSIZE);
                    snprintf(log_msg, LOGSIZE -1, "Key word not found");
                    write_debug_file(argv[0], log_msg);
                    cJSON_Delete(input_json);
                    wpclose(wfd1);
                    return OS_INVALID;
                }
            }
        }
        wpclose(wfd1);

        if (flag == false) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to find 'filtering'");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

    } else {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", NPFCTL, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    wfd_t *wfd2 = NULL;
    if (wfd2 = wpopenv(NPFCTL, cmd, W_BIND_STDOUT), wfd2) {
        char output_buf[BUFFERSIZE];
        int flag = false;
        while (fgets(output_buf, BUFFERSIZE, wfd2->file)) {
            const char *pos = strstr(output_buf, "table <wazuh_blacklist>");
            if (pos != NULL) {
                flag = true;
                break;
            }
        }
        wpclose(wfd2);

        if (flag == false) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to find 'table <wazuh_blacklist>'");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

    } else {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", NPFCTL, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    char *exec_cmd[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    if (!strcmp("add", action)) {
        char *arg[6] = {NPFCTL, "table", "wazuh_blacklist", "add", srcip, NULL};
        memcpy(exec_cmd, arg, sizeof(exec_cmd));
    } else {
        char *arg[6] = {NPFCTL, "table", "wazuh_blacklist", "del", srcip, NULL};
        memcpy(exec_cmd, arg, sizeof(exec_cmd));
    }

    // Executing it
    wfd_t *wfd3 = wpopenv(NPFCTL, exec_cmd, W_BIND_STDOUT);
    if (!wfd3) {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", NPFCTL, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }
    wpclose(wfd3);

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
