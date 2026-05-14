/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

int main (int argc, char **argv) {
    (void)argc;
    char output_buf[OS_MAXSTR];
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    char *npfctl_path = NULL;
    cJSON *input_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get srcip
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (action == ADD_COMMAND) {
        char **keys = NULL;
        int action2 = OS_INVALID;

        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);

        os_free(keys);

        // If necessary, abort execution
        if (action2 != CONTINUE_COMMAND) {
            cJSON_Delete(input_json);

            if (action2 == ABORT_COMMAND) {
                write_debug_file(argv[0], "Aborted");
                return OS_SUCCESS;
            } else {
                return OS_INVALID;
            }
        }
    }

    // Checking if npfctl is present
    if (get_binary_path("npfctl", &npfctl_path) < 0) {
        write_debug_file(argv[0], "The NPFCTL is not accessible");
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }

    char *exec_cmd1[3] = { npfctl_path, "show", NULL };

    wfd_t *wfd = wpopenv(npfctl_path, exec_cmd1, W_BIND_STDOUT);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", npfctl_path, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }

    int flag = false;
    while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
        const char *pos = strstr(output_buf, "filtering:");

        if (pos != NULL) {
            char state[15];

            if (pos && sscanf(pos, "%*s %9s", state) == 1) {
                if (strcmp(state, "active") != 0) {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR -1, "The filter property is inactive");
                    write_debug_file(argv[0], log_msg);
                    cJSON_Delete(input_json);
                    wpclose(wfd);
                    os_free(npfctl_path);
                    return OS_INVALID;
                }
                flag = true;
                break;
            } else {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Key word not found");
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                wpclose(wfd);
                os_free(npfctl_path);
                return OS_INVALID;
            }
        }
    }
    wpclose(wfd);

    if (flag == false) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to find 'filtering'");
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }

    wfd = wpopenv(npfctl_path, exec_cmd1, W_BIND_STDOUT);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", npfctl_path, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }

    flag = false;
    while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
        const char *pos = strstr(output_buf, "table <wazuh_blacklist>");

        if (pos != NULL) {
            flag = true;
            break;
        }
    }
    wpclose(wfd);

    if (flag == false) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to find 'table <wazuh_blacklist>'");
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }

    char *exec_cmd2[6] = { NULL, NULL, NULL, NULL, NULL, NULL };

    if (action == ADD_COMMAND) {
        const char *arg3[6] = { npfctl_path, "table", "wazuh_blacklist", "add", srcip, NULL };
        memcpy(exec_cmd2, arg3, sizeof(exec_cmd2));
    } else {
        const char *arg3[6] = { npfctl_path, "table", "wazuh_blacklist", "del", srcip, NULL };
        memcpy(exec_cmd2, arg3, sizeof(exec_cmd2));
    }

    // Executing it
    wfd = wpopenv(npfctl_path, exec_cmd2, W_BIND_STDOUT);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", npfctl_path, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(npfctl_path);
        return OS_INVALID;
    }
    wpclose(wfd);

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);
    os_free(npfctl_path);

    return OS_SUCCESS;
}
