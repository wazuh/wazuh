/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define PATH_TO_KASPERSKY   "active-response/bin/kaspersky.py"

int main (int argc, char **argv) {
    (void)argc;
    char log_msg[OS_MAXSTR];
    char *python_path = NULL;
    char *extra_args = NULL;
    int action = OS_INVALID;
    cJSON *input_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get extra_args
    extra_args = get_extra_args_from_json(input_json);
    if (!extra_args) {
        write_debug_file(argv[0], "Cannot read 'extra_args' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (get_binary_path("python", &python_path) < 0) {
        os_free(python_path);
        if (get_binary_path("python3", &python_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Python binary not found");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(extra_args);
            os_free(python_path);
            return OS_INVALID;
        }
    }

    char *exec_cmd[4] = {python_path, PATH_TO_KASPERSKY, extra_args, NULL};
    wfd_t *wfd = wpopenv(exec_cmd[0], exec_cmd, W_BIND_STDOUT);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", python_path, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(extra_args);
        os_free(python_path);
        return OS_INVALID;
    }
    wpclose(wfd);

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);
    os_free(extra_args);
    os_free(python_path);

    return OS_SUCCESS;
}
