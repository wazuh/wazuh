/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define PYTHON2             "/usr/bin/python"
#define PYTHON3             "/usr/bin/python3"
#define PATH_TO_KASPERSKY   "active-response/bin/kaspersky.py"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char log_msg[LOGSIZE];
    char *extra_args;
    cJSON *input_json = NULL;
    struct stat file_status;
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

    // Get extra_args
    extra_args = get_extra_args_from_json(input_json);
    if (!extra_args) {
        write_debug_file(argv[0], "Cannot read 'extra_args' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!stat(PYTHON2, &file_status)) {
        char *exec_cmd[4] = {"python", PATH_TO_KASPERSKY, extra_args, NULL};
        wfd_t *wfd = wpopenv(exec_cmd[0], exec_cmd, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error executing 'python' : %s", strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(extra_args);
            return OS_INVALID;
        }
        wpclose(wfd);

    } else if (!stat(PYTHON3, &file_status)) {
        char *exec_cmd[4] = {"python3", PATH_TO_KASPERSKY, extra_args, NULL};
        wfd_t *wfd = wpopenv(exec_cmd[0], exec_cmd, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error executing 'python3' : %s", strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(extra_args);
            return OS_INVALID;
        }
        wpclose(wfd);

    } else {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE - 1, "Python binary not found");
        write_debug_file(argv[0], log_msg);
    }

    cJSON_Delete(input_json);
    os_free(extra_args);

    write_debug_file(argv[0], "Ended");

    return OS_SUCCESS;
}
