/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
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

#ifndef WIN32
    char log_msg[LOGSIZE];
    char *exec_cmd[3] = { "bin/wazuh-control", "restart", NULL};
    wfd_t *wfd = NULL;

    if (wfd = wpopenv(*exec_cmd, exec_cmd, W_BIND_STDERR), !wfd) {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE -1, "Error executing '%s': %s", *exec_cmd, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    while (waitpid(-1, NULL, 0) > 0);

    wpclose(wfd);
#else
    char cmd[OS_MAXSTR + 1];

    snprintf(cmd, OS_MAXSTR, "net stop Wazuh");
    system(cmd);

    snprintf(cmd, OS_MAXSTR, "net start Wazuh");
    system(cmd);
#endif

    write_debug_file(argv[0], "Ended");

	cJSON_Delete(input_json);

    return OS_SUCCESS;
}
