/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define IPBLOCK "/ipblock/"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char log_msg[LOGSIZE];
    char *action;
    char *srcip;
    cJSON *input_json = NULL;
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

    char srcip_path[BUFFERSIZE];
    strcpy(srcip_path, IPBLOCK);
    strncat(srcip_path, srcip, (BUFFERSIZE - strlen(IPBLOCK)) - 1);

    if (!strcmp("add", action)) {
        // Create directory
        if (mkdir_ex(IPBLOCK)) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error executing '%s' : %s", IPBLOCK, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        FILE *fp = fopen(srcip_path, "a");
        if(fp == NULL) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error creating %s file", srcip_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
        fclose(fp);

    } else {
        if(remove(srcip_path) != 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "Error deleting %s file", srcip_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
