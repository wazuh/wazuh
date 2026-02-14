/* Copyright (C) 2015, Wazuh Inc.
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
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
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

    char srcip_path[COMMANDSIZE_4096];
    strcpy(srcip_path, IPBLOCK);
    strncat(srcip_path, srcip, (COMMANDSIZE_4096 - strlen(IPBLOCK)) - 1);

    if (action == ADD_COMMAND) {
        // Create directory
        if (mkdir_ex(IPBLOCK)) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Error executing '%s' : %s", IPBLOCK, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        FILE *fp = wfopen(srcip_path, "a");
        if(fp == NULL) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Error creating %s file", srcip_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
        fclose(fp);

    } else {
        if(remove(srcip_path) != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Error deleting %s file", srcip_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
