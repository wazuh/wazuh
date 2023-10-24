/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

#define TABLE_ID "00001"
#define SET_ID "2"

int main (int argc, char **argv) {
    (void)argc;
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    cJSON *input_json = NULL;
    struct utsname uname_buffer;

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

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        bool add_table = true;
        wfd_t *wfd = NULL;
        char *ipfw_path = NULL;

        // Checking if ipfw is present
        if (get_binary_path("ipfw", &ipfw_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The ipfw file '%s' is not accessible: %s (%d)", ipfw_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(ipfw_path);
            return OS_SUCCESS;
        }

        char table_name[COMMANDSIZE_4096];
        memset(table_name, '\0', COMMANDSIZE_4096);
        snprintf(table_name, COMMANDSIZE_4096 - 1, "table(%s)", TABLE_ID);

        char *exec_cmd1[3] = { ipfw_path, "show", NULL };

        wfd = wpopenv(ipfw_path, exec_cmd1, W_BIND_STDOUT);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", ipfw_path, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(ipfw_path);
            return OS_INVALID;
        }

        char output_buf[OS_MAXSTR];
        while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
            if ((strncmp(output_buf, TABLE_ID, 5) == 0) && (strstr(output_buf, table_name) != NULL)) {
                add_table = false;
                break;
            }
        }
        wpclose(wfd);

        if (add_table) {
            char *exec_cmd2[11] = { ipfw_path, "-q", TABLE_ID, "add", "deny", "ip", "from", table_name, "to", "any", NULL };
            char *exec_cmd3[11] = { ipfw_path, "-q", TABLE_ID, "add", "deny", "ip", "from", "any", "to", table_name, NULL };

            wfd = wpopenv(ipfw_path, exec_cmd2, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", ipfw_path, strerror(errno));
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                os_free(ipfw_path);
                return OS_INVALID;
            }
            wpclose(wfd);

            wfd = wpopenv(ipfw_path, exec_cmd3, W_BIND_STDERR);
            if (!wfd) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", ipfw_path, strerror(errno));
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                os_free(ipfw_path);
                return OS_INVALID;
            }
            wpclose(wfd);
        }

        char *exec_cmd4[7] = { ipfw_path, "-q", "table", TABLE_ID, (action == ADD_COMMAND) ? "add" : "delete", (char *)srcip, NULL };

        // Executing it
        wfd = wpopenv(ipfw_path, exec_cmd4, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", ipfw_path, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(ipfw_path);
            return OS_INVALID;
        }
        wpclose(wfd);
        os_free(ipfw_path);

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
