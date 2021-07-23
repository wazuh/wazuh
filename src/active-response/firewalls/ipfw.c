/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

#define IPFW "/sbin/ipfw"
#define TABLE_ID "00001"
#define SET_ID "2"

int main (int argc, char **argv) {
    (void)argc;
    char *srcip;
    char *action;
    char input[BUFFERSIZE];
    char log_msg[LOGSIZE];
    cJSON *input_json = NULL;
    struct utsname uname_buffer;
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

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        bool add_table = true;
        wfd_t *wfd = NULL;

        // Checking if ipfw is present
        if (access(IPFW, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The ipfw file '%s' is not accessible: %s (%d)", IPFW, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        char table_name[COMMANDSIZE];
        memset(table_name, '\0', COMMANDSIZE);
        snprintf(table_name, COMMANDSIZE - 1, "table(%s)", TABLE_ID);

        char *command_ex_1[3] = { IPFW, "show", NULL };
        if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDOUT), wfd) {
            char output_buf[BUFFERSIZE];
            while (fgets(output_buf, BUFFERSIZE, wfd->file)) {
                if ((strncmp(output_buf, TABLE_ID, 5) == 0) && (strstr(output_buf, table_name) != NULL)) {
                    add_table = false;
                    break;
                }
            }
            wpclose(wfd);
        } else {
            write_debug_file(argv[0], "Unable to run ipfw");
        }

        if (add_table) {
            char *command_ex_2[11] = { IPFW, "-q", TABLE_ID, "add", "deny", "ip", "from", table_name, "to", "any", NULL };
            char *command_ex_3[11] = { IPFW, "-q", TABLE_ID, "add", "deny", "ip", "from", "any", "to", table_name, NULL };

            wfd_t *wfd = NULL;
            if (wfd = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run ipfw");
            } else {
                wpclose(wfd);
            }

            if (wfd = wpopenv(*command_ex_3, command_ex_3, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run ipfw");
            } else {
                wpclose(wfd);
            }
        }

        // Execute the command
        char *command_ex_4[7] = { IPFW, "-q", "table", TABLE_ID, action, srcip, NULL };
        if (wfd = wpopenv(*command_ex_4, command_ex_4, W_BIND_STDERR), !wfd) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Error executing '%s': %s", IPFW, strerror(errno));
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }
        wpclose(wfd);

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
