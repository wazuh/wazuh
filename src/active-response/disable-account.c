/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
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
    char args[COMMANDSIZE];
    char log_msg[LOGSIZE];
    char *action;
    char *user;
    char *command_ex;
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

    // Detect username
    user = get_username_from_json(input_json);
    if (!user) {
        write_debug_file(argv[0], "Cannot read 'dstuser' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("root", user)) {
        write_debug_file(argv[0], "Invalid username");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname)) {
        // Checking if passwd is present
        if (access(PASSWD, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The passwd file '%s' is not accessible: %s (%d)", PASSWD, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        os_strdup(PASSWD, command_ex);
        memset(args, '\0', COMMANDSIZE);
        if (!strcmp("add", action)) {
            snprintf(args, COMMANDSIZE -1, "-l");
        } else {
            snprintf(args, COMMANDSIZE -1, "-u");
        }

    } else if (!strcmp("AIX", uname_buffer.sysname)) {
        // Checking if chuser is present
        if (access(CHUSER, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The chuser file '%s' is not accessible: %s (%d)", CHUSER, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        os_strdup(CHUSER, command_ex);
        // Disabling an account
        memset(args, '\0', COMMANDSIZE);
        if (!strcmp("add", action)) {
            snprintf(args, COMMANDSIZE -1, "account_locked=true");
        } else {
            snprintf(args, COMMANDSIZE -1, "account_locked=false");
        }

    } else {
        write_debug_file(argv[0], "Invalid system");
        cJSON_Delete(input_json);
        return OS_SUCCESS;
    }

    // Execute the command
    char *exec_cmd[4] = { command_ex, args, user, NULL };
    wfd_t *wfd = NULL;
    if (wfd = wpopenv(*exec_cmd, exec_cmd, W_BIND_STDERR), !wfd) {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE -1, "Error executing '%s': %s", command_ex, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(command_ex);
        return OS_INVALID;
    }
    wpclose(wfd);

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);
    os_free(command_ex);

    return OS_SUCCESS;
}
