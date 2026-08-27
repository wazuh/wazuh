/* Copyright (C) 2015, Wazuh Inc.
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
    char args[COMMANDSIZE_4096];
    char *cmd_path = NULL;
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    int end_of_options = 0;
    cJSON *input_json = NULL;
    struct utsname uname_buffer;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Detect username (now validated automatically by get_username_from_json)
    const char *user = get_username_from_json(input_json);
    if (!user) {
        write_debug_file(argv[0], "Cannot read 'dstuser' from data or invalid username format");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (action == ADD_COMMAND) {
        char **keys = NULL;
        int action2 = OS_INVALID;

        os_calloc(2, sizeof(char *), keys);
        os_strdup(user, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);

        os_free(keys[0]);
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

    if (!strcmp("Linux", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname)) {
        // passwd parses options with getopt, so the username must be delimited
        end_of_options = 1;

        // Checking if passwd is present
        if (get_binary_path("passwd", &cmd_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The passwd file '%s' is not accessible: %s (%d)", cmd_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(cmd_path);
            return OS_INVALID;
        }

        memset(args, '\0', COMMANDSIZE_4096);
        if (action == ADD_COMMAND) {
            snprintf(args, COMMANDSIZE_4096 -1, "-l");
        } else {
            snprintf(args, COMMANDSIZE_4096 -1, "-u");
        }

    } else if (!strcmp("AIX", uname_buffer.sysname)) {
        // Checking if chuser is present
        if (get_binary_path("chuser", &cmd_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The chuser file '%s' is not accessible: %s (%d)", cmd_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(cmd_path);
            return OS_INVALID;
        }

        // Disabling an account
        memset(args, '\0', COMMANDSIZE_4096);
        if (action == ADD_COMMAND) {
            snprintf(args, COMMANDSIZE_4096 -1, "account_locked=true");
        } else {
            snprintf(args, COMMANDSIZE_4096 -1, "account_locked=false");
        }

    } else {
        write_debug_file(argv[0], "Invalid system");
        cJSON_Delete(input_json);
        return OS_SUCCESS;
    }

    // Execute the command
    char *exec_cmd1[5];
    int argc_cmd = 0;

    exec_cmd1[argc_cmd++] = cmd_path;
    exec_cmd1[argc_cmd++] = args;
    if (end_of_options) {
        exec_cmd1[argc_cmd++] = "--";
    }
    exec_cmd1[argc_cmd++] = (char *)user;
    exec_cmd1[argc_cmd] = NULL;

    wfd_t *wfd = wpopenv(cmd_path, exec_cmd1, W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Error executing '%s': %s", cmd_path, strerror(errno));
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(cmd_path);
        return OS_INVALID;
    }
    // Keep the first diagnostic line, then drain to EOF: wpclose() closes the read
    // end before waiting, so output left buffered would give the child a SIGPIPE
    // and make a successful command look like a failure. The drain runs
    // unconditionally, since the first read may fail without reaching EOF.
    char cmd_output[OS_SIZE_1024];
    char discarded[OS_SIZE_1024];
    memset(cmd_output, '\0', OS_SIZE_1024);
    if (fgets(cmd_output, OS_SIZE_1024, wfd->file_out)) {
        char *newline = strchr(cmd_output, '\n');
        if (newline) {
            *newline = '\0';
        }
    }
    while (fgets(discarded, OS_SIZE_1024, wfd->file_out)) {
        continue;
    }

    int wp_closefd = wpclose(wfd);
    if (!WIFEXITED(wp_closefd) || WEXITSTATUS(wp_closefd) != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        if (WIFEXITED(wp_closefd)) {
            snprintf(log_msg, OS_MAXSTR -1, "Command '%s' failed to %s the account '%s' (exit code %d): %s",
                     cmd_path, action == ADD_COMMAND ? "disable" : "enable", user,
                     WEXITSTATUS(wp_closefd), cmd_output);
        } else {
            snprintf(log_msg, OS_MAXSTR -1, "Command '%s' terminated abnormally while trying to %s the account '%s': %s",
                     cmd_path, action == ADD_COMMAND ? "disable" : "enable", user, cmd_output);
        }
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        os_free(cmd_path);
        return OS_INVALID;
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);
    os_free(cmd_path);

    return OS_SUCCESS;
}
