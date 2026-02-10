/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define LOCK_PATH "active-response/bin/fw-drop"
#define LOCK_FILE "active-response/bin/fw-drop/pid"

int main (int argc, char **argv) {
    (void)argc;
    char rule[COMMANDSIZE_4096];
    char log_msg[OS_MAXSTR];
    char lock_path[COMMANDSIZE_4096];
    char lock_pid_path[COMMANDSIZE_4096];
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

    int ip_version = get_ip_version(srcip);
    memset(rule, '\0', COMMANDSIZE_4096);
    if (ip_version == 4) {
        snprintf(rule, COMMANDSIZE_4096 -1, "rule family=ipv4 source address=%s drop", srcip);
    } else if (ip_version == 6) {
        snprintf(rule, COMMANDSIZE_4096 -1, "rule family=ipv6 source address=%s drop", srcip);
    } else {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run active response (invalid IP: '%s').", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        char arg1[COMMANDSIZE_4096] = {0};
        char *fw_cmd_path = NULL;

        if (action == ADD_COMMAND) {
            strcpy(arg1, "--add-rich-rule");
        } else {
            strcpy(arg1, "--remove-rich-rule");
        }

        // Checking if firewall-cmd is present
        if (get_binary_path("firewall-cmd", &fw_cmd_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "The firewall-cmd file '%s' is not accessible: %s (%d)", fw_cmd_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(fw_cmd_path);
            return OS_INVALID;
        }

        memset(lock_path, '\0', COMMANDSIZE_4096);
        memset(lock_pid_path, '\0', COMMANDSIZE_4096);
        snprintf(lock_path, COMMANDSIZE_4096 - 1, "%s", LOCK_PATH);
        snprintf(lock_pid_path, COMMANDSIZE_4096 - 1, "%s", LOCK_FILE);

        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(fw_cmd_path);
            return OS_INVALID;
        }

        int count = 0;
        bool flag = true;
        while (flag) {
            char *exec_cmd1[4] = { fw_cmd_path, arg1, rule, NULL };

            wfd_t *wfd = wpopenv(fw_cmd_path, exec_cmd1, W_BIND_STDERR);
            if (wfd) {
                int wp_closefd = wpclose(wfd);
                if ( WIFEXITED(wp_closefd) ) {
                    int wstatus = WEXITSTATUS(wp_closefd);
                    if (wstatus == 0) {
                        flag = false;
                    }
                }
            }
            if (flag) {
                count++;
                if (count > 4) {
                    flag = false;
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR -1, "Unable to run firewall-cmd, action: '%s', rule: '%s'", arg1, rule);
                    write_debug_file(argv[0], log_msg);
                } else {
                    sleep(count);
                }
            }
        }
        unlock(lock_path, argv[0]);
        os_free(fw_cmd_path);
    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
