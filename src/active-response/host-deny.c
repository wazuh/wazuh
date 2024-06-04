/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define LOCK_PATH "active-response/bin/host-deny-lock"
#define LOCK_FILE "active-response/bin/host-deny-lock/pid"
#define DEFAULT_HOSTS_DENY_PATH "/etc/hosts.deny"
#define FREEBSD_HOSTS_DENY_PATH "/etc/hosts.allow"

int main (int argc, char **argv) {
    (void)argc;
    char hosts_deny_rule[COMMANDSIZE_4096];
    char hosts_deny_path[COMMANDSIZE_4096];
    char log_msg[OS_MAXSTR];
    char lock_path[COMMANDSIZE_4096];
    char lock_pid_path[COMMANDSIZE_4096];
    char output_buf[OS_MAXSTR - 25];
    int action = OS_INVALID;
    cJSON *input_json = NULL;
    struct utsname uname_buffer;
    FILE *host_deny_fp = NULL;

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

    if (get_ip_version(srcip) == OS_INVALID) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run active response (invalid IP: '%s')", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    memset(hosts_deny_rule, '\0', COMMANDSIZE_4096);
    memset(hosts_deny_path, '\0', COMMANDSIZE_4096);
    if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        snprintf(hosts_deny_rule, COMMANDSIZE_4096 -1, "ALL : %s : deny", srcip);
        strcpy(hosts_deny_path, FREEBSD_HOSTS_DENY_PATH);
    } else {
        snprintf(hosts_deny_rule, COMMANDSIZE_4096 -1, "ALL:%s", srcip);
        strcpy(hosts_deny_path, DEFAULT_HOSTS_DENY_PATH);
    }

    memset(lock_path, '\0', COMMANDSIZE_4096);
    memset(lock_pid_path, '\0', COMMANDSIZE_4096);
    snprintf(lock_path, COMMANDSIZE_4096 - 1, "%s", LOCK_PATH);
    snprintf(lock_pid_path, COMMANDSIZE_4096 - 1, "%s", LOCK_FILE);

    if (action == ADD_COMMAND) {
        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        host_deny_fp = wfopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        // Looking for duplication
        memset(output_buf, '\0', OS_MAXSTR - 25);
        while (fgets(output_buf, OS_MAXSTR - 25, host_deny_fp)) {
            if (strstr(output_buf, srcip) != NULL) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "IP %s already exists on '%s'", srcip, hosts_deny_path);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                fclose(host_deny_fp);
                unlock(lock_path, argv[0]);
                return OS_INVALID;
            }
        }
        fclose(host_deny_fp);

        // Open again to append rule
        host_deny_fp = wfopen(hosts_deny_path, "a");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        if (fprintf(host_deny_fp, "%s\n", hosts_deny_rule) <= 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to write rule '%s' on '%s'", hosts_deny_rule, hosts_deny_path);
            write_debug_file(argv[0], log_msg);
        }
        fclose(host_deny_fp);

        unlock(lock_path, argv[0]);

    } else {
        FILE *temp_host_deny_fp = NULL;
        char temp_hosts_deny_path[COMMANDSIZE_4096];

        memset(temp_hosts_deny_path, '\0', COMMANDSIZE_4096);
        snprintf(temp_hosts_deny_path, COMMANDSIZE_4096 - 1, "%s", "active-response/bin/temp-hosts-deny");

        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        bool write_fail = false;

        host_deny_fp = wfopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        // Create the temporary file
        temp_host_deny_fp = wfopen(temp_hosts_deny_path, "w");
        if (!temp_host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Could not open file '%s'", temp_hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            fclose(host_deny_fp);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        memset(output_buf, '\0', OS_MAXSTR - 25);
        while (fgets(output_buf, OS_MAXSTR - 25, host_deny_fp)) {
            if (strstr(output_buf, srcip) == NULL) {
                if (fwrite(output_buf, 1, strlen(output_buf), temp_host_deny_fp) != strlen(output_buf)) {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR -1, "Unable to write line '%s'", output_buf);
                    write_debug_file(argv[0], log_msg);
                    write_fail = true;
                    break;
                }
            }
            memset(output_buf, '\0', OS_MAXSTR - 25);
        }

        fclose(host_deny_fp);
        fclose(temp_host_deny_fp);

        if (write_fail || rename(temp_hosts_deny_path, hosts_deny_path) != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to write file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
        }

        unlink(temp_hosts_deny_path);
        unlock(lock_path, argv[0]);
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
