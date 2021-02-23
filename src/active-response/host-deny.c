/* Copyright (C) 2015-2021, Wazuh Inc.
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
    char *srcip;
    char *action;
    char input[BUFFERSIZE];
    char hosts_deny_rule[COMMANDSIZE];
    char log_msg[LOGSIZE];
    char lock_path[PATH_MAX];
    char lock_pid_path[PATH_MAX];
    char output_buf[BUFFERSIZE];
    cJSON *input_json = NULL;
    struct utsname uname_buffer;
    char hosts_deny_path[PATH_MAX];
    FILE *host_deny_fp = NULL;
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

    if (!strstr(srcip, ".") && !strstr(srcip, ":")) {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE -1, "Unable to run active response (invalid IP: '%s')", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    memset(hosts_deny_rule, '\0', COMMANDSIZE);
    memset(hosts_deny_path, '\0', PATH_MAX);
    if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        snprintf(hosts_deny_rule, COMMANDSIZE -1, "ALL : %s : deny", srcip);
        strcpy(hosts_deny_path, FREEBSD_HOSTS_DENY_PATH);
    } else {
        snprintf(hosts_deny_rule, COMMANDSIZE -1, "ALL:%s", srcip);
        strcpy(hosts_deny_path, DEFAULT_HOSTS_DENY_PATH);
    }

    memset(lock_path, '\0', PATH_MAX);
    memset(lock_pid_path, '\0', PATH_MAX);
    snprintf(lock_path, PATH_MAX - 1, "%s", LOCK_PATH);
    snprintf(lock_pid_path, PATH_MAX - 1, "%s", LOCK_FILE);

    if (!strcmp("add", action)) {
        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        host_deny_fp = fopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        // Looking for duplication
        memset(output_buf, '\0', BUFFERSIZE);
        while (fgets(output_buf, BUFFERSIZE, host_deny_fp)) {
            if (strstr(output_buf, srcip) != NULL) {
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE -1, "IP %s already exists on '%s'", srcip, hosts_deny_path);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                fclose(host_deny_fp);
                unlock(lock_path, argv[0]);
                return OS_INVALID;
            }
        }
        fclose(host_deny_fp);

        // Open again to append rule
        host_deny_fp = fopen(hosts_deny_path, "a");
        if (!host_deny_fp) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        if (fprintf(host_deny_fp, "%s\n", hosts_deny_rule) <= 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to write rule '%s' on '%s'", hosts_deny_rule, hosts_deny_path);
            write_debug_file(argv[0], log_msg);
        }
        fclose(host_deny_fp);

        unlock(lock_path, argv[0]);

    } else {
        FILE *temp_host_deny_fp = NULL;
        char temp_hosts_deny_path[PATH_MAX];

        memset(temp_hosts_deny_path, '\0', PATH_MAX);
        snprintf(temp_hosts_deny_path, PATH_MAX - 1, "%s", "active-response/bin/temp-hosts-deny");

        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        bool write_fail = false;

        host_deny_fp = fopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Could not open file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        // Create the temporary file
        temp_host_deny_fp = fopen(temp_hosts_deny_path, "w");
        if (!temp_host_deny_fp) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Could not open file '%s'", temp_hosts_deny_path);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            fclose(host_deny_fp);
            unlock(lock_path, argv[0]);
            return OS_INVALID;
        }

        memset(output_buf, '\0', BUFFERSIZE);
        while (fgets(output_buf, BUFFERSIZE, host_deny_fp)) {
            if (strstr(output_buf, srcip) == NULL) {
                if (fwrite(output_buf, 1, strlen(output_buf), temp_host_deny_fp) != strlen(output_buf)) {
                    memset(log_msg, '\0', LOGSIZE);
                    snprintf(log_msg, LOGSIZE -1, "Unable to write line '%s'", output_buf);
                    write_debug_file(argv[0], log_msg);
                    write_fail = true;
                    break;
                }
            }
            memset(output_buf, '\0', BUFFERSIZE);
        }

        fclose(host_deny_fp);
        fclose(temp_host_deny_fp);

        if (write_fail || rename(temp_hosts_deny_path, hosts_deny_path) != 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to write file '%s'", hosts_deny_path);
            write_debug_file(argv[0], log_msg);
        }

        unlink(temp_hosts_deny_path);
        unlock(lock_path, argv[0]);
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
