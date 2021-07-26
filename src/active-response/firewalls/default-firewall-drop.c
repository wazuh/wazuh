/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../active_responses.h"

#define LOCK_PATH "active-response/bin/fw-drop"
#define LOCK_FILE "active-response/bin/fw-drop/pid"
#define IP4TABLES "/sbin/iptables"
#define IP6TABLES "/sbin/ip6tables"

int main (int argc, char **argv) {
    (void)argc;
    char *srcip;
    char *action;
    char iptables[COMMANDSIZE];
    char input[BUFFERSIZE];
    char log_msg[LOGSIZE];
    char *home_path = w_homedir(argv[0]);
    cJSON *input_json = NULL;
    struct utsname uname_buffer;

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

    int ip_version = get_ip_version(srcip);
    memset(iptables, '\0', COMMANDSIZE);
    if (ip_version == 4) {
        strcpy(iptables, IP4TABLES);
    } else if (ip_version == 6) {
        strcpy(iptables, IP6TABLES);
    } else {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE -1, "Unable to run active response (invalid IP: '%s').", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) < 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        char lock_path[PATH_MAX];
        char lock_pid_path[PATH_MAX];

        // Checking if iptables is present
        if (access(iptables, F_OK) < 0) {
            char iptables_path[PATH_MAX];
            memset(iptables_path, '\0', PATH_MAX);
            snprintf(iptables_path, PATH_MAX - 1, "/usr%s", iptables);
            if (access(iptables_path, F_OK) < 0) {
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE -1, "The iptables file '%s' is not accessible: %s (%d)", iptables_path, strerror(errno), errno);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return OS_SUCCESS;
            }
            memset(iptables, '\0', COMMANDSIZE);
            strncpy(iptables, iptables_path, COMMANDSIZE - 1);
        }

        char arg[3];
        memset(arg, '\0', 3);
        if (!strcmp("add", action)) {
            strcpy(arg, "-I");
        } else {
            strcpy(arg, "-D");
        }

        char *command_ex_1[8] = {iptables, arg, "INPUT", "-s", srcip, "-j", "DROP", NULL};
        char *command_ex_2[8] = {iptables, arg, "FORWARD", "-s", srcip, "-j", "DROP", NULL};

        memset(lock_path, '\0', PATH_MAX);
        memset(lock_pid_path, '\0', PATH_MAX);
        snprintf(lock_path, PATH_MAX - 1, "%s", LOCK_PATH);
        snprintf(lock_pid_path, PATH_MAX - 1, "%s", LOCK_FILE);

        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        int count = 0;
        bool flag = true;
        while (flag) {
            wfd_t *wfd = NULL;
            if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDERR), !wfd) {
                count++;
                write_debug_file(argv[0], "Unable to run iptables");
                sleep(count);

                if (count > 4) {
                    flag = false;
                }
            } else {
                flag = false;
                wpclose(wfd);
            }
        }

        count = 0;
        flag = true;
        while (flag) {
            wfd_t *wfd = NULL;
            if (wfd = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDERR), !wfd) {
                count++;
                write_debug_file(argv[0], "Unable to run iptables");
                sleep(count);

                if (count > 4) {
                    flag = false;
                }
            } else {
                flag = false;
                wpclose(wfd);
            }
        }
        unlock(lock_path, argv[0]);

    } else if (!strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname) || !strcmp("NetBSD", uname_buffer.sysname)) {
        char arg1[COMMANDSIZE];
        char arg2[COMMANDSIZE];
        char ipfarg[COMMANDSIZE];

        // Checking if ipfilter is present
        char ipfilter_path[PATH_MAX];
        memset(ipfilter_path, '\0', PATH_MAX);
        if (!strcmp("SunOS", uname_buffer.sysname)) {
            strcpy(ipfilter_path, "/usr/sbin/ipf");
        } else {
            strcpy(ipfilter_path, "/sbin/ipf");
        }

        if (access(ipfilter_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The ipfilter file '%s' is not accessible: %s (%d)", ipfilter_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        // Checking if echo is present
        if (access(ECHO, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The echo file '%s' is not accessible: %s (%d)", ECHO, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        memset(arg1, '\0', COMMANDSIZE);
        memset(arg2, '\0', COMMANDSIZE);
        memset(ipfarg, '\0', COMMANDSIZE);

        snprintf(arg1, COMMANDSIZE -1, "block out quick from any to %s", srcip);
        snprintf(arg2, COMMANDSIZE -1, "block in quick from %s to any", srcip);
        if (!strcmp("add", action)) {
            snprintf(ipfarg, COMMANDSIZE -1,"-f");
        } else {
            snprintf(ipfarg, COMMANDSIZE -1,"-rf");
        }

        char *command_ex_1[4] = {ipfilter_path, ipfarg, "-", NULL};
        char *command_ex_2[4] = {ipfilter_path, ipfarg, "-", NULL};

        wfd_t *wfd = NULL;
        if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDIN), !wfd) {
            write_debug_file(argv[0], "Unable to run ipf");
        } else {
            fprintf(wfd->file_in, "%s\n", arg1);
            fflush(wfd->file_in);
            wpclose(wfd);
        }

        if (wfd = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDIN), !wfd) {
            write_debug_file(argv[0], "Unable to run ipf");
        } else {
            fprintf(wfd->file_in, "%s\n", arg2);
            fflush(wfd->file_in);
            wpclose(wfd);
        }

    } else if (!strcmp("AIX", uname_buffer.sysname)) {
        char genfilt_path[20] = "/usr/sbin/genfilt";
        char lsfilt_path[20] = "/usr/sbin/lsfilt";
        char mkfilt_path[20] = "/usr/sbin/mkfilt";
        char rmfilt_path[20] = "/usr/sbin/rmfilt";

        // Checking if genfilt is present
        if (access(genfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The genfilt file '%s' is not accessible: %s (%d)", genfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        // Checking if lsfilt is present
        if (access(lsfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The lsfilt file '%s' is not accessible: %s (%d)", lsfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        // Checking if mkfilt is present
        if (access(mkfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The mkfilt file '%s' is not accessible: %s (%d)", mkfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        // Checking if rmfilt is present
        if (access(rmfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The rmfilt file '%s' is not accessible: %s (%d)", rmfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_SUCCESS;
        }

        if (!strcmp("add", action)) {
            wfd_t *wfd = NULL;
            char *command_ex_1[18] = {genfilt_path, "-v", "4", "-a", "D", "-s", srcip, "-m", "255.255.255.255", "-d", "0.0.0.0", "-M", "0.0.0.0", "-w", "B", "-D", "\"Access Denied by WAZUH\"", NULL};
            if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run genfilt");
            } else {
                wpclose(wfd);
            }

            // Deactivate and activate the filter rules.
            char *command_ex_2[5] = {mkfilt_path, "-v", "4", "-d", NULL};
            if (wfd = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run mkfilt");
            } else {
                wpclose(wfd);
            }

            char *command_ex_3[5] = {mkfilt_path, "-v", "4", "-u", NULL};
            if (wfd = wpopenv(*command_ex_3, command_ex_3, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run mkfilt");
            } else {
                wpclose(wfd);
            }
        } else {
            wfd_t *wfd = NULL;
            char *command_ex_1[5] = {lsfilt_path, "-v", "4", "-O", NULL};
            if (wfd = wpopenv(*command_ex_1, command_ex_1, W_BIND_STDOUT), wfd) {
                char output_buf[BUFFERSIZE];
                while (fgets(output_buf, BUFFERSIZE, wfd->file_out)) {
                    if (strstr(output_buf, srcip) != NULL) {
                        // removing a specific rule
                        wfd_t *wfd2 = NULL;
                        char *rule_str = strtok(output_buf, "|");
                        char *command_ex_2[6] = {rmfilt_path, "-v", "4", "-n", rule_str, NULL};
                        if (wfd2 = wpopenv(*command_ex_2, command_ex_2, W_BIND_STDERR), wfd2) {
                            wpclose(wfd2);
                        }
                    }
                }
                wpclose(wfd);
            } else {
                write_debug_file(argv[0], "Unable to run lsfilt");
            }

            // Deactivate and activate the filter rules.
            char *command_ex_3[5] = {mkfilt_path, "-v", "4", "-d", NULL};
            if (wfd = wpopenv(*command_ex_3, command_ex_3, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run mkfilt");
            } else {
                wpclose(wfd);
            }

            char *command_ex_4[5] = {mkfilt_path, "-v", "4", "-u", NULL};
            if (wfd = wpopenv(*command_ex_4, command_ex_4, W_BIND_STDERR), !wfd) {
                write_debug_file(argv[0], "Unable to run mkfilt");
            } else {
                wpclose(wfd);
            }
        }

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
