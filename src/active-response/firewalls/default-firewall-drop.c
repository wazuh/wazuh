/* Copyright (C) 2015, Wazuh Inc.
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
#define IP4TABLES "iptables"
#define IP6TABLES "ip6tables"

int main (int argc, char **argv) {
    (void)argc;
    char iptables_tmp[COMMANDSIZE_4096 - 5] = "";
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

    int ip_version = get_ip_version(srcip);
    if (ip_version == 4) {
        strcpy(iptables_tmp, IP4TABLES);
    } else if (ip_version == 6) {
        strcpy(iptables_tmp, IP6TABLES);
    } else {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run active response (invalid IP: '%s').", srcip);
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
        char lock_path[COMMANDSIZE_4096];
        char lock_pid_path[COMMANDSIZE_4096];
        char *iptables = NULL;
        wfd_t *wfd = NULL;

        // Checking if iptables is present
        if (get_binary_path(iptables_tmp, &iptables) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "The iptables file '%s' is not accessible: %s (%d)", iptables, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(iptables);
            return OS_SUCCESS;
        }

        char arg[3] = {0};
        if (action == ADD_COMMAND) {
            strcpy(arg, "-I");
        } else {
            strcpy(arg, "-D");
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
            os_free(iptables);
            return OS_INVALID;
        }

        int count = 0;
        bool flag = true;
        while (flag) {
            char *exec_cmd1[8] = { iptables, arg, "INPUT", "-s", (char *)srcip, "-j", "DROP", NULL };

            wfd = wpopenv(iptables, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                count++;
                if (count > 4) {
                    flag = false;
                    write_debug_file(argv[0], "Unable to run iptables");
                } else {
                    sleep(count);
                }
            } else {
                flag = false;
                wpclose(wfd);
            }
        }

        count = 0;
        flag = true;
        while (flag) {
            char *exec_cmd2[8] = { iptables, arg, "FORWARD", "-s", (char *)srcip, "-j", "DROP", NULL };

            wfd = wpopenv(iptables, exec_cmd2, W_BIND_STDERR);
            if (!wfd) {
                count++;
                if (count > 4) {
                    flag = false;
                    write_debug_file(argv[0], "Unable to run iptables");
                } else {
                    sleep(count);
                }
            } else {
                flag = false;
                wpclose(wfd);
            }
        }
        unlock(lock_path, argv[0]);
        os_free(iptables);

    } else if (!strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname) || !strcmp("NetBSD", uname_buffer.sysname)) {
        char arg1[COMMANDSIZE_4096];
        char arg2[COMMANDSIZE_4096];
        char ipfarg[COMMANDSIZE_4096];
        char *ipfilter_path = NULL;
        wfd_t *wfd = NULL;

        // Checking if ipfilter is present
        if (get_binary_path("ipf", &ipfilter_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The ipfilter file '%s' is not accessible: %s (%d)", ipfilter_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(ipfilter_path);
            return OS_SUCCESS;
        }

        memset(arg1, '\0', COMMANDSIZE_4096);
        memset(arg2, '\0', COMMANDSIZE_4096);
        memset(ipfarg, '\0', COMMANDSIZE_4096);

        snprintf(arg1, COMMANDSIZE_4096 -1, "block out quick from any to %s", srcip);
        snprintf(arg2, COMMANDSIZE_4096 -1, "block in quick from %s to any", srcip);
        if (action == ADD_COMMAND) {
            snprintf(ipfarg, COMMANDSIZE_4096 -1,"-f");
        } else {
            snprintf(ipfarg, COMMANDSIZE_4096 -1,"-rf");
        }

        char *exec_cmd1[4] = { ipfilter_path, ipfarg, "-", NULL };

        wfd = wpopenv(ipfilter_path, exec_cmd1, W_BIND_STDIN);
        if (!wfd) {
            write_debug_file(argv[0], "Unable to run ipf");
        } else {
            fprintf(wfd->file_in, "%s\n", arg1);
            fflush(wfd->file_in);
            wpclose(wfd);
        }

        wfd = wpopenv(ipfilter_path, exec_cmd1, W_BIND_STDIN);
        if (!wfd) {
            write_debug_file(argv[0], "Unable to run ipf");
        } else {
            fprintf(wfd->file_in, "%s\n", arg2);
            fflush(wfd->file_in);
            wpclose(wfd);
        }
        os_free(ipfilter_path);

    } else if (!strcmp("AIX", uname_buffer.sysname)) {
        char *genfilt_path = NULL;
        char *lsfilt_path = NULL;
        char *mkfilt_path = NULL;
        char *rmfilt_path = NULL;
        wfd_t *wfd = NULL;

        // Checking if genfilt is present
        if (get_binary_path("genfilt", &genfilt_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The genfilt file '%s' is not accessible: %s (%d)", genfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(genfilt_path);
            return OS_SUCCESS;
        }

        // Checking if lsfilt is present
        if (get_binary_path("lsfilt", &lsfilt_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The lsfilt file '%s' is not accessible: %s (%d)", lsfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(genfilt_path);
            os_free(lsfilt_path);
            return OS_SUCCESS;
        }

        // Checking if mkfilt is present
        if (get_binary_path("mkfilt", &mkfilt_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The mkfilt file '%s' is not accessible: %s (%d)", mkfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(genfilt_path);
            os_free(lsfilt_path);
            os_free(mkfilt_path);
            return OS_SUCCESS;
        }

        // Checking if rmfilt is present
        if (get_binary_path("rmfilt", &rmfilt_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "The rmfilt file '%s' is not accessible: %s (%d)", rmfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            os_free(genfilt_path);
            os_free(lsfilt_path);
            os_free(mkfilt_path);
            os_free(rmfilt_path);
            return OS_SUCCESS;
        }

        if (action == ADD_COMMAND) {
            char *exec_cmd1[18] = { genfilt_path, "-v", "4", "-a", "D", "-s", (char *)srcip, "-m", "255.255.255.255", "-d", "0.0.0.0", "-M", "0.0.0.0", "-w", "B", "-D", "\"Access Denied by WAZUH\"", NULL };

            wfd = wpopenv(genfilt_path, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run genfilt");
            } else {
                wpclose(wfd);
            }
        } else {
            char *exec_cmd1[5] = { lsfilt_path, "-v", "4", "-O", NULL };

            wfd = wpopenv(lsfilt_path, exec_cmd1, W_BIND_STDOUT);
            if (!wfd) {
                write_debug_file(argv[0], "Unable to run lsfilt");
            } else {
                char output_buf[OS_MAXSTR];
                while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
                    if (strstr(output_buf, srcip) != NULL) {
                        // Removing a specific rule
                        char *rule_str = strtok(output_buf, "|");
                        char *exec_cmd2[6] = { rmfilt_path, "-v", "4", "-n", rule_str, NULL };

                        wfd_t *wfd2 = wpopenv(rmfilt_path, exec_cmd2, W_BIND_STDERR);
                        if (!wfd2) {
                            write_debug_file(argv[0], "Unable to run rmfilt");
                        } else {
                            wpclose(wfd2);
                        }
                    }
                }
                wpclose(wfd);
            }
        }

        // Deactivate and activate the filter rules
        char *exec_cmd3[5] = { mkfilt_path, "-v", "4", "-d", NULL };

        wfd = wpopenv(mkfilt_path, exec_cmd3, W_BIND_STDERR);
        if (!wfd) {
            write_debug_file(argv[0], "Unable to run mkfilt");
        } else {
            wpclose(wfd);
        }

        char *exec_cmd4[5] = { mkfilt_path, "-v", "4", "-u", NULL };

        wfd = wpopenv(mkfilt_path, exec_cmd4, W_BIND_STDERR);
        if (!wfd) {
            write_debug_file(argv[0], "Unable to run mkfilt");
        } else {
            wpclose(wfd);
        }

        os_free(genfilt_path);
        os_free(lsfilt_path);
        os_free(mkfilt_path);
        os_free(rmfilt_path);

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
