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
    char iptables[COMMANDSIZE];
    char log_msg[LOGSIZE];
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
        wfd_t *wfd = NULL;

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
        if (action == ADD_COMMAND) {
            strcpy(arg, "-I");
        } else {
            strcpy(arg, "-D");
        }

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
            char *exec_cmd1[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

            const char *arg1[8] = { iptables, arg, "INPUT", "-s", srcip, "-j", "DROP", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

            wfd = wpopenv(iptables, exec_cmd1, W_BIND_STDERR);
            if (!wfd) {
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
            char *exec_cmd2[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

            const char *arg2[8] = { iptables, arg, "FORWARD", "-s", srcip, "-j", "DROP", NULL };
            memcpy(exec_cmd2, arg2, sizeof(exec_cmd2));

            wfd = wpopenv(iptables, exec_cmd2, W_BIND_STDERR);
            if (!wfd) {
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
        wfd_t *wfd = NULL;

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
        if (action == ADD_COMMAND) {
            snprintf(ipfarg, COMMANDSIZE -1,"-f");
        } else {
            snprintf(ipfarg, COMMANDSIZE -1,"-rf");
        }

        char *exec_cmd1[4] = { ipfilter_path, ipfarg, "-", NULL };
        char *exec_cmd2[4] = { ipfilter_path, ipfarg, "-", NULL };

        wfd = wpopenv(ipfilter_path, exec_cmd1, W_BIND_STDIN);
        if (!wfd) {
            write_debug_file(argv[0], "Unable to run ipf");
        } else {
            fprintf(wfd->file_in, "%s\n", arg1);
            fflush(wfd->file_in);
            wpclose(wfd);
        }

        wfd = wpopenv(ipfilter_path, exec_cmd2, W_BIND_STDIN);
        if (!wfd) {
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
        wfd_t *wfd = NULL;

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

        if (action == ADD_COMMAND) {
            char *exec_cmd1[18] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

            const char *arg1[18] = { genfilt_path, "-v", "4", "-a", "D", "-s", srcip, "-m", "255.255.255.255", "-d", "0.0.0.0", "-M", "0.0.0.0", "-w", "B", "-D", "\"Access Denied by WAZUH\"", NULL };
            memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

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
                char output_buf[BUFFERSIZE];
                while (fgets(output_buf, BUFFERSIZE, wfd->file_out)) {
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

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
