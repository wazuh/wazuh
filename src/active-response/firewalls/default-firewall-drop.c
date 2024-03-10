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
#define NFTABLES "nft"

int main (int argc, char **argv) {
    (void)argc;
    // iptables specific command selection (it must be iptables for IPv4 and ip6tables for IPv6)
    char iptables_tmp[COMMANDSIZE_4096 - 5] = "";
    // log message buffer
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
        /* The behaviour for linux systems has changed with nftables compatibility. The active response
         * now follows this workflow :
         * 1. Try to find the ip(6)tables binary and perform the block
         * 2. Try to find the nftables binary, upsert the wazuh-agent inet table then perform the block
         * 3. Fail if we cannot find both binaries
         *
         * We must prioritize ip(6)tables over nftables as some compatibility modules exist (e.g. iptables-nft
         * under Debian). Some nftables concept unreachable in iptables, so we cannot use them while assuming
         * administrators did entirely migrate to nftables, especially when iptables-nft packages exist.
         * We should store the errno when checking if iptables can be found. If we cannot find ip(6)tables nor nftables,
         * providing extra debugging information for each binary is important.
         */

        // Following variables are both used for ip(6)tables and nftables
        char lock_path[COMMANDSIZE_4096] = "";
        char lock_pid_path[COMMANDSIZE_4096] = "";
        wfd_t *wfd = NULL;

        // Checking if iptables is present
        char *iptables = NULL;
        if (!get_binary_path(iptables_tmp, &iptables)) {
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
                snprintf(log_msg, OS_MAXSTR - 1, "Unable to take lock. End.");
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                os_free(iptables);
                return OS_INVALID;
            }

            int count = 0;
            bool flag = true;
            while (flag) {
                char *exec_cmd1[8] = {iptables, arg, "INPUT", "-s", (char *) srcip, "-j", "DROP", NULL};

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
                char *exec_cmd2[8] = {iptables, arg, "FORWARD", "-s", (char *) srcip, "-j", "DROP", NULL};

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
            return OS_SUCCESS;
        } else {
            // Store the iptables binary search errno for later, if we need to log it
            int iptables_errno = errno;
            // We do not really need the iptables variable as we already have the wanted binary string in iptables_tmp
            os_free(iptables);

            // Directly try to find nftables and handle the "no binary found" stuff, it's much easier to read
            char *nftables = NULL;
            if (get_binary_path(NFTABLES, &nftables) < 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1,
                         "Cannot find the iptables file '%s': %s (%d) nor the nftables file '%s': %s (%d)",
                         iptables_tmp, strerror(iptables_errno), iptables_errno,
                         NFTABLES, strerror(errno), errno);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                os_free(nftables);
                return OS_SUCCESS;
            }

            memset(lock_path, '\0', COMMANDSIZE_4096);
            memset(lock_pid_path, '\0', COMMANDSIZE_4096);
            snprintf(lock_path, COMMANDSIZE_4096 - 1, "%s", LOCK_PATH);
            snprintf(lock_pid_path, COMMANDSIZE_4096 - 1, "%s", LOCK_FILE);

            // Taking lock
            if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Unable to take lock. End.");
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                os_free(iptables);
                return OS_INVALID;
            }

            // We now create if it does not already exist the inet table wazuh-agent with two chains, input and forward
            // Note that we use the "add" keyword instead of the "create" keyword, the later returns an error
            // if the table already exist, which we want to avoid here
            char *exec_cmd[5][17] = {
                    {nftables, "add", "table", "inet", "wazuh-agent", NULL},
                    {nftables, "add", "chain", "inet", "wazuh-agent", "input",   "{", "type", "filter", "hook", "input",   "priority", "filter;", "policy", "accept;", "}", NULL},
                    {nftables, "add", "chain", "inet", "wazuh-agent", "forward", "{", "type", "filter", "hook", "forward", "priority", "filter;", "policy", "accept;", "}", NULL},

            };

            // All commands must return in order successfully, execute them in loop
            // We also write a retry counter, resetting for each successful command
            // This variable is reused afterward
            int retry_counter = 0;
            for (int i = 0; i < 3; i++) {
                wfd = wpopenv(nftables, exec_cmd[i], W_BIND_STDERR);
                if (!wfd) {
                    if (++retry_counter > 4) {
                        write_debug_file(argv[0], "Unable to run nftables");
                        unlock(lock_path, argv[0]);
                        cJSON_Delete(input_json);
                        os_free(nftables);
                        return OS_SUCCESS;
                    } else {
                        i--; // Decrement i so the next loop iteration will be using the same command
                        sleep(retry_counter);
                    }
                } else {
                    wpclose(wfd);
                    retry_counter = 0; // As this command was successfully executed, set the retry counter to 0
                }
            }

            if (action == ADD_COMMAND) {
                char *ban_cmd[2][17] = {
                        // The last two cmd_exec are the effective ban rules
                        {nftables, "add", "rule", "inet", "wazuh-agent", "input",
                                                                                    ip_version == 6 ? "ip6"
                                                                                                    : "ip", "saddr", (char *) srcip, "drop", NULL},
                        {nftables, "add", "rule", "inet", "wazuh-agent", "forward", ip_version == 6 ? "ip6"
                                                                                                    : "ip", "saddr", (char *) srcip, "drop", NULL}
                };

                retry_counter = 0;
                for (int i = 0; i < 2; i++) {
                    wfd = wpopenv(nftables, ban_cmd[i], W_BIND_STDERR);
                    if (!wfd) {
                        if (++retry_counter > 4) {
                            write_debug_file(argv[0], "Unable to run nftables");
                            unlock(lock_path, argv[0]);
                            cJSON_Delete(input_json);
                            os_free(nftables);
                            return OS_SUCCESS;
                        } else {
                            i--; // Decrement i so the next loop iteration will be using the same command
                            sleep(retry_counter);
                        }
                    } else {
                        wpclose(wfd);
                        retry_counter = 0; // As this command was successfully executed, set the retry counter to 0
                    }
                }
            } else {
                char *chains[2] = {"input", "forward"};
                // Deleting our rules is trickier because nftables doesn't support passive removal (i.e. removing a rule
                // by passing its content). We need to get the id assigned to the rule (a.k.a the handle) beforehand.
                // To do that, we parse the output of the command using nft -a, which includes handles

                retry_counter = 0;
                for (int i = 0; i < 2; i++) {
                    char *list_cmd[8] = {nftables, "-a",
                                         "list", "chain", "inet", "wazuh-agent", (char *) chains[i], NULL};
                    wfd = wpopenv(nftables, list_cmd, W_BIND_STDOUT | W_BIND_STDERR);
                    if (!wfd) {
                        if (++retry_counter > 4) {
                            write_debug_file(argv[0], "Unable to run nftables");
                            unlock(lock_path, argv[0]);
                            cJSON_Delete(input_json);
                            os_free(nftables);
                            return OS_SUCCESS;
                        } else {
                            sleep(retry_counter);
                            i--; // Decrement i so the next iteration would still be i
                        }
                    } else {
                        char nft_stdout_buf[OS_MAXSTR] = "";
                        memset(nft_stdout_buf, '\0', OS_MAXSTR);

                        // Read and replace on the fly the stdout stream to scan it later
                        char *ptr = nft_stdout_buf;
                        while (((*ptr) = (char) fgetc(wfd->file_out)) != EOF && ptr < nft_stdout_buf + OS_MAXSTR - 1) {
                            if (*ptr == '\n' || *ptr == '\t') {
                                *ptr = 0x20; //ASCII space
                            }
                            ptr++;
                        }
                        *ptr = '\0';

                        // Scan the content, looking for the 'ip saddr <IP> drop # handle %d' syntax.
                        // We only look for one handle at a time, so if a drop is duplicated, it will be removed
                        // once per delete command only.

                        // We first prepare our sscanf format
                        char format_tmp[200] = ""; format_tmp[199] = '\0';
                        snprintf(format_tmp, 199, "%s saddr %s drop", ip_version == 6 ? "ip6" : "ip", srcip);

                        // We now look for our rule in the nft output to scan it afterward
                        char *scan_base = strstr(nft_stdout_buf, format_tmp);

                        if (scan_base == NULL) {
                            memset(log_msg, '\0', OS_MAXSTR);
                            snprintf(log_msg, OS_MAXSTR - 1,
                                     "Unable to fetch rule handles from nftables, cannot find the rule '%s' in chain '%s'",
                                     format_tmp, chains[i]);
                            write_debug_file(argv[0], log_msg);

                            if (++retry_counter > 4) {
                                wpclose(wfd);
                                write_debug_file(argv[0], "Unable to run nftables");
                                unlock(lock_path, argv[0]);
                                cJSON_Delete(input_json);
                                os_free(nftables);
                                return OS_SUCCESS;
                            } else {
                                sleep(retry_counter);
                                i--; // Decrement i so the next iteration would still be i
                            }
                        }

                        // Prepare the format for the scan, now that we have located the rule in the ruleset
                        snprintf(format_tmp, 199, "%s saddr %s drop # handle %%s",
                                 ip_version == 6 ? "ip6" : "ip", srcip);
                        // We use a 21 maximum chars integer, which is sufficient for 8-bytes long storage
                        char handle_tmp[21] = "";
                        errno = 0; // Explicitly set errno to check matching error later
                        if (sscanf(scan_base, format_tmp, handle_tmp) <= 0) {
                            memset(log_msg, '\0', OS_MAXSTR);
                            snprintf(log_msg, OS_MAXSTR - 1,
                                     "Unable to run nftables, read error when trying to get input rule handle from nftables output for IP '%s': %s (%d)",
                                     srcip, errno == 0 ? "Matching error" : strerror(errno), errno);
                            write_debug_file(argv[0], log_msg);

                            if (++retry_counter > 4) {
                                wpclose(wfd);
                                write_debug_file(argv[0], "Unable to run nftables");
                                unlock(lock_path, argv[0]);
                                cJSON_Delete(input_json);
                                os_free(nftables);
                                return OS_SUCCESS;
                            } else {
                                sleep(retry_counter);
                                i--; // Decrement i so the next iteration would still be i
                            }

                        } else {
                            // Parse using strtol the obtained handle
                            errno = 0;
                            long handle = strtol(handle_tmp, NULL, 10);
                            if (errno != 0) {
                                memset(log_msg, '\0', OS_MAXSTR);
                                snprintf(log_msg, OS_MAXSTR - 1,
                                         "Unable to get handles from nftables, parse error on handle string: %s (%d)",
                                         strerror(errno), errno);
                                write_debug_file(argv[0], log_msg);

                                if (++retry_counter > 4) {
                                    wpclose(wfd);
                                    write_debug_file(argv[0], "Unable to run nftables");
                                    unlock(lock_path, argv[0]);
                                    cJSON_Delete(input_json);
                                    os_free(nftables);
                                    return OS_SUCCESS;
                                } else {
                                    sleep(retry_counter);
                                    i--; // Decrement i so the next iteration would still be i
                                }
                            }

                            wpclose(wfd);

                            // Now, we can remove the rule. Note that we convert the handle back to string
                            // One may think that we could just pass the handle string obtained before, but parsing it
                            // allows us to make sure we deal with an integer. If someday the handle comment changes,
                            // this would prevent unwanted side effects as we do not catch nft command results
                            snprintf(handle_tmp, 20, "%ld", handle);
                            char *remove_cmd[9] = {nftables, "delete", "rule", "inet", "wazuh-agent", chains[i],
                                                   "handle", handle_tmp, NULL};

                            wfd = wpopenv(nftables, remove_cmd, W_BIND_STDERR);
                            if (!wfd) {
                                if (++retry_counter > 4) {
                                    write_debug_file(argv[0], "Unable to run nftables");
                                    unlock(lock_path, argv[0]);
                                    cJSON_Delete(input_json);
                                    os_free(nftables);
                                    return OS_SUCCESS;
                                } else {
                                    sleep(retry_counter);
                                    i--; // Decrement i so the next iteration would still be i
                                }
                            } else {
                                wpclose(wfd);
                            }
                        }
                    }
                }
            }


            unlock(lock_path, argv[0]);
            cJSON_Delete(input_json);
            os_free(nftables);
            return OS_SUCCESS;
        }
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
