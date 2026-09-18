/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"
#include "helpers/firewall_helpers.h"

#ifdef __APPLE__

/**
 * macOS-specific block-ip implementation
 * Method chain: pf (Packet Filter) -> hosts.deny -> route (blackhole fallback)
 */

firewall_result_t try_pf_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_hostsdeny_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_macos(const char *srcip, int action, int ip_version, const char *argv0);

int main(int argc, char **argv) {
    (void)argc;
    int action = OS_INVALID;
    int action2 = OS_INVALID;
    cJSON *input_json = NULL;

    // Setup and parse JSON input
    action = setup_and_check_message(argv, &input_json);
    if ((action != ENABLE_COMMAND) && (action != DISABLE_COMMAND)) {
        return OS_INVALID;
    }

    // Extract source IP from WCS-compliant JSON
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'source.ip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Send keys and check for abort (ENABLE command only)
    if (action == ENABLE_COMMAND) {
        char **keys = NULL;
        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);
        os_free(keys[0]);
        os_free(keys);

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

    // Validate IP and get version
    int ip_version = get_ip_version(srcip);
    if (ip_version == OS_INVALID) {
        char log_msg[OS_MAXSTR];
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Invalid IP address: '%s'", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // macOS method chain, same pattern as the other Unix/BSD platforms:
    // pf -> hosts.deny -> route (blackhole), so a stock install with neither
    // pf enabled nor /etc/hosts.deny present still has a working fallback.
    const firewall_method_t methods[] = {
        {"pf", try_pf_macos, false},
        {"hostsdeny", try_hostsdeny_macos, false},
        {"route", try_route_macos, false},
        {NULL, NULL, false}  // Sentinel
    };

    int result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);

    cJSON_Delete(input_json);
    return result;
}

firewall_result_t try_pf_macos(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // pf handles both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *pfctl_path = NULL;

    // Check if pfctl binary is available
    if (check_binary_available("pfctl", &pfctl_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if /dev/pf exists
    if (access("/dev/pf", F_OK) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "/dev/pf not accessible: %s (%d)", strerror(errno), errno);
        write_debug_file(argv0, log_msg);
        os_free(pfctl_path);
        return FIREWALL_INVALID_STATE;
    }

    // Check if PF is enabled
    char *exec_cmd1[] = {pfctl_path, "-s", "info", NULL};
    wfd_t *wfd = wpopenv(pfctl_path, exec_cmd1, W_BIND_STDOUT);

    if (wfd) {
        char output_buf[OS_MAXSTR];
        bool enabled = false;

        while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
            if (strstr(output_buf, "Status: Enabled") != NULL) {
                enabled = true;
                break;
            }
        }
        wpclose(wfd);

        if (!enabled) {
            write_debug_file(argv0, "PF firewall is not enabled");
            os_free(pfctl_path);
            return FIREWALL_INVALID_STATE;
        }
    } else {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute pfctl -s info");
        write_debug_file(argv0, log_msg);
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    // Check if wazuh_fwtable exists and create if necessary
    char *exec_cmd_check[] = {pfctl_path, "-t", "wazuh_fwtable", "-T", "show", NULL};
    wfd = wpopenv(pfctl_path, exec_cmd_check, W_BIND_STDOUT | W_BIND_STDERR);

    bool table_exists = false;
    if (wfd) {
        int check_result = wpclose(wfd);
        if (WIFEXITED(check_result) && WEXITSTATUS(check_result) == 0) {
            table_exists = true;
        }
    }

    // If table doesn't exist, create it by adding configuration to pf.conf
    if (!table_exists) {
        const char *pf_conf_path = "/etc/pf.conf";

        // Check if pf.conf exists
        if (access(pf_conf_path, F_OK) >= 0) {
            // First check if wazuh_fwtable is already configured in pf.conf
            bool config_exists = false;
            FILE *pf_conf_check = wfopen(pf_conf_path, "r");
            if (pf_conf_check) {
                char line_buf[OS_MAXSTR];
                while (fgets(line_buf, OS_MAXSTR, pf_conf_check)) {
                    if (strstr(line_buf, "wazuh_fwtable") != NULL) {
                        config_exists = true;
                        break;
                    }
                }
                fclose(pf_conf_check);
            }

            if (!config_exists) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Table 'wazuh_fwtable' does not exist");
                write_debug_file(argv0, log_msg);

                // Append table configuration to pf.conf
                FILE *pf_conf = wfopen(pf_conf_path, "a");
                if (pf_conf) {
                    fprintf(pf_conf, "\n# Wazuh active response table\n");
                    fprintf(pf_conf, "table <wazuh_fwtable> persist\n");
                    fprintf(pf_conf, "block in quick from <wazuh_fwtable> to any\n");
                    fprintf(pf_conf, "block out quick from any to <wazuh_fwtable>\n");
                    fclose(pf_conf);
                } else {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR - 1, "Failed to open %s for writing", pf_conf_path);
                    write_debug_file(argv0, log_msg);
                    os_free(pfctl_path);
                    return FIREWALL_EXECUTION_FAILED;
                }
            }

            // Reload PF configuration
            char *exec_cmd_reload[] = {pfctl_path, "-f", (char *)pf_conf_path, NULL};
            wfd = wpopenv(pfctl_path, exec_cmd_reload, W_BIND_STDOUT | W_BIND_STDERR);
            if (wfd) {
                // Consume all output to prevent SIGPIPE
                char buffer[OS_MAXSTR];
                while (fgets(buffer, OS_MAXSTR, wfd->file_out) != NULL) {
                    // Just consume the output
                }

                int reload_result = wpclose(wfd);

                // Check both normal exit and signal termination
                if (reload_result != 0 && !(WIFEXITED(reload_result) && WEXITSTATUS(reload_result) == 0)) {
                    memset(log_msg, '\0', OS_MAXSTR);
                    if (WIFEXITED(reload_result)) {
                        snprintf(log_msg, OS_MAXSTR - 1, "Failed to reload PF configuration (exit code: %d)",
                                WEXITSTATUS(reload_result));
                    } else if (WIFSIGNALED(reload_result)) {
                        snprintf(log_msg, OS_MAXSTR - 1, "pfctl terminated by signal %d",
                                WTERMSIG(reload_result));
                    } else {
                        snprintf(log_msg, OS_MAXSTR - 1, "pfctl failed with status %d", reload_result);
                    }
                    write_debug_file(argv0, log_msg);
                    os_free(pfctl_path);
                    return FIREWALL_EXECUTION_FAILED;
                }
            } else {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Failed to execute pfctl reload command");
                write_debug_file(argv0, log_msg);
                os_free(pfctl_path);
                return FIREWALL_EXECUTION_FAILED;
            }
        } else {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "PF configuration file %s does not exist", pf_conf_path);
            write_debug_file(argv0, log_msg);
            os_free(pfctl_path);
            return FIREWALL_INVALID_STATE;
        }
    }

    // Add or delete IP from table
    const char *table_operation = (action == ENABLE_COMMAND) ? "add" : "delete";
    char *exec_cmd2[] = {pfctl_path, "-t", "wazuh_fwtable", "-T", (char *)table_operation, (char *)srcip, NULL};

    wfd = wpopenv(pfctl_path, exec_cmd2, W_BIND_STDOUT | W_BIND_STDERR);
    if (!wfd) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute pfctl table operation");
        write_debug_file(argv0, log_msg);
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    // Consume output to prevent SIGPIPE and capture any error messages
    char buffer[OS_MAXSTR];
    char error_msg[OS_MAXSTR];
    memset(error_msg, '\0', OS_MAXSTR);
    while (fgets(buffer, OS_MAXSTR, wfd->file_out) != NULL) {
        if (error_msg[0] == '\0') {
            strncpy(error_msg, buffer, OS_MAXSTR - 1);
        }
    }

    int wp_closefd = wpclose(wfd);
    if (WIFEXITED(wp_closefd) && WEXITSTATUS(wp_closefd) != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        if (error_msg[0] != '\0') {
            // Remove newline
            char *newline = strchr(error_msg, '\n');
            if (newline) *newline = '\0';
            snprintf(log_msg, OS_MAXSTR - 1, "pfctl table operation failed (exit %d): %s",
                    WEXITSTATUS(wp_closefd), error_msg);
        } else {
            snprintf(log_msg, OS_MAXSTR - 1, "pfctl table operation failed with exit code %d",
                    WEXITSTATUS(wp_closefd));
        }
        write_debug_file(argv0, log_msg);
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    // If adding, also kill existing connections from this IP
    if (action == ENABLE_COMMAND) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Killing existing connections from %s", srcip);
        write_debug_file(argv0, log_msg);

        char *exec_cmd3[] = {pfctl_path, "-k", (char *)srcip, NULL};
        wfd = wpopenv(pfctl_path, exec_cmd3, W_BIND_STDERR);
        if (wfd) {
            wpclose(wfd);
        }
    }

    os_free(pfctl_path);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// macOS: hosts.deny (TCP wrappers) implementation
// ============================================================================

#define HOSTSDENY_LOCK_PATH "active-response/bin/block-ip-hostsdeny-lock"
#define HOSTSDENY_LOCK_FILE "active-response/bin/block-ip-hostsdeny-lock/pid"
#define DEFAULT_HOSTS_DENY_PATH "/etc/hosts.deny"

firewall_result_t try_hostsdeny_macos(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // TCP wrappers work for both IPv4 and IPv6
    char hosts_deny_rule[COMMANDSIZE_4096];
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR - 25];
    FILE *host_deny_fp = NULL;
    lock_context_t lock_ctx = {
        .lock_path = HOSTSDENY_LOCK_PATH,
        .lock_pid_path = HOSTSDENY_LOCK_FILE,
        .log_prefix = argv0,
        .acquired = false
    };

    // macOS uses standard hosts.deny format
    memset(hosts_deny_rule, '\0', COMMANDSIZE_4096);
    snprintf(hosts_deny_rule, COMMANDSIZE_4096 - 1, "ALL:%s", srcip);

    // Check if hosts.deny file exists
    if (access(DEFAULT_HOSTS_DENY_PATH, F_OK) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "File '%s' not found", DEFAULT_HOSTS_DENY_PATH);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "check", log_msg);
        return FIREWALL_NOT_AVAILABLE;
    }

    // Acquire lock
    if (acquire_ar_lock(&lock_ctx) == OS_INVALID) {
        return FIREWALL_EXECUTION_FAILED;
    }

    if (action == ENABLE_COMMAND) {
        // Open file for reading to check for duplicates
        host_deny_fp = wfopen(DEFAULT_HOSTS_DENY_PATH, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", DEFAULT_HOSTS_DENY_PATH);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Check for duplicates
        memset(output_buf, '\0', OS_MAXSTR - 25);
        while (fgets(output_buf, OS_MAXSTR - 25, host_deny_fp)) {
            if (strstr(output_buf, srcip) != NULL) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "IP %s already exists in '%s'", srcip, DEFAULT_HOSTS_DENY_PATH);
                log_firewall_action(argv0, LOG_LEVEL_INFO, "hostsdeny", "add", log_msg);
                fclose(host_deny_fp);
                release_ar_lock(&lock_ctx);
                return FIREWALL_SUCCESS;  // Already exists, consider it success
            }
        }
        fclose(host_deny_fp);

        // Open again to append rule
        host_deny_fp = wfopen(DEFAULT_HOSTS_DENY_PATH, "a");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for appending", DEFAULT_HOSTS_DENY_PATH);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        if (fprintf(host_deny_fp, "%s\n", hosts_deny_rule) <= 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to write rule to '%s'", DEFAULT_HOSTS_DENY_PATH);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            fclose(host_deny_fp);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }
        fclose(host_deny_fp);

    } else {
        // DISABLE_COMMAND: Remove IP from hosts.deny
        FILE *temp_host_deny_fp = NULL;
        char temp_hosts_deny_path[COMMANDSIZE_4096];
        bool write_fail = false;

        memset(temp_hosts_deny_path, '\0', COMMANDSIZE_4096);
        snprintf(temp_hosts_deny_path, COMMANDSIZE_4096 - 1, "%s", "active-response/bin/temp-hosts-deny");

        host_deny_fp = wfopen(DEFAULT_HOSTS_DENY_PATH, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", DEFAULT_HOSTS_DENY_PATH);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "delete", log_msg);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Create the temporary file
        temp_host_deny_fp = wfopen(temp_hosts_deny_path, "w");
        if (!temp_host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not create temporary file '%s'", temp_hosts_deny_path);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "delete", log_msg);
            fclose(host_deny_fp);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Copy all lines except those containing the srcip
        memset(output_buf, '\0', OS_MAXSTR - 25);
        while (fgets(output_buf, OS_MAXSTR - 25, host_deny_fp)) {
            if (strstr(output_buf, srcip) == NULL) {
                if (fwrite(output_buf, 1, strlen(output_buf), temp_host_deny_fp) != strlen(output_buf)) {
                    memset(log_msg, '\0', OS_MAXSTR);
                    snprintf(log_msg, OS_MAXSTR - 1, "Unable to write to temporary file");
                    log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "delete", log_msg);
                    write_fail = true;
                    break;
                }
            }
            memset(output_buf, '\0', OS_MAXSTR - 25);
        }

        fclose(host_deny_fp);
        fclose(temp_host_deny_fp);

        // Replace original file with temp file
        if (write_fail || OS_MoveFile(temp_hosts_deny_path, DEFAULT_HOSTS_DENY_PATH) != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to update file '%s'", DEFAULT_HOSTS_DENY_PATH);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "delete", log_msg);
            unlink(temp_hosts_deny_path);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        unlink(temp_hosts_deny_path);
    }

    release_ar_lock(&lock_ctx);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// macOS: route (blackhole) implementation
// ============================================================================
// Needs no firewall to be configured or enabled: it works on a stock
// install, same as the route fallback on Linux/FreeBSD/OpenBSD/NetBSD.
// macOS route is BSD-derived and takes the same -blackhole syntax as
// FreeBSD/OpenBSD/NetBSD in block-ip-unix.c's try_route().

firewall_result_t try_route_macos(const char *srcip, int action, int ip_version, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    if (check_binary_available("route", &route_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // The blackhole route needs a gateway placeholder of the same address
    // family as srcip -- an IPv4 loopback gateway is invalid for an IPv6
    // destination and the command fails at the OS level. macOS route(8) also
    // needs -inet6 to disambiguate the family for an IPv6 destination; the
    // gateway itself is still required either way (confirmed empirically --
    // `route add <ip> -blackhole` with no gateway fails with "Invalid
    // argument" on macOS, only `route add <ip> 127.0.0.1 -blackhole`
    // works: https://discussions.apple.com/thread/6869503).
    const char *gateway = (ip_version == 6) ? "::1" : "127.0.0.1";
    wfd_t *wfd = NULL;

    // Both streams are bound (not just stderr): route(8) reports the
    // EEXIST/ESRCH failures try_route_macos checks for below via printf() to
    // stdout, not stderr (confirmed against Apple's route.tproj/route.c) --
    // matches try_pf_macos's own W_BIND_STDOUT | W_BIND_STDERR three lines
    // up in this same file, for the same reason.
    if (action == ENABLE_COMMAND) {
        if (ip_version == 6) {
            char *exec_cmd[] = {route_path, "-q", "add", "-inet6", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDOUT | W_BIND_STDERR);
        } else {
            char *exec_cmd[] = {route_path, "-q", "add", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDOUT | W_BIND_STDERR);
        }
    } else {
        if (ip_version == 6) {
            char *exec_cmd[] = {route_path, "-q", "delete", "-inet6", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDOUT | W_BIND_STDERR);
        } else {
            char *exec_cmd[] = {route_path, "-q", "delete", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDOUT | W_BIND_STDERR);
        }
    }

    os_free(route_path);

    if (!wfd) {
        write_debug_file(argv0, "Unable to execute route");
        return FIREWALL_EXECUTION_FAILED;
    }

    // Drain stderr (bound via W_BIND_STDERR) before wpclose, same pattern
    // try_pf_macos already uses -- an unread pipe can leave the child
    // blocked on write(), and the first line is kept for diagnostics.
    char buffer[OS_MAXSTR];
    char error_msg[OS_MAXSTR];
    memset(error_msg, '\0', OS_MAXSTR);
    while (fgets(buffer, OS_MAXSTR, wfd->file_out) != NULL) {
        if (error_msg[0] == '\0') {
            strncpy(error_msg, buffer, OS_MAXSTR - 1);
        }
    }

    int wp_closefd = wpclose(wfd);
    if (WIFEXITED(wp_closefd) && WEXITSTATUS(wp_closefd) == 0) {
        return FIREWALL_SUCCESS;
    }

    // route(8) exits non-zero when the blackhole route already exists (add)
    // or is already gone (delete) -- treat both as a successful no-op, same
    // as try_hostsdeny_macos already does for a duplicate hosts.deny entry.
    // Confirmed against Apple's own route.tproj/route.c: ESRCH is mapped to
    // "not in table" explicitly; EEXIST falls through to strerror(), which
    // is "File exists" on macOS/BSD.
    if (strstr(error_msg, "File exists") != NULL || strstr(error_msg, "not in table") != NULL) {
        return FIREWALL_SUCCESS;
    }

    memset(log_msg, '\0', OS_MAXSTR);
    if (error_msg[0] != '\0') {
        char *newline = strchr(error_msg, '\n');
        if (newline) *newline = '\0';
        snprintf(log_msg, OS_MAXSTR - 1, "route command failed (exit %d): %s",
                 WIFEXITED(wp_closefd) ? WEXITSTATUS(wp_closefd) : wp_closefd, error_msg);
    } else if (WIFSIGNALED(wp_closefd)) {
        snprintf(log_msg, OS_MAXSTR - 1, "route command terminated by signal %d", WTERMSIG(wp_closefd));
    } else {
        snprintf(log_msg, OS_MAXSTR - 1, "route command failed with status %d", wp_closefd);
    }
    write_debug_file(argv0, log_msg);
    return FIREWALL_EXECUTION_FAILED;
}

#endif // __APPLE__
