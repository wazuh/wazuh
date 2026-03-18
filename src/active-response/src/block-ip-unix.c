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

#ifndef WIN32

// Platform detection at compile time
#if defined(__linux__)
    #define PLATFORM_LINUX 1
#elif defined(__FreeBSD__)
    #define PLATFORM_FREEBSD 1
#elif defined(__OpenBSD__)
    #define PLATFORM_OPENBSD 1
#elif defined(__NetBSD__)
    #define PLATFORM_NETBSD 1
#else
    #error "Unsupported Unix/BSD platform for block-ip"
#endif

// Lock definitions (shared across all methods that need locking)
#define LOCK_PATH "active-response/bin/block-ip-lock"
#define LOCK_FILE "active-response/bin/block-ip-lock/pid"

// Forward declarations for platform-specific methods
#ifdef PLATFORM_LINUX
firewall_result_t try_firewalld(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_iptables(const char *srcip, int action, int ip_version, const char *argv0);
#endif

#if defined(PLATFORM_FREEBSD) || defined(PLATFORM_OPENBSD)
firewall_result_t try_pf(const char *srcip, int action, int ip_version, const char *argv0);
#endif

#ifdef PLATFORM_FREEBSD
firewall_result_t try_ipfw(const char *srcip, int action, int ip_version, const char *argv0);
#endif

#ifdef PLATFORM_NETBSD
firewall_result_t try_npf(const char *srcip, int action, int ip_version, const char *argv0);
#endif

firewall_result_t try_hostsdeny(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route(const char *srcip, int action, int ip_version, const char *argv0);

int main(int argc, char **argv) {
    (void)argc;
    int action = OS_INVALID;
    int action2 = OS_INVALID;
    cJSON *input_json = NULL;

    // Setup and parse JSON input
    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Extract source IP from WCS-compliant JSON
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'source.ip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Send keys and check for abort (ADD command only)
    if (action == ADD_COMMAND) {
        char **keys = NULL;
        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);
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

    // Define platform-specific method chain
    const firewall_method_t methods[] = {
#ifdef PLATFORM_LINUX
        {"firewalld", try_firewalld, true},
        {"iptables", try_iptables, true},
        {"hostsdeny", try_hostsdeny, false},
        {"route", try_route, false},
#elif defined(PLATFORM_FREEBSD)
        {"ipfw", try_ipfw, false},
        {"pf", try_pf, false},
        {"hostsdeny", try_hostsdeny, false},
        {"route", try_route, false},
#elif defined(PLATFORM_OPENBSD)
        {"pf", try_pf, false},
        {"hostsdeny", try_hostsdeny, false},
        {"route", try_route, false},
#elif defined(PLATFORM_NETBSD)
        {"npf", try_npf, false},
        {"hostsdeny", try_hostsdeny, false},
        {"route", try_route, false},
#endif
        {NULL, NULL, false}  // Sentinel
    };

    // Execute firewall chain with fallback
    int result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);

    cJSON_Delete(input_json);
    return result;
}

// ============================================================================
// LINUX: firewalld implementation
// ============================================================================
#ifdef PLATFORM_LINUX

firewall_result_t try_firewalld(const char *srcip, int action, int ip_version, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char *fw_cmd_path = NULL;
    lock_context_t lock_ctx = {
        .lock_path = LOCK_PATH,
        .lock_pid_path = LOCK_FILE,
        .log_prefix = argv0,
        .acquired = false
    };

    // Check if firewall-cmd binary is available
    if (check_binary_available("firewall-cmd", &fw_cmd_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if firewalld service is active
    char *systemctl_path = NULL;
    if (get_binary_path("systemctl", &systemctl_path) >= 0) {
        char *check_cmd[] = {systemctl_path, "is-active", "firewalld", NULL};
        wfd_t *wfd = wpopenv(systemctl_path, check_cmd, W_BIND_STDOUT);
        if (wfd) {
            char output[256] = {0};
            if (fgets(output, sizeof(output), wfd->file_out)) {
                wpclose(wfd);
                if (strncmp(output, "active", 6) != 0) {
                    log_firewall_action(argv0, LOG_LEVEL_WARNING, "firewalld", "check",
                                      "firewalld service is not active");
                    os_free(systemctl_path);
                    os_free(fw_cmd_path);
                    return FIREWALL_INVALID_STATE;
                }
            } else {
                wpclose(wfd);
            }
        }
        os_free(systemctl_path);
    }

    // Acquire lock
    if (acquire_ar_lock(&lock_ctx) == OS_INVALID) {
        os_free(fw_cmd_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    // Build firewall-cmd command
    const char *family = (ip_version == 4) ? "ipv4" : "ipv6";
    const char *operation = (action == ADD_COMMAND) ? "--add-rich-rule" : "--remove-rich-rule";

    char rule[COMMANDSIZE_4096];
    memset(rule, '\0', COMMANDSIZE_4096);
    snprintf(rule, COMMANDSIZE_4096 - 1, "rule family=%s source address=%s drop", family, srcip);

    char *exec_cmd[] = {fw_cmd_path, (char *)operation, rule, NULL};

    // Configure retry
    retry_config_t retry_cfg = {
        .max_retries = 4,
        .backoff_base_seconds = 1,
        .exponential_backoff = true
    };

    // Execute with retry
    firewall_result_t result = execute_with_retry(fw_cmd_path, exec_cmd, W_BIND_STDERR,
                                                  &retry_cfg, argv0);

    // Release lock
    release_ar_lock(&lock_ctx);
    os_free(fw_cmd_path);

    return result;
}

// ============================================================================
// LINUX: iptables/ip6tables implementation
// ============================================================================

firewall_result_t try_iptables(const char *srcip, int action, int ip_version, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char *iptables = NULL;
    const char *iptables_name = (ip_version == 4) ? "iptables" : "ip6tables";
    lock_context_t lock_ctx = {
        .lock_path = LOCK_PATH,
        .lock_pid_path = LOCK_FILE,
        .log_prefix = argv0,
        .acquired = false
    };

    // Check if iptables binary is available
    if (check_binary_available(iptables_name, &iptables, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Acquire lock
    if (acquire_ar_lock(&lock_ctx) == OS_INVALID) {
        os_free(iptables);
        return FIREWALL_EXECUTION_FAILED;
    }

    // Determine argument for add/delete
    const char *arg = (action == ADD_COMMAND) ? "-I" : "-D";

    firewall_result_t final_result = FIREWALL_SUCCESS;

    // Execute INPUT chain with retry
    int count = 0;
    bool flag = true;
    while (flag) {
        char *exec_cmd1[] = {iptables, (char *)arg, "INPUT", "-s", (char *)srcip, "-j", "DROP", NULL};
        wfd_t *wfd = wpopenv(iptables, exec_cmd1, W_BIND_STDERR);

        if (!wfd) {
            count++;
            if (count > 4) {
                flag = false;
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Unable to run %s on INPUT chain", iptables_name);
                write_debug_file(argv0, log_msg);
                final_result = FIREWALL_EXECUTION_FAILED;
            } else {
                sleep(count);
            }
        } else {
            flag = false;
            wpclose(wfd);
        }
    }

    // Execute FORWARD chain with retry
    count = 0;
    flag = true;
    while (flag) {
        char *exec_cmd2[] = {iptables, (char *)arg, "FORWARD", "-s", (char *)srcip, "-j", "DROP", NULL};
        wfd_t *wfd = wpopenv(iptables, exec_cmd2, W_BIND_STDERR);

        if (!wfd) {
            count++;
            if (count > 4) {
                flag = false;
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "Unable to run %s on FORWARD chain", iptables_name);
                write_debug_file(argv0, log_msg);
                final_result = FIREWALL_EXECUTION_FAILED;
            } else {
                sleep(count);
            }
        } else {
            flag = false;
            wpclose(wfd);
        }
    }

    // Release lock
    release_ar_lock(&lock_ctx);
    os_free(iptables);

    return final_result;
}

#endif // PLATFORM_LINUX

// ============================================================================
// FREEBSD: ipfw implementation
// ============================================================================
#ifdef PLATFORM_FREEBSD

firewall_result_t try_ipfw(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // ipfw handles both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *ipfw_path = NULL;
    char output_buf[OS_MAXSTR];
    bool add_table = true;

    // Check if ipfw binary is available
    if (check_binary_available("ipfw", &ipfw_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if table exists
    char *exec_cmd1[] = {ipfw_path, "show", NULL};
    wfd_t *wfd = wpopenv(ipfw_path, exec_cmd1, W_BIND_STDOUT);

    if (wfd) {
        while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
            if ((strncmp(output_buf, "00001", 5) == 0) && (strstr(output_buf, "table(00001)") != NULL)) {
                add_table = false;
                break;
            }
        }
        wpclose(wfd);
    }

    // Add table rules if needed
    if (add_table) {
        log_firewall_action(argv0, LOG_LEVEL_INFO, "ipfw", "setup", "Creating table 00001");

        char *exec_cmd2[] = {ipfw_path, "-q", "00001", "add", "deny", "ip", "from", "table(00001)", "to", "any", NULL};
        wfd = wpopenv(ipfw_path, exec_cmd2, W_BIND_STDERR);
        if (wfd) wpclose(wfd);

        char *exec_cmd3[] = {ipfw_path, "-q", "00001", "add", "deny", "ip", "from", "any", "to", "table(00001)", NULL};
        wfd = wpopenv(ipfw_path, exec_cmd3, W_BIND_STDERR);
        if (wfd) wpclose(wfd);
    }

    // Add or delete IP from table
    const char *table_operation = (action == ADD_COMMAND) ? "add" : "delete";
    char *exec_cmd4[] = {ipfw_path, "-q", "table", "00001", (char *)table_operation, (char *)srcip, NULL};

    wfd = wpopenv(ipfw_path, exec_cmd4, W_BIND_STDERR);
    os_free(ipfw_path);

    if (!wfd) {
        return FIREWALL_EXECUTION_FAILED;
    }

    wpclose(wfd);
    return FIREWALL_SUCCESS;
}

#endif // PLATFORM_FREEBSD

// ============================================================================
// FREEBSD/OPENBSD: pf (Packet Filter) implementation
// ============================================================================
#if defined(PLATFORM_FREEBSD) || defined(PLATFORM_OPENBSD)

firewall_result_t try_pf(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // pf handles both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *pfctl_path = NULL;

    // Check if pfctl binary is available
    if (check_binary_available("pfctl", &pfctl_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if /dev/pf exists
    if (access("/dev/pf", F_OK) < 0) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "pf", "check", "/dev/pf not accessible");
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
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "pf", "check", "PF is not enabled");
            os_free(pfctl_path);
            return FIREWALL_INVALID_STATE;
        }
    } else {
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    // Add or delete IP from table
    const char *table_operation = (action == ADD_COMMAND) ? "add" : "delete";
    char *exec_cmd2[] = {pfctl_path, "-t", "wazuh_fwtable", "-T", (char *)table_operation, (char *)srcip, NULL};

    wfd = wpopenv(pfctl_path, exec_cmd2, W_BIND_STDERR);
    if (!wfd) {
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }
    wpclose(wfd);

    // If adding, also kill existing connections
    if (action == ADD_COMMAND) {
        char *exec_cmd3[] = {pfctl_path, "-k", (char *)srcip, NULL};
        wfd = wpopenv(pfctl_path, exec_cmd3, W_BIND_STDERR);
        if (wfd) wpclose(wfd);
    }

    os_free(pfctl_path);
    return FIREWALL_SUCCESS;
}

#endif // PLATFORM_FREEBSD || PLATFORM_OPENBSD

// ============================================================================
// NETBSD: npf (NetBSD Packet Filter) implementation
// ============================================================================
#ifdef PLATFORM_NETBSD

firewall_result_t try_npf(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // npf handles both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *npfctl_path = NULL;

    // Check if npfctl binary is available
    if (check_binary_available("npfctl", &npfctl_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if NPF is active
    char *exec_cmd1[] = {npfctl_path, "show", NULL};
    wfd_t *wfd = wpopenv(npfctl_path, exec_cmd1, W_BIND_STDOUT);

    if (!wfd) {
        os_free(npfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    char output_buf[OS_MAXSTR];
    bool filtering_active = false;
    bool table_exists = false;

    if (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
        char state[15];
        char *pos = strstr(output_buf, "filtering:");
        if (pos && sscanf(pos, "%*s %9s", state) == 1) {
            if (strcmp(state, "active") == 0) {
                filtering_active = true;
            }
        }
    }

    // Check for table existence
    while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
        if (strstr(output_buf, "table <wazuh_blacklist>") != NULL) {
            table_exists = true;
            break;
        }
    }
    wpclose(wfd);

    if (!filtering_active) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "npf", "check", "NPF filtering is not active");
        os_free(npfctl_path);
        return FIREWALL_INVALID_STATE;
    }

    if (!table_exists) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "npf", "check", "wazuh_blacklist table not found");
        os_free(npfctl_path);
        return FIREWALL_INVALID_STATE;
    }

    // Add or delete IP from table
    const char *table_operation = (action == ADD_COMMAND) ? "add" : "del";
    char *exec_cmd2[] = {npfctl_path, "table", "wazuh_blacklist", (char *)table_operation, (char *)srcip, NULL};

    wfd = wpopenv(npfctl_path, exec_cmd2, W_BIND_STDERR);
    os_free(npfctl_path);

    if (!wfd) {
        return FIREWALL_EXECUTION_FAILED;
    }

    wpclose(wfd);
    return FIREWALL_SUCCESS;
}

#endif // PLATFORM_NETBSD

// ============================================================================
// ALL PLATFORMS: route implementation (fallback)
// ============================================================================

firewall_result_t try_route(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // route works for both IPv4 and IPv6
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    // Check if route binary is available
    if (check_binary_available("route", &route_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    wfd_t *wfd = NULL;

#ifdef PLATFORM_LINUX
    // Linux: route add <ip> reject / route del <ip> reject
    if (action == ADD_COMMAND) {
        char *exec_cmd[] = {route_path, "add", (char *)srcip, "reject", NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    } else {
        char *exec_cmd[] = {route_path, "del", (char *)srcip, "reject", NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    }
#elif defined(PLATFORM_FREEBSD)
    // FreeBSD: route -q add <ip> 127.0.0.1 -blackhole
    if (action == ADD_COMMAND) {
        char *exec_cmd[] = {route_path, "-q", "add", (char *)srcip, "127.0.0.1", "-blackhole", NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    } else {
        char *exec_cmd[] = {route_path, "-q", "delete", (char *)srcip, "127.0.0.1", "-blackhole", NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    }
#elif defined(PLATFORM_OPENBSD) || defined(PLATFORM_NETBSD)
    // OpenBSD/NetBSD: Similar to FreeBSD
    if (action == ADD_COMMAND) {
        char *exec_cmd[] = {route_path, "-q", "add", (char *)srcip, "127.0.0.1", "-blackhole", NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    } else {
        char *exec_cmd[] = {route_path, "-q", "delete", (char *)srcip, NULL};
        wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    }
#endif

    os_free(route_path);

    if (!wfd) {
        return FIREWALL_EXECUTION_FAILED;
    }

    wpclose(wfd);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// ALL PLATFORMS: hosts.deny/hosts.allow (TCP wrappers) implementation
// ============================================================================

#define HOSTSDENY_LOCK_PATH "active-response/bin/block-ip-hostsdeny-lock"
#define HOSTSDENY_LOCK_FILE "active-response/bin/block-ip-hostsdeny-lock/pid"
#define DEFAULT_HOSTS_DENY_PATH "/etc/hosts.deny"
#define FREEBSD_HOSTS_DENY_PATH "/etc/hosts.allow"

firewall_result_t try_hostsdeny(const char *srcip, int action, int ip_version, const char *argv0) {
    (void)ip_version;  // TCP wrappers work for both IPv4 and IPv6
    char hosts_deny_rule[COMMANDSIZE_4096];
    char hosts_deny_path[COMMANDSIZE_4096];
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR - 25];
    struct utsname uname_buffer;
    FILE *host_deny_fp = NULL;
    lock_context_t lock_ctx = {
        .lock_path = HOSTSDENY_LOCK_PATH,
        .lock_pid_path = HOSTSDENY_LOCK_FILE,
        .log_prefix = argv0,
        .acquired = false
    };

    // Get system name to determine hosts.deny path
    if (uname(&uname_buffer) != 0) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "check",
                          "Cannot get system name");
        return FIREWALL_EXECUTION_FAILED;
    }

    // Determine the rule format and file path based on OS
    memset(hosts_deny_rule, '\0', COMMANDSIZE_4096);
    memset(hosts_deny_path, '\0', COMMANDSIZE_4096);
    if (!strcmp("FreeBSD", uname_buffer.sysname)) {
        snprintf(hosts_deny_rule, COMMANDSIZE_4096 - 1, "ALL : %s : deny", srcip);
        strcpy(hosts_deny_path, FREEBSD_HOSTS_DENY_PATH);
    } else {
        snprintf(hosts_deny_rule, COMMANDSIZE_4096 - 1, "ALL:%s", srcip);
        strcpy(hosts_deny_path, DEFAULT_HOSTS_DENY_PATH);
    }

    // Check if hosts.deny file exists
    if (access(hosts_deny_path, F_OK) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "File '%s' not found", hosts_deny_path);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "check", log_msg);
        return FIREWALL_NOT_AVAILABLE;
    }

    // Acquire lock
    if (acquire_ar_lock(&lock_ctx) == OS_INVALID) {
        return FIREWALL_EXECUTION_FAILED;
    }

    if (action == ADD_COMMAND) {
        // Open file for reading to check for duplicates
        host_deny_fp = wfopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", hosts_deny_path);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Check for duplicates
        memset(output_buf, '\0', OS_MAXSTR - 25);
        while (fgets(output_buf, OS_MAXSTR - 25, host_deny_fp)) {
            if (strstr(output_buf, srcip) != NULL) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "IP %s already exists in '%s'", srcip, hosts_deny_path);
                log_firewall_action(argv0, LOG_LEVEL_INFO, "hostsdeny", "add", log_msg);
                fclose(host_deny_fp);
                release_ar_lock(&lock_ctx);
                return FIREWALL_SUCCESS;  // Already exists, consider it success
            }
        }
        fclose(host_deny_fp);

        // Open again to append rule
        host_deny_fp = wfopen(hosts_deny_path, "a");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for appending", hosts_deny_path);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }

        if (fprintf(host_deny_fp, "%s\n", hosts_deny_rule) <= 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to write rule to '%s'", hosts_deny_path);
            log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "add", log_msg);
            fclose(host_deny_fp);
            release_ar_lock(&lock_ctx);
            return FIREWALL_EXECUTION_FAILED;
        }
        fclose(host_deny_fp);

    } else {
        // DELETE_COMMAND: Remove IP from hosts.deny
        FILE *temp_host_deny_fp = NULL;
        char temp_hosts_deny_path[COMMANDSIZE_4096];
        bool write_fail = false;

        memset(temp_hosts_deny_path, '\0', COMMANDSIZE_4096);
        snprintf(temp_hosts_deny_path, COMMANDSIZE_4096 - 1, "%s", "active-response/bin/temp-hosts-deny");

        host_deny_fp = wfopen(hosts_deny_path, "r");
        if (!host_deny_fp) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", hosts_deny_path);
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
        if (write_fail || OS_MoveFile(temp_hosts_deny_path, hosts_deny_path) != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to update file '%s'", hosts_deny_path);
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

#endif // !WIN32
