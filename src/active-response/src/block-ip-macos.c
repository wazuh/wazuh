/* Copyright (C) Wazuh Inc.
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
 * Method chain: pf (Packet Filter) -> route (blackhole fallback)
 * hosts.deny is not used: macOS has no TCP wrappers.
 */

firewall_result_t try_pf_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_macos(const char *srcip, int action, int ip_version, const char *argv0);
bool remove_legacy_hostsdeny_rule(const char *srcip, const char *argv0);

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

    // pf -> route (blackhole), so a stock install without pf enabled still blocks
    const firewall_method_t methods[] = {
        {"pf", try_pf_macos, false},
        {"route", try_route_macos, false},
        {NULL, NULL, false}  // Sentinel
    };

    // Outside the chain: it must neither stop it before route nor change the result
    if (action == DISABLE_COMMAND) {
        remove_legacy_hostsdeny_rule(srcip, argv[0]);
    }

    int result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);

    cJSON_Delete(input_json);
    return result;
}

// Reads the whole stream before wpclose(), which would otherwise SIGPIPE the
// child, and joins it into one string: on a shared pipe stdout and stderr do
// not arrive in a dependable order. pfctl's ALTQ notices are dropped as noise.
static int drain_and_close(wfd_t *wfd, char *output, size_t size) {
    char buffer[OS_MAXSTR];
    size_t used = 0;

    if (output && size) {
        output[0] = '\0';
    }

    while (fgets(buffer, OS_MAXSTR, wfd->file_out) != NULL) {
        if (!output || used + 1 >= size || strstr(buffer, "ALTQ") != NULL) {
            continue;
        }

        buffer[strcspn(buffer, "\r\n")] = '\0';
        if (buffer[strspn(buffer, " \t")] == '\0') {
            continue;
        }

        int written = snprintf(output + used, size - used, "%s%s", used ? " " : "", buffer);
        used = (written > 0 && (size_t)written < size - used) ? used + (size_t)written : size - 1;
    }

    return wpclose(wfd);
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

        // Read to the end rather than breaking out: an unread pipe kills pfctl
        while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
            if (strstr(output_buf, "Status: Enabled") != NULL) {
                enabled = true;
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

    // Check if wazuh_fwtable exists
    char *exec_cmd_check[] = {pfctl_path, "-t", "wazuh_fwtable", "-T", "show", NULL};
    wfd = wpopenv(pfctl_path, exec_cmd_check, W_BIND_STDOUT | W_BIND_STDERR);

    if (!wfd) {
        write_debug_file(argv0, "Unable to execute pfctl table check");
        os_free(pfctl_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    int check_result = drain_and_close(wfd, NULL, 0);
    bool table_exists = WIFEXITED(check_result) && WEXITSTATUS(check_result) == 0;

    // The table is an administrator-owned precondition, as it is for npf in
    // block-ip-unix.c: decline instead of editing /etc/pf.conf.
    if (!table_exists) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "pf", "check", "wazuh_fwtable table not found");
        os_free(pfctl_path);
        return FIREWALL_INVALID_STATE;
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

    char error_msg[OS_SIZE_1024];
    int wp_closefd = drain_and_close(wfd, error_msg, sizeof(error_msg));

    if (WIFEXITED(wp_closefd) && WEXITSTATUS(wp_closefd) != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        if (error_msg[0] != '\0') {
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

    // "0/1 addresses deleted." means pf never held it. Decline, or the chain
    // stops here and the method that did hold it is never asked to undo it.
    if (action == DISABLE_COMMAND && strstr(error_msg, "0/1 addresses deleted") != NULL) {
        log_firewall_action(argv0, LOG_LEVEL_INFO, "pf", "skip", "address not in wazuh_fwtable");
        os_free(pfctl_path);
        return FIREWALL_INVALID_STATE;
    }

    // If adding, also kill existing connections from this IP
    if (action == ENABLE_COMMAND) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Killing existing connections from %s", srcip);
        write_debug_file(argv0, log_msg);

        char *exec_cmd3[] = {pfctl_path, "-k", (char *)srcip, NULL};
        wfd = wpopenv(pfctl_path, exec_cmd3, W_BIND_STDERR);
        if (wfd) {
            drain_and_close(wfd, NULL, 0);
        }
    }

    os_free(pfctl_path);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// macOS: hosts.deny entries left by an earlier version
// ============================================================================

#define HOSTSDENY_LOCK_PATH "active-response/bin/block-ip-hostsdeny-lock"
#define HOSTSDENY_LOCK_FILE "active-response/bin/block-ip-hostsdeny-lock/pid"
#define DEFAULT_HOSTS_DENY_PATH "/etc/hosts.deny"
#define TEMP_HOSTS_DENY_PATH "active-response/bin/temp-hosts-deny"

static bool is_legacy_rule(const char *line, const char *rule, const char *canonical_rule) {
    return hosts_deny_rule_matches(line, rule) ||
           (canonical_rule[0] != '\0' && hosts_deny_rule_matches(line, canonical_rule));
}

// Read without the lock, so an unblock only waits on it when there is a line to remove
static bool has_legacy_rule(const char *rule, const char *canonical_rule, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR - 25];
    bool found = false;
    FILE *fp = wfopen(DEFAULT_HOSTS_DENY_PATH, "r");

    if (!fp) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", DEFAULT_HOSTS_DENY_PATH);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "unblock", log_msg);
        return false;
    }

    while (!found && fgets(output_buf, sizeof(output_buf), fp)) {
        found = is_legacy_rule(output_buf, rule, canonical_rule);
    }

    fclose(fp);
    return found;
}

// Earlier versions appended "ALL:<ip>", with the address as received, which
// macOS never enforces. Removes that exact line; true if one was removed.
bool remove_legacy_hostsdeny_rule(const char *srcip, const char *argv0) {
    char rule[COMMANDSIZE_4096];
    char canonical_rule[COMMANDSIZE_4096];
    char canonical_ip[NI_MAXHOST];
    char log_msg[OS_MAXSTR];
    char output_buf[OS_MAXSTR - 25];
    FILE *host_deny_fp = NULL;
    FILE *temp_host_deny_fp = NULL;
    bool removed = false;
    bool write_fail = false;
    lock_context_t lock_ctx = {
        .lock_path = HOSTSDENY_LOCK_PATH,
        .lock_pid_path = HOSTSDENY_LOCK_FILE,
        .log_prefix = argv0,
        .acquired = false
    };

    // Absent on a stock install: nothing to clean up
    if (access(DEFAULT_HOSTS_DENY_PATH, F_OK) < 0) {
        return false;
    }

    snprintf(rule, sizeof(rule), "ALL:%s", srcip);
    canonical_rule[0] = '\0';
    if (canonicalize_ip(srcip, canonical_ip, sizeof(canonical_ip)) && strcmp(canonical_ip, srcip) != 0) {
        snprintf(canonical_rule, sizeof(canonical_rule), "ALL:%s", canonical_ip);
    }

    if (!has_legacy_rule(rule, canonical_rule, argv0)) {
        return false;
    }

    if (acquire_ar_lock(&lock_ctx) == OS_INVALID) {
        return false;
    }

    host_deny_fp = wfopen(DEFAULT_HOSTS_DENY_PATH, "r");
    if (!host_deny_fp) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Could not open file '%s' for reading", DEFAULT_HOSTS_DENY_PATH);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "unblock", log_msg);
        release_ar_lock(&lock_ctx);
        return false;
    }

    temp_host_deny_fp = wfopen(TEMP_HOSTS_DENY_PATH, "w");
    if (!temp_host_deny_fp) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Could not create temporary file '%s'", TEMP_HOSTS_DENY_PATH);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "unblock", log_msg);
        fclose(host_deny_fp);
        release_ar_lock(&lock_ctx);
        return false;
    }

    while (fgets(output_buf, sizeof(output_buf), host_deny_fp)) {
        if (is_legacy_rule(output_buf, rule, canonical_rule)) {
            removed = true;
            continue;
        }

        size_t len = strlen(output_buf);
        if (fwrite(output_buf, 1, len, temp_host_deny_fp) != len) {
            write_fail = true;
            break;
        }
    }

    fclose(host_deny_fp);
    if (fclose(temp_host_deny_fp) != 0) {
        write_fail = true;
    }

    // Leave the file alone when nothing matched: replacing it changes its inode and mode
    if (!write_fail && !removed) {
        unlink(TEMP_HOSTS_DENY_PATH);
        release_ar_lock(&lock_ctx);
        return false;
    }

    if (write_fail || OS_MoveFile(TEMP_HOSTS_DENY_PATH, DEFAULT_HOSTS_DENY_PATH) != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Unable to update file '%s'", DEFAULT_HOSTS_DENY_PATH);
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "hostsdeny", "unblock", log_msg);
        unlink(TEMP_HOSTS_DENY_PATH);
        release_ar_lock(&lock_ctx);
        return false;
    }

    unlink(TEMP_HOSTS_DENY_PATH);
    release_ar_lock(&lock_ctx);

    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR - 1, "Removed the entry for %s that an earlier version added to '%s'", srcip,
             DEFAULT_HOSTS_DENY_PATH);
    log_firewall_action(argv0, LOG_LEVEL_INFO, "hostsdeny", "unblock", log_msg);
    return true;
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

    // Only stderr is bound: route(8) always writes to stdout, but writes to
    // stderr only when the routing socket write failed.
    if (action == ENABLE_COMMAND) {
        if (ip_version == 6) {
            char *exec_cmd[] = {route_path, "-q", "add", "-inet6", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        } else {
            char *exec_cmd[] = {route_path, "-q", "add", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        }
    } else {
        if (ip_version == 6) {
            char *exec_cmd[] = {route_path, "-q", "delete", "-inet6", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        } else {
            char *exec_cmd[] = {route_path, "-q", "delete", (char *)srcip, (char *)gateway, "-blackhole", NULL};
            wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
        }
    }

    os_free(route_path);

    if (!wfd) {
        write_debug_file(argv0, "Unable to execute route");
        return FIREWALL_EXECUTION_FAILED;
    }

    char error_msg[OS_SIZE_1024];
    int wp_closefd = drain_and_close(wfd, error_msg, sizeof(error_msg));

    // route(8) exits 0 whatever happens, so the result comes from stderr:
    // empty on success, the reason on failure.
    if (error_msg[0] == '\0') {
        // A non-zero status here means the child never became route.
        if (WIFEXITED(wp_closefd) && WEXITSTATUS(wp_closefd) == 0) {
            return FIREWALL_SUCCESS;
        }

        memset(log_msg, '\0', OS_MAXSTR);
        if (WIFSIGNALED(wp_closefd)) {
            snprintf(log_msg, OS_MAXSTR - 1, "route command terminated by signal %d", WTERMSIG(wp_closefd));
        } else {
            snprintf(log_msg, OS_MAXSTR - 1, "route command did not run (status %d)", wp_closefd);
        }
        write_debug_file(argv0, log_msg);
        return FIREWALL_EXECUTION_FAILED;
    }

    // The route is already there (add) or already gone (delete): the end state
    // is the one that was asked for, so report success either way.
    if (strstr(error_msg, "File exists") != NULL || strstr(error_msg, "not in table") != NULL) {
        return FIREWALL_SUCCESS;
    }

    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR - 1, "route command failed: %s", error_msg);
    write_debug_file(argv0, log_msg);
    return FIREWALL_EXECUTION_FAILED;
}

#endif // __APPLE__
