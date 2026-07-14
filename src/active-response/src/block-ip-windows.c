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

#ifdef WIN32

#include "dll_load_notify.h"

/**
 * Windows-specific block-ip implementation
 *
 * Method chain (first success wins): netsh (Windows Firewall) -> route (null-route).
 * netsh provides true bidirectional (inbound + outbound) blocking, but its rules are only
 * enforced while a firewall profile is enabled. On ENABLE, try_netsh checks the EFFECTIVE
 * firewall state; when the firewall is off it defers to the route fallback, which
 * null-routes the target to loopback (dropping the attacker's reverse path). netsh.exe
 * being unavailable also falls through to route.
 */

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0);
static bool firewall_is_effectively_on(const char *netsh_path, const char *argv0);

int main(int argc, char **argv) {
    // This must always be the first instruction on Windows
    enable_dll_verification();

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

    // Define Windows method chain
    const firewall_method_t methods[] = {
        {"netsh", try_netsh, false},
        {"route", try_route_windows, false},
        {NULL, NULL, false}  // Sentinel
    };

    int ip_version = (strchr(srcip, ':') != NULL) ? 6 : 4;

    // Execute firewall chain with fallback
    int result = execute_firewall_chain(methods, srcip, action, ip_version, argv[0]);

    cJSON_Delete(input_json);
    return result;
}

// ============================================================================
// WINDOWS: effective firewall-state detection
// ============================================================================

// Returns true if ANY firewall profile is effectively enabled (enforcing), read from
// `netsh advfirewall show allprofiles state`. This reports the effective state and, in
// particular, correctly returns ON when the local EnableFirewall value is ABSENT (the
// Windows default).
// On any failure to determine the state (or when the "ON" token is not recognized, e.g.
// on a localized Windows) we return false, so try_netsh conservatively defers to the
// route fallback rather than adding a rule that might never be enforced.
static bool firewall_is_effectively_on(const char *netsh_path, const char *argv0) {
    char *exec_cmd[] = {(char *)netsh_path, "advfirewall", "show", "allprofiles", "state", NULL};
    wfd_t *wfd = wpopenv(netsh_path, exec_cmd, W_BIND_STDOUT);
    if (!wfd) {
        write_debug_file(argv0, "Unable to query firewall state via netsh - assuming disabled");
        return false;
    }

    char output_buf[OS_MAXSTR];
    bool any_on = false;

    while (fgets(output_buf, OS_MAXSTR, wfd->file_out)) {
        char *p = strstr(output_buf, "State");
        if (!p) {
            continue;
        }
        p += 5;  // strlen("State")
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if ((p[0] == 'O' || p[0] == 'o') && (p[1] == 'N' || p[1] == 'n') &&
            (p[2] == '\0' || p[2] == '\r' || p[2] == '\n' || p[2] == ' ' || p[2] == '\t')) {
            any_on = true;
            break;
        }
    }

    wpclose(wfd);
    return any_on;
}

// ============================================================================
// WINDOWS: netsh (Windows Firewall) implementation
// ============================================================================

firewall_result_t try_netsh(const char *srcip, int action, int ip_version, const char *argv0) {
    static const char rule_name[] = "name=\"WAZUH ACTIVE RESPONSE BLOCKED IP\"";
    char log_msg[OS_MAXSTR];
    char *netsh_path = NULL;

    // Check if netsh.exe is available
    if (check_binary_available("netsh.exe", &netsh_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    // A netsh block rule is only enforced while a firewall profile is enabled. On ENABLE,
    // if the firewall is effectively OFF, defer to the route fallback instead of adding a
    // dormant rule. We read the EFFECTIVE state via netsh (which reports ON even when the
    // local EnableFirewall value is absent). This is ENABLE-only: on DISABLE we must
    // always try to remove the rule, which may have been added while the firewall was
    // enabled.
    if (action == ENABLE_COMMAND && !firewall_is_effectively_on(netsh_path, argv0)) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "netsh", "check",
                          "Windows Firewall is effectively disabled - deferring to route fallback");
        os_free(netsh_path);
        return FIREWALL_INVALID_STATE;
    }

    // Single-host prefix for netsh remoteip: /32 for IPv4, /128 for IPv6.
    const char *host_prefix = (ip_version == 6) ? "128" : "32";

    // Build netsh command
    wfd_t *wfd = NULL;

    if (action == ENABLE_COMMAND) {
        // netsh advfirewall firewall add rule name="..." interface=any dir=in action=block remoteip=<IP>/<prefix>
        char remote_ip_arg[OS_MAXSTR];
        memset(remote_ip_arg, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, host_prefix);

        char *exec_cmd_in[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            (char *)rule_name,
            "interface=any",
            "dir=in",
            "action=block",
            remote_ip_arg,
            NULL
        };

        // Add inbound rule
        wfd = wpopenv(netsh_path, exec_cmd_in, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute netsh add rule (inbound)");
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        int result_in = wpclose(wfd);
        if (result_in != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "netsh inbound rule failed with exit code %d", result_in);
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        // Add outbound rule (from PR #34675 fix for bidirectional blocking)
        char remote_ip_arg_out[OS_MAXSTR];
        memset(remote_ip_arg_out, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg_out, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, host_prefix);

        char *exec_cmd_out[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            (char *)rule_name,
            "interface=any",
            "dir=out",
            "action=block",
            remote_ip_arg_out,
            NULL
        };

        wfd = wpopenv(netsh_path, exec_cmd_out, W_BIND_STDERR);
        if (wfd) {
            int result_out = wpclose(wfd);
            if (result_out != 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1, "netsh outbound rule failed with exit code %d", result_out);
                write_debug_file(argv0, log_msg);
                // Don't fail - outbound rule is optional
            }
        }

    } else {
        // DELETE: netsh advfirewall firewall delete rule name="..." remoteip=<IP>/32
        char remote_ip_arg_del[OS_MAXSTR];
        memset(remote_ip_arg_del, '\0', OS_MAXSTR);
        snprintf(remote_ip_arg_del, OS_MAXSTR - 1, "remoteip=%s/%s", srcip, host_prefix);

        char *exec_cmd[] = {
            netsh_path,
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            (char *)rule_name,
            remote_ip_arg_del,
            NULL
        };

        wfd = wpopenv(netsh_path, exec_cmd, W_BIND_STDERR);
        if (!wfd) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "Unable to execute netsh delete rule");
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }

        int result_del = wpclose(wfd);
        if (result_del != 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1, "netsh delete rule failed with exit code %d", result_del);
            write_debug_file(argv0, log_msg);
            os_free(netsh_path);
            return FIREWALL_EXECUTION_FAILED;
        }
    }

    os_free(netsh_path);
    return FIREWALL_SUCCESS;
}

// ============================================================================
// WINDOWS: route implementation (fallback)
// ============================================================================

firewall_result_t try_route_windows(const char *srcip, int action, int ip_version, const char *argv0) {
    char log_msg[OS_MAXSTR];
    char *route_path = NULL;

    // Reached when netsh is unavailable, or (via try_netsh) when the firewall is
    // effectively OFF. BEST-EFFORT: null-routes the target to loopback so the host drops
    // packets destined to it, which in principle also breaks the reverse path of inbound
    // TCP sessions to a routed/remote attacker.
    // LIMITATION: this does NOT block a target on a directly-connected
    // subnet - on-link hosts are reached via ARP and the /32-via-loopback route does not
    // redirect that egress. Effectiveness against routed/remote attackers was not verified.
    // netsh (Windows Firewall) remains the only comprehensive blocking mechanism.

    // The IPv4 mask below only applies to IPv4 targets; netsh already covers IPv6.
    if (ip_version == 6) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "check",
                          "route fallback supports IPv4 only - skipping IPv6 target");
        return FIREWALL_NOT_AVAILABLE;
    }

    // Check if route.exe is available
    if (check_binary_available("route.exe", &route_path, argv0) != FIREWALL_SUCCESS) {
        return FIREWALL_NOT_AVAILABLE;
    }

    if (action == ENABLE_COMMAND) {
        log_firewall_action(argv0, LOG_LEVEL_WARNING, "route", "best_effort",
                          "Applying best-effort null-route (firewall off or netsh unavailable): "
                          "blocks routed/remote attackers but NOT same-subnet hosts - enable "
                          "Windows Firewall for comprehensive blocking");
    }

    char **exec_cmd = NULL;
    // Null-route to the loopback so outbound packets to the target are discarded.
    char *add_cmd[] = {route_path, "-p", "ADD", (char *)srcip,
                       "MASK", "255.255.255.255", "127.0.0.1", NULL};
    char *del_cmd[] = {route_path, "DELETE", (char *)srcip, NULL};
    exec_cmd = (action == ENABLE_COMMAND) ? add_cmd : del_cmd;

    wfd_t *wfd = wpopenv(route_path, exec_cmd, W_BIND_STDERR);
    if (!wfd) {
        os_free(route_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    int rc = wpclose(wfd);
    if (rc != 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "route %s failed with exit code %d",
                 action == ENABLE_COMMAND ? "add" : "delete", rc);
        write_debug_file(argv0, log_msg);
        os_free(route_path);
        return FIREWALL_EXECUTION_FAILED;
    }

    os_free(route_path);
    return FIREWALL_SUCCESS;
}

#endif // WIN32
